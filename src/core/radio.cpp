#include "radio.h"
#include "esp_chip_info.h" // official chip-identification API (radioHas5GHz)
#include "osint/vendor.h"
#include "osint/osint.h"  // initProbeTracker() for the CT-entry retention re-init
#include "modes/ct.h"     // ct_dwell_ms / ct_timing_apply(): CT F1 timing foundation
#include "capture/capture.h"
#include "modes/ble.h"
#include "UbuntuMono_Regular9pt7b.h"
#include <string.h>
#include <stdio.h>

RadioMode currentRadioMode = RADIO_WIFI;
int current_ch_idx = 0;

// ---------------------------------------------------------------------------
// Chip capability groundwork for the eventual ESP32-C5 dual-band target.
// 5 GHz support (channels, band switching, hopping) is NOT implemented; this
// only reports whether the running chip is 5 GHz-capable. Detection uses the
// official Espressif chip-identification API and is cached after the first
// query. On the current esp32dev/WROOM build the IDF target macro resolves
// the answer at compile time to false, so behavior is unchanged; on a future
// C5 build environment esp_chip_info() confirms the chip at runtime.
bool radioHas5GHz() {
  static bool cached_5ghz = false;    // chip model is fixed for the lifetime
  static bool cached_init = false;
  if (!cached_init) {
    cached_init = true;
#if defined(CONFIG_IDF_TARGET_ESP32C5)
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    cached_5ghz = (chip.model == CHIP_ESP32C5); // C5: 2.4 GHz + 5 GHz capable
#else
    cached_5ghz = false;                        // esp32dev/WROOM: 2.4 GHz only
#endif
  }
  return cached_5ghz;
}
uint8_t hop_channels[NUM_CHANNELS]; // custom hop set (0 = unused slot)
uint8_t hop_count = 0;              // 0 = full CHANNELS[] sweep
uint8_t hop_pos = 0;
uint8_t target_bssid[6] = {0};
int target_channel = 0;
bool target_locked = false;
char target_ssid[33] = {0};

static bool ble_initialized = false;

class BLEPassiveCallbacks: public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice* advertisedDevice) {
    if (pause_sniffing) return;

    const uint8_t* rawMac = advertisedDevice->getAddress().getNative();

    // ==========================================
    // BLE FOXHUNT ISR FEEDER
    // ==========================================
    if (is_foxhunting) {
        if (memcmp(rawMac, foxhunt_target_mac, 6) == 0) {
            updateFoxhuntSignal(advertisedDevice->getRSSI());
        }
    }

    // ==========================================
    // ON-THE-FLY RAW HEX DUMP (DISABLED: hot-path serial spam)
    // ==========================================
    // uint8_t* rawPayload = advertisedDevice->getPayload();
    // size_t payloadLen = advertisedDevice->getPayloadLength();
    //
    // // Print MAC directly from bytes to avoid NimBLE's .toString() std::string allocation
    // Serial.printf("RAW [%02d bytes] MAC: %02X:%02X:%02X:%02X:%02X:%02X | ",
    //               payloadLen, rawMac[5], rawMac[4], rawMac[3], rawMac[2], rawMac[1], rawMac[0]);
    //
    // for (size_t p = 0; p < payloadLen; p++) {
    //     Serial.printf("%02X ", rawPayload[p]);
    // }
    // Serial.println();

    int rssi = advertisedDevice->getRSSI();
    int txPower = advertisedDevice->haveTXPower() ? advertisedDevice->getTXPower() : 0;
    int sdCount = advertisedDevice->getServiceDataCount();

    // ==========================================
    // DE-STRINGIFIED PARSING VARIABLES
    // ==========================================
    char tempName[25] = {0};
    uint8_t tempPriority = 0;

    uint8_t newTrackerType = TRACKER_NONE;
    uint16_t newAppearanceId = 0;
    uint16_t newServiceId = 0;

    // ==========================================
    // STEP 1: Name (Priority 4)
    // ==========================================
    if (advertisedDevice->haveName()) {
        strlcpy(tempName, advertisedDevice->getName().c_str(), sizeof(tempName));
        tempPriority = 4;
    }

    // ==========================================
    // STEP 2: Manufacturer Data (Priority 1 & 2)
    // ==========================================
    if (advertisedDevice->haveManufacturerData()) {
        // NimBLE forces a std::string return here, but we immediately extract its data
        std::string mfg = advertisedDevice->getManufacturerData();

        if (mfg.length() >= 2) {
            uint16_t companyId = (uint8_t)mfg[1] << 8 | (uint8_t)mfg[0];
            const char* resolvedCompany = resolveBleCompanyId(companyId);

            // Identify Tracker Types
            if (companyId == 0x004C && mfg.length() >= 3 && mfg[2] == 0x12) newTrackerType = TRACKER_APPLE_FINDMY;
            else if (companyId == 0x004C && mfg.length() >= 3 && mfg[2] == 0x02) newTrackerType = TRACKER_APPLE_IBEACON;
            else if (companyId == 0x00E0 && mfg.length() >= 3 && mfg[2] == 0xFC) newTrackerType = TRACKER_GOOGLE_FASTPAIR;
            else if (companyId == 0x000D) newTrackerType = TRACKER_TILE;
            else if (companyId == 0x0075 && mfg.length() >= 3 && mfg[2] == 0x42) newTrackerType = TRACKER_SAMSUNG_SMARTTAG;
            else if (companyId == 0x0006 && mfg.length() >= 3 && mfg[2] == 0x09) newTrackerType = TRACKER_MS_SWIFTPAIR;

            // Only format manufacturer strings if we don't already have a better name (Priority 3 or 4)
            if (tempPriority < 2) {
                if (newTrackerType != TRACKER_NONE) {
                    if (newTrackerType == TRACKER_APPLE_FINDMY) strlcpy(tempName, "Apple Find My", sizeof(tempName));
                    else if (newTrackerType == TRACKER_APPLE_IBEACON) strlcpy(tempName, "Apple iBeacon", sizeof(tempName));
                    else if (newTrackerType == TRACKER_GOOGLE_FASTPAIR) strlcpy(tempName, "Google FastPair", sizeof(tempName));
                    else if (newTrackerType == TRACKER_SAMSUNG_SMARTTAG) strlcpy(tempName, "Samsung SmartTag", sizeof(tempName));
                    else if (newTrackerType == TRACKER_TILE) strlcpy(tempName, "Tile Tracker", sizeof(tempName));
                    else if (newTrackerType == TRACKER_MS_SWIFTPAIR) strlcpy(tempName, "MS Swift Pair", sizeof(tempName));

                    tempPriority = 2; // Priority 2: Known Tracker Type
                }
                else if (resolvedCompany != nullptr && tempPriority < 1) {
                    if (mfg.length() >= 3) {
                        snprintf(tempName, sizeof(tempName), "%.12s:0x%02X", resolvedCompany, (uint8_t)mfg[2]);
                    } else {
                        snprintf(tempName, sizeof(tempName), "%.24s", resolvedCompany);
                    }
                    tempPriority = 1; // Priority 1: Manufacturer Fallback
                }
            }
        }
    }

    // ==========================================
    // STEP 3: Corporate Trackers & Eddystone (0x16)
    // ==========================================
    for (int k = 0; k < sdCount; k++) {
        NimBLEUUID sdUUID = advertisedDevice->getServiceDataUUID(k);

        if (sdUUID.bitSize() == 16) {
            uint16_t uuid16 = sdUUID.getNative()->u16.value;

            if (uuid16 == 0xFEAA) {
                newTrackerType = TRACKER_EDDYSTONE;

                // Only decode the URL if we don't have a real Broadcast Name (Priority 4)
                if (tempPriority < 4) {
                    decodeEddystoneURL(advertisedDevice->getServiceData(k), tempName, sizeof(tempName));
                    tempPriority = 3; // Priority 3: Eddystone URL
                }
                break;
            }

            if (newServiceId == 0) {
                newServiceId = uuid16;
            }
        }
    }

    // ==========================================
    // STEP 4: Appearance (0x19) & Standard Services
    // ==========================================
    if (advertisedDevice->haveAppearance()) {
        newAppearanceId = advertisedDevice->getAppearance();
    }

    if (advertisedDevice->haveServiceUUID()) {
        NimBLEUUID sUUID = advertisedDevice->getServiceUUID();
        if (sUUID.bitSize() == 16 && newServiceId == 0) {
            newServiceId = sUUID.getNative()->u16.value;
        }
    }

    // ==========================================
    // ARRAY MATCHING & STRUCT UPDATES (The Gatekeeper)
    // ==========================================
    bool found = false;

    for (int i = 0; i < liveBleCount; i++) {
        if (memcmp((void*)(uint8_t*)liveBleData[i].mac, rawMac, 6) == 0) {
            liveBleData[i].hits++;
            liveBleData[i].lastSeen = millis();
            liveBleData[i].rssi = rssi;
            liveBleData[i].txPower = txPower;

            // THE GATEKEEPER: Only overwrite the name if the new string has higher priority,
            // or if it's an equal priority update (e.g., an Eddystone URL changing)
            if (tempPriority > liveBleData[i].namePriority ||
               (tempPriority == liveBleData[i].namePriority && tempPriority > 0)) {

                strlcpy((char*)liveBleData[i].name, tempName, sizeof(liveBleData[i].name));
                liveBleData[i].namePriority = tempPriority;
            }

            if (newTrackerType != TRACKER_NONE) liveBleData[i].trackerType = newTrackerType;
            if (newAppearanceId != 0) liveBleData[i].appearanceId = newAppearanceId;
            if (newServiceId != 0) liveBleData[i].serviceId = newServiceId;

            found = true;
            break;
        }
    }

    if (!found && liveBleCount < MAX_BLE_DEVICES) {
        memcpy((void*)(uint8_t*)liveBleData[liveBleCount].mac, rawMac, 6);

        // First time seeing it, write whatever we have and establish the baseline priority
        strlcpy((char*)liveBleData[liveBleCount].name, tempName, sizeof(liveBleData[liveBleCount].name));
        liveBleData[liveBleCount].namePriority = tempPriority;

        liveBleData[liveBleCount].trackerType = newTrackerType;
        liveBleData[liveBleCount].appearanceId = newAppearanceId;
        liveBleData[liveBleCount].serviceId = newServiceId;

        liveBleData[liveBleCount].rssi = rssi;
        liveBleData[liveBleCount].hits = 1;
        liveBleData[liveBleCount].txPower = txPower;

        liveBleData[liveBleCount].firstSeen = millis();
        liveBleData[liveBleCount].lastSeen = millis();

        liveBleCount++;
    }
  }
};


// ---------------------------------------------------------------------------
// SELECT CH keypad parser (Step-1 menu refinement)
// Grammar:  list   := channel (',' channel)*
//           channel := number ('-' number)?
// Whitespace is not accepted. The result is deduped in ascending encounter
// order; range bounds and values are validated against CHANNELS[] so the
// accepted range always matches the firmware's radio table (1..13).
bool parseChannelList(const char *s, uint8_t *out, uint8_t *out_count) {
  const int ch_min = CHANNELS[0];
  const int ch_max = CHANNELS[NUM_CHANNELS - 1];
  bool seen[NUM_CHANNELS + 1] = {false}; // index by channel number (1..13)
  uint8_t count = 0;
  const char *p = s;

  if (s == nullptr || *s == '\0') return false; // reject empty input

  while (*p != '\0') {
    if (*p < '0' || *p > '9') return false; // each item starts with a digit
    int a = 0;
    int digits = 0;
    while (*p >= '0' && *p <= '9') {
      a = a * 10 + (*p - '0');
      p++;
      if (++digits > 2) return false; // no channel is 3+ digits
    }
    if (a < ch_min || a > ch_max) return false;
    int b = a;
    if (*p == '-') {
      p++;
      if (*p < '0' || *p > '9') return false;
      b = 0;
      digits = 0;
      while (*p >= '0' && *p <= '9') {
        b = b * 10 + (*p - '0');
        p++;
        if (++digits > 2) return false;
      }
      if (b < ch_min || b > ch_max || b < a) return false; // empty/invalid range
    }
    for (int c = a; c <= b; c++) { // expand ranges, dedupe channels
      if (!seen[c]) {
        seen[c] = true;
        if (count >= NUM_CHANNELS) return false;
        out[count++] = (uint8_t)c;
      }
    }
    if (*p == ',') {          // next item must follow a separator
      p++;
      if (*p == '\0') return false; // reject trailing comma
    } else if (*p != '\0') {
      return false;               // any other trailing character is malformed
    }
  }

  if (count == 0) return false;
  *out_count = count;
  return true;
}

// Apply a validated channel set to the radio in one fenced-shaped step:
// hop list, position, hardware channel, and the current_ch_idx sync
// invariant (CHANNELS[current_ch_idx] attribution and CT's per-window
// channel mask both index by current_ch_idx = channel - 1). CT calls this
// at a statistical-window boundary while its capture fence is already up.
void radio_apply_channel_set(const uint8_t *chans, uint8_t cnt) {
  if (chans == nullptr || cnt == 0) return;
  memcpy(hop_channels, chans, cnt);
  hop_count = cnt;
  // Arm at the LAST slot: the hopper pre-increments before tuning, so the
  // first fire after this apply wraps to slot 0 (the lowest channel), which
  // is where the radio is already parked below.
  hop_pos = cnt - 1;
  current_ch_idx = hop_channels[0] - 1; // CHANNELS[] = 1..13
  esp_wifi_set_channel(hop_channels[0], WIFI_SECOND_CHAN_NONE);
}

void switchRadioMode(RadioMode targetMode) {
  if (currentRadioMode == targetMode) return;

  // 1. Close the software gate IMMEDIATELY
  pause_sniffing = true;
  delay(10); // Give the interrupt callback 10ms to finish parsing

  // 2. WIPE ARRAYS (Manual wipe ensures the software gate stays closed!)
  memset((void*)sessionData, 0, sizeof(sessionData));
  memset((void*)sortData, 0, sizeof(sortData));
  memset((void*)liveData, 0, sizeof(liveData));

  sessionMacCount = 0; sortMacCount = 0; liveMacCount = 0;
  sessionOtherBytes = 0; liveOtherBytes = 0;
  sessionBleCount = 0; sortBleCount = 0; liveBleCount = 0;
  sessionApCount = 0; sortApCount = 0; liveApCount = 0;
  sessionChannelCount = 0; sortChannelCount = 0; liveChannelCount = 0;

  // The SELECT CH custom hop set is mode-local: every mode transition
  // forgets it and the new mode starts from the default full CHANNELS[]
  // sweep. START/RESUME within the same mode is unaffected (early return
  // above skips this whole block).
  hop_count = 0;
  hop_pos = 0;
  // Arm the sweep to START AT THE LOWEST CHANNEL: the hopper pre-increments
  // before tuning, so the armed position is one before CHANNELS[0]; the
  // first fire wraps to channel 1. Locked modes keep their own channel
  // state (the locked branch never hops).
  if (!target_locked) current_ch_idx = NUM_CHANNELS - 1;

  // 3. HARDWARE ANTENNA TOGGLE
  // RADIO_CT reuses the Wi-Fi promiscuous/capture initialization path
  // verbatim (BLE sleep, Wi-Fi wake, promiscuous on, callback reattach) —
  // CT observes the same RF environment the Wi-Fi modes do. RADIO_PCAP is
  // deliberately NOT added here: it inherits the prior mode's radio state
  // (documented latent quirk), and this step must not change that.
  if (targetMode == RADIO_WIFI || targetMode == RADIO_AP || targetMode == RADIO_CHANNELS || targetMode == RADIO_CT) {
    // Put BLE to sleep so Wi-Fi gets 100% of the antenna
    if (pBLEScan != nullptr) {
      pBLEScan->stop();
      pBLEScan->clearResults();
    }
    // Wake up Wi-Fi
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_promiscuous(true);

    // THE MISSING LINK: Reattach the interrupt!
    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);

  } else if (targetMode == RADIO_BLE) {
    // Violently kill Wi-Fi to free the antenna lock
    esp_wifi_set_promiscuous(false);
    WiFi.mode(WIFI_OFF);

    // Cold Boot BLE the very first time
    if (!ble_initialized) {
      BLEDevice::init("");
      pBLEScan = BLEDevice::getScan();
      pBLEScan->setAdvertisedDeviceCallbacks(new BLEPassiveCallbacks(), true);
      pBLEScan->setActiveScan(false);
      pBLEScan->setInterval(100);
      pBLEScan->setWindow(99);
      ble_initialized = true;
    }
    pBLEScan->clearResults();
    pBLEScan->start(0, nullptr, false);
  }

  currentRadioMode = targetMode;

  // CT probe retention re-init: the blanket union wipe above zeroed
  // ctState.probe_list, but the tracker's non-zero sentinels (chain heads,
  // rssi floor, vendor defaults, rotation counters) must be restored before
  // CT resumes accumulating. initProbeTracker() also resets the global
  // ssidPool so no stale first_ssid_idx chains survive the entry.
  if (targetMode == RADIO_CT) initProbeTracker();
  // CT F1 timing: derive dwell/window for the freshly selected channel set
  // (hop_count was reset above, so CT entry always starts from the full
  // sweep: k=1, dwell=385, window=5005 for the default 13-channel set).
  if (targetMode == RADIO_CT) ct_timing_apply();

  // 4. Open the gate!
  pause_sniffing = false;

  // Session reset for the cumulative PCAP waterfall counters (matching the
  // wipe above); reset AFTER the gate opens so no in-flight callback can
  // re-increment between the zeroing and the mode change.
  pcap_upstream_total  = 0;
  pcap_cooldown_total  = 0;
  pcap_displayed_total = 0;
}

bool updateRadioHopper() {
    bool trigger_render = false; // Local render trigger

    // Include SCREEN_LEAK_LIST so the radio keeps scanning while the leak list is on screen.
    if (currentState == SCREEN_CHART || currentState == SCREEN_FOXHUNT || currentState == SCREEN_LEAK_LIST) {
        static unsigned long lastTimer = 0;
        // Wall-clock waterfall column pacing for the non-CT Wi-Fi-family
        // modes: one column per ~5 s regardless of N and sweep length
        // (CT paces on its statistical-window close instead). Reset by
        // request only; carries across mode switches by design.
        static unsigned long last_col_ms = 0;

        tft.setTextWrap(false);

        // ==========================================
        // RADIO-AWARE TIMERS
        // ==========================================
        // Both Wi-Fi and AP modes need the Channel Hopper! CT hops too —
        // its environment signal is defined over a full channel sweep.
        if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP || currentRadioMode == RADIO_CHANNELS || currentRadioMode == RADIO_PCAP || currentRadioMode == RADIO_CT) {
            if (!target_locked) {
                if (millis() - lastTimer > ct_hop_interval()) {
                    lastTimer = millis();
                    uint8_t hop_ch; // channel being applied this tick

                    if (hop_count > 0) {
                        // Custom channel set (SELECT CH keypad): cycle the
                        // user's list instead of the full CHANNELS[] sweep.
                        // Keep the full-sweep index in sync so CHANNELS-mode
                        // attribution (CHANNELS[current_ch_idx]) stays valid,
                        // and render once per set-cycle like the full sweep
                        // (otherwise the render/processing gate starves and
                        // the chart shows zero traffic).
                        hop_pos = (hop_pos + 1) % hop_count;
                        hop_ch = hop_channels[hop_pos];
                        current_ch_idx = hop_ch - 1; // CHANNELS[] = 1..13
                        // Column pacing (non-CT): fire at the SWEEP BOUNDARY
                        // once ~5 s of wall time has elapsed, so the bar
                        // always lands on the same channel (the set's lowest)
                        // AND the cadence stays ~5 s regardless of sweep
                        // length. A pure wall-clock tick drifts against the
                        // sweep (renders make sweeps run slightly long) and
                        // the bar's landing channel slides around the set.
                        if (hop_pos == 0 && currentRadioMode != RADIO_CT &&
                            millis() - last_col_ms >= (unsigned long)CT_WIFI_WINDOW_MS) {
                            last_col_ms = millis();
                            trigger_render = true;
                        }
                    } else {
                        current_ch_idx++;
                        if (current_ch_idx >= NUM_CHANNELS) {
                            current_ch_idx = 0;
                            // Same boundary-anchored column pacing for the
                            // default full sweep (fires at the channel-1
                            // wrap, ~5 s or one sweep apart, whichever is
                            // later). CT is excluded: window-paced instead.
                            if (currentRadioMode != RADIO_CT &&
                                millis() - last_col_ms >= (unsigned long)CT_WIFI_WINDOW_MS) {
                                last_col_ms = millis();
                                trigger_render = true;
                            }
                        }
                        hop_ch = CHANNELS[current_ch_idx];
                    }

                    esp_wifi_set_channel(hop_ch, WIFI_SECOND_CHAN_NONE);

                    // Only draw the channel indicator if we are on the main chart!
                    if (currentState == SCREEN_CHART) {
                        tft.setFreeFont(&UbuntuMono_Regular9pt7b);
                        tft.setTextDatum(TL_DATUM);
                        tft.setTextColor(COLOR_HOT_CHEST);

                        // Digit-adaptive compact prefix matching
                        // drawChartHeader()'s fmtChPrefix() ("CH:06|" today,
                        // "CH:149|" for future C5 channels); the wipe width
                        // derives from text metrics so neither a third digit
                        // nor the pipe can collide with the banner tail.
                        char chStr[16];
                        snprintf(chStr, sizeof(chStr),
                                 (hop_ch >= 100) ? "CH:%03d|" : "CH:%02d|", hop_ch);
                        int wipe_w = tft.textWidth(chStr) + 8;
                        tft.fillRect(5, 0, wipe_w, 20, TFT_BLACK);

                        // Changed y from 0 to 1 to match drawChartHeader() exactly
                        tft.drawString(chStr, 5, 1);
                    }
                }
            }
            else {
                // High-speed drain for Foxhunting / Target Locking
                if (millis() - lastTimer > LOCKED_UPDATE_INTERVAL) {
                    lastTimer = millis();
                    trigger_render = true; // Replaces should_render = true
                }
            }
        }
        else if (currentRadioMode == RADIO_BLE) {
            // BLE MODE WATERFALL
            if (millis() - lastTimer > BLE_UPDATE_INTERVAL) {
                lastTimer = millis();
                trigger_render = true; // Replaces should_render = true

                // Only draw the BLE sniffing indicator if we are on the main chart!
                if (currentState == SCREEN_CHART) {
                    tft.fillRect(5, 0, 200, 20, TFT_BLACK);
                    tft.setFreeFont(&UbuntuMono_Regular9pt7b);
                    tft.setTextDatum(TL_DATUM);
                    tft.setTextColor(COLOR_HOT_CHEST);
                    tft.drawString("SCANNING BLE DEVICES", 5, 4);
                }
            }
        }
    }

    return trigger_render;
}

