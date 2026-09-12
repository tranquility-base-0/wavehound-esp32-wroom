#include "radio.h"
#include "osint/vendor.h"
#include "capture/capture.h"
#include "modes/ble.h"
#include "UbuntuMono_Regular9pt7b.h"
#include <string.h>
#include <stdio.h>

RadioMode currentRadioMode = RADIO_WIFI;
int current_ch_idx = 0;
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

  // 3. HARDWARE ANTENNA TOGGLE
  if (targetMode == RADIO_WIFI || targetMode == RADIO_AP || targetMode == RADIO_CHANNELS) {
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
  
  // 4. Open the gate!
  pause_sniffing = false; 

  // Session reset for the cumulative PCAP waterfall counters (matching the
  // wipe above); reset AFTER the gate opens so no in-flight callback can
  // re-increment between the zeroing and the mode change.
  pcap_upstream_total  = 0;
  pcap_displayed_total = 0;
}

bool updateRadioHopper() {
    bool trigger_render = false; // Local render trigger

    // THE FIX: Added SCREEN_LEAK_LIST so the radio continues scanning the spectrum
    if (currentState == SCREEN_CHART || currentState == SCREEN_FOXHUNT || currentState == SCREEN_LEAK_LIST) {
        static unsigned long lastTimer = 0;

        tft.setTextWrap(false);

        // ==========================================
        // RADIO-AWARE TIMERS
        // ==========================================
        // Both Wi-Fi and AP modes need the Channel Hopper!
        if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP || currentRadioMode == RADIO_CHANNELS || currentRadioMode == RADIO_PCAP) {
            if (!target_locked) {
                if (millis() - lastTimer > HOP_INTERVAL) {
                    lastTimer = millis();
                    current_ch_idx++;

                    if (current_ch_idx >= NUM_CHANNELS) {
                        current_ch_idx = 0;
                        trigger_render = true; // Replaces should_render = true
                    }

                    esp_wifi_set_channel(CHANNELS[current_ch_idx], WIFI_SECOND_CHAN_NONE);

                    // Only draw the channel indicator if we are on the main chart!
                    if (currentState == SCREEN_CHART) {
                        // 1. Reduced width from 75 to 62 to prevent clipping the " | "
                        tft.fillRect(5, 0, 62, 20, TFT_BLACK);
                        
                        tft.setFreeFont(&UbuntuMono_Regular9pt7b);
                        tft.setTextDatum(TL_DATUM);
                        
                        tft.setTextColor(COLOR_HOT_CHEST);

                        char chStr[16];
                        sprintf(chStr, "CH: %02d", CHANNELS[current_ch_idx]);
                        
                        // 2. Changed y from 0 to 1 to match drawChartHeader() exactly
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
                    tft.drawString("SNIFFING BLE DEVICES", 5, 4);
                }
            }
        }
    }
    
    return trigger_render;
}

