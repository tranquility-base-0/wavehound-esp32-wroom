#include "input.h"
#include "ui_utils.h"
#include "ui_state.h"
#include "views/chart.h"
#include "views/lists.h"
#include "views/foxhunt.h"
#include "core/radio.h"
#include "core/wavehound_state.h"
#include "capture/capture.h"
#include "modes/wifi.h"
#include "modes/ap_scanner.h"
#include "modes/ble.h"
#include "modes/channel_scanner.h"
#include "osint/osint.h"
#include "UbuntuMono_Regular9pt7b.h"
#include <string.h>
#include <stdio.h>

static void forceSessionSort() {
  if (currentRadioMode == RADIO_WIFI) {
    insertionSort(sessionData, sessionMacCount, sizeof(MacRecord),
                  (int)currentSortMode, sort_descending, uiSortMetricWifi);
  }
  else if (currentRadioMode == RADIO_BLE) {
    insertionSort(sessionBleData, sessionBleCount, sizeof(BLERecord),
                  (int)currentBleSortMode, sort_descending,
                  uiSortMetricBle, uiSortKeyValidBle);
  }
  else if (currentRadioMode == RADIO_AP) {
    insertionSort(sessionApData, sessionApCount, sizeof(ApRecord),
                  (int)currentSortMode, sort_descending, uiSortMetricAp);
  }
  else if (currentRadioMode == RADIO_CHANNELS) {
    // Original forceSessionSort guard was key_val > 0.0 (not the
    // channel_scanner.cpp "!= 0" variant) — keep nullptr default.
    insertionSort(sessionChannelData, sessionChannelCount,
                  sizeof(ChannelRecord), (int)currentSortMode,
                  sort_descending, uiSortMetricChannel);
  }
}

// --- SELECT CH keypad state (menu-local; capture stays paused while open) ---
static bool   ch_keypad_open = false;
static char   ch_buf[40];       // raw text: "1,6,11-13"
static int    ch_len = 0;
static const char *ch_err = nullptr;
// One-press-one-key debounce: a key is accepted only on a down-edge
// (fresh_press) AND at least KEYPAD_DEBOUNCE_MS after the previous key,
// which also swallows single-frame touch dropouts mid-press. Holding a
// finger therefore never generates repeats.
static const unsigned long KEYPAD_DEBOUNCE_MS = 150;
static unsigned long ch_last_press_ms = 0;

// Redraw only the keypad echo line (called on each keypress).
static void ch_keypad_echo() {
  drawMenuKeypad(ch_buf, ch_err);
}

bool handleTouchInputs(uint16_t t_x, uint16_t t_y, bool fresh_press) {
  bool trigger_render = false; // 1. Create local tracking variable

    // ==========================================
    // 1. CHART SCREEN TOUCH LOGIC
    // ==========================================
    if (currentState == SCREEN_CHART) {
      // TOP RIGHT: Menu Button
      if (t_x > 400 && t_y < 40) {
        currentState = SCREEN_MENU;
        menu_selection = (int)currentRadioMode; // submenu follows this mode
        pause_sniffing = true;
        esp_wifi_set_promiscuous(false);
        drawMenu();
        delay(300);
      }

      // BOTTOM FOOTER: Live Data Controls
      else if (t_y > 260) {

        // ==========================================
        // ZONE 1 (Left 0-145): SORT METRIC
        // ==========================================
        if (t_x < CHART_FOOT_TOUCH_X1) {
          // 1. Wipe the inside
          tft.fillRect(3, 299, 139, 17, TFT_BLACK);

          // 2. Toggle the variable
          if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP) {
            if (currentSortMode == SORT_TOTAL) currentSortMode = SORT_TX;
            else if (currentSortMode == SORT_TX) currentSortMode = SORT_RX;
            else if (currentSortMode == SORT_RX) currentSortMode = SORT_AVG;
            else if (currentSortMode == SORT_AVG) currentSortMode = SORT_CV;
            else if (currentSortMode == SORT_CV) currentSortMode = SORT_DIST;
            else if (currentSortMode == SORT_DIST) currentSortMode = SORT_AGE;
            else currentSortMode = SORT_TOTAL;
          }
          else if (currentRadioMode == RADIO_CHANNELS) {
            if (currentSortMode == SORT_TOTAL) currentSortMode = SORT_TX;
            else if (currentSortMode == SORT_TX) currentSortMode = SORT_RX;
            else if (currentSortMode == SORT_RX) currentSortMode = SORT_AVG;
            else if (currentSortMode == SORT_AVG) currentSortMode = SORT_CV;
            else if (currentSortMode == SORT_CV) currentSortMode = SORT_DIST;
            else if (currentSortMode == SORT_DIST) currentSortMode = SORT_AGE;
            else currentSortMode = SORT_TOTAL;
          }
          else if (currentRadioMode == RADIO_BLE) {
            if (currentBleSortMode == SORT_BLE_HITS) currentBleSortMode = SORT_BLE_DIST;
            else if (currentBleSortMode == SORT_BLE_DIST) currentBleSortMode = SORT_BLE_AGE;
            else currentBleSortMode = SORT_BLE_HITS;
          }
          // --- ADDED PCAP LIVE TOGGLE ---
          else if (currentRadioMode == RADIO_PCAP) {
            if (currentLeakSort == SORT_LEAK_AGE) currentLeakSort = SORT_LEAK_LENGTH;
            else if (currentLeakSort == SORT_LEAK_LENGTH) currentLeakSort = SORT_LEAK_HITS;
            else currentLeakSort = SORT_LEAK_AGE;
          }

          // 3. Redraw
          drawChartFooter();
          trigger_render = true; // Trigger the engine to re-sort and redraw the bars
          delay(200);
        }

        // ==========================================
        // ZONE 2 (Center 145-290): SORT DIRECTION
        // ==========================================
        else if (t_x >= CHART_FOOT_TOUCH_X1 && t_x <= CHART_FOOT_TOUCH_X2) {
          tft.fillRect(148, 299, 139, 17, TFT_BLACK);
          sort_descending = !sort_descending;
          drawChartFooter();
          delay(200);
        }

        // ==========================================
        // ZONE 3 (Right 290-435): LOG/LINEAR SCALE
        // (chart-bearing modes only — CT has no scale control; its traffic
        // pane is always linear absolute bytes, so taps there do nothing)
        // ==========================================
        else if (currentRadioMode != RADIO_CT && t_x > CHART_FOOT_TOUCH_X2 && t_x <= CHART_FOOT_TOUCH_X3) {
          tft.fillRect(293, 299, 139, 17, TFT_BLACK);
          useLogScale = !useLogScale;
          drawChartFooter();
          delay(200);
        }
      }
    }

    // ==========================================
    // 2. MENU SCREEN TOUCH LOGIC (two-column main menu + mode submenu)
    //    Left column: one button per radio mode + SETTINGS.
    //    Right column: the selected entry's submenu actions.
    //    Capture stays gated for the whole visit; START/RESUME SCAN (the
    //    last row of each submenu) leaves via the old EXIT path (gate
    //    reopen + channel relock) to the real-time screen.
    // ==========================================
    else if (currentState == SCREEN_MENU) {

      // ---- SELECT CH KEYPAD (open state consumes all touches) ----
      if (ch_keypad_open) {
        bool key_accept = fresh_press &&
                          (millis() - ch_last_press_ms) >= KEYPAD_DEBOUNCE_MS;
        for (int k = 0; k < 15 && key_accept; k++) {
          if (!uiHit(KEYPAD_BTN[k], t_x, t_y)) continue;
          ch_last_press_ms = millis();  // one key per physical press

          if (k <= 9) {                                 // digits 1..0
            if (ch_len >= 40) { ch_err = "TOO LONG"; ch_keypad_echo(); break; }
            ch_buf[ch_len++] = (char)('0' + (k == 9 ? 0 : k + 1));
            ch_buf[ch_len] = '\0';
            ch_err = nullptr;
            ch_keypad_echo();
          } else if (k == 10) {                         // ','
            if (ch_len > 0 && ch_buf[ch_len-1] >= '0' && ch_buf[ch_len-1] <= '9') {
              ch_buf[ch_len++] = ','; ch_buf[ch_len] = '\0';
              ch_err = nullptr; ch_keypad_echo();
            }
          } else if (k == 11) {                         // '-' (one per token)
            bool tok_dash = false;
            for (int j = ch_len - 1; j >= 0 && ch_buf[j] != ','; j--)
              if (ch_buf[j] == '-') { tok_dash = true; break; }
            if (ch_len > 0 && ch_buf[ch_len-1] >= '0' && ch_buf[ch_len-1] <= '9' && !tok_dash) {
              ch_buf[ch_len++] = '-'; ch_buf[ch_len] = '\0';
              ch_err = nullptr; ch_keypad_echo();
            }
          } else if (k == 12) {                         // '<-' backspace
            if (ch_len > 0) { ch_len--; ch_buf[ch_len] = '\0'; }
            ch_err = nullptr;
            ch_keypad_echo();
          } else if (k == 13) {                         // OK: validate + apply
            uint8_t tmp[NUM_CHANNELS];
            uint8_t cnt = 0;
            if (!parseChannelList(ch_buf, tmp, &cnt)) {
              // Rejected input: the channel configuration is unchanged.
              ch_err = "INVALID (1-13)";
              ch_keypad_echo();
            } else {
              memcpy(hop_channels, tmp, cnt);
              hop_count = cnt;
              hop_pos = 0;
              // NETWORKS/PCAP: the old cycle button owned target lock; a
              // confirmed hop regime must be free to run, so unlock.
              // WIFI: target_locked is the AP-target lock (SELECT AP) --
              // left untouched; the regime applies when hopping resumes.
              if (currentRadioMode != RADIO_WIFI) target_locked = false;
              if (!target_locked)
                esp_wifi_set_channel(hop_channels[0], WIFI_SECOND_CHAN_NONE);
              ch_keypad_open = false;
              drawMenu();
              delay(150);
            }
          } else {                                      // X: cancel, no change
            ch_keypad_open = false;
            drawMenu();
            delay(150);
          }
          break;
        }

        // Preset column: fills the input box (confirm with OK), so cancel
        // semantics and the single apply path stay intact.
        if (key_accept) {
          if (uiHit(PRESET_BTN[0], t_x, t_y)) {          // 2.4GHz = 1..13
            strcpy(ch_buf, "1-13");
            ch_len = 4;
            ch_err = nullptr;
            ch_last_press_ms = millis();
            ch_keypad_echo();
          } else if (uiHit(PRESET_BTN[1], t_x, t_y)) {   // 5GHz: placeholder
            // Current ESP32 target has no 5 GHz support; inert on purpose.
          } else if (uiHit(PRESET_BTN[2], t_x, t_y)) {   // ALL (current target full set)
            // ALL = the full channel set the firmware supports. On this
            // 2.4 GHz-only ESP32 target that is 1..13; a dual-band target
            // (ESP32-C5) would extend this preset with its 5 GHz set.
            strcpy(ch_buf, "1-13");
            ch_len = 4;
            ch_err = nullptr;
            ch_last_press_ms = millis();
            ch_keypad_echo();
          }
        }
      }

      // ---- LEFT COLUMN: mode / settings selection ----
      else {
      bool hit_main = false;
      for (int i = 0; i < 7 && !hit_main; i++) {
        if (!uiHit(MAINMENU_BTN[i], t_x, t_y)) continue;
        hit_main = true;
        if (i <= 5) {
          RadioMode m = (RadioMode)i;
          menu_selection = i;
          if (m != currentRadioMode) {
            target_locked = false;
            memset(traffic_history, 0, sizeof(traffic_history));
            absolute_max_traffic = 10;
            // THE UNION SCRUB FIX (carried from the old mode-toggle path):
            // leakHistory shares a union with Wi-Fi/BLE session data; scrub
            // it before switching to PCAP or the PCAP sorting engine will
            // choke on Wi-Fi garbage bytes.
            if (m == RADIO_PCAP) {
              memset(leakHistory, 0, sizeof(LeakHistoryEntry) * MAX_LEAK_SLOTS);
            }
            switchRadioMode(m);
            // The menu stays capture-paused: switchRadioMode() reopens the
            // gate for the new mode, but a mode selected from the menu must
            // not start capture in the background.
            pause_sniffing = true;
            menu_scan_started = false; // real-time screen not yet entered
          }
          ch_keypad_open = false;
          drawMenu();
          delay(150);
        } else {
          // SETTINGS placeholder: no radio change, no actions yet.
          menu_selection = 6;
          drawMenu();
          delay(150);
        }
      }

      // ---- RIGHT COLUMN: submenu actions of the selected entry ----
      if (!hit_main && menu_selection <= 5) {
        RadioMode m = (RadioMode)menu_selection;

        // FOXHUNT: unchanged data-availability gating and entry flow.
        auto foxhuntAction = [&]() {
          ch_keypad_open = false;
          bool foxhunt_available = false;
          if (currentRadioMode == RADIO_WIFI) foxhunt_available = (target_locked && sessionMacCount > 0);
          else if (currentRadioMode == RADIO_BLE) foxhunt_available = (sessionBleCount > 0);
          else if (currentRadioMode == RADIO_AP) foxhunt_available = (sessionApCount > 0);
          if (!foxhunt_available) return;
          is_selecting_target = true;
          currentState = SCREEN_DEVICE_LIST;
          drawDeviceList();
          delay(400);
        };

        // Old EXIT path, reused verbatim as START/RESUME SCAN (and BACK):
        // leaves the menu for the real-time screen, reopens the capture
        // gate, re-locks the channel, resumes promiscuous capture.
        auto scanAction = [&]() {
          ch_keypad_open = false;
          currentState = SCREEN_CHART;
          tft.fillScreen(TFT_BLACK);
          drawChartHeader();
          drawChartFooter();

          force_ui_refresh = true;

          if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP || currentRadioMode == RADIO_CHANNELS || currentRadioMode == RADIO_PCAP || currentRadioMode == RADIO_CT) {
            esp_wifi_set_promiscuous(true);
          }

          // Menu -> real-time screen starts a fresh x/y/z telemetry session:
          // zero the three cumulative waterfall counters without
          // resetMonitorState()'s union wipes (this path deliberately resumes
          // capture/history state). Before the gate reopens so post-resume
          // increments land on fresh counts.
          pcap_displayed_total = 0;
          pcap_upstream_total  = 0;
          pcap_cooldown_total  = 0;

          // Restore the software capture gate.
          pause_sniffing = false;

          if ((currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP || currentRadioMode == RADIO_PCAP) && target_locked) {
            esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);
          } else if (currentRadioMode != RADIO_BLE) {
            // Begin on the configured channel set when one exists.
            if (hop_count > 0) esp_wifi_set_channel(hop_channels[hop_pos], WIFI_SECOND_CHAN_NONE);
            else esp_wifi_set_channel(CHANNELS[current_ch_idx], WIFI_SECOND_CHAN_NONE);
          }

          current_x = 0;
          menu_scan_started = true;
          delay(300);
        };

        // DEVICES: old SNIFF LIST action, verbatim.
        auto devicesAction = [&]() {
          ch_keypad_open = false;
          currentState = SCREEN_DEVICE_LIST;
          device_current_page = 0;

          // Force an immediate sort before drawing so the array is ready
          if (currentRadioMode == RADIO_PCAP) processPcapData();
          else forceSessionSort();

          drawDeviceList();
          delay(300);
        };

        // SELECT AP (WIFI only): AP scanner, verbatim.
        auto selectApAction = [&]() {
          ch_keypad_open = false;
          currentState = SCREEN_AP_SCAN;
          drawApScanner();
          delay(300);
        };

        // SELECT CH (WIFI, NETWORKS & PCAP): opens the compact channel
        // keypad below the button. Capture remains paused; confirm parses
        // and applies the channel set, cancel leaves everything unchanged.
        auto selectChAction = [&]() {
          ch_len = 0;
          ch_buf[0] = '\0';
          ch_err = nullptr;
          ch_keypad_open = true;
          drawMenu();
          drawMenuKeypad(ch_buf, ch_err);
        };

        // Row -> action dispatch (matches drawMenu()'s row table).
        if (m == RADIO_WIFI) {
          if      (uiHit(SUBMENU_BTN[0], t_x, t_y)) foxhuntAction();
          else if (uiHit(SUBMENU_BTN[1], t_x, t_y)) selectApAction();
          else if (uiHit(SUBMENU_BTN[2], t_x, t_y)) devicesAction();
          else if (uiHit(SUBMENU_BTN[3], t_x, t_y)) scanAction();
          else if (uiHit(SUBMENU_BTN[4], t_x, t_y)) selectChAction();
        } else if (m == RADIO_BLE) {
          if      (uiHit(SUBMENU_BTN[0], t_x, t_y)) foxhuntAction();
          else if (uiHit(SUBMENU_BTN[1], t_x, t_y)) devicesAction();
          else if (uiHit(SUBMENU_BTN[2], t_x, t_y)) scanAction();
        } else if (m == RADIO_AP) {
          if      (uiHit(SUBMENU_BTN[0], t_x, t_y)) foxhuntAction();
          else if (uiHit(SUBMENU_BTN[1], t_x, t_y)) devicesAction();
          else if (uiHit(SUBMENU_BTN[2], t_x, t_y)) scanAction();
          else if (uiHit(SUBMENU_BTN[3], t_x, t_y)) selectChAction();
        } else if (m == RADIO_CHANNELS) {
          if      (uiHit(SUBMENU_BTN[0], t_x, t_y)) devicesAction();
          else if (uiHit(SUBMENU_BTN[1], t_x, t_y)) scanAction();
        } else if (m == RADIO_PCAP) {
          if      (uiHit(SUBMENU_BTN[0], t_x, t_y)) devicesAction();
          else if (uiHit(SUBMENU_BTN[1], t_x, t_y)) scanAction();
          else if (uiHit(SUBMENU_BTN[2], t_x, t_y)) selectChAction();
        } else { // RADIO_CT
          if      (uiHit(SUBMENU_BTN[0], t_x, t_y)) {
            ch_keypad_open = false;
            currentState = SCREEN_PROBE_TRACKER;
            probe_current_page = 0;
            drawProbeTracker();
            delay(300);
          }
          else if (uiHit(SUBMENU_BTN[1], t_x, t_y)) devicesAction();
          else if (uiHit(SUBMENU_BTN[2], t_x, t_y)) scanAction(); // RF ENVS -> CT real-time screen
          else if (uiHit(SUBMENU_BTN[3], t_x, t_y)) scanAction();
        }
      }
      } // end not-keypad-open
    }

    // ==========================================
    // 3. OSINT PROBE TRACKER TOUCH LOGIC
    // ==========================================
    else if (currentState == SCREEN_PROBE_TRACKER) {

      // HEADER TOUCH (SORT CONTROLS)
      if (t_y <= 30) {
        if (t_x >= LIST_SORT_BTN.x && t_x < LIST_DIR_BTN.x) {
          if (currentProbeSortMode == PROBE_SORT_HITS) currentProbeSortMode = PROBE_SORT_DIST;
          else if (currentProbeSortMode == PROBE_SORT_DIST) currentProbeSortMode = PROBE_SORT_SSIDS;
          else if (currentProbeSortMode == PROBE_SORT_SSIDS) currentProbeSortMode = PROBE_SORT_AGE;
          else currentProbeSortMode = PROBE_SORT_HITS;

          probe_current_page = 0;
          drawProbeTracker();
          delay(200);
        }
        else if (t_x >= LIST_DIR_BTN.x) {
          probe_sort_descending = !probe_sort_descending;
          probe_current_page = 0;
          drawProbeTracker();
          delay(200);
        }
      }

      // FOOTER TOUCH (NAVIGATION)
      else if (t_y > 285) {
        if (t_x < SCREEN_W / 3 && probe_current_page > 0) {
          probe_current_page--;
          drawProbeTracker();
          delay(250);
        }
        else if (t_x > SCREEN_W * 2 / 3 && ((probe_current_page + 1) * PROBES_PER_PAGE) < total_sniffed_probes) {
          probe_current_page++;
          drawProbeTracker();
          delay(250);
        }
        else if (t_x >= SCREEN_W / 3 && t_x <= SCREEN_W * 2 / 3) {
          currentState = SCREEN_MENU;
          menu_selection = (int)currentRadioMode;
          drawMenu();
          delay(300);
        }
      }
    }

    // ==========================================
    // 4. AP SCANNER TOUCH LOGIC
    // ==========================================
    else if (currentState == SCREEN_AP_SCAN) {

      // 1. SNIFF ALL BUTTON (Free Airspace)
      if (t_y > 40 && t_y < 65) {
        target_locked = false;
        WiFi.scanDelete();
        esp_wifi_set_promiscuous(true);
        resetMonitorState();
        currentState = SCREEN_CHART;
        tft.fillScreen(TFT_BLACK);
        drawChartHeader();
        drawChartFooter();
        delay(300);
      }

      // 2. AP SELECTION LIST ROWS (y: 80 to 290)
      else if (t_y >= 80 && t_y < 290) {

        int clicked_row = (t_y - 80) / 35;

        int actual_index = (ap_current_page * APS_PER_PAGE) + clicked_row;
        int n = WiFi.scanComplete();

        if (actual_index < n) {
          memcpy(target_bssid, WiFi.BSSID(actual_index), 6);
          target_channel = WiFi.channel(actual_index);
          target_rssi = WiFi.RSSI(actual_index);

          uint8_t* bssid = WiFi.BSSID(actual_index);
          String raw_ssid = WiFi.SSID(actual_index);

          bool has_clone = false;
          if (raw_ssid.length() > 0) {
            for (int j = 0; j < n; ++j) {
              if (actual_index != j && WiFi.SSID(j) == raw_ssid) {
                has_clone = true;
                break;
              }
            }
          }

          if (raw_ssid.length() == 0) {
            snprintf(target_ssid, sizeof(target_ssid), "<HIDDEN>~%02X%02X", bssid[4], bssid[5]);
          } else if (has_clone) {
            char temp_ssid[13];
            strncpy(temp_ssid, raw_ssid.c_str(), 12);
            temp_ssid[12] = '\0';
            snprintf(target_ssid, sizeof(target_ssid), "%s~%02X%02X", temp_ssid, bssid[4], bssid[5]);
          } else {
            char temp_ssid[18];
            strncpy(temp_ssid, raw_ssid.c_str(), 17);
            temp_ssid[17] = '\0';
            snprintf(target_ssid, sizeof(target_ssid), "%s", temp_ssid);
          }

          target_locked = true;

          WiFi.scanDelete();
          esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);
          esp_wifi_set_promiscuous(true);

          resetMonitorState();
          currentState = SCREEN_CHART;
          tft.fillScreen(TFT_BLACK);
          drawChartHeader();
          drawChartFooter();
          delay(300);
        }
      }

      // 3. PAGINATION & BACK FOOTER
      else if (t_y >= 290) {
        int total_aps = WiFi.scanComplete();

        if (t_x < SCREEN_W / 3 && ap_current_page > 0) {
          ap_current_page--;
          drawApScanner();
          delay(250);
        }
        else if (t_x > SCREEN_W * 2 / 3 && ((ap_current_page + 1) * APS_PER_PAGE) < total_aps) {
          ap_current_page++;
          drawApScanner();
          delay(250);
        }
        else if (t_x >= SCREEN_W / 3 && t_x <= SCREEN_W * 2 / 3) {
          currentState = SCREEN_MENU;
          menu_selection = (int)currentRadioMode;
          ap_current_page = 0;
          drawMenu();
          delay(300);
        }
      }
    }

    // ==========================================
    // 5. FOXHUNT SCREEN TOUCH LOGIC
    // ==========================================
    else if (currentState == SCREEN_FOXHUNT) {
      if (t_x > FOXHUNT_ABORT_BTN.x && t_x < FOXHUNT_ABORT_BTN.x + FOXHUNT_ABORT_BTN.w && t_y > FOXHUNT_ABORT_BTN.y - 2 /* deliberate 2px top expansion, unbounded below */) {
        is_foxhunting = false;
        is_selecting_target = false;
        foxhunt_bounds_seeded = false;

        target_locked = false;
        current_ch_idx = 0;
        esp_wifi_set_channel(CHANNELS[current_ch_idx], WIFI_SECOND_CHAN_NONE);

        currentState = SCREEN_MENU;
        menu_selection = (int)currentRadioMode;
        drawMenu();
        delay(300);
      }
    }

    // ==========================================
    // 6. SEEN DEVICES / LEAK LIST TOUCH LOGIC
    // ==========================================
    else if (currentState == SCREEN_DEVICE_LIST) {

      // ==========================================
      // A. HEADER TOUCH LOGIC (SORT CONTROLS)
      // ==========================================
      if (t_y <= 30) {
        // ZONE 1: TOGGLE SORT METRIC (X: 275 to 405)
        if (t_x >= LIST_SORT_BTN.x && t_x < LIST_SORT_BTN.x + LIST_SORT_BTN.w) {

          if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP) {
            if (currentSortMode == SORT_TOTAL) currentSortMode = SORT_TX;
            else if (currentSortMode == SORT_TX) currentSortMode = SORT_RX;
            else if (currentSortMode == SORT_RX) currentSortMode = SORT_AVG;
            else if (currentSortMode == SORT_AVG) currentSortMode = SORT_CV;
            else if (currentSortMode == SORT_CV) currentSortMode = SORT_DIST;
            else if (currentSortMode == SORT_DIST) currentSortMode = SORT_AGE;
            else currentSortMode = SORT_TOTAL;
          }
          else if (currentRadioMode == RADIO_CHANNELS) {
            if (currentSortMode == SORT_TOTAL) currentSortMode = SORT_TX;
            else if (currentSortMode == SORT_TX) currentSortMode = SORT_RX;
            else if (currentSortMode == SORT_RX) currentSortMode = SORT_AVG;
            else if (currentSortMode == SORT_AVG) currentSortMode = SORT_CV;
            else if (currentSortMode == SORT_CV) currentSortMode = SORT_DIST;
            else currentSortMode = SORT_TOTAL;
          }
          else if (currentRadioMode == RADIO_BLE) {
            if (currentBleSortMode == SORT_BLE_HITS) currentBleSortMode = SORT_BLE_DIST;
            else if (currentBleSortMode == SORT_BLE_DIST) currentBleSortMode = SORT_BLE_AGE;
            else currentBleSortMode = SORT_BLE_HITS;
          }
          // --- ADDED PCAP SORT TOGGLE ---
          else if (currentRadioMode == RADIO_PCAP) {
            if (currentLeakSort == SORT_LEAK_AGE) currentLeakSort = SORT_LEAK_LENGTH;
            else if (currentLeakSort == SORT_LEAK_LENGTH) currentLeakSort = SORT_LEAK_HITS;
            else currentLeakSort = SORT_LEAK_AGE;
          }

          device_current_page = 0;

          // Force sort array before rendering list
          if (currentRadioMode == RADIO_PCAP) processPcapData();
          else forceSessionSort();

          drawDeviceList();
          delay(200);
        }
        // ZONE 2: TOGGLE SORT DIRECTION (X: 410 to 480)
        else if (t_x >= LIST_DIR_BTN.x) {
          sort_descending = !sort_descending;
          device_current_page = 0;

          // Force sort array before rendering list
          if (currentRadioMode == RADIO_PCAP) processPcapData();
          else forceSessionSort();

          drawDeviceList();
          delay(200);
        }
      }

      // ==========================================
      // B. FOOTER NAVIGATION (Y >= 294)
      // ==========================================
      else if (t_y >= LIST_FOOTER_TOP) {
        // --- PAGINATION MATH ---
        // PCAP uses the shared dynamic pagination (rendered-height packing) so
        // the NEXT gate matches the drawn NEXT -> button exactly. Other modes
        // keep the fixed 7-per-page grid.
        int items_per_page = 7;
        int total_devices = 0;
        int total_pages = 0;

        if (currentRadioMode == RADIO_WIFI) total_devices = sessionMacCount;
        else if (currentRadioMode == RADIO_BLE) total_devices = sessionBleCount;
        else if (currentRadioMode == RADIO_AP) total_devices = sessionApCount;
        else if (currentRadioMode == RADIO_CHANNELS) total_devices = sessionChannelCount;
        else if (currentRadioMode == RADIO_PCAP) {
            int valid_indices[MAX_LEAK_SLOTS];
            int valid_count = 0;
            computePcapPagination(valid_indices, valid_count, total_pages);
            total_devices = valid_count;
        }

        bool has_next_page = (currentRadioMode == RADIO_PCAP)
                                 ? (device_current_page < total_pages)
                                 : (((device_current_page + 1) * items_per_page) < total_devices);

        // 1. PREV PAGE
        if (t_x < 160 && device_current_page > 0) {
          device_current_page--;
          drawDeviceList();
          delay(250);
        }
        // 2. NEXT PAGE
        else if (t_x > 320 && has_next_page) {
          device_current_page++;
          drawDeviceList();
          delay(250);
        }
        // 3. BACK TO MENU
        else if (t_x >= 160 && t_x <= 320) {
          currentState = SCREEN_MENU;
          menu_selection = (int)currentRadioMode;
          device_current_page = 0;
          drawMenu();
          delay(300);
        }
      }
      else if (t_y >= DEV_LIST_TOP && t_y < LIST_FOOTER_TOP) {

        // --- ADDED PCAP GUARD (No foxhunting for leaks yet) ---
        if (currentRadioMode == RADIO_PCAP) return false;

        int tapped_screen_row = (t_y - DEV_LIST_TOP) / DEV_LIST_ROW_H;
        int total_devices = 0;

        if (currentRadioMode == RADIO_WIFI) total_devices = sessionMacCount;
        else if (currentRadioMode == RADIO_BLE) total_devices = sessionBleCount;
        else if (currentRadioMode == RADIO_AP) total_devices = sessionApCount;

        int tapped_array_index = (device_current_page * 7) + tapped_screen_row;

        if (tapped_screen_row < 7 && tapped_array_index < total_devices) {
          if (is_selecting_target) {
            is_selecting_target = false;
            is_foxhunting = true;
            smoothed_rssi = -100.0f;
            last_displayed_rssi = -999;

            if (currentRadioMode == RADIO_WIFI) {
               memcpy(foxhunt_target_mac, sessionData[tapped_array_index].mac, 6);
              strncpy(foxhunt_target_vendor, sessionData[tapped_array_index].vendor, sizeof(foxhunt_target_vendor) - 1);
              foxhunt_target_vendor[sizeof(foxhunt_target_vendor) - 1] = '\0';

              foxhunt_rssi_min = sessionData[tapped_array_index].rssi_min;
              foxhunt_rssi_max = sessionData[tapped_array_index].rssi_max;
              foxhunt_bounds_seeded = (sessionData[tapped_array_index].packets > 6);

            } else if (currentRadioMode == RADIO_AP) {
              memcpy(foxhunt_target_mac, sessionApData[tapped_array_index].bssid, 6);
              strncpy(foxhunt_target_vendor, sessionApData[tapped_array_index].ssid, sizeof(foxhunt_target_vendor) - 1);
              foxhunt_target_vendor[sizeof(foxhunt_target_vendor) - 1] = '\0';

              foxhunt_rssi_min = sessionApData[tapped_array_index].rssi_min;
              foxhunt_rssi_max = sessionApData[tapped_array_index].rssi_max;
              foxhunt_bounds_seeded = (sessionApData[tapped_array_index].packets > 6);

              target_locked = true;
              target_channel = sessionApData[tapped_array_index].channel;
              esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);

            } else if (currentRadioMode == RADIO_BLE) {
              memcpy(foxhunt_target_mac, sessionBleData[tapped_array_index].mac, 6);
              strncpy(foxhunt_target_vendor, sessionBleData[tapped_array_index].name, 25);
              if (foxhunt_target_vendor[0] == '\0') {
                strncpy(foxhunt_target_vendor, "<Unnamed BLE>", 25);
              }
              foxhunt_target_vendor[25] = '\0';

              foxhunt_rssi_min = -100;
              foxhunt_rssi_max = -100;
              foxhunt_bounds_seeded = false;

              target_locked = false;
            }

            currentState = SCREEN_FOXHUNT;

            if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP) {
                esp_wifi_set_promiscuous(true);
            }
            pause_sniffing = false;

            drawFoxhuntScreen();
            delay(200);
          }
        }
      }

    }

    // (Notice SCREEN_LEAK_LIST block is completely deleted!)

    return trigger_render;
}
