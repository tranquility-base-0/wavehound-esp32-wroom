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

bool handleTouchInputs(uint16_t t_x, uint16_t t_y) {
  bool trigger_render = false; // 1. Create local tracking variable

    // ==========================================
    // 1. CHART SCREEN TOUCH LOGIC
    // ==========================================
    if (currentState == SCREEN_CHART) {
      // TOP RIGHT: Menu Button
      if (t_x > 400 && t_y < 40) {
        currentState = SCREEN_MENU;
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
    // 2. MENU SCREEN TOUCH LOGIC
    // ==========================================
    else if (currentState == SCREEN_MENU) {

      // FOXHUNT BUTTON TOUCH ZONE
      if (uiHit(MENU_BTN_FOXHUNT, t_x, t_y)) {

          bool foxhunt_available = false;
          if (currentRadioMode == RADIO_WIFI) foxhunt_available = (target_locked && sessionMacCount > 0);
          else if (currentRadioMode == RADIO_BLE) foxhunt_available = (sessionBleCount > 0);
          else if (currentRadioMode == RADIO_AP) foxhunt_available = (sessionApCount > 0);

          if (!foxhunt_available) return false;

          is_selecting_target = true;
          currentState = SCREEN_DEVICE_LIST;
          drawDeviceList();
          delay(400);
      }
      // Probe Request Tracker Button
      else if (uiHit(MENU_BTN_PROBES, t_x, t_y)) {
        currentState = SCREEN_PROBE_TRACKER;
        probe_current_page = 0;
        drawProbeTracker();
        delay(300);
      }
      // AP Scanner / CH Select Button
      else if (uiHit(MENU_BTN_SELECT_AP, t_x, t_y)) {
        if (currentRadioMode == RADIO_WIFI) {
          currentState = SCREEN_AP_SCAN;
          drawApScanner();
          delay(300);
        } else if (currentRadioMode == RADIO_AP || currentRadioMode == RADIO_PCAP) {
          if (!target_locked) {
              target_locked = true;
              target_channel = 1;
          } else {
              target_channel++;
              if (target_channel > 13) {
                  target_locked = false;
                  target_channel = 0;
              }
          }

          memset(traffic_history, 0, sizeof(traffic_history));
          absolute_max_traffic = 10;
          if (currentRadioMode == RADIO_PCAP) {
            // PCAP channel re-lock: fresh telemetry session WITHOUT
            // resetMonitorState()'s union wipes — sessionData aliases
            // leakHistory there, so the wipe would destroy the persistent
            // capture/alert list. Same zero set as the MENU-EXIT path.
            // pause_sniffing stays closed until MENU-EXIT reopens it.
            pcap_displayed_total = 0;
            pcap_upstream_total  = 0;
            pcap_cooldown_total  = 0;
          } else {
            resetMonitorState();
          }

          drawMenu();
          delay(150);
        }
      }
      // ==========================================
      // UNIFIED SNIFFED DEVICES / LEAK LIST BUTTON
      // ==========================================
      else if (uiHit(MENU_BTN_SNIFFLIST, t_x, t_y)) {
        currentState = SCREEN_DEVICE_LIST;
        device_current_page = 0;

        // Force an immediate sort before drawing so the array is ready
        if (currentRadioMode == RADIO_PCAP) processPcapData();
        else forceSessionSort();

        drawDeviceList();
        delay(300);
      }
      // ==========================================
      // RADIO MODE TOGGLE TOUCH LOGIC (X:300-450, Y:190-230)
      // ==========================================
      else if (uiHit(MENU_BTN_MODE, t_x, t_y)) {

        target_locked = false;
        memset(traffic_history, 0, sizeof(traffic_history));
        absolute_max_traffic = 10;

        RadioMode nextMode;
        if (currentRadioMode == RADIO_WIFI) nextMode = RADIO_BLE;
        else if (currentRadioMode == RADIO_BLE) nextMode = RADIO_AP;
        else if (currentRadioMode == RADIO_AP) nextMode = RADIO_CHANNELS;
        else if (currentRadioMode == RADIO_CHANNELS) nextMode = RADIO_PCAP;
        else if (currentRadioMode == RADIO_PCAP) nextMode = RADIO_CT;
        else nextMode = RADIO_WIFI;

        tft.setFreeFont(&UbuntuMono_Regular9pt7b);
        tft.setTextDatum(MC_DATUM);

        if (nextMode == RADIO_WIFI) {
          tft.fillRect(MENU_BTN_MODE.x, MENU_BTN_MODE.y, MENU_BTN_MODE.w, MENU_BTN_MODE.h, TFT_BLUE);
          tft.drawRect(MENU_BTN_MODE.x, MENU_BTN_MODE.y, MENU_BTN_MODE.w, MENU_BTN_MODE.h, TFT_WHITE);
          tft.setTextColor(TFT_WHITE);
          tft.drawString("MODE: WI-FI", 375, 210);
        } else if (nextMode == RADIO_BLE) {
          tft.fillRect(MENU_BTN_MODE.x, MENU_BTN_MODE.y, MENU_BTN_MODE.w, MENU_BTN_MODE.h, TFT_PURPLE);
          tft.drawRect(MENU_BTN_MODE.x, MENU_BTN_MODE.y, MENU_BTN_MODE.w, MENU_BTN_MODE.h, TFT_WHITE);
          tft.setTextColor(TFT_WHITE);
          tft.drawString("MODE: BLE", 375, 210);
        } else if (nextMode == RADIO_AP) {
          tft.fillRect(MENU_BTN_MODE.x, MENU_BTN_MODE.y, MENU_BTN_MODE.w, MENU_BTN_MODE.h, TFT_DARKGREEN);
          tft.drawRect(MENU_BTN_MODE.x, MENU_BTN_MODE.y, MENU_BTN_MODE.w, MENU_BTN_MODE.h, TFT_WHITE);
          tft.setTextColor(TFT_WHITE);
          tft.drawString("MODE: NETWORKS", 375, 210);
        } else if (nextMode == RADIO_CHANNELS) {
          tft.fillRect(MENU_BTN_MODE.x, MENU_BTN_MODE.y, MENU_BTN_MODE.w, MENU_BTN_MODE.h, TFT_ORANGE);
          tft.drawRect(MENU_BTN_MODE.x, MENU_BTN_MODE.y, MENU_BTN_MODE.w, MENU_BTN_MODE.h, TFT_WHITE);
          tft.setTextColor(TFT_WHITE);
          tft.drawString("MODE: CHANNELS", 375, 210);
        } else if (nextMode == RADIO_PCAP) {
          tft.fillRect(MENU_BTN_MODE.x, MENU_BTN_MODE.y, MENU_BTN_MODE.w, MENU_BTN_MODE.h, TFT_MAROON);
          tft.drawRect(MENU_BTN_MODE.x, MENU_BTN_MODE.y, MENU_BTN_MODE.w, MENU_BTN_MODE.h, TFT_WHITE);
          tft.setTextColor(TFT_WHITE);
          tft.drawString("MODE: PCAP", 375, 210);
        } else if (nextMode == RADIO_CT) {
          tft.fillRect(MENU_BTN_MODE.x, MENU_BTN_MODE.y, MENU_BTN_MODE.w, MENU_BTN_MODE.h, TFT_NAVY);
          tft.drawRect(MENU_BTN_MODE.x, MENU_BTN_MODE.y, MENU_BTN_MODE.w, MENU_BTN_MODE.h, TFT_WHITE);
          tft.setTextColor(TFT_WHITE);
          tft.drawString("MODE: CT", 375, 210);
        }

        bool foxhunt_available = false;

        if (nextMode == RADIO_BLE) {
            if (sessionBleCount > 0) foxhunt_available = true;
        } else if (nextMode == RADIO_AP) {
            if (sessionApCount > 0) foxhunt_available = true;
        } else if (nextMode == RADIO_WIFI) {
            if (target_locked == true && sessionMacCount > 0) foxhunt_available = true;
        }

        if (foxhunt_available) {
            tft.fillRoundRect(50, 90, 200, 40, 3, TFT_RED);
            tft.drawRoundRect(50, 90, 200, 40, 3, TFT_WHITE);
            tft.setTextColor(TFT_WHITE);
            tft.drawString("FOXHUNT", 150, 110);
        } else {
            uint16_t deadGrey = hex24to565(0x222222);
            tft.fillRect(50, 90, 200, 50, deadGrey);
            tft.drawRect(50, 90, 200, 40, TFT_DARKGREY);
            tft.setTextColor(TFT_DARKGREY);
            tft.drawString("FOXHUNT", 150, 110);

            tft.setTextColor(hex24to565(0x444444));
            tft.drawString("(no targets yet)", 150, 125);
        }

        tft.setTextDatum(TL_DATUM);

        // ==========================================
        // THE UNION SCRUB FIX
        // Because leakHistory shares a union with Wi-Fi/BLE session data,
        // we MUST scrub it clean when switching to PCAP. If we don't, the
        // PCAP sorting engine will choke on Wi-Fi garbage bytes!
        // ==========================================
        if (nextMode == RADIO_PCAP) {
            memset(leakHistory, 0, sizeof(LeakHistoryEntry) * MAX_LEAK_SLOTS);
        }

        switchRadioMode(nextMode);
        delay(200);
      }
      // ==========================================
      // EXIT BUTTON TOUCH LOGIC
      // ==========================================
      else if (uiHit(MENU_BTN_EXIT, t_x, t_y)) {
        currentState = SCREEN_CHART;
        tft.fillScreen(TFT_BLACK);
        drawChartHeader();
        drawChartFooter();

        force_ui_refresh = true;

        if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP || currentRadioMode == RADIO_CHANNELS || currentRadioMode == RADIO_PCAP || currentRadioMode == RADIO_CT) {
            esp_wifi_set_promiscuous(true);
        }

        // MENU → EXIT starts a fresh x/y/z telemetry session: zero the three
        // cumulative waterfall counters without resetMonitorState()'s union
        // wipes (this path deliberately resumes capture/history state).
        // Before the gate reopens so post-resume increments land on fresh counts.
        pcap_displayed_total = 0;
        pcap_upstream_total  = 0;
        pcap_cooldown_total  = 0;

        // Restore the software capture gate (the MENU path raised it and the
        // EXIT path used to leave it set, deadlocking capture for up to the
        // next runProbeCorrelationEngine cycle).
        pause_sniffing = false;

        if ((currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP || currentRadioMode == RADIO_PCAP) && target_locked) {
          esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);
        } else if (currentRadioMode != RADIO_BLE) {
          esp_wifi_set_channel(CHANNELS[current_ch_idx], WIFI_SECOND_CHAN_NONE);
        }

        current_x = 0;
        delay(300);
      }
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
