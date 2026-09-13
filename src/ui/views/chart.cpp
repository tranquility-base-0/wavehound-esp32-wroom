#include "chart.h"
#include "ui/ui_state.h"
#include "core/radio.h"
#include "core/wavehound_state.h"
#include "capture/capture.h"
#include "modes/ap_scanner.h"
#include "osint/vendor.h"
#include "parsers/parser_common.h"
#include "UbuntuMono_Regular11pt7b.h"
#include "UbuntuMono_Regular9pt7b.h"
#include "UbuntuMono_Regular8pt7b.h"
#include "UbuntuMono_B9pt7b.h"
#include <cmath>
#include <string.h>
#include <stdio.h>

#include "foxhunt.h"

void drawTelemetryHeader(uint32_t leaks, uint32_t enqueued, uint32_t attempted) {
    // Pure renderer: values are ~3 s window deltas computed in loop()'s DIAG block.
    tft.setFreeFont(&UbuntuMono_Regular8pt7b);
    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(COLOR_HOT_CHEST, TFT_BLACK);

    // Erase the previous tally before redrawing.
    tft.fillRect(285, 0, 135, 20, TFT_BLACK);

    // displayed / enqueued / gate-accepted (~3 s window) — 4-digit fields to prevent jitter
    char stat_text[32];
    snprintf(stat_text, sizeof(stat_text), "%4u/%4u/%4u", leaks, enqueued, attempted);

    tft.drawString(stat_text, 285, 1);
}
void drawChartHeader() {
  // 1. Gate the horizontal separator line so it doesn't cut through the PCAP terminal
  if (currentRadioMode != RADIO_PCAP) {
    tft.drawLine(0, HEADER_HEIGHT - 8, 480, HEADER_HEIGHT - 8, COLOR_HOT_CHEST);
  }

  // MENU BUTTON
  tft.drawRoundRect(420, 1, 55, 16, 2, TFT_WHITE);
  tft.setTextColor(TFT_WHITE);
  tft.setFreeFont(&UbuntuMono_Regular9pt7b);
  tft.setTextDatum(MC_DATUM);
  tft.drawString("MENU", 447, 7);
  tft.setTextDatum(TL_DATUM);

  // BANNER
  tft.setTextWrap(false);
  tft.setFreeFont(&UbuntuMono_Regular9pt7b);
  tft.setTextDatum(TL_DATUM);

  char bannerStr[64];

  // ==========================================
  // THE 4-STATE HEADER LOGIC
  // ==========================================
  tft.setTextColor(COLOR_HOT_CHEST);
  if (currentRadioMode == RADIO_BLE) {
    snprintf(bannerStr, sizeof(bannerStr), "SNIFFING BLE DEVICES");
  }
  else if (currentRadioMode == RADIO_AP) {
    if (!target_locked) {
        snprintf(bannerStr, sizeof(bannerStr), "CH: %02d | SNIFFING NETWORKS", CHANNELS[current_ch_idx]);
    } else {
        snprintf(bannerStr, sizeof(bannerStr), "CH: %02d | TARGET LOCKED", target_channel);
    }
  }
  else if (currentRadioMode == RADIO_CHANNELS) {
    snprintf(bannerStr, sizeof(bannerStr), "CH: %02d | SNIFFING SPECTRUM", CHANNELS[current_ch_idx]);
  }
  else if (currentRadioMode == RADIO_PCAP) {
    if (!target_locked) {
      snprintf(bannerStr, sizeof(bannerStr), "CH: %02d | PCAP (HOPPING)", CHANNELS[current_ch_idx]);
    } else {
      snprintf(bannerStr, sizeof(bannerStr), "CH: %02d | PCAP (LOCKED)", target_channel);
    }
  }
  else if (currentRadioMode == RADIO_WIFI) {
    if (!target_locked) {
      snprintf(bannerStr, sizeof(bannerStr), "CH: %02d | FREE AIRSPACE", CHANNELS[current_ch_idx]);
    } else {
      char safe_ssid[15];
      strncpy(safe_ssid, target_ssid, 14);
      safe_ssid[14] = '\0';
      snprintf(bannerStr, sizeof(bannerStr), "CH: %02d | %s (%ddBm)", target_channel, safe_ssid, target_rssi);
    }
  }
  tft.drawString(bannerStr, 5, 1);
}
void drawChartFooter() {
  tft.fillRect(0, 296, 480, 24, TFT_BLACK);

  tft.setFreeFont(&UbuntuMono_Regular9pt7b);
  tft.setTextColor(TFT_WHITE);
  tft.setTextDatum(MC_DATUM);

  if (currentRadioMode != RADIO_PCAP) {
      // ==========================================
      // ZONE 1: SORT METRIC (Center X = 72)
      // ==========================================
      tft.drawRoundRect(2, 302, 141, 17, 3, TFT_WHITE);

      char metricStr[32] = "SORT: ERR";

      if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP) {
        if (currentSortMode == SORT_TOTAL) { strcpy(metricStr, "SORT: TOTAL"); tft.setTextColor(TFT_WHITE); }
        else if (currentSortMode == SORT_TX) { strcpy(metricStr, "SORT: TX"); tft.setTextColor(TFT_CYAN); }
        else if (currentSortMode == SORT_RX) { strcpy(metricStr, "SORT: RX"); tft.setTextColor(TFT_MAGENTA); }
        else if (currentSortMode == SORT_AVG) { strcpy(metricStr, "SORT: AVG"); tft.setTextColor(TFT_YELLOW); }
        else if (currentSortMode == SORT_CV) { strcpy(metricStr, "SORT: CV%"); tft.setTextColor(TFT_ORANGE); }
        else if (currentSortMode == SORT_DIST) { strcpy(metricStr, "SORT: DIST"); tft.setTextColor(TFT_GREEN); }
        else if (currentSortMode == SORT_AGE) { strcpy(metricStr, "SORT: AGE"); tft.setTextColor(TFT_BLUE); }
      }
      else if (currentRadioMode == RADIO_CHANNELS) {
        if (currentSortMode == SORT_TOTAL) { strcpy(metricStr, "SORT: TOTAL"); tft.setTextColor(TFT_WHITE); }
        else if (currentSortMode == SORT_TX) { strcpy(metricStr, "SORT: DN"); tft.setTextColor(TFT_CYAN); }
        else if (currentSortMode == SORT_RX) { strcpy(metricStr, "SORT: UP"); tft.setTextColor(TFT_MAGENTA); }
        else if (currentSortMode == SORT_AVG) { strcpy(metricStr, "SORT: AVG"); tft.setTextColor(TFT_YELLOW); }
        else if (currentSortMode == SORT_CV) { strcpy(metricStr, "SORT: CV%"); tft.setTextColor(TFT_ORANGE); }
        else if (currentSortMode == SORT_DIST) { strcpy(metricStr, "SORT: PWR"); tft.setTextColor(TFT_GREEN); }
        else if (currentSortMode == SORT_AGE) { strcpy(metricStr, "SORT: AGE"); tft.setTextColor(TFT_BLUE); }
      }
      else if (currentRadioMode == RADIO_BLE) {
        if (currentBleSortMode == SORT_BLE_HITS) { strcpy(metricStr, "SORT: HITS"); tft.setTextColor(TFT_WHITE); }
        else if (currentBleSortMode == SORT_BLE_DIST) { strcpy(metricStr, "SORT: DIST"); tft.setTextColor(TFT_GREEN); }
        else if (currentBleSortMode == SORT_BLE_AGE) { strcpy(metricStr, "SORT: AGE"); tft.setTextColor(TFT_BLUE); }
      }

      tft.drawString(metricStr, 72, 308);
      tft.setTextColor(TFT_WHITE);

      // ==========================================
      // ZONE 2: SORT DIRECTION (Center X = 217)
      // ==========================================
      tft.drawRoundRect(147, 302, 141, 17, 3, TFT_WHITE);

      if (sort_descending) {
        tft.drawString("ORDER: DESC", 217, 309);
      } else {
        tft.setTextColor(TFT_GREEN);
        tft.drawString("ORDER: ASC", 217, 309);
        tft.setTextColor(TFT_WHITE);
      }

      // ==========================================
      // ZONE 3: SCALE MODE (Center X = 362)
      // ==========================================
      tft.drawRoundRect(292, 302, 141, 17, 3, TFT_WHITE);

      if (useLogScale) {
        tft.setTextColor(TFT_YELLOW);
        tft.drawString("SCALE: LOG", 362, 309);
      } else {
        tft.drawString("SCALE: LIN", 362, 309);
      }
  } else {
      // PCAP gets a clean, unified label instead of useless sort buttons
      tft.setTextColor(TFT_DARKGREY);
      // Draw the static time scale on the far left
      tft.setTextDatum(TL_DATUM);
      tft.drawString("|=2m", 10, 301);

      // Draw the main status label perfectly centered
      tft.setTextDatum(MC_DATUM);
      tft.drawString("PROMISCUOUS CAPTURE MODE", 240, 309); // 240 is true center of 480px screen
      tft.setTextColor(TFT_WHITE);
  }

  // ==========================================
  // ZONE 4: BATTERY PLACEHOLDER
  // ==========================================
  tft.drawRect(445, 304, 22, 12, TFT_WHITE);
  tft.fillRect(467, 307, 3, 6, TFT_WHITE);
  tft.fillRect(447, 306, 18, 8, TFT_GREEN);

  tft.setTextDatum(TL_DATUM);
  tft.setTextColor(TFT_WHITE);
}
void drawPersistentTopN() {
    tft.setFreeFont(&UbuntuMono_B9pt7b);
    tft.setTextDatum(TL_DATUM);

    int top_count = 0;
    if (currentRadioMode == RADIO_WIFI) top_count = sessionMacCount;
    else if (currentRadioMode == RADIO_BLE) top_count = sessionBleCount;
    else if (currentRadioMode == RADIO_AP) top_count = sessionApCount;
    else if (currentRadioMode == RADIO_CHANNELS) top_count = sessionChannelCount;

    if (top_count > 10) top_count = 10;

    // 1. Static state trackers for delta-drawing (REMOVED HEAP-FRAG STRINGS)
    static char lastLabels[10][32] = {0};
    static int lastTopCount = 0;
    static uint8_t lastRadioMode = 255; // 255 forces an initial redraw on boot

    // 2. Force a full block wipe ONLY when changing radio modes
    bool forceRedraw = (currentRadioMode != lastRadioMode) || force_ui_refresh;
    if (forceRedraw) {
        tft.fillRect(0, 18, 480, HEADER_HEIGHT - 27, TFT_BLACK);
        for(int i = 0; i < 10; i++) {
            lastLabels[i][0] = '\0'; // Clear the cache array
        }
        lastRadioMode = currentRadioMode;
        force_ui_refresh = false; // Consume the flag so it only runs once
    }

    for (int i = 0; i < top_count; i++) {
        // Grid Math
        int col = i % 2;
        int row = i / 2;

        int x_pos = 5 + (col * 240);
        int y_pos = 18 + (row * 16);

        char display_name[28] = "Unknown"; // Buffer for the raw text

        if (currentRadioMode == RADIO_WIFI) {
            strncpy(display_name, sessionData[i].vendor, 26);
            display_name[26] = '\0';
        }
        else if (currentRadioMode == RADIO_BLE) {
            if (strlen((char*)sessionBleData[i].name) > 0) {
                strncpy(display_name, (char*)sessionBleData[i].name, 26);
                display_name[26] = '\0';
            } else {
                snprintf(display_name, sizeof(display_name), "%02X:%02X:%02X:%02X:%02X:%02X",
                         sessionBleData[i].mac[0], sessionBleData[i].mac[1], sessionBleData[i].mac[2],
                         sessionBleData[i].mac[3], sessionBleData[i].mac[4], sessionBleData[i].mac[5]);
            }
        }
        else if (currentRadioMode == RADIO_AP) {
            // Uses sessionApData, display_name, and wider truncation bounds
            if (strcmp(sessionApData[i].ssid, "<HIDDEN>") == 0 || strcmp(sessionApData[i].ssid, "<UNKNOWN>") == 0) {
                snprintf(display_name, sizeof(display_name), "%s", sessionApData[i].ssid);
            } else if (sessionApData[i].has_clone) {
                char temp_ssid[22];
                strncpy(temp_ssid, sessionApData[i].ssid, 21); // 21 chars max for list
                temp_ssid[21] = '\0';
                snprintf(display_name, sizeof(display_name), "%s~%02X%02X",
                         temp_ssid, sessionApData[i].bssid[4], sessionApData[i].bssid[5]);
            } else {
                strncpy(display_name, sessionApData[i].ssid, 26); // 26 chars max for list
                display_name[26] = '\0';
            }
        }
        else if (currentRadioMode == RADIO_CHANNELS) {
            float rho = 0.0;
            if (sessionChannelData[i].ema_variance > 0.01) {
                rho = sessionChannelData[i].ema_cov / sessionChannelData[i].ema_variance;
            }
            const char* stateStr = "STATIC";
            if (sessionChannelData[i].packets < 5) stateStr = "CALC...";
            else if (rho > 0.6) stateStr = "DRIFT";
            else if (rho > 0.2) stateStr = "ACTIVE";

            snprintf(display_name, sizeof(display_name), "CH:%02d [%s]", sessionChannelData[i].channel, stateStr);
        }

        // Final assembly of index + display name
        char label[32];
        snprintf(label, sizeof(label), "%d.%s", i + 1, display_name);

        // 3. Delta Check: Only draw if the string changed or a mode swap forced it
        if (forceRedraw || strcmp(label, lastLabels[i]) != 0) {
            if (!forceRedraw) {
                // Wipe just this specific 235x16 cell to prevent trailing characters
                // from a previous, longer string ghosting on the screen.
                tft.fillRect(x_pos, y_pos, 235, 16, TFT_BLACK);
            }

            tft.setTextColor(TFT_WHITE, TFT_BLACK);
            tft.drawString(label, x_pos, y_pos);

            // Store the new label for future delta checks
            strncpy(lastLabels[i], label, sizeof(lastLabels[i]) - 1);
            lastLabels[i][sizeof(lastLabels[i]) - 1] = '\0';
        }
    }

    // 4. Stale Data Cleanup: If the list shrank, wipe the abandoned grid cells
    for (int i = top_count; i < lastTopCount; i++) {
        int col = i % 2;
        int row = i / 2;
        int x_pos = 5 + (col * 240);
        int y_pos = 18 + (row * 16);

        tft.fillRect(x_pos, y_pos, 235, 16, TFT_BLACK);
        lastLabels[i][0] = '\0'; // Clear the tracker
    }

    lastTopCount = top_count;
}
void drawTemporalLegend() {
    int displayCount = 0;
    if (currentRadioMode == RADIO_WIFI) displayCount = sortMacCount;
    else if (currentRadioMode == RADIO_BLE) displayCount = sortBleCount;
    else if (currentRadioMode == RADIO_AP) displayCount = sortApCount;
    else if (currentRadioMode == RADIO_CHANNELS) displayCount = sortChannelCount;

    // Bail early if there's nothing to draw
    if (!(displayCount > 0 || ((currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP || currentRadioMode == RADIO_CHANNELS) && sortOtherBytes > 0))) {
        return;
    }

    // 1. CALCULATE AND DRAW "OTHER" IN THE TOP MENU BANNER
    int otherCount = 0;
    // REDUCED: The threshold for "Other" is now > 6
    if (displayCount > 6) {
        otherCount = displayCount - 6;
    }

    tft.setFreeFont(&UbuntuMono_Regular9pt7b);
    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(COLOR_HOT_CHEST, TFT_BLACK);

    // FIX 1: Start the wipe at y=0 to catch the top ascenders of the font.
    // Height expanded to 20 to fully encapsulate the 9pt7b bounding box.
    tft.fillRect(315, 0, 95, 20, TFT_BLACK);

    char otherStr[16];
    // FIX 2: Force a 2-digit format so the string is always the exact same length
    snprintf(otherStr, sizeof(otherStr), "OTHER:%d", otherCount);

    // The text draws starting at y=1, safely inside the wiped area!
    tft.drawString(otherStr, 315, 1);

    // 2. DRAW THE MAIN 6-DEVICE LEGEND (Now in the bottom position)
    int start_y = HEADER_HEIGHT - 6;
    // Wipe exactly the space between the header line and the chart
    tft.fillRect(0, start_y, 480, chart_start_y - start_y, TFT_BLACK);

    tft.setFreeFont(&UbuntuMono_Regular11pt7b);

    int renderCount = 0;
    if (currentRadioMode == RADIO_WIFI) renderCount = sortMacCount;
    else if (currentRadioMode == RADIO_BLE) renderCount = sortBleCount;
    else if (currentRadioMode == RADIO_AP) renderCount = sortApCount;
    else if (currentRadioMode == RADIO_CHANNELS) renderCount = sortChannelCount;

    // REDUCED: Only loop up to 6 items max
    for(int i = 0; i < 6 && i < renderCount; i++) {
        char short_text[25]; // Safe size for 20-char strings + null terminator

        if (currentRadioMode == RADIO_WIFI) {
            strncpy(short_text, sortData[i].vendor, 19);
            short_text[19] = '\0';
        }
        else if (currentRadioMode == RADIO_BLE) {
            if (strlen(sortBleData[i].name) > 0) {
                strncpy(short_text, sortBleData[i].name, 19);
                short_text[19] = '\0';
            } else {
                snprintf(short_text, sizeof(short_text), "%02X:%02X:%02X:%02X:%02X:%02X",
                         sortBleData[i].mac[0], sortBleData[i].mac[1], sortBleData[i].mac[2],
                         sortBleData[i].mac[3], sortBleData[i].mac[4], sortBleData[i].mac[5]);
            }
        }
        else if (currentRadioMode == RADIO_AP) {
            // Uses sortApData, short_text, and tighter truncation bounds
            if (strcmp(sortApData[i].ssid, "<HIDDEN>") == 0 || strcmp(sortApData[i].ssid, "<UNKNOWN>") == 0) {
                snprintf(short_text, sizeof(short_text), "%s", sortApData[i].ssid);
            } else if (sortApData[i].has_clone) {
                char temp_ssid[16];
                strncpy(temp_ssid, sortApData[i].ssid, 14); // 14 chars max for legend
                temp_ssid[14] = '\0';
                snprintf(short_text, sizeof(short_text), "%s~%02X%02X",
                         temp_ssid, sortApData[i].bssid[4], sortApData[i].bssid[5]);
            } else {
                strncpy(short_text, sortApData[i].ssid, 19); // 19 chars max for legend
                short_text[19] = '\0';
            }
        }
        else if (currentRadioMode == RADIO_CHANNELS) {
            snprintf(short_text, sizeof(short_text), "CH %02d", sortChannelData[i].channel);
        }

        tft.setTextColor(colors[i]);

        // Grid Math (3 rows x 2 columns)
        int x_pos = 5 + (i % 2) * 240;
        int y_pos = start_y + (i / 2) * 20;

        // UPDATED: Eliminated dynamic String object for pure char array
        char label[32];
        snprintf(label, sizeof(label), "%d.%s", i + 1, short_text);

        tft.drawString(label, x_pos, y_pos);
    }

    // Draw the white separator line between the new bottom legend and the waterfall chart
    tft.drawLine(0, chart_start_y, 480, chart_start_y, COLOR_HOT_CHEST);
}
void drawWaterfallChart() {
    // 1. Gate the legends
    if (currentRadioMode != RADIO_PCAP) {
        drawTemporalLegend();
        drawPersistentTopN();
    }

    int chart_area_height = CHART_BOTTOM - chart_start_y;

    // FIX 3: Use the exact same 3/4 split for ALL modes to keep the bottom graph height identical
    int split_y = chart_start_y + (chart_area_height * 3) / 4;

    int ERASER_WIDTH = 44;

    // 3. Adjust the eraser to ONLY clear the bottom pane in PCAP mode
    int clear_start_y = (currentRadioMode == RADIO_PCAP) ? (split_y + 1) : (chart_start_y + 1);
    int clear_height = CHART_BOTTOM - clear_start_y;

    // Pure wipe logic (using dynamic clear_start_y and clear_height)
    if (current_x + ERASER_WIDTH <= 480) {
        tft.fillRect(current_x, clear_start_y, ERASER_WIDTH, clear_height, TFT_BLACK);
    } else {
        int w1 = 480 - current_x;
        tft.fillRect(current_x, clear_start_y, w1, clear_height, TFT_BLACK);
        tft.fillRect(0, clear_start_y, ERASER_WIDTH - w1, clear_height, TFT_BLACK);
    }

    // X-Axis Time Ticks
    if (current_x % 60 == 0) {
        tft.drawLine(current_x, split_y - 3, current_x, split_y + 3, COLOR_HOT_CHEST);
        tft.drawLine(current_x + 1, split_y - 3, current_x + 1, split_y + 3, COLOR_HOT_CHEST);
    } else {
        tft.drawPixel(current_x, split_y, COLOR_HOT_CHEST);
        tft.drawPixel(current_x + 1, split_y, COLOR_HOT_CHEST);
    }

    int current_y = split_y - 1;
    uint32_t current_total_metric = 0;

    // --- CHART PLOTTING ---
    if (currentRadioMode == RADIO_WIFI) {
        uint32_t total_bytes = sortOtherBytes;
        for(int i = 0; i < 6 && i < sortMacCount; i++) total_bytes += (sortData[i].tx_bytes + sortData[i].rx_bytes);
        current_total_metric = total_bytes;

        if (total_bytes > 0) {
            double log_total = 0;
            if (useLogScale) {
                for(int j = 0; j < 6 && j < sortMacCount; j++) {
                    uint32_t device_total = sortData[j].tx_bytes + sortData[j].rx_bytes;
                    log_total += log10((double)device_total + 1.0);
                }
                log_total += log10((double)sortOtherBytes + 1.0);
            }

            for(int i = 0; i < 6 && i < sortMacCount; i++) {
                double fraction;
                uint32_t current_device_bytes = sortData[i].tx_bytes + sortData[i].rx_bytes;

                if (useLogScale) fraction = log10((double)current_device_bytes + 1.0) / log_total;
                else fraction = (double)current_device_bytes / (double)total_bytes;

                int bar_height = (int)(fraction * (split_y - chart_start_y - 1));
                if (bar_height > (split_y - chart_start_y - 1)) bar_height = split_y - chart_start_y - 1;

                tft.drawLine(current_x, current_y, current_x, current_y - bar_height, colors[i]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, current_y - bar_height, colors[i]);
                current_y -= bar_height;
            }

            if (sortOtherBytes > 0 && current_y > chart_start_y) {
                tft.drawLine(current_x, current_y, current_x, chart_start_y + 1, colors[8]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, chart_start_y + 1, colors[8]);
            } else if (sortOtherBytes == 0 && current_y > chart_start_y && sortMacCount > 0) {
                tft.drawLine(current_x, current_y, current_x, chart_start_y + 1, colors[sortMacCount - 1]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, chart_start_y + 1, colors[sortMacCount - 1]);
            }
        }
    }
    else if (currentRadioMode == RADIO_BLE) {
        uint32_t total_hits = 0;
        uint32_t other_hits = 0;
        int ble_count = (sortBleCount > 6) ? 6 : sortBleCount;

        for(int i = 0; i < ble_count; i++) total_hits += sortBleData[i].hits;
        if (sortBleCount > 6) {
            for (int i = 6; i < sortBleCount; i++) other_hits += sortBleData[i].hits;
            total_hits += other_hits;
        }
        current_total_metric = total_hits;

        if (total_hits > 0) {
            double log_total = 0;
            if (useLogScale) {
                for(int j = 0; j < ble_count; j++) log_total += log10((double)sortBleData[j].hits + 1.0);
                if (other_hits > 0) log_total += log10((double)other_hits + 1.0);
            }

            for(int i = 0; i < ble_count; i++) {
                double fraction;
                if (useLogScale) fraction = log10((double)sortBleData[i].hits + 1.0) / log_total;
                else fraction = (double)sortBleData[i].hits / (double)total_hits;

                int bar_height = (int)(fraction * (split_y - chart_start_y - 1));
                if (bar_height > (split_y - chart_start_y - 1)) bar_height = split_y - chart_start_y - 1;

                tft.drawLine(current_x, current_y, current_x, current_y - bar_height, colors[i]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, current_y - bar_height, colors[i]);
                current_y -= bar_height;
            }

            if (other_hits > 0 && current_y > chart_start_y) {
                tft.drawLine(current_x, current_y, current_x, chart_start_y + 1, colors[8]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, chart_start_y + 1, colors[8]);
            } else if (other_hits == 0 && current_y > chart_start_y && ble_count > 0) {
                tft.drawLine(current_x, current_y, current_x, chart_start_y + 1, colors[ble_count - 1]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, chart_start_y + 1, colors[ble_count - 1]);
            }
        }
    }
    else if (currentRadioMode == RADIO_AP) {
        uint32_t total_bytes = sortOtherBytes;
        for(int i = 0; i < 6 && i < sortApCount; i++) total_bytes += (sortApData[i].tx_bytes + sortApData[i].rx_bytes);
        current_total_metric = total_bytes;

        if (total_bytes > 0) {
            double log_total = 0;
            if (useLogScale) {
                for(int j = 0; j < 6 && j < sortApCount; j++) {
                    uint32_t device_total = sortApData[j].tx_bytes + sortApData[j].rx_bytes;
                    log_total += log10((double)device_total + 1.0);
                }
                log_total += log10((double)sortOtherBytes + 1.0);
            }

            for(int i = 0; i < 6 && i < sortApCount; i++) {
                double fraction;
                uint32_t current_device_bytes = sortApData[i].tx_bytes + sortApData[i].rx_bytes;

                if (useLogScale) fraction = log10((double)current_device_bytes + 1.0) / log_total;
                else fraction = (double)current_device_bytes / (double)total_bytes;

                int bar_height = (int)(fraction * (split_y - chart_start_y - 1));
                if (bar_height > (split_y - chart_start_y - 1)) bar_height = split_y - chart_start_y - 1;

                tft.drawLine(current_x, current_y, current_x, current_y - bar_height, colors[i]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, current_y - bar_height, colors[i]);
                current_y -= bar_height;
            }

            if (sortOtherBytes > 0 && current_y > chart_start_y) {
                tft.drawLine(current_x, current_y, current_x, chart_start_y + 1, colors[8]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, chart_start_y + 1, colors[8]);
            } else if (sortOtherBytes == 0 && current_y > chart_start_y && sortApCount > 0) {
                tft.drawLine(current_x, current_y, current_x, chart_start_y + 1, colors[sortApCount - 1]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, chart_start_y + 1, colors[sortApCount - 1]);
            }
        }
    }
    else if (currentRadioMode == RADIO_CHANNELS) {
        uint32_t total_bytes = sortOtherBytes;
        for(int i = 0; i < 6 && i < sortChannelCount; i++) total_bytes += (sortChannelData[i].tx_bytes + sortChannelData[i].rx_bytes);
        current_total_metric = total_bytes;

        if (total_bytes > 0) {
            double log_total = 0;
            if (useLogScale) {
                for(int j = 0; j < 6 && j < sortChannelCount; j++) {
                    uint32_t c_total = sortChannelData[j].tx_bytes + sortChannelData[j].rx_bytes;
                    log_total += log10((double)c_total + 1.0);
                }
                log_total += log10((double)sortOtherBytes + 1.0);
            }

            for(int i = 0; i < 6 && i < sortChannelCount; i++) {
                double fraction;
                uint32_t current_c_bytes = sortChannelData[i].tx_bytes + sortChannelData[i].rx_bytes;

                if (useLogScale) fraction = log10((double)current_c_bytes + 1.0) / log_total;
                else fraction = (double)current_c_bytes / (double)total_bytes;

                int bar_height = (int)(fraction * (split_y - chart_start_y - 1));
                if (bar_height > (split_y - chart_start_y - 1)) bar_height = split_y - chart_start_y - 1;

                tft.drawLine(current_x, current_y, current_x, current_y - bar_height, colors[i]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, current_y - bar_height, colors[i]);
                current_y -= bar_height;
            }

            if (sortOtherBytes > 0 && current_y > chart_start_y) {
                tft.drawLine(current_x, current_y, current_x, chart_start_y + 1, colors[8]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, chart_start_y + 1, colors[8]);
            } else if (sortOtherBytes == 0 && current_y > chart_start_y && sortChannelCount > 0) {
                tft.drawLine(current_x, current_y, current_x, chart_start_y + 1, colors[sortChannelCount - 1]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, chart_start_y + 1, colors[sortChannelCount - 1]);
            }
        }
    }
    static uint32_t last_rendered_leak_timestamp = 0;
    if (currentRadioMode == RADIO_PCAP) {
        current_total_metric = capture_bytes_render;

        // Redraw only if the newest packet in the buffer has changed
        if (terminal_history[0].meta.timestamp != last_rendered_leak_timestamp && terminal_history[0].meta.timestamp > 0) {
            last_rendered_leak_timestamp = terminal_history[0].meta.timestamp;

            int terminal_start_y = 26;
            tft.fillRect(0, terminal_start_y, 480, split_y - terminal_start_y - 1, TFT_BLACK);

            tft.setFreeFont(&UbuntuMono_Regular8pt7b);
            tft.setTextDatum(TL_DATUM);

            int cursor_y = terminal_start_y + 4;

            // --- PASS 1: figure out which packets actually fit, newest-first ---
            int drawIdx[MAX_TERMINAL_LINES];
            int drawCount = 0;
            {
                int scan_y = cursor_y;
                for (int i = 0; i < MAX_TERMINAL_LINES; i++) {
                    if (terminal_history[i].meta.timestamp == 0) continue;

                    int pLen = strnlen(terminal_history[i].text, MAX_LEAK_STR_LEN);
                    int payload_lines = (pLen > 0) ? ((pLen - 1) / 57) + 1 : 1;
                    if (payload_lines > 9) payload_lines = 9;
                    int needed = 42 + (payload_lines * 14) + 5; // 3 meta rows + payload + margin

                    if (scan_y + needed > split_y) break;
                    scan_y += needed;
                    drawIdx[drawCount++] = i;
                }
            }

            // --- PASS 2: draw them oldest-of-the-kept-set first, for the scroll effect ---
                for (int k = drawCount - 1; k >= 0; k--) {
                    int i = drawIdx[k];

                // ==========================================
                // LIVE VENDOR LOOKUP — RAM CACHE ONLY
                //
                // IMPORTANT:
                // No leakHistory dependency.
                // No SD access.
                // No vendor resolution.
                // This is strictly an ephemeral fast-path lookup.
                // ==========================================

                char srcVend[9] = "";
                char dstVend[9] = "";

                if (!lookupVendorCache(
                        terminal_history[i].meta.src_mac,
                        srcVend,
                        sizeof(srcVend))) {

                    strlcpy(srcVend, "Unknown", sizeof(srcVend));
                }

                if (!lookupVendorCache(
                        terminal_history[i].meta.dst_mac,
                        dstVend,
                        sizeof(dstVend))) {

                    strlcpy(dstVend, "Unknown", sizeof(dstVend));
                }

                // --- INLINE FORMATTERS ---
                // 1. Compact Length (Max 4 chars)
                char lenStr[8];
                uint16_t fLen = terminal_history[i].meta.frame_length;
                if (fLen < 1000) snprintf(lenStr, sizeof(lenStr), "%dB", fLen);
                else snprintf(lenStr, sizeof(lenStr), "%dK", fLen / 1000);

                // 2. Safe IPv6 Buffers (40 bytes to prevent overflow)
                char srcIpRaw[40] = {0}, dstIpRaw[40] = {0};
                getIpString(terminal_history[i].meta.ip_version, terminal_history[i].meta.src_ip, srcIpRaw, sizeof(srcIpRaw));
                getIpString(terminal_history[i].meta.ip_version, terminal_history[i].meta.dst_ip, dstIpRaw, sizeof(dstIpRaw));

                // 3. IPv6 Compression (RFC 5952 longest-run collapse, replaces old sequential strstr/memmove approach)
                char srcIpStr[40] = {0}, dstIpStr[40] = {0};
                if (terminal_history[i].meta.ip_version == 6) {
                    compress_ipv6(srcIpRaw, srcIpStr, sizeof(srcIpStr));
                    compress_ipv6(dstIpRaw, dstIpStr, sizeof(dstIpStr));
                } else {
                    strncpy(srcIpStr, srcIpRaw, sizeof(srcIpStr) - 1);
                    strncpy(dstIpStr, dstIpRaw, sizeof(dstIpStr) - 1);
                }

                // 4. Fast Live Age Calculator (Seconds Resolution)
                char firstSeenStr[8], lastSeenStr[8], ageCombo[18];
                uint32_t now_ms = millis();
                uint32_t first_sec = (now_ms - terminal_first_seen[i]) / 1000;
                uint32_t last_sec = (now_ms - terminal_history[i].meta.timestamp) / 1000;

                if (first_sec < 60) snprintf(firstSeenStr, sizeof(firstSeenStr), "%ds", first_sec);
                else if (first_sec < 3600) snprintf(firstSeenStr, sizeof(firstSeenStr), "%dm", first_sec / 60);
                else snprintf(firstSeenStr, sizeof(firstSeenStr), "%dh", first_sec / 3600);

                if (last_sec < 60) snprintf(lastSeenStr, sizeof(lastSeenStr), "%ds", last_sec);
                else if (last_sec < 3600) snprintf(lastSeenStr, sizeof(lastSeenStr), "%dm", last_sec / 60);
                else snprintf(lastSeenStr, sizeof(lastSeenStr), "%dh", last_sec / 3600);

                snprintf(ageCombo, sizeof(ageCombo), "%s|%s", firstSeenStr, lastSeenStr);

                // 5. Fetch Live SSID (Using persistent cache to bypass the union)
                char safeSsid[13] = "Unknown";
                for (int ap = 0; ap < MAX_BSSID_CACHE; ap++) {
                    if (bssidCache[ap].last_seen == 0) continue; // Skip empty slots

                    if (memcmp(terminal_history[i].meta.bssid, bssidCache[ap].bssid, 6) == 0) {
                        strncpy(safeSsid, bssidCache[ap].ssid, 12);
                        safeSsid[12] = '\0';
                        break;
                    }
                }

                // --- ROW 1: MAC(Vend)>MAC(Vend)|Len|C ---
                tft.setTextColor(TFT_CYAN);
                char line1[80];
                snprintf(line1, sizeof(line1), "%02X%02X%02X%02X%02X%02X(%s)>%02X%02X%02X%02X%02X%02X(%s)|%s|C%d",
                         terminal_history[i].meta.src_mac[0], terminal_history[i].meta.src_mac[1], terminal_history[i].meta.src_mac[2],
                         terminal_history[i].meta.src_mac[3], terminal_history[i].meta.src_mac[4], terminal_history[i].meta.src_mac[5],
                         srcVend,
                         terminal_history[i].meta.dst_mac[0], terminal_history[i].meta.dst_mac[1], terminal_history[i].meta.dst_mac[2],
                         terminal_history[i].meta.dst_mac[3], terminal_history[i].meta.dst_mac[4], terminal_history[i].meta.dst_mac[5],
                         dstVend, lenStr, terminal_history[i].meta.channel);
                tft.drawString(line1, 4, cursor_y);
                cursor_y += 14;

                // --- ROW 2: BSSID(SSID)|DIR|SUBTYPE|PROTO|PORTS ---
                tft.setTextColor(TFT_YELLOW);
                char portStr[24] = "";
                if (terminal_history[i].meta.protocol == 6 || terminal_history[i].meta.protocol == 17) {
                    snprintf(portStr, sizeof(portStr), "|%d>%d", terminal_history[i].meta.src_port, terminal_history[i].meta.dst_port);
                }
                char line2[80];
                snprintf(line2, sizeof(line2), "%02X%02X%02X%02X%02X%02X(%s)|%s|%s|%s%s",
                         terminal_history[i].meta.bssid[0], terminal_history[i].meta.bssid[1], terminal_history[i].meta.bssid[2],
                         terminal_history[i].meta.bssid[3], terminal_history[i].meta.bssid[4], terminal_history[i].meta.bssid[5],
                         safeSsid,
                         getDirectionStr(terminal_history[i].meta.direction),
                         getSubtypeStr(terminal_history[i].meta.frame_subtype),
                         getProtocolStr(terminal_history[i].meta.protocol), portStr);
                tft.drawString(line2, 4, cursor_y);
                cursor_y += 14;

                // --- ROW 3: IP>IP|first/last ---
                tft.setTextColor(TFT_ORANGE);
                char line3[90];
                snprintf(line3, sizeof(line3), "%s>%s|%s",
                         srcIpStr, dstIpStr, ageCombo);
                tft.drawString(line3, 4, cursor_y);
                cursor_y += 14;

                // --- ROW 4 & 5: PAYLOAD ---
                tft.setTextColor(TFT_GREEN);

                int pLen = strnlen(terminal_history[i].text, MAX_LEAK_STR_LEN);
                const int maxChars = 57; // (460-4)/8
                int n_lines = (pLen > 0) ? ((pLen - 1) / maxChars) + 1 : 1;
                if (n_lines > 9) n_lines = 9;

                char sanitized[MAX_LEAK_STR_LEN + 1] = {0};
                memcpy(sanitized, terminal_history[i].text, pLen);
                for (int c = 0; c < pLen; c++) {
                    if (sanitized[c] < 32 || sanitized[c] > 126) sanitized[c] = '.';
                }

                for (int line = 0; line < n_lines; line++) {
                    char lineBuf[60] = {0};
                    int offset = line * maxChars;
                    int remaining = pLen - offset;
                    int chunk = (remaining < maxChars) ? remaining : maxChars;
                    strncpy(lineBuf, sanitized + offset, chunk);
                    tft.drawString(lineBuf, 4, cursor_y);
                    cursor_y += 14;
                }
                tft.drawLine(0, cursor_y + 2, 480, cursor_y + 2, COLOR_HOT_CHEST);
                cursor_y += 5;
            }
        }
    }

    // --- BOTTOM PANE: SCALING ENGINE ---
    static RadioMode last_seen_mode = currentRadioMode;
    static uint8_t last_seen_bssid[6] = {0};

    static uint32_t true_max = 10;
    static uint16_t peak_h_index = 0;

    bool did_rescale = false;

    if (currentRadioMode != last_seen_mode || memcmp(target_bssid, last_seen_bssid, 6) != 0) {
        true_max = 10;
        peak_h_index = 0;
        absolute_max_traffic = 10;

        last_seen_mode = currentRadioMode;
        memcpy(last_seen_bssid, target_bssid, 6);

        memset(traffic_history, 0, sizeof(traffic_history));
        did_rescale = true;
    }

    int h_index = current_x / 2;
    traffic_history[h_index] = current_total_metric;

    if (current_total_metric > absolute_max_traffic) {
        true_max = current_total_metric;
        peak_h_index = h_index;
        absolute_max_traffic = current_total_metric + (current_total_metric / 5);
        did_rescale = true;
    } else {
        if (current_total_metric > true_max) {
            true_max = current_total_metric;
            peak_h_index = h_index;
        }

        if (h_index == peak_h_index && current_total_metric < true_max) {
            true_max = 0;
            for (int i = 0; i < 240; i++) {
                if (traffic_history[i] > true_max) {
                    true_max = traffic_history[i];
                    peak_h_index = i;
                }
            }

            uint32_t next_scale = true_max + (true_max / 5);
            if (next_scale < 10) next_scale = 10;

            if (next_scale < absolute_max_traffic) {
                absolute_max_traffic = next_scale;
                did_rescale = true;
            }
        }
    }

    if (did_rescale) {
        tft.fillRect(0, split_y + 1, 480, CHART_BOTTOM - split_y, TFT_BLACK);
        tft.drawLine(0, split_y, 480, split_y, COLOR_HOT_CHEST);

        for (int c = 0; c < 240; c++) {
            int px = c * 2;
            if (px % 60 == 0) {
                tft.drawLine(px, split_y + 1, px, split_y + 3, COLOR_HOT_CHEST);
                tft.drawLine(px + 1, split_y + 1, px + 1, split_y + 3, COLOR_HOT_CHEST);
            }

            if (traffic_history[c] > 0) {
                int h = (int)(((double)traffic_history[c] / (double)absolute_max_traffic) * (CHART_BOTTOM - split_y - 1));
                if (h > CHART_BOTTOM - split_y - 4) h = CHART_BOTTOM - split_y - 4;

                tft.drawLine(px, CHART_BOTTOM, px, CHART_BOTTOM - h, COLOR_HOT_CHEST);
                tft.drawLine(px + 1, CHART_BOTTOM, px + 1, CHART_BOTTOM - h, COLOR_HOT_CHEST);
            }
        }
    } else {
        if (current_total_metric > 0) {
            int h = (int)(((double)current_total_metric / (double)absolute_max_traffic) * (CHART_BOTTOM - split_y - 1));
            if (h > CHART_BOTTOM - split_y - 4) h = CHART_BOTTOM - split_y - 4;

            tft.drawLine(current_x, CHART_BOTTOM, current_x, CHART_BOTTOM - h, COLOR_HOT_CHEST);
            tft.drawLine(current_x + 1, CHART_BOTTOM, current_x + 1, CHART_BOTTOM - h, COLOR_HOT_CHEST);
        }
    }

    // --- OVERLAYS ---
    // Gate the sweeping vertical lines to ONLY draw in the area below clear_start_y
    tft.drawFastVLine(current_x + 2, clear_start_y, clear_height, COLOR_HOT_CHEST);

    if (current_x + ERASER_WIDTH <= 480) {
        tft.drawFastVLine(current_x + ERASER_WIDTH - 1, clear_start_y, clear_height, COLOR_HOT_CHEST);
        tft.drawFastHLine(current_x, split_y, ERASER_WIDTH, COLOR_HOT_CHEST);
    } else {
        int w1 = 480 - current_x;
        tft.drawFastVLine(ERASER_WIDTH - w1 - 1, clear_start_y, clear_height, COLOR_HOT_CHEST);
        tft.drawFastHLine(current_x, split_y, w1, COLOR_HOT_CHEST);
        tft.drawFastHLine(0, split_y, ERASER_WIDTH - w1, COLOR_HOT_CHEST);
    }

    if (current_x <= 480 - ERASER_WIDTH || did_rescale) {
        int text_x = current_x + 6;
        if (text_x > 480 - 40) text_x = 480 - 40;

        tft.setFreeFont(&UbuntuMono_Regular8pt7b);
        tft.setTextDatum(TL_DATUM);
        tft.setTextColor(COLOR_HOT_CHEST);

        // Gate the top pane percentages AND the time scale so they don't overwrite PCAP text
        if (currentRadioMode != RADIO_PCAP) {
            tft.drawString("100%", text_x, chart_start_y + 4);
            int mid_y = chart_start_y + ((split_y - chart_start_y) / 2);
            tft.drawString("50%", text_x, mid_y - 6);

            if (currentRadioMode == RADIO_BLE || target_locked) tft.drawString("|=1m", text_x, split_y - 15);
            else tft.drawString("|=2m", text_x, split_y - 15);
        }

        char maxStr[16];
        if (currentRadioMode == RADIO_BLE) {
            snprintf(maxStr, sizeof(maxStr), "%lu", absolute_max_traffic);
        } else {
            if (absolute_max_traffic < 1024) snprintf(maxStr, sizeof(maxStr), "%lu", absolute_max_traffic);
            else if (absolute_max_traffic < 1048576) snprintf(maxStr, sizeof(maxStr), "%luK", absolute_max_traffic / 1024);
            else if (absolute_max_traffic < 1073741824) snprintf(maxStr, sizeof(maxStr), "%luM", absolute_max_traffic / 1048576);
            else snprintf(maxStr, sizeof(maxStr), "%.1fG", (float)absolute_max_traffic / 1073741824.0);
        }

        tft.drawString(maxStr, text_x, split_y + 4);
        tft.drawString("0", text_x, CHART_BOTTOM - 12);
    }

    current_x += 2;
    if (current_x >= 480) current_x = 0;
}
