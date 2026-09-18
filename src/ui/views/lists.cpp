#include "lists.h"
#include "ui/ui_state.h"
#include "ui/ui_utils.h"
#include "core/radio.h"
#include "core/wavehound_state.h"
#include "core/rf_utils.h"
#include "modes/ap_scanner.h"
#include "modes/wifi.h"
#include "capture/capture.h"
#include "osint/osint.h"
#include "osint/vendor.h"
#include "parsers/parser_common.h"
#include "UbuntuMono_Regular11pt7b.h"
#include "UbuntuMono_Regular9pt7b.h"
#include "UbuntuMono_Regular8pt7b.h"
#include "UbuntuMono_B9pt7b.h"
#include <string.h>
#include <stdio.h>

#include "foxhunt.h"

void drawMenu() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(1);

  // HEADER
  tft.setFreeFont(&UbuntuMono_Regular11pt7b);
  tft.setTextDatum(MC_DATUM);
  tft.setTextColor(TFT_WHITE);
  tft.drawString("DASHBOARD SETTINGS", 240, 40);

  tft.setFreeFont(&UbuntuMono_Regular9pt7b);

  // ==========================================
  // FOXHUNT BUTTON (Tactical Mode)
  // ==========================================
  tft.setTextDatum(MC_DATUM);

  bool foxhunt_available = false;

  // 1. BLE MODE EVALUATION
  if (currentRadioMode == RADIO_BLE) {
    if (sessionBleCount > 0) {
        foxhunt_available = true;
    }
  }
  // 2. NETWORKS (AP) MODE EVALUATION
  else if (currentRadioMode == RADIO_AP) {
      if (sessionApCount > 0) {
          foxhunt_available = true;
      }
  }
  // 3. WI-FI MODE EVALUATION (Isolated at the bottom)
  else if (currentRadioMode == RADIO_WIFI) {
      if (target_locked == true && sessionMacCount > 0) {
          foxhunt_available = true;
      }
  }

  if (foxhunt_available) {
      // Draw active red button
      tft.fillRoundRect(50, 90, 200, 40, 3, TFT_RED);   // Fill it red
      tft.drawRoundRect(50, 90, 200, 40, 3, TFT_WHITE); // Add the crisp border
      tft.setTextColor(TFT_WHITE);
      tft.drawString("FOXHUNT", 150, 110);
  } else {
      // Greyed out — no target locked
      uint16_t deadGrey = hex24to565(0x222222);
      tft.fillRect(50, 90, 200, 40, deadGrey);
      tft.drawRect(50, 90, 200, 40, TFT_DARKGREY);
      tft.setTextColor(TFT_DARKGREY);
      tft.drawString("FOXHUNT", 150, 110);

      // Hint text
      tft.setFreeFont(&UbuntuMono_Regular9pt7b);
      tft.setTextColor(hex24to565(0x444444));
      tft.drawString("(no targets yet)", 150, 125);
  }

  // ==========================================
  // PROBE REQUEST BUTTON (Right Column)
  // ==========================================
  uint16_t purpleColor = hex24to565(0x4A148C);
  tft.fillRect(300, 140, 150, 40, purpleColor);
  tft.drawRect(300, 140, 150, 40, TFT_WHITE);
  tft.setTextColor(TFT_WHITE);
  tft.drawString("SNIFFED PROBES", 375, 160);

  // ==========================================
  // 3. AP SCANNER / CH SELECT BUTTON (Y: 190 - 230)
  // ==========================================
  if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP || currentRadioMode == RADIO_PCAP) {
    // Active State
    tft.fillRect(50, 190, 200, 40, TFT_BLACK);
    tft.drawRect(50, 190, 200, 40, TFT_WHITE);
    tft.setTextColor(TFT_WHITE);

    if (currentRadioMode == RADIO_WIFI) {
        tft.drawString("SELECT AP", 150, 210);
    } else if (currentRadioMode == RADIO_AP || currentRadioMode == RADIO_PCAP) {
        if (target_locked) {
            char chStr[16];
            snprintf(chStr, sizeof(chStr), "LOCKED: CH %d", target_channel);
            tft.drawString(chStr, 150, 210);
        } else {
            tft.drawString("SELECT CH", 150, 210);
        }
    }
  } else {
    // "Cold" Abyss State
    uint16_t deadGrey = hex24to565(0x222222);      // Almost black
    tft.fillRect(50, 190, 200, 40, deadGrey);
    tft.drawRect(50, 190, 200, 40, TFT_DARKGREY);
    tft.setTextColor(TFT_DARKGREY);
    tft.drawString("SELECT AP", 150, 210);
  }

  // 4. SEEN DEVICES BUTTON
  tft.fillRect(50, 240, 200, 40, TFT_BLACK);
  tft.drawRect(50, 240, 200, 40, TFT_WHITE);
  tft.setTextColor(TFT_WHITE);
  tft.drawString("SNIFF LIST", 150, 260);

  // ==========================================
  // RADIO MODE TOGGLE
  // ==========================================
  tft.setTextColor(TFT_WHITE); // Set this once for all modes

  // 1. Draw the filled background based on the current mode
  if (currentRadioMode == RADIO_WIFI) {
    tft.fillRect(300, 190, 150, 40, TFT_BLUE);
  }
  else if (currentRadioMode == RADIO_BLE) {
    tft.fillRect(300, 190, 150, 40, TFT_PURPLE);
  }
  else if (currentRadioMode == RADIO_AP) {
    tft.fillRect(300, 190, 150, 40, TFT_DARKGREEN);
  }
  else if (currentRadioMode == RADIO_CHANNELS) {
    tft.fillRect(300, 190, 150, 40, TFT_ORANGE);
  }
  else if (currentRadioMode == RADIO_PCAP) {
    tft.fillRect(300, 190, 150, 40, TFT_MAROON);
  }

  // 2. Draw the universal white border
  tft.drawRect(300, 190, 150, 40, TFT_WHITE);

  // 3. Draw the corresponding text label
  if (currentRadioMode == RADIO_WIFI) {
    tft.drawString("MODE: WI-FI", 375, 210);
  }
  else if (currentRadioMode == RADIO_BLE) {
    tft.drawString("MODE: BLE", 375, 210);
  }
  else if (currentRadioMode == RADIO_AP) {
    tft.drawString("MODE: NETWORKS", 375, 210);
  }
  else if (currentRadioMode == RADIO_CHANNELS) {
    tft.drawString("MODE: CHANNELS", 375, 210);
  }
  else if (currentRadioMode == RADIO_PCAP) {
    tft.drawString("MODE: PCAP", 375, 210);
  }

  // 5. EXIT BUTTON
  tft.fillRect(300, 240, 150, 40, TFT_RED);
  tft.drawRect(300, 240, 150, 40, TFT_WHITE);
  tft.setTextColor(TFT_WHITE);
  tft.drawString("EXIT", 375, 260);

  // THE FIX: Reset datum to Top-Left for the rest of the UI ONLY at the very end!
  tft.setTextDatum(TL_DATUM);
}
void drawApScanner() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(1);

  int n = WiFi.scanComplete();
  if (n < 0) {
    ap_current_page = 0;

    tft.setFreeFont(&UbuntuMono_Regular11pt7b);
    tft.setTextDatum(MC_DATUM);
    tft.setTextColor(TFT_WHITE);
    tft.fillRect(0, 0, 480, 30, TFT_BLUE);
    tft.drawString("SCANNING ACCESS POINTS...", 240, 15);

    esp_wifi_set_promiscuous(false);
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);

    n = WiFi.scanNetworks();
  }

  tft.setFreeFont(&UbuntuMono_Regular11pt7b);
  tft.setTextDatum(MC_DATUM);
  tft.setTextColor(TFT_WHITE);
  tft.fillRect(0, 0, 480, 30, TFT_BLUE);

  // Build the dynamic header string using the 'n' variable
  char headerStr[64];
  snprintf(headerStr, sizeof(headerStr), "SELECT TARGET AP (%d)", n);
  tft.drawString(headerStr, 240, 15);

  tft.setFreeFont(&UbuntuMono_Regular11pt7b);
  tft.setTextDatum(TL_DATUM);
  tft.setTextColor(TFT_GREEN);
  tft.drawRect(0, 40, 480, 35, TFT_DARKGREY);
  tft.drawString("CH:ALL (Sniff Free Airspace)", 5, 50);

  tft.setTextColor(TFT_WHITE);

  // ==========================================
  // LIST GENERATION
  // ==========================================
  if (n == 0) {
    tft.drawString("No networks found in airspace.", 5, 90);
  } else {
    int start_idx = ap_current_page * APS_PER_PAGE;

    if (start_idx >= n) {
      ap_current_page = 0;
      start_idx = 0;
    }

    int end_idx = start_idx + APS_PER_PAGE;
    if (end_idx > n) end_idx = n;

    int row = 0;
    for (int i = start_idx; i < end_idx; ++i) {
      int y = 80 + (row * 35);

      // 1. Get the raw BSSID bytes and the SSID string
      uint8_t* bssid = WiFi.BSSID(i);
      String raw_ssid = WiFi.SSID(i);
      char tactical_ssid[26];

      // 2. Determine if this SSID is a duplicate in the airspace
      bool has_clone = false;
      if (raw_ssid.length() > 0) {
        for (int j = 0; j < n; ++j) {
          if (i != j && WiFi.SSID(j) == raw_ssid) {
            has_clone = true;
            break;
          }
        }
      }

      // 3. Construct the Tactical Suffix String
      if (raw_ssid.length() == 0) {
        snprintf(tactical_ssid, sizeof(tactical_ssid), "<HIDDEN> [%02X%02X]", bssid[4], bssid[5]);
      } else if (has_clone) {
        char temp_ssid[16];
        strncpy(temp_ssid, raw_ssid.c_str(), 15);
        temp_ssid[15] = '\0';
        snprintf(tactical_ssid, sizeof(tactical_ssid), "%s~%02X%02X", temp_ssid, bssid[4], bssid[5]);
      } else {
        char temp_ssid[22];
        strncpy(temp_ssid, raw_ssid.c_str(), 21);
        temp_ssid[21] = '\0';
        snprintf(tactical_ssid, sizeof(tactical_ssid), "%s", temp_ssid);
      }

      // 4. Calculate Distance dynamically
      float dist = calculateRfDistance(WiFi.RSSI(i), 0, RADIO_WIFI_24GHZ);

      // 5. SPLIT DRAWING LOGIC FOR PERFECT ALIGNMENT

      // Build the Left String (Channel & SSID)
      char leftStr[60];
      snprintf(leftStr, sizeof(leftStr), "CH:%02d %s", WiFi.channel(i), tactical_ssid);

      // Build the Right String (RSSI & Distance) with rigid width padding
      char rightStr[30];
      snprintf(rightStr, sizeof(rightStr), "%4ddBm %3.0fm", WiFi.RSSI(i), dist);

      // Paint Left Side (Flush Left at X=5)
      tft.setTextDatum(TL_DATUM);
      tft.drawString(leftStr, 5, y + 10);

      // Paint Right Side (Flush Right at X=475)
      tft.setTextDatum(TR_DATUM);
      tft.drawString(rightStr, 475, y + 10);

      tft.drawRect(0, y, 480, 35, TFT_DARKGREY);
      row++;
    }
  }

  // ==========================================
  // FOOTER & NAVIGATION (Synced to Y=294)
  // ==========================================
  tft.setFreeFont(&UbuntuMono_Regular9pt7b);
  tft.setTextDatum(TL_DATUM);

  // THE FIX: Pushed down from 285 to perfectly match the Probe Tracker footer
  tft.drawLine(0, 294, 480, 294, TFT_WHITE);

  tft.setTextColor(TFT_RED);
  tft.drawString("BACK", 215, 300);

  if (n > APS_PER_PAGE) {
    tft.setTextColor(TFT_WHITE);

    if (ap_current_page > 0) {
      tft.drawString("<- PREV", 20, 300);
    }

    if (((ap_current_page + 1) * APS_PER_PAGE) < n) {
      tft.drawString("NEXT ->", 360, 300);
    }
  }
}
// Shared dynamic PCAP pagination (declared in lists.h): gathers occupied
// leakHistory entries (the same timestamp>0 predicate the renderer uses) and
// packs them into pages by rendered height. Used by BOTH drawDeviceList() and
// the touch handler so the drawn NEXT -> button and the NEXT touch gate agree.
PcapPagination computePcapPagination(int *valid_indices,
                                            int &valid_count,
                                            int &total_pages) {
  PcapPagination pp;
  memset(pp.page_starts, 0, sizeof(pp.page_starts));
  total_pages = 0;
  valid_count = 0;

  // --- 1. GATHER LOGICAL ENTRIES ---
  for (int i = 0; i < MAX_LEAK_SLOTS; i++) {
    if (leakHistory[i].leak.meta.timestamp > 0) {
      valid_indices[valid_count++] = i;
    }
  }

  // --- 2. DYNAMIC PCAP "SNUG" PACKING ---
  const int maxChars = 58;
  int test_y = 32;

  for (int v = 0; v < valid_count; v++) {
    int idx = valid_indices[v];
    int pLen = leakHistory[idx].leak.retained_len;

    // FRIEND'S FIX: Defensive clamping for the packing math
    if (pLen > MAX_LEAK_STR_LEN - 1)
      pLen = MAX_LEAK_STR_LEN - 1;

    // Dynamically scale up to 9 lines (512 bytes / 58 chars)
    int n_lines = (pLen > 0) ? ((pLen - 1) / maxChars) + 1 : 1;
    if (n_lines > 9)
      n_lines = 9;

    int item_h = 42 + (n_lines * 14) + 5;

    if (test_y + item_h > 290) {
      if (total_pages < MAX_LEAK_SLOTS - 1) { // Prevents out-of-bounds on page_starts
        total_pages++;
        pp.page_starts[total_pages] = v;
      }
      test_y = 32 + item_h;
    } else {
      test_y += item_h;
    }
  }

  return pp;
}

void drawDeviceList() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextDatum(TL_DATUM);
  tft.setTextSize(1);

  // ==========================================
  // 1. DEVICE COUNTING
  // ==========================================
  int total_devices = 0;

  if (currentRadioMode == RADIO_WIFI) total_devices = sessionMacCount;
  else if (currentRadioMode == RADIO_BLE) total_devices = sessionBleCount;
  else if (currentRadioMode == RADIO_AP) total_devices = sessionApCount;
  else if (currentRadioMode == RADIO_CHANNELS) total_devices = sessionChannelCount;
  else if (currentRadioMode == RADIO_PCAP) {
      for (int i = 0; i < MAX_LEAK_SLOTS; i++) {
          if (leakHistory[i].leak.meta.timestamp > 0) total_devices++;
      }
  }

  // ==========================================
  // 2. DYNAMIC PAGINATION MATH
  // ==========================================
  int start_idx = 0;
  int end_idx = 0;
  bool has_next_page = false;

  // DECLARE IN OUTER SCOPE SO RENDERER CAN SEE THEM!
  int valid_indices[MAX_LEAK_SLOTS] = {0};
  int valid_count = 0;

  if (currentRadioMode == RADIO_PCAP) {
      int total_pages = 0;
      PcapPagination pp = computePcapPagination(valid_indices, valid_count,
                                                total_pages);

      if (device_current_page > total_pages) device_current_page = total_pages;
      start_idx = pp.page_starts[device_current_page];
      end_idx = (device_current_page < total_pages)
                    ? pp.page_starts[device_current_page + 1]
                    : valid_count;
      has_next_page = (device_current_page < total_pages);

  } else {
      // --- FIXED GRID PACKING (WIFI/AP/BLE/CHANNELS) ---
      int items_per_page = 7;
      start_idx = device_current_page * items_per_page;
      if (start_idx >= total_devices) {
          device_current_page = 0;
          start_idx = 0;
      }
      end_idx = start_idx + items_per_page;
      if (end_idx > total_devices) end_idx = total_devices;
      has_next_page = (((device_current_page + 1) * items_per_page) < total_devices);
  }

  // ==========================================
  // 3. DRAW TOP BANNER (WITH FOXHUNT OVERRIDE)
  // ==========================================
  tft.setTextColor(TFT_WHITE);
  tft.setFreeFont(&UbuntuMono_B9pt7b);

  if (is_selecting_target) {
    tft.fillRect(0, 0, 480, 24, TFT_RED);
    char huntStr[64];
    const char* modeName = (currentRadioMode == RADIO_WIFI) ? "WI-FI" : (currentRadioMode == RADIO_BLE) ? "BLE" : "NETWORKS";
    snprintf(huntStr, sizeof(huntStr), " FOXHUNT TARGET (%s)", modeName);
    tft.drawString(huntStr, 5, 5);
  } else {
    uint16_t headerColor = TFT_BLUE;
    const char* modeStr = "WI-FI";

    if (currentRadioMode == RADIO_BLE) { headerColor = TFT_PURPLE; modeStr = "BLE"; }
    else if (currentRadioMode == RADIO_AP) { headerColor = TFT_DARKGREEN; modeStr = "NETWORKS"; }
    else if (currentRadioMode == RADIO_CHANNELS) { headerColor = TFT_ORANGE; modeStr = "CHANNELS"; }
    else if (currentRadioMode == RADIO_PCAP) { headerColor = TFT_MAROON; modeStr = "PCAP LEAKS"; }

    tft.fillRect(0, 0, 480, 24, headerColor);
    char headerStr[64];
    snprintf(headerStr, sizeof(headerStr), " SNIFFED %s (%d)", modeStr, total_devices);
    tft.drawString(headerStr, 5, 5);
  }

  // ==========================================
  // 4. DYNAMIC SORT BUTTONS
  // ==========================================
  tft.setFreeFont(&UbuntuMono_Regular9pt7b);
  char metricStr[32] = "SORT:ERR";
  uint16_t metricColor = TFT_RED;

  if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP) {
    if (currentSortMode == SORT_TOTAL) { strcpy(metricStr, "SORT:TOTAL"); metricColor = TFT_WHITE; }
    else if (currentSortMode == SORT_TX) { strcpy(metricStr, "SORT:TX"); metricColor = TFT_CYAN; }
    else if (currentSortMode == SORT_RX) { strcpy(metricStr, "SORT:RX"); metricColor = TFT_MAGENTA; }
    else if (currentSortMode == SORT_AVG) { strcpy(metricStr, "SORT:AVG"); metricColor = TFT_YELLOW; }
    else if (currentSortMode == SORT_CV) { strcpy(metricStr, "SORT:CV%"); metricColor = TFT_ORANGE; }
    else if (currentSortMode == SORT_DIST) { strcpy(metricStr, "SORT:DIST"); metricColor = TFT_GREEN; }
    else if (currentSortMode == SORT_AGE) { strcpy(metricStr, "SORT:AGE"); metricColor = TFT_BLUE; }
  }
  else if (currentRadioMode == RADIO_CHANNELS) {
    if (currentSortMode == SORT_TOTAL) { strcpy(metricStr, "SORT:TOTAL"); metricColor = TFT_WHITE; }
    else if (currentSortMode == SORT_TX) { strcpy(metricStr, "SORT:DN"); metricColor = TFT_CYAN; }
    else if (currentSortMode == SORT_RX) { strcpy(metricStr, "SORT:UP"); metricColor = TFT_MAGENTA; }
    else if (currentSortMode == SORT_AVG) { strcpy(metricStr, "SORT:AVG"); metricColor = TFT_YELLOW; }
    else if (currentSortMode == SORT_CV) { strcpy(metricStr, "SORT:CV%"); metricColor = TFT_ORANGE; }
    else if (currentSortMode == SORT_DIST) { strcpy(metricStr, "SORT:PWR"); metricColor = TFT_GREEN; }
  }
  else if (currentRadioMode == RADIO_BLE) {
    if (currentBleSortMode == SORT_BLE_HITS) { strcpy(metricStr, "SORT:HITS"); metricColor = TFT_WHITE; }
    else if (currentBleSortMode == SORT_BLE_DIST) { strcpy(metricStr, "SORT:DIST"); metricColor = TFT_GREEN; }
    else if (currentBleSortMode == SORT_BLE_AGE) { strcpy(metricStr, "SORT:AGE"); metricColor = TFT_BLUE; }
  }
  else if (currentRadioMode == RADIO_PCAP) {
    if (currentLeakSort == SORT_LEAK_AGE) { strcpy(metricStr, "SORT:AGE"); metricColor = TFT_BLUE; }
    else if (currentLeakSort == SORT_LEAK_LENGTH) { strcpy(metricStr, "SORT:SIZE"); metricColor = TFT_CYAN; }
    else if (currentLeakSort == SORT_LEAK_HITS) { strcpy(metricStr, "SORT:HITS"); metricColor = TFT_WHITE; }
  }

  tft.fillRoundRect(275, 2, 130, 20, 3, TFT_BLACK);
  tft.drawRoundRect(275, 2, 130, 20, 3, TFT_WHITE);
  tft.setTextColor(metricColor);
  tft.drawString(metricStr, 282, 4);

  tft.fillRoundRect(410, 2, 65, 20, 3, TFT_BLACK);
  tft.drawRoundRect(410, 2, 65, 20, 3, TFT_WHITE);

  if (sort_descending) {
    tft.setTextColor(TFT_WHITE);
    tft.drawString("DESC", 423, 4);
  } else {
    tft.setTextColor(TFT_GREEN);
    tft.drawString("ASC", 427, 4);
  }

  tft.setTextColor(TFT_WHITE);

  if (total_devices == 0) {
    tft.setFreeFont(&UbuntuMono_Regular9pt7b);
    tft.drawString("No devices captured yet.", 5, 45);
  } else {
    // ==========================================
    // 5. DRAW THE UNIFIED DUAL COLUMN HEADERS
    // ==========================================
    if (currentRadioMode != RADIO_PCAP) {
        tft.setTextColor(TFT_GREEN);
        if (currentRadioMode == RADIO_WIFI) {
          tft.setFreeFont(&UbuntuMono_B9pt7b);
          tft.drawString("     VENDOR                 MAC            RSSI TOTAL", 5, 26);
          tft.setFreeFont(&UbuntuMono_Regular9pt7b);
          tft.drawString("Per(s) FIRST | LAST DIST Mbps  AVG    CV%    TX | RX", 5, 41);
        }
        else if (currentRadioMode == RADIO_AP) {
          tft.setFreeFont(&UbuntuMono_B9pt7b);
          tft.drawString("     SSID                 BSSID         CC RSSI TOTAL", 5, 26);
          tft.setFreeFont(&UbuntuMono_Regular9pt7b);
          tft.drawString("    FIRST | LAST  DIST CH RATE  AVG  CV%    TX | RX", 5, 41);
        }
        else if (currentRadioMode == RADIO_CHANNELS) {
          tft.setFreeFont(&UbuntuMono_B9pt7b);
          tft.drawString("     CHANNEL           PWR(AVG dBm|STD)         TOTAL", 5, 26);
          tft.setFreeFont(&UbuntuMono_Regular9pt7b);
          tft.drawString("    FIRST | LAST         STATE   AVG  CV%    DN | UP", 5, 41);
        }
        else {
          tft.setFreeFont(&UbuntuMono_B9pt7b);
          tft.drawString("    NAME                FIRST|LAST    RSSI  DIST  HITS", 5, 26);
          tft.setFreeFont(&UbuntuMono_Regular9pt7b);
          tft.drawString("MAC ADDRESS        VENDOR/DIAGNOSTIC PAYLOAD", 5, 41);
        }
        tft.setTextColor(TFT_WHITE);
        tft.drawLine(0, 57, 480, 57, TFT_WHITE);
    }

    // ==========================================
    // 6. DRAW THE DATA ROWS
    // ==========================================
    int row = 0;
    int base_y = (currentRadioMode == RADIO_PCAP) ? 32 : 62;
    int y_spacing = 33; // Fixed spacing for all non-PCAP modes
    int dyn_y = base_y; // Dynamic tracker exclusively for PCAP mode

    for (int i = start_idx; i < end_idx; i++) {

      // Select the correct Y coordinate based on the mode
      int y = (currentRadioMode == RADIO_PCAP) ? dyn_y : (base_y + (row * y_spacing));

      if (currentRadioMode == RADIO_WIFI) {
        // ... [WIFI MODE LOGIC REMAINS UNCHANGED] ...
        char line1[90]; char line2[90];
        resolveMacVendor(&sessionData[i]);

        char macStr[18];
        snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                 sessionData[i].mac[0], sessionData[i].mac[1], sessionData[i].mac[2],
                 sessionData[i].mac[3], sessionData[i].mac[4], sessionData[i].mac[5]);

        char safeVendor[20];
        snprintf(safeVendor, sizeof(safeVendor), "%-18.18s", sessionData[i].vendor);

        double mean = 0.0; double cv_percent = 0.0;
        if (sessionData[i].packets > 0) {
            mean = (double)sessionData[i].sum_bytes / (double)sessionData[i].packets;
            double avg_sq_sum = (double)sessionData[i].sum_sq_bytes / (double)sessionData[i].packets;
            double variance = avg_sq_sum - (mean * mean);
            if (variance < 0) variance = 0;
            double std_dev = sqrt(variance);
            if (mean > 0) cv_percent = (std_dev / mean) * 100.0;
        }

        char firstSeenStr[8], lastSeenStr[8], ageCombo[16];
        getAgeString(sessionData[i].first_seen, firstSeenStr, sizeof(firstSeenStr));
        getAgeString(sessionData[i].last_seen, lastSeenStr, sizeof(lastSeenStr));
        snprintf(ageCombo, sizeof(ageCombo), "%s|%s", firstSeenStr, lastSeenStr);

        uint32_t total_bytes = sessionData[i].tx_bytes + sessionData[i].rx_bytes;
        char totStr[10];
        formatTotalUnit(total_bytes, totStr, sizeof(totStr));

        char txStr[6], rxStr[6], trafficCombo[12];
        formatShortUnit(sessionData[i].tx_bytes, txStr, sizeof(txStr));
        formatShortUnit(sessionData[i].rx_bytes, rxStr, sizeof(rxStr));
        snprintf(trafficCombo, sizeof(trafficCombo), "%s|%s", txStr, rxStr);

        char avgStr[6];
        formatShortUnit((uint32_t)mean, avgStr, sizeof(avgStr));

        int keep_alive_s = 0;
        if (sessionData[i].packets > 1) {
            unsigned long duration_ms = sessionData[i].last_seen - sessionData[i].first_seen;
            keep_alive_s = (duration_ms / sessionData[i].packets) / 1000;
            if (keep_alive_s > 99) keep_alive_s = 99;
        }

        snprintf(line1, sizeof(line1), "%3d. %-18.18s %17s %4d %-5.5s",
                 (i + 1), safeVendor, macStr, sessionData[i].rssi, totStr);

        snprintf(line2, sizeof(line2), "  %02d  %13s %4.0fm %3d  %-5.5s %4.0f%%   %9s",
                 keep_alive_s, ageCombo, sessionData[i].smoothedDistance, sessionData[i].rate,
                 avgStr, cv_percent, trafficCombo);

        tft.setFreeFont(&UbuntuMono_B9pt7b);
        tft.drawString(line1, 5, y);
        tft.setTextColor(TFT_LIGHTGREY);
        tft.setFreeFont(&UbuntuMono_Regular9pt7b);
        tft.drawString(line2, 5, y + 15);
        tft.setTextColor(TFT_WHITE);

      } else if (currentRadioMode == RADIO_BLE) {
        // ... [BLE MODE LOGIC REMAINS UNCHANGED] ...
        char line1[90];
        char safeName[20];

        snprintf(safeName, sizeof(safeName), "%-18.18s", sessionBleData[i].name);

        char firstSeenStr[8], lastSeenStr[8], ageCombo[16];
        getAgeString(sessionBleData[i].firstSeen, firstSeenStr, sizeof(firstSeenStr));
        getAgeString(sessionBleData[i].lastSeen, lastSeenStr, sizeof(lastSeenStr));
        snprintf(ageCombo, sizeof(ageCombo), "%s|%s", firstSeenStr, lastSeenStr);

        const char* trackerStr = "";
        switch (sessionBleData[i].trackerType) {
            case TRACKER_APPLE_FINDMY: trackerStr = "Apple: Find My"; break;
            case TRACKER_APPLE_IBEACON: trackerStr = "Apple: iBeacon"; break;
            case TRACKER_GOOGLE_FASTPAIR: trackerStr = "Google: FastPair"; break;
            case TRACKER_SAMSUNG_SMARTTAG: trackerStr = "Samsung: SmartTag"; break;
            case TRACKER_TILE: trackerStr = "Tile Tracker"; break;
            case TRACKER_MS_SWIFTPAIR: trackerStr = "MS: Swift Pair"; break;
            case TRACKER_EDDYSTONE: trackerStr = "Eddystone"; break;
            default: trackerStr = ""; break;
        }

        const char* appStr = resolveBleAppearance(sessionBleData[i].appearanceId);
        const char* srvStr = resolveBleServiceUuid(sessionBleData[i].serviceId);

        char tagStr[64] = {0};

        if (strlen(trackerStr) > 0 && sessionBleData[i].namePriority != 1) {
            strlcpy(tagStr, trackerStr, sizeof(tagStr));
        }

        if (appStr != nullptr && appStr[0] != '\0') {
            if (tagStr[0] != '\0') strlcat(tagStr, " | ", sizeof(tagStr));
            strlcat(tagStr, appStr, sizeof(tagStr));
        }

        if (srvStr != nullptr && srvStr[0] != '\0') {
            if (tagStr[0] != '\0') strlcat(tagStr, " | ", sizeof(tagStr));
            strlcat(tagStr, srvStr, sizeof(tagStr));
        }

        if (tagStr[0] == '\0') {
            if (sessionBleData[i].payload[0] != '\0') {
                if (sessionBleData[i].trackerType == TRACKER_APPLE_IBEACON) {
                    snprintf(tagStr, sizeof(tagStr), "iBeacon | %s", sessionBleData[i].payload);
                } else {
                    strlcpy(tagStr, sessionBleData[i].payload, sizeof(tagStr));
                }
            } else {
                strlcpy(tagStr, "No Data", sizeof(tagStr));
            }
        }

        cleanOsintString(tagStr);

        char macStr[18];
        snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                 sessionBleData[i].mac[0], sessionBleData[i].mac[1], sessionBleData[i].mac[2],
                 sessionBleData[i].mac[3], sessionBleData[i].mac[4], sessionBleData[i].mac[5]);

        snprintf(line1, sizeof(line1), "%2d.%-18.18s %13s %4d %4.0fm %5u",
                 (i + 1), safeName, ageCombo, sessionBleData[i].rssi,
                 sessionBleData[i].smoothedDistance, sessionBleData[i].hits);

        char line2[90];
        snprintf(line2, sizeof(line2), "%17s  %-33.33s", macStr, tagStr);

        tft.setFreeFont(&UbuntuMono_B9pt7b);
        tft.drawString(line1, 5, y);
        tft.setTextColor(TFT_LIGHTGREY);
        tft.setFreeFont(&UbuntuMono_Regular9pt7b);
        tft.drawString(line2, 5, y + 15);
        tft.setTextColor(TFT_WHITE);

      } else if (currentRadioMode == RADIO_AP) {
        // ... [AP MODE LOGIC REMAINS UNCHANGED] ...
        char line1[90];
        char line2[90];

        bool has_clone = false;
        if (strcmp(sessionApData[i].ssid, "<HIDDEN>") != 0 && strcmp(sessionApData[i].ssid, "<UNKNOWN>") != 0) {
          for (int j = 0; j < sessionApCount; j++) {
            if (i != j && strcmp(sessionApData[i].ssid, sessionApData[j].ssid) == 0) {
              has_clone = true; break;
            }
          }
        }

        char safeSsid[20];
        if (strcmp(sessionApData[i].ssid, "<HIDDEN>") == 0 || strcmp(sessionApData[i].ssid, "<UNKNOWN>") == 0) {
           snprintf(safeSsid, sizeof(safeSsid), "%-18.18s", sessionApData[i].ssid);
        } else if (has_clone) {
           char temp_ssid[13];
           strncpy(temp_ssid, sessionApData[i].ssid, 12); temp_ssid[12] = '\0';
           snprintf(safeSsid, sizeof(safeSsid), "%s~%02X%02X", temp_ssid, sessionApData[i].bssid[4], sessionApData[i].bssid[5]);
        } else {
           snprintf(safeSsid, sizeof(safeSsid), "%-18.18s", sessionApData[i].ssid);
        }

        char bssidStr[18];
        snprintf(bssidStr, sizeof(bssidStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                 sessionApData[i].bssid[0], sessionApData[i].bssid[1], sessionApData[i].bssid[2],
                 sessionApData[i].bssid[3], sessionApData[i].bssid[4], sessionApData[i].bssid[5]);

        double mean = 0.0;
        double cv_percent = 0.0;
        if (sessionApData[i].packets > 0) {
            mean = (double)sessionApData[i].sum_bytes / (double)sessionApData[i].packets;
            double avg_sq_sum = (double)sessionApData[i].sum_sq_bytes / (double)sessionApData[i].packets;
            double variance = avg_sq_sum - (mean * mean);
            if (variance < 0) variance = 0;
            double std_dev = sqrt(variance);
            if (mean > 0) cv_percent = (std_dev / mean) * 100.0;
        }

        char avgStr[6];
        formatShortUnit((uint32_t)mean, avgStr, sizeof(avgStr));

        char firstSeenStr[8], lastSeenStr[8], ageCombo[16];
        getAgeString(sessionApData[i].first_seen, firstSeenStr, sizeof(firstSeenStr));
        getAgeString(sessionApData[i].last_seen, lastSeenStr, sizeof(lastSeenStr));
        snprintf(ageCombo, sizeof(ageCombo), "%s|%s", firstSeenStr, lastSeenStr);

        uint32_t total_bytes = sessionApData[i].tx_bytes + sessionApData[i].rx_bytes;
        char totStr[10];
        formatTotalUnit(total_bytes, totStr, sizeof(totStr));

        char txStr[6], rxStr[6], trafficCombo[12];
        formatShortUnit(sessionApData[i].tx_bytes, txStr, sizeof(txStr));
        formatShortUnit(sessionApData[i].rx_bytes, rxStr, sizeof(rxStr));
        snprintf(trafficCombo, sizeof(trafficCombo), "%s|%s", txStr, rxStr);

        char safeCountry[3] = "--";
        if (sessionApData[i].country[0] != '\0') {
            safeCountry[0] = sessionApData[i].country[0];
            safeCountry[1] = sessionApData[i].country[1];
        }

        snprintf(line1, sizeof(line1), "%3d. %-18.18s %17s %2s %4d %-5.5s",
                 (i + 1), safeSsid, bssidStr, safeCountry, sessionApData[i].rssi, totStr);

        snprintf(line2, sizeof(line2), "    %13s %3.0fm %02d %3uM %-4.4s %3.0f%%   %9s",
                 ageCombo, sessionApData[i].smoothedDistance, sessionApData[i].channel,
                 sessionApData[i].max_rate, avgStr, cv_percent, trafficCombo);

        tft.setFreeFont(&UbuntuMono_B9pt7b);
        tft.drawString(line1, 5, y);
        tft.setTextColor(TFT_LIGHTGREY);
        tft.setFreeFont(&UbuntuMono_Regular9pt7b);
        tft.drawString(line2, 5, y + 15);
        tft.setTextColor(TFT_WHITE);
      }
      else if (currentRadioMode == RADIO_CHANNELS) {
        // ... [CHANNELS MODE LOGIC REMAINS UNCHANGED] ...
        char line1[90];
        char line2[90];

        double mean = 0.0;
        double cv_percent = 0.0;
        if (sessionChannelData[i].packets > 0) {
            mean = (double)sessionChannelData[i].sum_bytes / (double)sessionChannelData[i].packets;
            double avg_sq_sum = (double)sessionChannelData[i].sum_sq_bytes / (double)sessionChannelData[i].packets;
            double variance = avg_sq_sum - (mean * mean);
            if (variance < 0) variance = 0;
            double std_dev = sqrt(variance);
            if (mean > 0) cv_percent = (std_dev / mean) * 100.0;
        }

        float avg_rssi = sessionChannelData[i].avg_rssi;
        double std_dev_rssi = sqrt(sessionChannelData[i].ema_variance);

        float rho = 0.0;
        if (sessionChannelData[i].ema_variance > 0.01) {
            rho = sessionChannelData[i].ema_cov / sessionChannelData[i].ema_variance;
        }

        char stateStr[10];
        if (sessionChannelData[i].packets < 5) strcpy(stateStr, "CALC..");
        else if (rho > 0.6) strcpy(stateStr, "DRIFT");
        else if (rho > 0.2) strcpy(stateStr, "ACTIVE");
        else strcpy(stateStr, "STATIC");

        char avgStr[6];
        formatShortUnit((uint32_t)mean, avgStr, sizeof(avgStr));

        char firstSeenStr[8], lastSeenStr[8], ageCombo[16];
        getAgeString(sessionChannelData[i].first_seen, firstSeenStr, sizeof(firstSeenStr));
        getAgeString(sessionChannelData[i].last_seen, lastSeenStr, sizeof(lastSeenStr));
        snprintf(ageCombo, sizeof(ageCombo), "%s|%s", firstSeenStr, lastSeenStr);

        uint32_t total_bytes = sessionChannelData[i].tx_bytes + sessionChannelData[i].rx_bytes;
        char totStr[10];
        formatTotalUnit(total_bytes, totStr, sizeof(totStr));

        char txStr[6], rxStr[6], trafficCombo[12];
        formatShortUnit(sessionChannelData[i].tx_bytes, txStr, sizeof(txStr));
        formatShortUnit(sessionChannelData[i].rx_bytes, rxStr, sizeof(rxStr));
        snprintf(trafficCombo, sizeof(trafficCombo), "%s|%s", txStr, rxStr);

        char pwrStr[16];
        if (sessionChannelData[i].packets == 0) strcpy(pwrStr, "N/A");
        else snprintf(pwrStr, sizeof(pwrStr), "%3.0f|~%-2.0f", avg_rssi, std_dev_rssi);

        snprintf(line1, sizeof(line1), "%3d. CHANNEL %02d %14s %-11.11s   %-5.5s",
                 (i + 1), sessionChannelData[i].channel, "", pwrStr, totStr);

        snprintf(line2, sizeof(line2), "    %13s %5s %-7.7s %-4.4s %3.0f%%   %9s",
                 ageCombo, "", stateStr, avgStr, cv_percent, trafficCombo);

        tft.setFreeFont(&UbuntuMono_B9pt7b);
        tft.drawString(line1, 5, y);
        tft.setTextColor(TFT_LIGHTGREY);
        tft.setFreeFont(&UbuntuMono_Regular9pt7b);
        tft.drawString(line2, 5, y + 15);
        tft.setTextColor(TFT_WHITE);
      }
      else if (currentRadioMode == RADIO_PCAP) {
        // Map our logical loop variable 'i' back to the real array index!
        int real_idx = valid_indices[i];
        auto& lk = leakHistory[real_idx].leak;

        // ==========================================
        // PCAP MODE - DYNAMIC 1 TO 3 LINE RENDERING
        // ==========================================
        char line1[90], line2[90], line3[90];

        char firstSeenStr[8], lastSeenStr[8], ageCombo[18];
        getAgeString(leakHistory[real_idx].first_seen, firstSeenStr, sizeof(firstSeenStr));
        getAgeString(lk.meta.timestamp, lastSeenStr, sizeof(lastSeenStr));
        snprintf(ageCombo, sizeof(ageCombo), "%s|%s", firstSeenStr, lastSeenStr);

        char safeSsid[13] = "Unknown";
        for (int ap = 0; ap < MAX_BSSID_CACHE; ap++) {
            if (bssidCache[ap].last_seen == 0) continue;
            if (memcmp(lk.meta.bssid, bssidCache[ap].bssid, 6) == 0) {
                strncpy(safeSsid, bssidCache[ap].ssid, 12);
                safeSsid[12] = '\0';
                break;
            }
        }

        char srcVend[9], dstVend[9];
        strncpy(srcVend, leakHistory[real_idx].src_vendor, 8); srcVend[8] = '\0';
        strncpy(dstVend, leakHistory[real_idx].dst_vendor, 8); dstVend[8] = '\0';
        if(strlen(srcVend) == 0) strcpy(srcVend, "Unknown");
        if(strlen(dstVend) == 0) strcpy(dstVend, "Unknown");
        for (int v = 7; v >= 0; v--) { if (srcVend[v] == ' ') srcVend[v] = '\0'; else break; }
        for (int v = 7; v >= 0; v--) { if (dstVend[v] == ' ') dstVend[v] = '\0'; else break; }

        char lenStr[8];
        uint16_t fLen = lk.meta.frame_length;
        if (fLen < 1000) snprintf(lenStr, sizeof(lenStr), "%dB", fLen);
        else snprintf(lenStr, sizeof(lenStr), "%dK", fLen / 1000);

        char srcIpRaw[40] = {0}, dstIpRaw[40] = {0};
getIpString(lk.meta.ip_version, lk.meta.src_ip, srcIpRaw, sizeof(srcIpRaw));
getIpString(lk.meta.ip_version, lk.meta.dst_ip, dstIpRaw, sizeof(dstIpRaw));

char srcIpStr[40] = {0}, dstIpStr[40] = {0};
if (lk.meta.ip_version == 6) {
    compress_ipv6(srcIpRaw, srcIpStr, sizeof(srcIpStr));
    compress_ipv6(dstIpRaw, dstIpStr, sizeof(dstIpStr));
} else {
    strncpy(srcIpStr, srcIpRaw, sizeof(srcIpStr) - 1);
    strncpy(dstIpStr, dstIpRaw, sizeof(dstIpStr) - 1);
}

        snprintf(line1, sizeof(line1), "[x%d]%02X%02X%02X%02X%02X%02X(%s)>%02X%02X%02X%02X%02X%02X(%s)|%s|C%d",
                 leakHistory[real_idx].hitCount,
                 lk.meta.src_mac[0], lk.meta.src_mac[1], lk.meta.src_mac[2],
                 lk.meta.src_mac[3], lk.meta.src_mac[4], lk.meta.src_mac[5], srcVend,
                 lk.meta.dst_mac[0], lk.meta.dst_mac[1], lk.meta.dst_mac[2],
                 lk.meta.dst_mac[3], lk.meta.dst_mac[4], lk.meta.dst_mac[5], dstVend, lenStr, lk.meta.channel);

        char portStr[24] = "";
        if (lk.meta.protocol == 6 || lk.meta.protocol == 17) {
            snprintf(portStr, sizeof(portStr), "|%d>%d", lk.meta.src_port, lk.meta.dst_port);
        }
        snprintf(line2, sizeof(line2), "%02X%02X%02X%02X%02X%02X(%s)|%s|%s|%s%s",
                 lk.meta.bssid[0], lk.meta.bssid[1], lk.meta.bssid[2],
                 lk.meta.bssid[3], lk.meta.bssid[4], lk.meta.bssid[5],
                 safeSsid, getDirectionStr(lk.meta.direction),
                 getSubtypeStr(lk.meta.frame_subtype),
                 getProtocolStr(lk.meta.protocol), portStr);

        snprintf(line3, sizeof(line3), "%s>%s|%s", srcIpStr, dstIpStr, ageCombo);

        // --- SAFE PAYLOAD SLICING (Explicit memcpy & Clamp) ---
        int pLen = lk.retained_len;
        if (pLen > MAX_LEAK_STR_LEN - 1) {
            pLen = MAX_LEAK_STR_LEN - 1; // Defensive boundary clamp
        }

        char safePayload[MAX_LEAK_STR_LEN + 1] = {0};
        size_t copyLen = pLen;

        memcpy(safePayload, lk.text, copyLen);
        safePayload[copyLen] = '\0'; // Guarantee NUL termination

        // Fast sanitization loop utilizing clamped pLen
        for (int pt = 0; pt < pLen; pt++) {
            if (safePayload[pt] < 32 || safePayload[pt] > 126) safePayload[pt] = '.';
        }

        // --- DYNAMIC PAYLOAD SLICING (Loop-Based up to 9 lines) ---
        const int maxChars = 58;
        const int maxLinesAllowed = 9;
        char pLines[9][60] = {0}; // 2D array to hold up to 9 lines of 59 chars
        int n_lines = 1;

        for (int line = 0; line < maxLinesAllowed; line++) {
            int offset = line * maxChars;
            if (offset >= pLen) {
                if (line == 0) n_lines = 1; // Guarantee at least 1 line is counted
                break;
            }

            n_lines = line + 1;
            int remaining = pLen - offset;

            if (remaining <= maxChars) {
                strncpy(pLines[line], safePayload + offset, remaining);
            } else {
                // Truncate the final allowed line with +NNN if there's more payload
                if (line == maxLinesAllowed - 1) {
                    const int textChars = 54; // Leaves room for the "+NNN" tag
                    strncpy(pLines[line], safePayload + offset, textChars);
                    snprintf(pLines[line] + textChars, sizeof(pLines[line]) - textChars, "+%d", remaining - textChars);
                } else {
                    strncpy(pLines[line], safePayload + offset, maxChars);
                }
            }
        }

        // --- RENDER DYNAMIC HEIGHT ---
        // Alert records (recon alerts today) render red instead of cyan so
        // they are visually distinct from ordinary high-value captures.
        tft.setFreeFont(&UbuntuMono_Regular8pt7b);
        tft.setTextColor(lk.meta.alert_kind != ALERT_NONE ? TFT_RED
                                                          : TFT_CYAN);
        tft.drawString(line1, 5, y);
        tft.setTextColor(TFT_YELLOW);
        tft.drawString(line2, 5, y + 14);
        tft.setTextColor(TFT_ORANGE);
        tft.drawString(line3, 5, y + 28);

        tft.setTextColor(TFT_GREEN);

        // Dynamically print exactly as many lines as this specific packet needs
        for (int l = 0; l < n_lines; l++) {
            tft.drawString(pLines[l], 5, y + 42 + (l * 14));
        }

        int current_item_h = 42 + (n_lines * 14);
        tft.drawLine(0, y + current_item_h + 2, 480, y + current_item_h + 2, COLOR_HOT_CHEST);

        dyn_y += current_item_h + 5;
        tft.setTextColor(TFT_WHITE);
      }          // closes RADIO_PCAP branch
      row++;     // <-- also missing, see note below
    }            // closes the for loop
  }              // closes the total_devices==0 / else block

  // ==========================================
  // 7. SAFE NAVIGATION FOOTER
  // ==========================================
  tft.setFreeFont(&UbuntuMono_Regular9pt7b);
  tft.drawLine(0, 294, 480, 294, TFT_WHITE);

  if (device_current_page > 0 && total_devices > 0) {
    tft.setTextColor(TFT_WHITE);
    tft.drawString("<- PREV", 20, 300);
  }

  tft.setTextColor(TFT_RED);
  tft.drawString("BACK", 215, 300);

  if (has_next_page) {
    tft.setTextColor(TFT_WHITE);
    tft.drawString("NEXT ->", 360, 300);
  }
}
void drawProbeTracker() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(1);

  // ==========================================
  // 1. DYNAMIC HEADER BANNER (Unified UI)
  // ==========================================
  sortProbeList();

  int active_probes = 0;
  for (int i = 0; i < MAX_PROBE_SLOTS; i++) {
    for (int b = 0; b < 6; b++) {
      if (probeList[i].mac[b] != 0) {
        active_probes++;
        break;
      }
    }
  }
  total_sniffed_probes = active_probes;

  tft.setFreeFont(&UbuntuMono_B9pt7b);
  tft.setTextDatum(TL_DATUM);
  tft.setTextColor(TFT_WHITE);
  uint16_t osintHeaderColor = hex24to565(0x4A148C);
  tft.fillRect(0, 0, 480, 24, osintHeaderColor);

  char headerStr[64];
  snprintf(headerStr, sizeof(headerStr), "PHYSICAL TARGETS (%d)", active_probes);
  tft.drawString(headerStr, 0, 5);

  // --- INJECT SORT UI BUTTONS ---
  char metricStr[32];
  uint16_t metricColor = TFT_YELLOW;

  if (currentProbeSortMode == PROBE_SORT_HITS) strcpy(metricStr, "SORT:HITS");
  else if (currentProbeSortMode == PROBE_SORT_DIST) strcpy(metricStr, "SORT:DIST");
  else if (currentProbeSortMode == PROBE_SORT_SSIDS) strcpy(metricStr, "SORT:#SSIDs");
  else if (currentProbeSortMode == PROBE_SORT_AGE) strcpy(metricStr, "SORT:AGE");

  tft.fillRoundRect(275, 2, 130, 20, 3, TFT_BLACK);
  tft.drawRoundRect(275, 2, 130, 20, 3, TFT_WHITE);
  tft.setTextColor(metricColor);
  tft.drawString(metricStr, 282, 4);

  tft.fillRoundRect(410, 2, 65, 20, 3, TFT_BLACK);
  tft.drawRoundRect(410, 2, 65, 20, 3, TFT_WHITE);

  if (probe_sort_descending) {
    tft.setTextColor(TFT_WHITE);
    tft.drawString("DESC", 423, 4);
  } else {
    tft.setTextColor(TFT_GREEN);
    tft.drawString("ASC", 427, 4);
  }

  // ==========================================
  // 2. DUAL-LINE COLUMN HEADERS
  // ==========================================
  tft.setTextColor(TFT_GREEN);
  tft.setFreeFont(&UbuntuMono_B9pt7b);
  // --- UPDATED: Realigned spacing and injected #MAC column ---
  tft.drawString("ID VENDOR        FIRST|LAST   RSSI DIST #MAC HITS", 0, 26);
  tft.setFreeFont(&UbuntuMono_Regular9pt7b);
  tft.drawString("MAC ADDRESS       CAPTURED SSIDs", 0, 41);
  tft.drawLine(0, 57, 480, 57, TFT_WHITE);

  // ==========================================
  // 3. DATA ROWS (3-Line Data Injection)
  // ==========================================
  int start_idx = probe_current_page * PROBES_PER_PAGE;
  int end_idx = start_idx + PROBES_PER_PAGE;

  int row = 0;
  for (int i = start_idx; i < end_idx; i++) {
    bool is_slot_empty = true;
    for (int b = 0; b < 6; b++) {
      if (probeList[i].mac[b] != 0) {
        is_slot_empty = false;
        break;
      }
    }

    int y = 60 + (row * 46);

    if (!is_slot_empty) {

      // --- LINE 1: Metadata ---
      if (probeList[i].mac_rotations > 1) {
          tft.setTextColor(TFT_ORANGE);
      } else {
          tft.setTextColor(TFT_GREEN);
      }

      bool is_randomized = (probeList[i].mac[0] & 0x02) != 0;
      char safeVendor[20];
      char rawVendor[20];

      if (strcmp(probeList[i].vendor, "Resolving...") == 0) {
          strcpy(rawVendor, "Resolving...");
      } else if (strstr(probeList[i].vendor, "(IE)") != nullptr) {
          strncpy(rawVendor, probeList[i].vendor, 19);
          rawVendor[19] = '\0';
      } else if (is_randomized) {
          strcpy(rawVendor, "<Randomized>");
      } else if (probeList[i].vendor[2] == ':' || strcmp(probeList[i].vendor, "Unknown") == 0 || strlen(probeList[i].vendor) == 0) {
          strcpy(rawVendor, "Unknown Device");
      } else {
          strncpy(rawVendor, probeList[i].vendor, 19);
          rawVendor[19] = '\0';
      }

      // Reduced from 15 to 13 to make room for the new #MAC column
      snprintf(safeVendor, sizeof(safeVendor), "%-13.13s", rawVendor);

      char ageCombo[16];
      char firstSeenStr[8], lastSeenStr[8];
      getAgeString(probeList[i].first_seen, firstSeenStr, sizeof(firstSeenStr));
      getAgeString(probeList[i].last_seen, lastSeenStr, sizeof(lastSeenStr));
      snprintf(ageCombo, sizeof(ageCombo), "%s|%s", firstSeenStr, lastSeenStr);

      char metaStr[80];
      // --- UPDATED: Injected mac_rotations into the Line 1 format string ---
      snprintf(metaStr, sizeof(metaStr), "%02d.%-13.13s %13s %4d %4.0fm %4d %4u",
               i + 1, safeVendor, ageCombo, probeList[i].rssi, probeList[i].smoothedDistance, probeList[i].mac_rotations, probeList[i].hits);

      tft.setFreeFont(&UbuntuMono_B9pt7b);
      tft.drawString(metaStr, 0, y);

      // --- LINES 2 & 3: MAC Address & Smart SSID Word Wrapper ---
      tft.setFreeFont(&UbuntuMono_Regular8pt7b);

      // Keep MAC Orange if it's a rotated device to act as a visual anchor
      if (probeList[i].mac_rotations > 1) {
          tft.setTextColor(TFT_ORANGE);
      } else {
          tft.setTextColor(TFT_WHITE);
      }

      // --- UPDATED: Flush left MAC address string ---
      char macStr[20];
      snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
               probeList[i].mac[0], probeList[i].mac[1], probeList[i].mac[2],
               probeList[i].mac[3], probeList[i].mac[4], probeList[i].mac[5]);
      tft.drawString(macStr, 0, y + 16);

      tft.setTextColor(TFT_WHITE);
      char line1[80] = "";
      char line2[100] = "";

      int true_total_ssids = 0;
      int temp_node = probeList[i].first_ssid_idx;
      while (temp_node != -1) {
          if (strlen(ssidPool[temp_node].text) > 0) {
              true_total_ssids++;
          }
          temp_node = ssidPool[temp_node].next_node_idx;
      }

      int current_node = probeList[i].first_ssid_idx;
      int ssids_drawn = 0;
      bool on_line2 = false;

      while (current_node != -1) {
        char next_str[36];
        snprintf(next_str, sizeof(next_str), "%s", ssidPool[current_node].text);

        if (strlen(next_str) == 0) {
            current_node = ssidPool[current_node].next_node_idx;
            continue;
        }

        char addition[40];
        if (ssids_drawn == 0) snprintf(addition, sizeof(addition), "%s", next_str);
        else snprintf(addition, sizeof(addition), "|%s", next_str);

        // --- UPDATED: Expanded Line 1 limit to 41 chars ---
        if (!on_line2) {
            if (strlen(line1) + strlen(addition) <= 41) {
                strlcat(line1, addition, sizeof(line1));
                ssids_drawn++;
            } else {
                on_line2 = true;
            }
        }

        if (on_line2) {
            if (strlen(line2) == 0) snprintf(addition, sizeof(addition), "%s", next_str);
            else snprintf(addition, sizeof(addition), "|%s", next_str);

            if (strlen(line2) + strlen(addition) <= 58) {
                strlcat(line2, addition, sizeof(line2));
                ssids_drawn++;
            } else {
                break;
            }
        }
        current_node = ssidPool[current_node].next_node_idx;
      }

      if (ssids_drawn == 0) {
        strlcat(line1, "<no SSIDs captured>", sizeof(line1));
      } else if (ssids_drawn < true_total_ssids) {
        char plusStr[8];
        snprintf(plusStr, sizeof(plusStr), "|+%d", (true_total_ssids - ssids_drawn));

        // --- UPDATED: Increased Line 1 safety check to 36 for the +X tag ---
        if (on_line2 || strlen(line1) > 36) {
            strlcat(line2, plusStr, sizeof(line2));
        } else {
            strlcat(line1, plusStr, sizeof(line1));
        }
      }

      // --- UPDATED: Moved starting coordinate from 165 to 145 ---
      tft.drawString(line1, 145, y + 16);

      if (strlen(line2) > 0) {
        tft.drawString(line2, 0, y + 30);
      }
      tft.drawLine(0, y + 45, 480, y + 45, hex24to565(0x222222));
    }
    row++;
  }

  // ==========================================
  // 4. UNIFIED NAVIGATION FOOTER
  // ==========================================
  tft.setFreeFont(&UbuntuMono_Regular9pt7b);
  tft.drawLine(0, 294, 480, 294, TFT_WHITE);

  if (probe_current_page > 0 && total_sniffed_probes > 0) {
    tft.setTextColor(TFT_WHITE);
    tft.drawString("<- PREV", 20, 300);
  }

  tft.setTextColor(TFT_RED);
  tft.drawString("BACK", 215, 300);

  if (((probe_current_page + 1) * PROBES_PER_PAGE) < total_sniffed_probes) {
    tft.setTextColor(TFT_WHITE);
    tft.drawString("NEXT ->", 360, 300);
  }
}
