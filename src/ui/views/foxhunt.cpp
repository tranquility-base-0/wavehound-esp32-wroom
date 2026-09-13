#include "foxhunt.h"
#include "ui/ui_state.h"
#include "core/radio.h"
#include "waveHoundSprites.h"
#include "UbuntuMono_Regular11pt7b.h"
#include "UbuntuMono_Regular9pt7b.h"
#include "UbuntuMono_B9pt7b.h"
#include <cmath>
#include <string.h>
#include <stdio.h>

int target_rssi = 0;

// ==========================================
// FOXHUNT STATE GLOBALS
// ==========================================
bool is_selecting_target = false;
bool is_foxhunting = false;
uint8_t foxhunt_target_mac[6] = {0};
char foxhunt_target_vendor[28] = "Unknown";

// Foxhunt Math & Alert State
float smoothed_rssi = -100.0f;
int baseline_rssi = -100;
int last_displayed_rssi = -999;  // Sentinel: forces redraw on first frame.
                                  // Must differ from -100.0f initial smoothed_rssi
                                  // so updater redraws before first packet arrives.
int last_drawn_min = 0;          // NEW: Sentinel for bounds redraw
int last_drawn_max = 0;          // NEW: Sentinel for bounds redraw

// Cached spatial bounds — written from Core 1 only,
// read from Core 0 ISR via updateFoxhuntSignal. Avoids sessionData
// scan inside ISR callback path.
volatile int8_t foxhunt_rssi_min = -100;
volatile int8_t foxhunt_rssi_max = -100;
volatile bool foxhunt_bounds_seeded = false;
void updateFoxhuntSignal(int packet_rssi) {
  // 1. Set dynamic tuning parameters
  float current_alpha = 0.2; // Default for WiFi/AP

  if (currentRadioMode == RADIO_BLE) {
    current_alpha = 0.55;
  }

  // 2. Initialize or smooth the signal safely
  if (smoothed_rssi == -100.0f) {
    smoothed_rssi = (float)packet_rssi;
  } else {
    smoothed_rssi = (current_alpha * (float)packet_rssi) +
                    ((1.0f - current_alpha) * smoothed_rssi);
  }

  // ==========================================
  // 3. REAL-TIME TACTICAL STRETCHING
  // Mode-agnostic: Works for Wi-Fi, AP, and BLE
  // ==========================================

  // Stretch the floor (Triggering on 0 for Wi-Fi and -100 for BLE sentinels)
  if (foxhunt_rssi_min == 0 || foxhunt_rssi_min == -100 || packet_rssi < foxhunt_rssi_min) {
      foxhunt_rssi_min = packet_rssi;
  }

  // Stretch the ceiling
  if (foxhunt_rssi_max == -100 || packet_rssi > foxhunt_rssi_max) {
      foxhunt_rssi_max = packet_rssi;
      foxhunt_bounds_seeded = true;
  }
}
void drawFoxhuntScreen() {
    last_displayed_rssi = -999; // Force redraw on every full screen draw
    last_drawn_min = 0;         // NEW: Force bounds redraw
    last_drawn_max = 0;         // NEW: Force bounds redraw
    tft.fillScreen(TFT_BLACK);

    // ==========================================
    // ZONE MAP (non-overlapping):
    // Y=0-30:    Header (static)
    // Y=35-55:   MAC address (static)
    // Y=58-75:   Vendor (static, truncated)
    // Y=80-100:  "SIGNAL:" label (static)
    // Y=100-130: RSSI value (DYNAMIC — owned by loop() updater)
    // Y=130-195: Spatial dashboard (DYNAMIC — owned by loop() updater)
    // Y=220-275: Alert banner (DYNAMIC — owned by loop() updater)
    // Y=285-320: Footer (static)
    // ==========================================

    // 1. HEADER (static)
    tft.fillRect(0, 0, 480, 30,
                 (currentRadioMode == RADIO_BLE) ? TFT_PURPLE : TFT_RED);
    tft.setTextColor(TFT_WHITE);
    tft.setTextDatum(MC_DATUM);
    tft.setFreeFont(&UbuntuMono_Regular11pt7b);
    const char* huntLabel = "WIFI FOXHUNT";
    if (currentRadioMode == RADIO_BLE) huntLabel = "BLE FOXHUNT";
    else if (currentRadioMode == RADIO_AP) huntLabel = "AP FOXHUNT";
    tft.drawString(huntLabel, 240, 15);

    // 2. TARGET MAC (static)
    tft.setFreeFont(&UbuntuMono_Regular9pt7b);
    tft.setTextColor(TFT_CYAN);
    char targetStr[64];
    snprintf(targetStr, sizeof(targetStr),
             "TARGET: %02X:%02X:%02X:%02X:%02X:%02X",
             foxhunt_target_mac[0], foxhunt_target_mac[1],
             foxhunt_target_mac[2], foxhunt_target_mac[3],
             foxhunt_target_mac[4], foxhunt_target_mac[5]);
    tft.drawString(targetStr, 240, 40);

    // 3. VENDOR (static, truncated to prevent width overflow)
    tft.setTextColor(TFT_LIGHTGREY);
    char safeVendor[21];
    strncpy(safeVendor, foxhunt_target_vendor, 20);
    safeVendor[20] = '\0';
    tft.drawString(safeVendor, 240, 58); // Nudged up slightly for perfect spacing

    // 4. TARGET CHANNEL (Replaces the phantom "SIGNAL" label)
    if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP) {
        tft.setTextColor(TFT_ORANGE);
        char chStr[16];
        snprintf(chStr, sizeof(chStr), "CH: %02d", target_channel);
        tft.drawString(chStr, 240, 76);
    }

    // 6. FOOTER (static)
    tft.drawLine(0, 285, 480, 285, TFT_WHITE);
    tft.drawRoundRect(190, 292, 100, 24, 3, TFT_RED);
    tft.setTextColor(TFT_WHITE);
    tft.setFreeFont(&UbuntuMono_Regular9pt7b);
    tft.setTextDatum(MC_DATUM);
    tft.drawString("ABORT", 240, 304);
    tft.setTextDatum(TL_DATUM); // Reset datum
}
void updateFoxhuntRadar() {
    // --- WAVE HOUND ANIMATION ENGINE ---
    static unsigned long last_anim_tick = 0;
    static int sequence_index = 0; // Tracks where we are in the script
    static unsigned long current_delay = 300; // Tracks how long the current frame should stay on screen

    // Define the custom animation script (0 = sniff, 1 = sniff/wag, 2 = look up)
    // This yields 8 standard loops, followed by 1 loop where the head raises
    const int ANIM_SEQUENCE[] = {0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2};
    const int SEQUENCE_LENGTH = 20;

    // Animate using the dynamic delay interval
    if (millis() - last_anim_tick > current_delay) {
        last_anim_tick = millis();

        int current_val = (int)smoothed_rssi;
        uint16_t houndColor = TFT_WHITE;
        int step_time = 300;

        // Tactical Color Feedback & Speed based on signal strength (Hot/Cold logic)
        if (current_val > -60) {
            houndColor = COLOR_HOT_CHEST;  // Hot / Close
            step_time = 100;               // Fast walk
        } else if (current_val > -75) {
            houndColor = COLOR_WARM;       // Warm / Medium
            step_time = 300;               // Normal walk
        } else {
            houndColor = COLOR_COLD;       // Cold / Far
            step_time = 600;               // Slow walk
        }

        int dog_x = HOUND_CENTER_X - (HOUND_WIDTH / 2);
        int dog_y = HOUND_BASELINE_Y - HOUND_HEIGHT;

        // Look up the actual frame (0, 1, or 2) from our sequence array
        int current_frame = ANIM_SEQUENCE[sequence_index];

        // Render the frame to the display
        tft.drawBitmap(dog_x, dog_y, houndAnimation[current_frame], HOUND_WIDTH, HOUND_HEIGHT, houndColor, TFT_BLACK);

        // NOW determine how long THIS newly drawn frame should stay on screen
        if (current_frame == 2) {
            current_delay = 1000;      // Always lock to 1-second pause when looking up
        } else {
            current_delay = step_time; // Apply the dynamically calculated walking speed
        }

        // Advance to the next step in the sequence, looping back to 0 at the end
        sequence_index = (sequence_index + 1) % SEQUENCE_LENGTH;
    }
    // -----------------------------------

    static unsigned long last_radar_update = 0;

    if (millis() - last_radar_update > 300) {
        int current_display_val = (int)smoothed_rssi;

        // 1. RSSI VALUE — Massive Font (owns Y=88 to Y=132)
        if (current_display_val != last_displayed_rssi) {
            tft.fillRect(0, 88, 480, 44, TFT_BLACK); // Expanded clear box for giant text
            tft.setTextDatum(MC_DATUM);
            tft.setFreeFont(&UbuntuMono_B9pt7b);

            // THE MULTIPLIER: Scales 9pt to ~27pt
            tft.setTextSize(3);

            // Color-code by signal strength
            if      (current_display_val > -60) tft.setTextColor(COLOR_HOT_CHEST);
            else if (current_display_val > -75) tft.setTextColor(COLOR_WARM);
            else                                tft.setTextColor(COLOR_COLD);

            char rssiStr[32];
            snprintf(rssiStr, sizeof(rssiStr), "%d dBm", current_display_val);
            tft.drawString(rssiStr, 240, 110);

            // THE RESET: Crucial to prevent UI corruption!
            tft.setTextSize(1);
            tft.setTextDatum(TL_DATUM);
            last_displayed_rssi = current_display_val;
        }

        // ==========================================
        // 2. THE DYNAMIC BOUNDS UPDATER (Gutted)
        // ==========================================
        if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP || currentRadioMode == RADIO_BLE) {
            if (foxhunt_rssi_min != last_drawn_min || foxhunt_rssi_max != last_drawn_max) {

                tft.fillRect(0, 135, 480, 60, TFT_BLACK); // Clean wipe
                tft.setFreeFont(&UbuntuMono_Regular9pt7b);
                tft.setTextDatum(MC_DATUM);

                char boundStr[64];
                snprintf(boundStr, sizeof(boundStr),
                         "FLOOR: %d dBm  |  CEILING: %d dBm", foxhunt_rssi_min, foxhunt_rssi_max);
                tft.setTextColor(TFT_GREEN);
                tft.drawString(boundStr, 240, 165); // Centered vertically in the 60px wipe box

                tft.setTextDatum(TL_DATUM);

                last_drawn_min = foxhunt_rssi_min;
                last_drawn_max = foxhunt_rssi_max;
            }
        }
        // ==========================================

        last_radar_update = millis();
    }
}
