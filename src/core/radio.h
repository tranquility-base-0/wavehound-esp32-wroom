#pragma once
#include <Arduino.h>
#include <stdint.h>
#include <stddef.h>
#include <atomic>
#include <string>
#include <TFT_eSPI.h>
#include <WiFi.h>
#include <NimBLEDevice.h>
#include "esp_wifi.h"
#include "core/wavehound_state.h"

// Shared heat-map colors (moved from main.cpp; UI + radio both use them)
#define COLOR_COLD      0xAEBC  // Light Blue (Far)
#define COLOR_WARM      0xFFE0  // Standard Yellow (Medium)
#define COLOR_HOT_CHEST 0xF360  // Light Chestnut (Close)

// Radio config (const, one copy per TU)
const int CHANNELS[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
const int NUM_CHANNELS = 13;
// 300 ms: the hop dwell floor the F1 derivation never goes below, and the
// BLE-mode hop interval. Wi-Fi-family modes (WIFI/NETWORKS/CHANNELS/PCAP/CT)
// derive their dwell from the selected channel count instead (see ct.h).
const int HOP_INTERVAL = 300;
const int LOCKED_UPDATE_INTERVAL = 2000;
const int BLE_UPDATE_INTERVAL = 2000;

// CT (RADIO_CT) v0.1: fixed Wi-Fi observation window. Superseded by the F1
// timing foundation (modes/ct.cpp): the live CT window is now DERIVED per
// channel selection (~5 s = k complete sweeps, dwell >= 300 ms); this
// constant remains the ~5 s target the derivation is calibrated against.
const int CT_WIFI_WINDOW_MS = 5000;

// Runtime chip capability: does the running SoC support the 5 GHz band?
// Exists as groundwork for the eventual ESP32-C5 dual-band radio
// implementation; the current ESP32 (WROOM) build does NOT support 5 GHz.
// The result is detected once via the official Espressif chip-identification
// API (esp_chip_info, esp_chip_info.h) and cached.
bool radioHas5GHz();

// Optional custom channel-hopping set (SELECT CH keypad). When
// hop_count > 0 the hopper cycles hop_channels[] instead of the full
// CHANNELS[] sweep; hop_count == 0 restores the default full sweep.
extern uint8_t hop_channels[NUM_CHANNELS]; // channel numbers (1..13), deduped
extern uint8_t hop_count;                  // 0 = default full CHANNELS[] sweep

extern uint8_t hop_pos;                    // position within the custom set

// Parse "1,6,11" / "1-13" / "1,6,11-13" into a deduped, in-range channel
// list. Returns false (and writes nothing) on empty, malformed or
// out-of-range input. Range is bounded by CHANNELS[] (see above).
bool parseChannelList(const char *s, uint8_t *out, uint8_t *out_count);

// Apply a validated selected-channel set to the radio (hop list + position +
// hardware channel) with the current_ch_idx = channel-1 sync invariant held.
// Used by CT's boundary-deferred SELECT CH apply; see modes/ct.cpp.
void radio_apply_channel_set(const uint8_t *chans, uint8_t cnt);

// CT BLE burst primitive (radio-owned: the NimBLE scanner configuration and
// its result callback live here). Ensures the one-shot NimBLE init — the
// exact same passive configuration RADIO_BLE entry uses — then runs ONE
// blocking bounded passive scan. NimBLE-Arduino 1.4.1 takes SECONDS and
// multiplies by 1000 internally. Returns the total advertisement hits the
// result callback counted while ct_ble_burst_active was set. Does NOT touch
// Wi-Fi: the caller (ct_ble_burst) owns the Wi-Fi/BLE time division.
void ble_init_only();  // ct.cpp CT burst: bring BLE up without scanning
void ble_shutdown();   // ct.cpp CT burst: supported NimBLEDevice::deinit(false)
uint32_t ble_radio_burst(uint32_t seconds);

// Mutable radio state (defined in radio.cpp)
extern RadioMode currentRadioMode;
extern int current_ch_idx;
extern uint8_t target_bssid[6];
extern int target_channel;
extern bool target_locked;
extern char target_ssid[33];

// Cross-module bridges: owned by main.cpp / ui / modes (see module layout notes).
extern BLEScan* pBLEScan;
extern bool is_foxhunting;
extern uint8_t foxhunt_target_mac[6];
extern UIState currentState;
extern TFT_eSPI tft;
void updateFoxhuntSignal(int packet_rssi);

void switchRadioMode(RadioMode targetMode);
bool updateRadioHopper();

