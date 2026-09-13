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
const int HOP_INTERVAL = 300;
const int LOCKED_UPDATE_INTERVAL = 2000;
const int BLE_UPDATE_INTERVAL = 2000;

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

