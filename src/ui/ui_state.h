#pragma once
#include <Arduino.h>
#include <stdint.h>
#include <TFT_eSPI.h>
#include "core/wavehound_state.h"

const int HEADER_HEIGHT = 108;
const int CHART_BOTTOM = 298;
const int chart_start_y = HEADER_HEIGHT + 53;

// UI state + display hardware (defined in ui_state.cpp)
extern UIState currentState;
extern bool useLogScale;
extern uint16_t calData[5];
extern TFT_eSPI tft;
extern int current_x;
extern bool force_ui_refresh;
extern uint16_t colors[9];
