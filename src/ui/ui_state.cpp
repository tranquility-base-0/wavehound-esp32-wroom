#include "ui_state.h"
#include "ui_utils.h"

UIState currentState = SCREEN_CHART;
bool useLogScale = false;
uint16_t calData[5] = { 288, 3501, 301, 3244, 7 };
TFT_eSPI tft = TFT_eSPI();
int current_x = 0;
bool force_ui_refresh = false;

// Active display dimensions. Defaults match the current 480x320
// rotation-1 panel; ui_init_geometry() re-queries the driver after
// tft.setRotation(1) so any panel resolution is picked up.
uint16_t SCREEN_W = 480;
uint16_t SCREEN_H = 320;
int CHART_BOTTOM = 298;      // re-derived below
int LIST_FOOTER_TOP = 294;   // re-derived below

void ui_init_geometry() {
  SCREEN_W = tft.width();
  SCREEN_H = tft.height();
  // Screen-relative vertical boundaries (fixed design deltas from the
  // screen bottom; reproduce 298/294 when SCREEN_H == 320).
  CHART_BOTTOM = SCREEN_H - 22;
  LIST_FOOTER_TOP = SCREEN_H - 26;
}

// ============================================================
// Authoritative control rectangles (see ui_state.h)
// ============================================================
const UiRect MENU_BTN_FOXHUNT    = { 50,  90, 200, 40 };
const UiRect MENU_BTN_PROBES     = { 300, 140, 150, 40 };
const UiRect MENU_BTN_SELECT_AP  = { 50,  190, 200, 40 };
const UiRect MENU_BTN_MODE       = { 300, 190, 150, 40 };
const UiRect MENU_BTN_SNIFFLIST  = { 50,  240, 200, 40 };
const UiRect MENU_BTN_EXIT       = { 300, 240, 150, 40 };

const UiRect LIST_SORT_BTN       = { 275, 2, 130, 20 };
const UiRect LIST_DIR_BTN        = { 410, 2, 65,  20 };

const UiRect CHART_FOOT_SORT_BTN  = { 2,   302, 141, 17 };
const UiRect CHART_FOOT_ORDER_BTN = { 147, 302, 141, 17 };
const UiRect CHART_FOOT_SCALE_BTN = { 292, 302, 141, 17 };

const UiRect FOXHUNT_ABORT_BTN   = { 190, 292, 100, 24 };

bool uiHit(const UiRect& r, uint16_t t_x, uint16_t t_y) {
  return t_x > (uint16_t)r.x && t_x < (uint16_t)(r.x + r.w) &&
         t_y > (uint16_t)r.y && t_y < (uint16_t)(r.y + r.h);
}

// 8-color array using standard web hex codes!
uint16_t colors[9] = {
  hex24to565(0x7CD9CA), // [0] Mint Green
  hex24to565(0xFF00FF), // [1] Magenta
  hex24to565(0xD9D680), // [2] Pale Yellow
  hex24to565(0xB75BE2), // [3] Purple
  hex24to565(0x87E370), // [4] Bright Green
  hex24to565(0xD1C9CA), // [5] Light Gray
  hex24to565(0xDA815E), // [6] Rust/Orange
  hex24to565(0x889FD7), // [7] Periwinkle Blue
  TFT_DARKGREY          // [8] "Other" category (unchanged)
  //hex24to565(0xE07EB6), // [6] Pink
};
