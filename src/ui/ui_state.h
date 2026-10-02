#pragma once
#include <Arduino.h>
#include <stdint.h>
#include <TFT_eSPI.h>
#include "core/wavehound_state.h"

// Vertical skeleton. HEADER_HEIGHT/chart_start_y are fixed design
// metrics (font/pixel-driven, not screen-relative). CHART_BOTTOM and
// LIST_FOOTER_TOP are screen-relative: ui_init_geometry() derives them
// from SCREEN_H (deltas 22/26 reproduce 298/294 on a 320-high panel).
const int HEADER_HEIGHT = 108;
extern int CHART_BOTTOM;      // bottom edge of the waterfall bars
extern int LIST_FOOTER_TOP;   // list views' nav separator / footer touch top
const int chart_start_y = HEADER_HEIGHT + 53;

// Device-list (grid modes WIFI/AP/BLE/CHANNELS) row geometry.
// Rows keep their fixed font-driven pitch; the visible row COUNT is
// derived from the space between DEV_LIST_TOP and LIST_FOOTER_TOP.
const int DEV_LIST_TOP = 62;    // first grid row y (fixed design metric)
const int DEV_LIST_ROW_H = 33;  // fixed row pitch (two 9pt lines)

// Active display dimensions, established at startup by ui_init_geometry()
// (queried from tft.width()/tft.height() AFTER tft.setRotation(1)).
// Defaults match the current 480x320 rotation-1 panel; the startup
// assignment makes them correct for any panel the driver reports.
extern uint16_t SCREEN_W;
extern uint16_t SCREEN_H;
void ui_init_geometry();

// ============================================================
// Control geometry (Phase 3): one authoritative rectangle per
// drawn control, consumed by BOTH rendering and touch handling.
// Touch tests use uiHit() (strictly inside the rect), which
// reproduces the original menu/list touch semantics exactly.
// Intentionally larger hitboxes are expressed at the touch site
// with an explicit margin, never silently.
// ============================================================
struct UiRect {
  int16_t x;
  int16_t y;
  int16_t w;
  int16_t h;
};

// Menu screen buttons (drawMenu + SCREEN_MENU touch)
extern const UiRect MENU_BTN_FOXHUNT;    // 50,90,200,40
extern const UiRect MENU_BTN_PROBES;     // 300,140,150,40
extern const UiRect MENU_BTN_SELECT_AP;  // 50,190,200,40
extern const UiRect MENU_BTN_MODE;       // 300,190,150,40
extern const UiRect MENU_BTN_SNIFFLIST;  // 50,240,200,40
extern const UiRect MENU_BTN_EXIT;       // 300,240,150,40

// List header sort controls (drawDeviceList/drawProbeTracker + touch)
extern const UiRect LIST_SORT_BTN;       // 275,2,130,20
extern const UiRect LIST_DIR_BTN;        // 410,2,65,20

// Chart footer buttons (drawChartFooter draw; touch uses fixed
// zone boundaries below, a deliberate ~2px slop around these rects)
extern const UiRect CHART_FOOT_SORT_BTN;   // 2,302,141,17
extern const UiRect CHART_FOOT_ORDER_BTN;  // 147,302,141,17
extern const UiRect CHART_FOOT_SCALE_BTN;  // 292,302,141,17

// Foxhunt abort button
extern const UiRect FOXHUNT_ABORT_BTN;   // 190,292,100,24

// Chart footer touch zone boundaries. The touch band intentionally
// spans t_y > 260 (much taller than the 302..319 buttons). The x
// splits sit between the drawn buttons with a fixed 2px slop.
const int CHART_FOOT_TOUCH_X1 = 145;  // sort | order split
const int CHART_FOOT_TOUCH_X2 = 290;  // order | scale split
const int CHART_FOOT_TOUCH_X3 = 435;  // scale right edge (+2 margin)

// Strictly-inside hit test: true when (t_x,t_y) is within the rect
// but not on its right/bottom edge, matching legacy touch semantics.
bool uiHit(const UiRect& r, uint16_t t_x, uint16_t t_y);

// UI state + display hardware (defined in ui_state.cpp)
extern UIState currentState;
extern bool useLogScale;
extern uint16_t calData[5];
extern TFT_eSPI tft;
extern int current_x;
extern bool force_ui_refresh;
extern uint16_t colors[9];
