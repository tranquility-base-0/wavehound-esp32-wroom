#pragma once
#include <stdint.h>

// foxhunt state globals
extern int target_rssi;
extern bool is_selecting_target;
extern bool is_foxhunting;
extern uint8_t foxhunt_target_mac[6];
extern char foxhunt_target_vendor[28];
extern float smoothed_rssi;
extern int baseline_rssi;
extern int last_displayed_rssi;
extern int last_drawn_min;
extern int last_drawn_max;
extern volatile int8_t foxhunt_rssi_min;
extern volatile int8_t foxhunt_rssi_max;
extern volatile bool foxhunt_bounds_seeded;

void updateFoxhuntSignal(int packet_rssi);
void drawFoxhuntScreen();
void updateFoxhuntRadar();
