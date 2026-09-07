#pragma once
#include <Arduino.h>
#include <stdint.h>
#include "esp_wifi.h"
#include "core/wavehound_state.h"

extern uint32_t leak_hash_history[32];
extern uint8_t leak_hash_idx;
extern LiveCaptureEvent* ptr_isr_evt;
extern LiveCaptureEvent* ptr_core1_evt;
extern QueueHandle_t liveDumpQueue;
extern QueueHandle_t leakQueue;
extern uint8_t leak_current_page;
extern LeakSortMode currentLeakSort;
extern volatile uint32_t capture_bytes_tick;
extern uint32_t capture_bytes_render;
extern PacketCapture terminal_history[MAX_TERMINAL_LINES];
extern uint16_t terminal_hits[MAX_TERMINAL_LINES];
extern uint32_t terminal_first_seen[MAX_TERMINAL_LINES];
extern volatile uint32_t debug_dropped_packets;
extern volatile uint32_t ui_total_arrived;
extern volatile uint32_t ui_dropped_packets;
extern volatile uint32_t leak_isr_attempts;
extern volatile uint32_t leak_isr_dropped;
extern volatile uint32_t leak_funnel_seen;
extern volatile uint32_t leak_funnel_suppressed;
extern volatile uint32_t leak_funnel_shipped;
extern volatile uint32_t live_dump_dropped;
extern uint32_t leak_core1_attempts;
extern uint32_t leak_core1_dropped;
extern uint32_t traffic_history[240];
extern uint32_t absolute_max_traffic;

void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type);
void processLiveDumpQueue();
void processLeakQueue();
void processPcapData();
void resetMonitorState();
bool should_alert_crypto(const uint8_t* mac_a, const uint8_t* mac_b, uint32_t current_ms);
void logLeakToSerial(const PacketCapture& leak, const char* src_vendor, const char* dst_vendor, const char* ssid);
