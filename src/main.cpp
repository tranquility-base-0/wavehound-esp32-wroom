#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <TFT_eSPI.h>
#include "SdFat.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "core/wavehound_state.h"
#include "core/radio.h"
#include "osint/vendor.h"
#include "capture/capture.h"
#include "modes/wifi.h"
#include "modes/ble.h"
#include "modes/ap_scanner.h"
#include "modes/channel_scanner.h"
#include "osint/osint.h"
#include "ui/ui_state.h"
#include "ui/views/chart.h"
#include "ui/views/lists.h"
#include "ui/views/foxhunt.h"
#include "ui/input.h"

// ---------------------------------------------------------------------------
// MEASUREMENT INSTRUMENTATION (diagnostic-only; reset each DIAG cycle)
// ---------------------------------------------------------------------------
#define PROF_TIME(call, us_tot, us_max, n) do { \
    uint32_t _t0 = micros(); \
    call; \
    uint32_t _dt = micros() - _t0; \
    (us_tot) += _dt; \
    if (_dt > (us_max)) (us_max) = _dt; \
    (n)++; \
} while (0)

static uint32_t prof_pend_us = 0, prof_pend_max = 0, prof_pend_n = 0;
static uint32_t prof_dump_us = 0, prof_dump_max = 0, prof_dump_n = 0;
static uint32_t prof_leak_us = 0, prof_leak_max = 0, prof_leak_n = 0;
static uint32_t prof_wf_us   = 0, prof_wf_max   = 0, prof_wf_n   = 0;
static uint32_t prof_qmax    = 0;   // max liveDumpQueue depth sampled per loop()
static uint32_t prof_over18  = 0;   // loop() iterations sampled with depth >= 18

void setup() {
  Serial.begin(460800);
  pinMode(15, OUTPUT); digitalWrite(15, HIGH);
  pinMode(21, OUTPUT); digitalWrite(21, HIGH);
  pinMode(5, OUTPUT);  digitalWrite(5, HIGH);

  Serial.printf("[MEM] Static footprint:  %u bytes\n", static_non_union);
Serial.printf("[MEM] Free heap at boot: %u bytes\n", esp_get_free_heap_size());
Serial.printf("[MEM] Free SRAM minimum: %u bytes\n", esp_get_minimum_free_heap_size());
Serial.printf("[MEM] sizeof(LiveCaptureEvent) = %u bytes\n", sizeof(LiveCaptureEvent));   // <-- add here
Serial.printf("[MEM] sizeof(PacketCapture)    = %u bytes\n", sizeof(PacketCapture));     // <-- and this one too
Serial.printf(
    "PacketCapture=%u bytes | leakQueue storage ~%u bytes\n",
    (unsigned)sizeof(PacketCapture),
    (unsigned)(sizeof(PacketCapture) * LEAK_QUEUE_DEPTH)
);
initProbeTracker();

// ==========================================
// 1. CREATE THE PCAP QUEUES + TRANSIENT BUFFERS
// ==========================================

// Allocate the two reusable full-payload buffers on the heap.
// These are NOT part of the persistent session union.
ptr_isr_evt = (LiveCaptureEvent*)malloc(sizeof(LiveCaptureEvent));
ptr_core1_evt = (LiveCaptureEvent*)malloc(sizeof(LiveCaptureEvent));

if (ptr_isr_evt == nullptr || ptr_core1_evt == nullptr) {
    Serial.println("FATAL: Failed to allocate transient buffers on heap!");
    while (true) delay(100);
}

// Post-parser queue: ONLY PacketCapture objects.
leakQueue = xQueueCreate(LEAK_QUEUE_DEPTH, sizeof(PacketCapture));

if (leakQueue == NULL) {
    Serial.println("[!] FATAL: Failed to create leakQueue!");
}

// Pre-parser queue: ONLY full-payload LiveCaptureEvent objects.
liveDumpQueue = xQueueCreate(
    LIVE_DUMP_QUEUE_DEPTH,
    sizeof(LiveCaptureEvent)
);

if (liveDumpQueue == NULL) {
    Serial.println("[!] FATAL: Failed to create liveDumpQueue!");
}

  // -----------------------------------------------------------

  // ==========================================
  // 2. INITIALIZE DISPLAY
  // ==========================================
  delay(1000);
  tft.init();
  tft.setTouch(calData);
  tft.setRotation(1);
  tft.fillScreen(TFT_BLACK);
  drawChartHeader();
  drawChartFooter();

  // ==========================================
  // 3. INITIALIZE SD CARD (Crucial to do this BEFORE the sniffer starts!)
  // ==========================================
  Serial.println("\n--- Initializing SD Card ---");
  if (!sd.begin(SdSpiConfig(5, SHARED_SPI, SD_SCK_MHZ(4)))) {
    Serial.println("[!] SD Card Mount Failed!");
    sd.initErrorPrint(&Serial);
  } else {
    Serial.println("[*] SD Card mounted successfully.");
    FsFile file = sd.open("/oui_db.txt", O_READ);
    if (!file) {
      Serial.println("[!] Failed to open /oui_db.txt! Check filename.");
    } else {
      Serial.printf("[*] SUCCESS! oui_db.txt found. Size: %llu bytes\n", file.fileSize());
      file.close();
    }
  }
  Serial.println("----------------------------\n");

  // ==========================================
  // 4. SPAWN CORE 1 TASKS (UI & SD Logging)
  // ==========================================
  // We will uncomment this in the next step once we write the task function!
  /*
  xTaskCreatePinnedToCore(
      sdLoggerTask,    // Task function
      "SD_Logger",     // Task name
      8192,            // Stack size (Bytes)
      NULL,            // Parameters
      1,               // Priority (1 is standard for Core 1)
      NULL,            // Task handle
      1                // Pin to Core 1
  );
  */

  // ==========================================
  // 5. TURN ON THE WATER (Start Sniffer)
  // ==========================================
  // The plumbing is fully ready. Open the valve.
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
  esp_wifi_set_channel(CHANNELS[current_ch_idx], WIFI_SECOND_CHAN_NONE);
  Serial.println("[*] Sniffer ISR active.");
}

void loop() {
  // ==========================================
  // BACKGROUND DATA ENGINES (Run every tick)
  // ==========================================
  { UBaseType_t _q = uxQueueMessagesWaiting(liveDumpQueue);
    if (_q > prof_qmax) prof_qmax = _q;
    if (_q >= 18) prof_over18++; }

  PROF_TIME(processPendingVendors(), prof_pend_us, prof_pend_max, prof_pend_n);
  runProbeCorrelationEngine(); 
  PROF_TIME(processLiveDumpQueue(), prof_dump_us, prof_dump_max, prof_dump_n);
  PROF_TIME(processLeakQueue(), prof_leak_us, prof_leak_max, prof_leak_n);
  
  uint16_t t_x = 0, t_y = 0;
  bool should_render = false;

  // 1. Check Touch inputs (State Controller)
  if (tft.getTouch(&t_x, &t_y)) {
      should_render = handleTouchInputs(t_x, t_y);
  }
    
  // 2. Run the Channel Hopper
  should_render |= updateRadioHopper();

  // 3. CONTINUOUS DELTA-DRAW: Foxhunt Animation Engine
  // (Must run every loop so the dog keeps walking even if signal is lost)
  if (currentState == SCREEN_FOXHUNT) {
      updateFoxhuntRadar();
  }

  // 4. EVENT-DRIVEN GATE: Heavy Math & Full UI Redraws
  if (should_render) {
    pause_sniffing = true; // Lock the radio buffers
    delay(10); // Give the in-flight Core-0 callback time to finish

    // --- MATH ENGINES ---
    if (currentRadioMode == RADIO_WIFI) processWifiData();
    else if (currentRadioMode == RADIO_BLE) processBleData();
    else if (currentRadioMode == RADIO_AP) processApData();
    else if (currentRadioMode == RADIO_CHANNELS) processChannelData();
    // --- ADDED PCAP MATH GATE ---
    else if (currentRadioMode == RADIO_PCAP) {
        // Snapshot the bytes for the UI and reset the ISR counter
        capture_bytes_render = capture_bytes_tick;
        capture_bytes_tick = 0;
        // IF THIS PRINTS '0', THE ISR IS BROKEN. 
        // IF THIS PRINTS '4000', THE CHART GRAPHICS ARE BROKEN.
        Serial.printf("PCAP Tick Vol: %u\n", capture_bytes_render);
    }

    pause_sniffing = false; // Unlock immediately!

    // --- FULL REDRAW GRAPHICS ENGINES ---
    if (currentState == SCREEN_CHART) {
        PROF_TIME(drawWaterfallChart(), prof_wf_us, prof_wf_max, prof_wf_n);
    } else if (currentState == SCREEN_DEVICE_LIST) {
        drawDeviceList();
    } else if (currentState == SCREEN_AP_SCAN) {
        drawApScanner();
    } else if (currentState == SCREEN_PROBE_TRACKER) {
        drawProbeTracker();
    } 
    // Do NOT add SCREEN_LEAK_LIST here. It updates itself asynchronously!
    
    Serial.printf("Free Heap: %d bytes\n", ESP.getFreeHeap());
  }
  // ==========================================
    // ASYNCHRONOUS DIAGNOSTICS (Runs every 3 seconds)
    // ==========================================
    static uint32_t last_debug_print = 0;
if (millis() - last_debug_print > 3000) {

    uint32_t isr_att       = leak_isr_attempts;
    uint32_t isr_drop     = leak_isr_dropped;

    uint32_t f_seen       = leak_funnel_seen;
    uint32_t f_suppressed = leak_funnel_suppressed;
    uint32_t f_shipped    = leak_funnel_shipped;
    uint32_t ld_drop      = live_dump_dropped;
    uint32_t ui_t         = ui_total_arrived;
    uint32_t ui_d         = ui_dropped_packets;
    uint32_t cons         = live_dump_consumed;

    Serial.printf(
        "[DIAG] Funnel: Seen=%u | Suppressed=%u | Shipped=%u\n",
        f_seen,
        f_suppressed,
        f_shipped
    );

    Serial.printf(
        "[DIAG] Drops: liveDumpQueue=%u | "
        "leakQueue ISR=%u/%u | Core1=%u/%u\n",
        ld_drop,
        isr_drop,
        isr_att,
        leak_core1_dropped,
        leak_core1_attempts
    );

    Serial.printf(
        "[DIAG] Free Heap: %d bytes\n",
        ESP.getFreeHeap()
    );

    Serial.printf(
        "[DIAG] Diversity stack high-water: %u bytes free\n",
        (unsigned)g_div_stack_highwater
    );

    uint32_t pend_ms = prof_pend_us / 1000, pend_mx = prof_pend_max / 1000;
    uint32_t dump_ms = prof_dump_us / 1000, dump_mx = prof_dump_max / 1000;
    uint32_t leak_ms = prof_leak_us / 1000, leak_mx = prof_leak_max / 1000;
    uint32_t wf_ms   = prof_wf_us   / 1000, wf_mx   = prof_wf_max   / 1000;
    uint32_t pend_avg = prof_pend_n ? prof_pend_us / prof_pend_n : 0;
    uint32_t dump_avg = prof_dump_n ? prof_dump_us / prof_dump_n : 0;
    uint32_t leak_avg = prof_leak_n ? prof_leak_us / prof_leak_n : 0;
    uint32_t wf_avg   = prof_wf_n   ? prof_wf_us   / prof_wf_n   : 0;

    Serial.printf(
        "[PROF] PEND n=%u tot=%ums max=%ums avg=%uus | DUMP n=%u tot=%ums max=%ums avg=%uus | LEAK n=%u tot=%ums max=%ums avg=%uus | WF n=%u tot=%ums max=%ums avg=%uus\n",
        (unsigned)prof_pend_n, (unsigned)pend_ms, (unsigned)pend_mx, (unsigned)pend_avg,
        (unsigned)prof_dump_n, (unsigned)dump_ms, (unsigned)dump_mx, (unsigned)dump_avg,
        (unsigned)prof_leak_n, (unsigned)leak_ms, (unsigned)leak_mx, (unsigned)leak_avg,
        (unsigned)prof_wf_n,   (unsigned)wf_ms,   (unsigned)wf_mx,   (unsigned)wf_avg
    );

    Serial.printf(
        "[PROF] qmax=%u over18=%u cons=%u | uiTot=%u uiDrop=%u ldDrop=%u\n",
        (unsigned)prof_qmax, (unsigned)prof_over18, (unsigned)cons,
        (unsigned)ui_t, (unsigned)ui_d, (unsigned)ld_drop
    );

    leak_funnel_seen       = 0;
    leak_funnel_suppressed = 0;
    leak_funnel_shipped    = 0;
    live_dump_dropped      = 0;
    live_dump_consumed     = 0;
    ui_total_arrived       = 0;
    ui_dropped_packets     = 0;
    leak_displayed         = 0;

    prof_pend_us = prof_pend_max = prof_pend_n = 0;
    prof_dump_us = prof_dump_max = prof_dump_n = 0;
    prof_leak_us = prof_leak_max = prof_leak_n = 0;
    prof_wf_us   = prof_wf_max   = prof_wf_n   = 0;
    prof_qmax    = 0;
    prof_over18  = 0;

    leak_isr_attempts      = 0;
    leak_isr_dropped       = 0;
    leak_core1_attempts    = 0;
    leak_core1_dropped     = 0;

    if (currentState == SCREEN_CHART &&
        currentRadioMode == RADIO_PCAP) {

        drawTelemetryHeader(pcap_displayed_total, pcap_upstream_total, pcap_upstream_total);
    }

    last_debug_print = millis();
}
}
