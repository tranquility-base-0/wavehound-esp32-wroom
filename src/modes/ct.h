#pragma once
#include <Arduino.h>
#include <string.h>
#include "core/wavehound_state.h"

// CT (Counter-surveillance) mode: Wi-Fi observation windows, horizon-bounded
// segmentation evidence, environment history, and persistent-device tracking.
void processCtData();

// Core-0 RX-context feeder (called from the mode-agnostic passive SSID
// scraper in sniffer_callback, RADIO_CT only). Gated on pause_sniffing at
// the callback entry; bounded work; no allocation; no serial I/O. Copies
// identities into the accumulator — never references bssidCache/ssidPool
// storage.
void ct_observe_bssid(const uint8_t *bssid, const char *ssid);

// ---- Core-0-written / Core-1-snapshotted CT window scratch ----
// Both are written by the RX callback (Core 0) while RADIO_CT is active and
// snapshot+cleared by Core 1 under the established window-close fence. They
// are plain globals (not file-local) because their ONLY writers are in
// capture.cpp — the same cross-core pattern as ct_observe_bssid itself.
extern uint32_t ct_window_bytes;   // per-window frame bytes (sig_len sum)
extern uint64_t ct_probe_hit_mask; // bit s = probeList[s] recorded a probe
                                   // request during the current window

// ---- Timing foundation (system-wide hop/window derivation) ----
// The statistical window (CT) and the sampling regime stay ~5 s:
//   N      = selected channels (hop_count, or 13 for the default sweep)
//   k      = max(1, floor(5000 / (N * 300)))   (sweeps per window)
//   dwell  = round(5000 / (k * N))             (>= 300 ms by construction)
//   window = k * N * dwell                     (~5000 ms for every N)
// Every channel receives the same number of visits per window, maximized
// s.t. the dwell floor. Recomputed at CT entry and when a SELECT CH set
// change is applied at a window boundary; the non-CT hopper derives the
// same dwell per fire. Segmentation constants are untouched: the
// statistical window stays ~5 s for every selection.
void ct_timing_apply();   // derive k/dwell/window from the current hop set

// Boundary-deferred SELECT CH for CT: stash a validated set; the CT engine
// applies it (radio_apply_channel_set + ct_timing_apply + new-environment
// boundary) at the NEXT complete-window close, never mid-window/mid-sweep.
void ct_request_reselect(const uint8_t *chans, uint8_t cnt);

// Apply any pending deferred SELECT CH set now (environment boundary:
// radio_apply_channel_set + ct_timing_apply + commit/reset + watcher
// re-anchor). Authoritative shared implementation — called from the window-
// close tail and from the CT resume path (scanAction) while the capture
// fence is still held, so a set chosen on the menu cannot leak an old-set
// first resumed window. No-op when nothing is pending; returns true when a
// pending set was applied.
bool ct_flush_reselect();

// Per-hop interval the shared hopper uses, per mode: CT persists its F1
// derivation in ct_dwell_ms; the other Wi-Fi-family modes (WIFI, NETWORKS,
// CHANNELS, PCAP) derive on the fly from the selected channel count so one
// sweep is ~5 s everywhere; BLE keeps the global HOP_INTERVAL.
uint16_t ct_hop_interval();

// F1-derived dwell for a set of n channels — the same value ct_hop_interval()
// feeds the hopper for the Wi-Fi-family modes. Exposed for diagnostics.
uint16_t ct_derived_dwell(uint16_t n);

// Typed CT waterfall render slots: the CT cycle produces one Wi-Fi column
// per statistical window close and (when the burst runs) one BLE column per
// burst. A plain boolean cannot queue both while the Core-1 loop is blocked
// inside the BLE burst, so slots ride a bounded 2-deep FIFO. The main loop
// consumes AT MOST ONE slot per iteration; the shared chart cursor
// (current_x / h_index / eraser head) is the single timeline for both lanes.
enum {
    CT_RTYPE_NONE = 0,
    CT_RTYPE_WIFI,
    CT_RTYPE_BLE
};
#define CT_RENDERQ_MAX 2

// Consume the oldest queued render slot (CT_RTYPE_NONE if the queue is
// empty). Single Core-1 loop context on both sides, so FIFO access is
// atomic by construction. The consumed slot type stays readable via
// ct_last_render_slot() for the CT chart branch.
uint8_t ct_take_render_slot();
uint8_t ct_last_render_slot();

// Total advertisement hits observed by the last completed CT BLE burst
// (0 when the burst has never run). Read by the chart when it renders a
// CT_RTYPE_BLE column. Display-only: never enters CT statistics.
uint32_t ct_last_burst_hits();

// Total frame bytes of the last COMPLETED CT statistical window, snapshotted
// at the close (0 for invalid windows). The Wi-Fi lane plots this directly:
// it renders one column per window, consumed in the same loop iteration as
// the zero-roll, so a delta of ct_window_bytes cannot recover the mass.
uint32_t ct_window_render_bytes();

// CT BLE burst accounting (incremented in the radio's BLE result callback,
// Core-0 NimBLE host context; consumed by the Core-1 burst under the
// capture fence — single 32-bit aligned words, no tearing on ESP32).
extern volatile bool     ct_ble_burst_active;
extern volatile uint32_t ct_ble_burst_hits;
