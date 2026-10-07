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

// Per-hop interval the shared hopper uses, per mode: CT persists its F1
// derivation in ct_dwell_ms; the other Wi-Fi-family modes (WIFI, NETWORKS,
// CHANNELS, PCAP) derive on the fly from the selected channel count so one
// sweep is ~5 s everywhere; BLE keeps the global HOP_INTERVAL.
uint16_t ct_hop_interval();

// F1-derived dwell for a set of n channels — the same value ct_hop_interval()
// feeds the hopper for the Wi-Fi-family modes. Exposed for diagnostics.
uint16_t ct_derived_dwell(uint16_t n);

// Window-boundary waterfall render request: set at every CT window close
// (valid or invalid), consumed-and-cleared by the main loop so the CT
// waterfall advances exactly one column per statistical window. Returns
// true at most once per window.
bool ct_take_render_request();