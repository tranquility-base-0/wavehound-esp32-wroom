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