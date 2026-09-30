#pragma once
#include <Arduino.h>
#include <string.h>
#include "core/wavehound_state.h"

// CT (Counter-surveillance) mode. Step 3: Wi-Fi observation windows +
// identity-set accumulation into CTState::acc. No segmentation, commit,
// ring advancement, candidate detection, or BLE observation yet.
void processCtData();

// Core-0 RX-context feeder (called from the mode-agnostic passive SSID
// scraper in sniffer_callback, RADIO_CT only). Gated on pause_sniffing at
// entry; bounded work; no allocation; no serial I/O. Copies identities into
// the accumulator — never references bssidCache/ssidPool storage.
void ct_observe_bssid(const uint8_t *bssid, const char *ssid);
