#include "capture.h"
#include "core/radio.h"
#include "modes/ap_scanner.h"
#include "osint/osint.h"
#include "osint/vendor.h"
#include "parsers/application.h"
#include "parsers/discovery.h"
#include "parsers/dns.h"
#include "parsers/link_layer.h"
#include "parsers/parser_common.h"
#include "parsers/structured.h"
#include "parsers/web.h"
#include "tag221Lookup.h"
#include <stdio.h>
#include <string.h>

extern int current_x;
int compareLeakAge(const void *a, const void *b);
int compareLeakLength(const void *a, const void *b);
int compareLeakHits(const void *a, const void *b);
void drawDeviceList();

// PCAP / live-dump state
// Core 0 leak-hash cache
uint32_t leak_hash_history[32] = {0};
uint8_t leak_hash_idx = 0;

// ------------------------------------------
// DUAL-CORE MESSAGE QUEUES & UNIFIED STRUCT
// ------------------------------------------
// Shared metadata — single source of truth

// --- TRANSIENT HEAP POINTERS ---
LiveCaptureEvent *ptr_isr_evt = nullptr;
LiveCaptureEvent *ptr_core1_evt = nullptr;

QueueHandle_t liveDumpQueue = NULL;
QueueHandle_t leakQueue = NULL;
uint8_t leak_current_page = 0;

LeakSortMode currentLeakSort = SORT_LEAK_AGE; // Default

// PCAP waterfall state
volatile uint32_t capture_bytes_tick = 0;
uint32_t capture_bytes_render = 0;
PacketCapture terminal_history[MAX_TERMINAL_LINES];
uint32_t terminal_first_seen[MAX_TERMINAL_LINES] = {0};

volatile uint32_t debug_dropped_packets = 0;
volatile uint32_t ui_total_arrived = 0;
volatile uint32_t ui_dropped_packets = 0;

// ISR-side (Core 0) — deauth + crypto/WEP interceptors
volatile uint32_t leak_isr_attempts = 0;
volatile uint32_t leak_isr_dropped = 0;
// ISR-side PCAP funnel diagnostics
volatile uint32_t leak_funnel_seen = 0;
volatile uint32_t leak_funnel_suppressed = 0;
volatile uint32_t leak_funnel_shipped = 0;
volatile uint32_t live_dump_dropped = 0;
volatile uint32_t live_dump_consumed = 0;
volatile uint32_t leak_displayed = 0;
// Cumulative session counters. The 3 s DIAG block derives display-window
// deltas from snapshots; it does not reset these counters.
// Invariant: displayed (x) <= upstream (y) <= cooldown (z).
volatile uint32_t pcap_upstream_total = 0;  // y: successful queue/bypass enqueue
volatile uint32_t pcap_cooldown_total = 0;  // z: passed cooldown gate
volatile uint32_t pcap_displayed_total = 0; // x: surfaced by processLeakQueue
// Core 1 — processLiveDumpQueue() repush after parsing
uint32_t leak_core1_attempts = 0;
uint32_t leak_core1_dropped = 0;

// ==========================================
// ABSOLUTE WATERFALL GLOBALS
// ==========================================
uint32_t traffic_history[240] = {0}; // 480 width / 2px increments = 240 columns
uint32_t absolute_max_traffic = 10;  // Seeded to prevent divide-by-zero
bool should_alert_crypto(const uint8_t *mac_a, const uint8_t *mac_b,
                         uint32_t current_ms) {

  // --- THE MAC NORMALIZATION FIX ---
  // Always store the numerically smaller MAC first.
  // This collapses AP->STA and STA->AP into a single bidirectional conversation
  // slot.
  const uint8_t *lo = (memcmp(mac_a, mac_b, 6) <= 0) ? mac_a : mac_b;
  const uint8_t *hi = (lo == mac_a) ? mac_b : mac_a;

  int oldest_idx = 0;
  uint32_t oldest_time = 0xFFFFFFFF;

  // 1. Scan the cache for a match AND track the oldest slot simultaneously
  for (int i = 0; i < ALERT_CACHE_SIZE; i++) {

    // Match found using the normalized MACs!
    if (memcmp(crypto_cache[i].mac_src, lo, 6) == 0 &&
        memcmp(crypto_cache[i].mac_dst, hi, 6) == 0) {

      if (current_ms - crypto_cache[i].last_alert_ms > SEC_COOLDOWN_MS) {
        crypto_cache[i].last_alert_ms = current_ms;
        return true;
      }
      return false; // Still in cooldown
    }

    // --- THE LRU EVICTION FIX ---
    // Keep track of the stalest entry in case we need to evict.
    if (crypto_cache[i].last_alert_ms < oldest_time) {
      oldest_time = crypto_cache[i].last_alert_ms;
      oldest_idx = i;
    }
  }

  // 2. New flow: Overwrite the genuinely oldest slot (True LRU)
  memcpy(crypto_cache[oldest_idx].mac_src, lo, 6);
  memcpy(crypto_cache[oldest_idx].mac_dst, hi, 6);
  crypto_cache[oldest_idx].last_alert_ms = current_ms;

  return true;
}

// ============================================================================
// ARP BURST / RECONNAISSANCE DETECTOR (approved design)
// Detects a short IPv4 ARP request burst from one source MAC:
// >= ARP_REQ_MIN requests AND >= ARP_TGT_MIN distinct target IPv4s within
// ARP_WINDOW_MS (reset window). Opcode-1 requests only; gratuitous/
// announcement ARP (sender_ip == target_ip) is excluded by the caller.
// One alert per burst; the slot re-arms after ARP_REARM_GAP_MS of scanner
// inactivity. State: ARP_SCANNERS x 52 B = 208 B static, file-scope — same
// accounting home as flow_cache/crypto_cache (outside the static_non_union
// SRAM assert). No heap, no new queue.
// ============================================================================
#define ARP_SCANNERS 4       // max simultaneously tracked scanners (LRU)
#define ARP_TARGETS 8        // remembered target IPv4s per scanner
#define ARP_WINDOW_MS 5000   // reset-window length
#define ARP_REQ_MIN 4        // minimum requests in window
#define ARP_TGT_MIN 4        // minimum distinct targets in window
#define ARP_REARM_GAP_MS 60000 // scanner silence required to re-arm

struct ArpScannerSlot {
  // Word-aligned members first to minimize padding: 52 B/slot (208 B total).
  uint32_t first_seen_ms;            // burst window anchor
  uint32_t last_seen_ms;             // last eligible request (also LRU)
  uint16_t req_count;                // saturating at 65535
  uint8_t mac[6];                    // scanner source MAC (slot key)
  uint8_t distinct;                  // saturating distinct-target counter
  uint8_t ntargets;                  // fill pointer into target_seen
  bool alerted;                      // burst already alerted (re-arm keyed on
                                     // last_seen_ms silence gap)
  uint8_t target_seen[ARP_TARGETS][4]; // per-scanner target dedup list
};

static ArpScannerSlot arp_scanners[ARP_SCANNERS]; // 208 B

// Feed one eligible ARP request. Returns true exactly on the threshold-
// crossing event of a not-currently-alerted slot, with the forensic text
// written to out_text. Pure detector state machine — no I/O here; the
// caller builds and enqueues the ALERT_RECON_ARP record (bypass pattern).
static bool arp_scan_feed(const uint8_t *scanner_mac, const uint8_t *sender_ip,
                          const uint8_t *target_ip, uint32_t now_ms,
                          char *out_text, size_t max_len) {
  ArpScannerSlot *slot = nullptr;
  ArpScannerSlot *stalest = &arp_scanners[0];

  for (int i = 0; i < ARP_SCANNERS; i++) {
    ArpScannerSlot &s = arp_scanners[i];
    if (slot == nullptr && memcmp(s.mac, scanner_mac, 6) == 0)
      slot = &s;
    if (s.last_seen_ms < stalest->last_seen_ms)
      stalest = &s;
  }

  if (slot == nullptr) {
    // New scanner: claim the stalest slot (zeroed/empty slots have
    // last_seen_ms == 0 and are chosen first).
    slot = stalest;
    memset(slot, 0, sizeof(ArpScannerSlot));
    memcpy(slot->mac, scanner_mac, 6);
  } else if (slot->last_seen_ms != 0 &&
             now_ms - slot->last_seen_ms >= ARP_REARM_GAP_MS) {
    // Re-arm: 60 s of scanner inactivity fully resets the slot, including
    // the alerted latch — the next burst is genuinely new.
    memset(slot, 0, sizeof(ArpScannerSlot));
    memcpy(slot->mac, scanner_mac, 6);
  } else if (slot->first_seen_ms != 0 &&
             now_ms - slot->first_seen_ms > ARP_WINDOW_MS) {
    // Reset window expired: counts restart, but the alert latch stays so a
    // continuously-active scanner cannot re-alert until it goes silent.
    slot->first_seen_ms = now_ms;
    slot->req_count = 0;
    slot->distinct = 0;
    slot->ntargets = 0;
  }

  if (slot->first_seen_ms == 0)
    slot->first_seen_ms = now_ms; // anchor a fresh burst window

  slot->last_seen_ms = now_ms;
  if (slot->req_count < 0xFFFF)
    slot->req_count++;

  // Distinct-target dedup. Once the 8-entry list is full the counter stops
  // (it is already >= the threshold and could no longer be verified exact);
  // the reported number degrades to "8+" at format time.
  bool known = false;
  for (int t = 0; t < slot->ntargets; t++) {
    if (memcmp(slot->target_seen[t], target_ip, 4) == 0) {
      known = true;
      break;
    }
  }
  if (!known && slot->ntargets < ARP_TARGETS) {
    memcpy(slot->target_seen[slot->ntargets], target_ip, 4);
    slot->ntargets++;
    if (slot->distinct < 255)
      slot->distinct++;
  }

  if (!slot->alerted && slot->req_count >= ARP_REQ_MIN &&
      slot->distinct >= ARP_TGT_MIN) {
    slot->alerted = true;

    // Forensic text: actual elapsed burst duration, exact distinct count
    // while the list is not full, "8+" once it is; complete IPv4s.
    // NOTE: with the default thresholds (req>=4, tgt>=4) the alert fires at
    // the crossing request where distinct == req_count == 4 exactly, so the
    // reported count is always "4". The "8+" branch is reachable only if
    // ARP_REQ_MIN is raised above 8 on hardware (e.g. req>=12); it is kept
    // so the text stays correct under any threshold retuning.
    char tgt_str[6];
    if (slot->ntargets >= ARP_TARGETS)
      strncpy(tgt_str, "8+", sizeof(tgt_str) - 1), tgt_str[2] = '\0';
    else
      snprintf(tgt_str, sizeof(tgt_str), "%u", slot->distinct);
    uint32_t elapsed_s =
        (now_ms - slot->first_seen_ms + 999) / 1000; // ceil to seconds
    snprintf(out_text, max_len,
             "ARP SCAN %u req/%s tgts %lus %u.%u.%u.%u->%u.%u.%u.%u",
             slot->req_count, tgt_str, (unsigned long)elapsed_s,
             sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3],
             target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
    return true;
  }
  return false;
}

// ============================================================================
// DEAUTH FLOOD TRIPWIRE (approved design)
// Detects a burst of >= DEAUTH_FLOOD_MIN deauthentication frames within
// DEAUTH_FLOOD_WINDOW_MS — deliberately GLOBAL (not keyed on transmitter
// MAC) so distributed/spoofed floods with many or random source addresses
// still trip. Broadcast and directed deauths both count. Individual deauth
// frames remain ordinary captures; this emits ONE extra ALERT_DEAUTH_FLOOD
// record per flood episode. Latch during continued activity; rearm only
// after DEAUTH_FLOOD_REARM_MS with zero deauths seen. Channel-hopping note:
// with 300 ms x 13 hopping the sniffer is on-channel ~25% of the time, so
// observed rates under-count real floods ~4x — the 8/2s threshold is
// conservative in the right direction. State: 12 B static, file-scope —
// same accounting home as arp_scanners. No heap, no new queue.
// ============================================================================
#define DEAUTH_FLOOD_MIN 8        // deauths within window to trip
#define DEAUTH_FLOOD_WINDOW_MS 2000 // burst window
#define DEAUTH_FLOOD_REARM_MS 60000 // silence required to re-arm

struct DeauthFloodState {
  // 12 B: 2 x u32 + u16 + bool (naturally packed, no tail padding needed).
  uint32_t window_start_ms; // anchor of the current burst window
  uint32_t last_deauth_ms;  // last deauth seen (rearm clock)
  uint16_t count;           // saturating deauths in current window
  bool alerted;             // flood episode already alerted
};

static DeauthFloodState deauth_flood; // 12 B

// Feed one observed deauth frame (any transmitter, broadcast or directed).
// Returns true exactly on the threshold-crossing event of an un-latched
// window, with the forensic text written to out_text. Pure state machine —
// the caller builds and enqueues the ALERT_DEAUTH_FLOOD record.
static bool deauth_flood_feed(uint32_t now_ms, char *out_text,
                              size_t max_len) {
  if (deauth_flood.last_deauth_ms != 0 &&
      now_ms - deauth_flood.last_deauth_ms >= DEAUTH_FLOOD_REARM_MS) {
    // Rearm: 60 s of total deauth silence resets the latch — the next
    // burst is a genuinely new episode.
    memset(&deauth_flood, 0, sizeof(DeauthFloodState));
  } else if (deauth_flood.window_start_ms != 0 &&
             now_ms - deauth_flood.window_start_ms >
                 DEAUTH_FLOOD_WINDOW_MS) {
    // Window expired: count restarts, latch persists so continuous
    // flooding cannot re-alert until silence.
    deauth_flood.window_start_ms = now_ms;
    deauth_flood.count = 0;
  }

  if (deauth_flood.window_start_ms == 0)
    deauth_flood.window_start_ms = now_ms; // anchor a fresh burst window

  deauth_flood.last_deauth_ms = now_ms;
  if (deauth_flood.count < 0xFFFF)
    deauth_flood.count++;

  if (!deauth_flood.alerted && deauth_flood.count >= DEAUTH_FLOOD_MIN) {
    deauth_flood.alerted = true;
    snprintf(out_text, max_len, "DEAUTH FLOOD %u frames/%us",
             deauth_flood.count,
             (unsigned)((now_ms - deauth_flood.window_start_ms + 999) / 1000));
    return true;
  }
  return false;
}

void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (pause_sniffing)
    return;
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint16_t len = pkt->rx_ctrl.sig_len;
  uint8_t *payload = pkt->payload;

  if (len < 24)
    return; // Safety check ensures bytes 22 and 23 exist!

  // Extract MAC addresses immediately since we need them for both modes
  uint8_t *addr1 = payload + 4;  // Receiver
  uint8_t *addr2 = payload + 10; // Transmitter
  uint8_t *mac3 = payload + 16;  // BSSID / Source / Dest

  // ==========================================
  // DIRECT FOXHUNT ISR FEEDER (GLOBAL)
  // ==========================================
  if (is_foxhunting) {
    // Pre-calculate to keep the ISR blazing fast
    bool target_is_tx = (memcmp(addr2, foxhunt_target_mac, 6) == 0);

    if (currentRadioMode == RADIO_AP || currentRadioMode == RADIO_WIFI) {

      // THE PHYSICS FIX (Signal Strength)
      // ONLY feed the math engine if our target is the physical transmitter.
      // Because we require an AP lock first, the channel is already frozen.
      // We don't need any dynamic channel-locking logic here!
      if (target_is_tx) {
        updateFoxhuntSignal(pkt->rx_ctrl.rssi);
      }
    }
  }
  // ==========================================

  // ==========================================
  // MODE-AGNOSTIC PASSIVE SSID SCRAPER
  // Runs in ALL modes to silently maintain the BSSID Cache
  // ==========================================
  uint16_t fc = payload[0] | (payload[1] << 8);

  // Check if Beacon (0x80) or Probe Response (0x50)
  if ((fc & 0xFF) == 0x80 || (fc & 0xFF) == 0x50) {
    // Address 3 (mac3) is the BSSID in these frames
    int offset =
        36; // Skip MAC header (24 bytes) + Fixed Mgmt Params (12 bytes)

    if (offset + 1 < len && payload[offset] == 0x00) { // Tag 0 is SSID
      uint8_t ssid_len = payload[offset + 1];

      if (ssid_len > 0 && ssid_len <= 32 && (offset + 2 + ssid_len) <= len) {
        int target_idx = -1;
        int oldest_idx = 0;
        uint32_t oldest_time = 0xFFFFFFFF;

        for (int i = 0; i < MAX_BSSID_CACHE; i++) {
          if (memcmp(bssidCache[i].bssid, mac3, 6) == 0) {
            target_idx = i;
            break;
          }
          if (bssidCache[i].last_seen < oldest_time) {
            oldest_time = bssidCache[i].last_seen;
            oldest_idx = i;
          }
        }

        if (target_idx == -1)
          target_idx = oldest_idx;

        memcpy(bssidCache[target_idx].bssid, mac3, 6);
        memcpy(bssidCache[target_idx].ssid, &payload[offset + 2], ssid_len);
        bssidCache[target_idx].ssid[ssid_len] = '\0';
        bssidCache[target_idx].last_seen = millis();
      }
    }
  }
  // ==========================================

  // ==========================================
  // BYPASS: AP WATERFALL MODE FUNNEL
  // ==========================================
  if (currentRadioMode == RADIO_AP) {

    // PART 1: THE DICTIONARY (Catch Beacons to learn SSIDs)
    if (type == WIFI_PKT_MGMT) {
      uint8_t subtype = (payload[0] >> 4) & 0x0F;

      // Subtype 8 is a Beacon Frame
      if (subtype == 8) {
        int ap_index = -1;
        for (int i = 0; i < liveApCount; i++) {
          if (memcmp((void *)liveApData[i].bssid, addr2, 6) == 0) {
            ap_index = i;
            break;
          }
        }

        if (ap_index == -1) {
          if (liveApCount < MAX_AP_RECORDS) {
            // Space available, claim the next slot
            ap_index = liveApCount;
            liveApCount++;
          } else {
            // ==========================================
            // THE STALE & WEAK HYBRID EVICTION
            // ==========================================
            unsigned long now = millis();
            int stalest_idx = 0;
            int weakest_idx = 0;
            unsigned long oldest_time = 0xFFFFFFFF;
            int lowest_rssi = 127; // Max possible int8_t

            for (int i = 0; i < MAX_AP_RECORDS; i++) {
              if (liveApData[i].last_seen < oldest_time) {
                oldest_time = liveApData[i].last_seen;
                stalest_idx = i;
              }
              if (liveApData[i].rssi < lowest_rssi) {
                lowest_rssi = liveApData[i].rssi;
                weakest_idx = i;
              }
            }

            // 1. The Ghost Hunt (Evict if silent for > 60 seconds)
            if ((now - oldest_time) > 60000) {
              ap_index = stalest_idx;
            }
            // 2. The Weakest Link (Evict if new AP is stronger than our worst
            // AP)
            else if (pkt->rx_ctrl.rssi > lowest_rssi) {
              ap_index = weakest_idx;
            }
          }

          // If we successfully claimed a slot (either a new one or an evicted
          // one)
          if (ap_index != -1) {

            // --- EVICTION SAFETY INIT ---
            // Explicitly clear the country memory before the IE walk so
            // the new AP doesn't inherit a stale code from the previous
            // occupant.
            liveApData[ap_index].country[0] = '\0';
            liveApData[ap_index].country[1] = '\0';
            liveApData[ap_index].country[2] = '\0';
            // ---------------------------------

            // ==========================================
            // THE BEACON DECODER (Extract True Channel & SSID)
            // ==========================================
            uint8_t true_channel =
                CHANNELS[current_ch_idx];         // Fallback to current hopper
            char extracted_ssid[32] = "<HIDDEN>"; // Default to hidden

            // Beacons have a 24-byte MAC Header + 12-byte Fixed Parameters = 36
            // bytes before Tags begin.
            int offset = 36;

            while (offset < len - 4) { // Loop through tags, stopping before the
                                       // 4-byte FCS checksum
              uint8_t tag_num = payload[offset];
              uint8_t tag_len = payload[offset + 1];

              if (offset + 2 + tag_len > len)
                break; // Memory safety bounds check

              // Tag 0: SSID
              if (tag_num == 0) {
                if (tag_len > 0 && tag_len <= 31) {
                  memcpy(extracted_ssid, payload + offset + 2, tag_len);
                  extracted_ssid[tag_len] = '\0'; // Null terminate
                }
              }
              // Tag 3: DS Parameter Set (Current Channel)
              else if (tag_num == 3 && tag_len == 1) {
                true_channel = payload[offset + 2];
              }
              // --- TAG 7 COUNTRY CODE PARSER ---
              else if (tag_num == 7 && tag_len >= 2) {
                uint8_t c0 = payload[offset + 2];
                uint8_t c1 = payload[offset + 3];

                // Sanity check: valid ISO country codes are uppercase ASCII
                // letters
                if (c0 >= 'A' && c0 <= 'Z' && c1 >= 'A' && c1 <= 'Z') {
                  liveApData[ap_index].country[0] = c0;
                  liveApData[ap_index].country[1] = c1;
                  liveApData[ap_index].country[2] = '\0';
                }
              }
              // --------------------------------------
              offset += 2 + tag_len; // Jump to the next tag
            }
            ingestBeacon(addr2, extracted_ssid, pkt->rx_ctrl.rssi);

            // ==========================================
            // POPULATE THE AP RECORD
            // ==========================================
            memcpy((void *)liveApData[ap_index].bssid, addr2, 6);

            unsigned long now = millis();
            liveApData[ap_index].first_seen = now;
            liveApData[ap_index].last_seen = now;
            liveApData[ap_index].packets = 0;
            liveApData[ap_index].sum_bytes = 0;
            liveApData[ap_index].sum_sq_bytes = 0;
            liveApData[ap_index].tx_bytes = 0;
            liveApData[ap_index].rx_bytes = 0;
            liveApData[ap_index].max_rate = 0;
            liveApData[ap_index].rssi = pkt->rx_ctrl.rssi;
            liveApData[ap_index].rssi_min = pkt->rx_ctrl.rssi;
            liveApData[ap_index].rssi_max = pkt->rx_ctrl.rssi;
            liveApData[ap_index].channel = true_channel;

            // ssid is char ssid[26] — trimmed from 28 to accommodate
            // rssi_min/rssi_max
            strncpy((char *)liveApData[ap_index].ssid, extracted_ssid,
                    sizeof(liveApData[ap_index].ssid));

            // ADD THIS LINE: Force null termination to prevent runaway memory
            // reads
            liveApData[ap_index].ssid[sizeof(liveApData[ap_index].ssid) - 1] =
                '\0';

            // ==========================================
            // O(N) CLONE DETECTION ON DISCOVERY
            // ==========================================
            liveApData[ap_index].has_clone = false;

            if (strlen((char *)liveApData[ap_index].ssid) > 0 &&
                strcmp((char *)liveApData[ap_index].ssid, "<HIDDEN>") != 0 &&
                strcmp((char *)liveApData[ap_index].ssid, "<UNKNOWN>") != 0) {

              for (int i = 0; i < liveApCount; i++) {
                // Skip self-comparison (crucial if ap_index claimed an evicted
                // slot)
                if (i == ap_index)
                  continue;

                if (strcmp((char *)liveApData[i].ssid,
                           (char *)liveApData[ap_index].ssid) == 0) {
                  liveApData[ap_index].has_clone = true;
                  liveApData[i].has_clone = true;
                  break;
                }
              }
            }
            // ==========================================

          } // Closes `if (ap_index != -1)`
        } // Closes `if (ap_index == -1)`

        // If the AP made it into the array, update metadata but IGNORE TRAFFIC
        // MATH!
        if (ap_index != -1) {
          liveApData[ap_index].last_seen = millis();
          liveApData[ap_index].rssi = pkt->rx_ctrl.rssi;
          if (pkt->rx_ctrl.rssi < liveApData[ap_index].rssi_min) {
            liveApData[ap_index].rssi_min = pkt->rx_ctrl.rssi;
          }
          // rssi_max == 0 means uninitialized — same sentinel logic as
          // MacRecord
          if (pkt->rx_ctrl.rssi > liveApData[ap_index].rssi_max ||
              liveApData[ap_index].rssi_max == 0) {
            liveApData[ap_index].rssi_max = pkt->rx_ctrl.rssi;
          }
          // --- TRAFFIC COUNTERS INTENTIONALLY DELETED HERE ---
          // We only want WIFI_PKT_DATA frames (handled below) to trigger the
          // math engine!

          uint8_t current_rate = getBitrateMbps(pkt);
          if (current_rate > liveApData[ap_index].max_rate) {
            liveApData[ap_index].max_rate = current_rate;
          }
        }
      }
    }

    // PART 2: THE COUNTER (Catch Data frames to measure volume)
    else if (type == WIFI_PKT_DATA) {
      for (int i = 0; i < liveApCount; i++) {
        bool is_tx = (memcmp((void *)liveApData[i].bssid, addr2, 6) == 0);
        bool is_rx = (memcmp((void *)liveApData[i].bssid, addr1, 6) == 0);

        if (is_tx || is_rx) {
          liveApData[i].packets += 1;
          liveApData[i].sum_bytes += len;
          liveApData[i].sum_sq_bytes += ((uint64_t)len * len);
          liveApData[i].rssi = pkt->rx_ctrl.rssi;
          liveApData[i].last_seen = millis();

          // Max Rate Trap: Only update if the new packet is faster!
          uint8_t current_rate = getBitrateMbps(pkt);
          if (current_rate > liveApData[i].max_rate) {
            liveApData[i].max_rate = current_rate;
          }

          // Route the traffic
          if (is_tx)
            liveApData[i].tx_bytes += len;
          else
            liveApData[i].rx_bytes += len;

          break;
        }
      }
    }

    return; // Returns cleanly from RADIO_AP mode
  }

  // ==========================================
  // BYPASS: CHANNEL SPECTRUM MODE
  // ==========================================
  if (currentRadioMode == RADIO_CHANNELS) {
    uint8_t ch = CHANNELS[current_ch_idx];
    int idx = -1;

    // 1. Search for the active channel in our existing array
    for (int i = 0; i < liveChannelCount; i++) {
      if (liveChannelData[i].channel == ch) {
        idx = i;
        break;
      }
    }

    // 2. If it's a completely new channel, claim the next available slot
    if (idx == -1) {
      if (liveChannelCount < MAX_CHANNEL_RECORDS) {
        idx = liveChannelCount;
        liveChannelData[idx].channel = ch;
        unsigned long now = millis();
        liveChannelData[idx].first_seen = now;
        liveChannelData[idx].last_seen = now;

        // Seed the physics engine
        liveChannelData[idx].avg_rssi = (float)pkt->rx_ctrl.rssi;
        liveChannelData[idx].prev_rssi =
            (float)pkt->rx_ctrl.rssi; // Remember the very first packet
        liveChannelData[idx].ema_variance = 0.0;
        liveChannelData[idx].ema_cov = 0.0;

        liveChannelCount++;
      } else {
        return;
      }
    }

    // 3. Process the packet exactly as before
    liveChannelData[idx].packets += 1;
    liveChannelData[idx].sum_bytes += len;
    liveChannelData[idx].sum_sq_bytes += ((uint64_t)len * len);
    liveChannelData[idx].last_seen = millis();

    // --- EMA MEAN, VARIANCE, & COVARIANCE CALCULATION ---
    float alpha = 0.05; // 5% weight to new packets, 95% to history
    float current_rssi = (float)pkt->rx_ctrl.rssi;

    // 1. Calculate the difference from the mean for the CURRENT packet
    float diff = current_rssi - liveChannelData[idx].avg_rssi;

    // 2. Calculate the difference from the mean for the PREVIOUS packet
    float prev_diff =
        liveChannelData[idx].prev_rssi - liveChannelData[idx].avg_rssi;

    // 3. Update Autocovariance (Must happen before updating variance/mean)
    liveChannelData[idx].ema_cov =
        (1.0 - alpha) *
        (liveChannelData[idx].ema_cov + alpha * diff * prev_diff);

    // 4. Update Variance
    liveChannelData[idx].ema_variance =
        (1.0 - alpha) *
        (liveChannelData[idx].ema_variance + alpha * diff * diff);

    // 5. Update Mean
    liveChannelData[idx].avg_rssi += (alpha * diff);

    // 6. Store current RSSI into memory for the next packet's covariance check
    liveChannelData[idx].prev_rssi = current_rssi;

    // --- UPLINK / DOWNLINK ROUTER ---
    uint8_t ds_flags = payload[1] & 0x03;
    bool to_ds = (ds_flags & 0x01);   // Client -> AP
    bool from_ds = (ds_flags & 0x02); // AP -> Client

    bool is_uplink = false;
    if (to_ds && !from_ds)
      is_uplink = true;
    else if (payload[0] == 0x40)
      is_uplink = true; // Probe Requests

    if (is_uplink)
      liveChannelData[idx].rx_bytes += len;
    else
      liveChannelData[idx].tx_bytes += len;

    return;
  }

  // ==========================================
  // PROBE REQUEST BOUNCER (Runs only in WIFI mode)
  // ==========================================
  // Check if Frame Control byte 0 is 0x40 (Subtype 4: Probe Request)
  if (payload[0] == 0x40) {
    // ==========================================
    // THE SMART BOUNCER & IE PARSER
    // ==========================================
    bool is_randomized = (addr2[0] & 0x02) != 0;

    int offset = 24;
    char final_ssid[33] = "";
    bool is_valid_ssid = false;

    char ie_vendor[25] = "";
    uint8_t highest_weight_found = 0; // Resets for every new packet
    uint32_t live_hw_hash = 5381;
    // 1. FIRST PASS: Parse the IE tags to build the profile
    while (offset < len - 4) {
      uint8_t tag_num = payload[offset];
      uint8_t tag_len = payload[offset + 1];

      if (offset + 2 + tag_len > len)
        break; // Memory safety boundary

      // --- BUILD THE HARDWARE HASH ---
      // 1. Always hash the tag_num (Captures the structural skeleton)
      live_hw_hash = ((live_hw_hash << 5) + live_hw_hash) + tag_num;

      // 2. Selectively hash the payload (Captures the unchangeable DNA)
      // Tag 45: HT Caps | Tag 127: Ext Caps | Tag 221: Vendor Specific
      if (tag_num == 45 || tag_num == 127 || tag_num == 221) {
        for (int p = 0; p < tag_len; p++) {
          live_hw_hash =
              ((live_hw_hash << 5) + live_hw_hash) + payload[offset + 2 + p];
        }
      }
      // ------------------------------------

      // Extract the SSID (Tag 0)
      if (tag_num == 0) {
        if (tag_len == 0) {
          strlcpy(final_ssid, "<Wld>", sizeof(final_ssid));
        } else if (tag_len <= 32) {
          if (payload[offset + 2] == 0x00) {
            strlcpy(final_ssid, "<Nul>", sizeof(final_ssid));
          } else {
            bool has_valid_chars = false;
            for (int c = 0; c < tag_len; c++) {
              char ch = payload[offset + 2 + c];
              if (ch >= 32 && ch <= 126) {
                final_ssid[c] = ch;
                has_valid_chars = true;
              } else {
                final_ssid[c] = '.';
              }
            }
            final_ssid[tag_len] = '\0';

            if (has_valid_chars) {
              is_valid_ssid = true; // Valid printable network name found!
            } else {
              strlcpy(final_ssid, "<Nul>", sizeof(final_ssid));
            }
          }
        }
      }

      // Extract the True Vendor via Tag 221
      else if (tag_num == 221 && tag_len >= 3) {
        // Search the compiled array from your include/tag221Lookup.h file
        for (int v = 0; v < TAG_221_COUNT; v++) {
          if (payload[offset + 2] == TAG_221_DATABASE[v].oui[0] &&
              payload[offset + 3] == TAG_221_DATABASE[v].oui[1] &&
              payload[offset + 4] == TAG_221_DATABASE[v].oui[2]) {

            if (TAG_221_DATABASE[v].weight > highest_weight_found) {
              highest_weight_found = TAG_221_DATABASE[v].weight;
              snprintf(ie_vendor, sizeof(ie_vendor), "%s~IE",
                       TAG_221_DATABASE[v].name);
            }
            break;
          }
        }
      }

      offset += 2 + tag_len;
    }

    // 2. THE DECISION GATE
    // Universal Pass: Real MACs get through.
    // Conditional Pass: Randomized MACs only get through if targeting a named
    // network.
    if (!is_randomized || (is_randomized && is_valid_ssid)) {
      if (strlen(final_ssid) > 0) {

        // ONLY pass the Tag 221 guess if the MAC is randomized!
        // If it is a physical MAC, pass an empty string so Core 1 checks the SD
        // Card.
        if (is_randomized) {
          processProbeRequestShared(addr2, final_ssid, ie_vendor,
                                    pkt->rx_ctrl.rssi, live_hw_hash);
        } else {
          processProbeRequestShared(addr2, final_ssid, "", pkt->rx_ctrl.rssi,
                                    live_hw_hash);
        }
      }
    }
    return; // EXIT EARLY: Do not let Management frames hit the bandwidth math!
  }
  // ==========================================
  // PCAP handling:
  // ==========================================
  // 1. MASTER FRAME FILTER (Data & Deauths)
  // ==========================================
  uint8_t frame_type = payload[0] & 0x0C;
  uint8_t frame_subtype = (payload[0] & 0xF0) >> 4;

  // Allow Data frames (Type 0x08) always; Deauth frames (Type 0x00, Subtype 12)
  // only in PCAP mode
  if (frame_type != 0x08 && !(frame_type == 0x00 && frame_subtype == 12 &&
                              currentRadioMode == RADIO_PCAP))
    return;

  // ==========================================
  // 2. INSTANT DEAUTH INTERCEPTOR
  // ==========================================
  if (frame_type == 0x00 && frame_subtype == 12) {
    uint32_t now_ms = xTaskGetTickCountFromISR() * portTICK_PERIOD_MS;

    // Management frame headers are strictly 24 bytes.
    // The 2-byte Reason Code sits immediately after the header (Little-Endian).
    uint16_t reason_code = 0;
    if (len >= 26) {
      reason_code = payload[24] | (payload[25] << 8);
    }

    PacketCapture leak;
    memset(&leak, 0, sizeof(PacketCapture));

    leak.meta.timestamp = now_ms;
    leak.meta.frame_length = pkt->rx_ctrl.sig_len;
    leak.meta.channel = pkt->rx_ctrl.channel;
    leak.meta.frame_subtype = 12;
    leak.meta.is_high_value = true; // Deauths are always a massive red flag!

    // Address 1: Destination, Address 2: Source, Address 3: BSSID
    memcpy(leak.meta.dst_mac, payload + 4, 6);
    memcpy(leak.meta.src_mac, payload + 10, 6);
    memcpy(leak.meta.bssid, payload + 16, 6);

    // Create a highly visible alert using the Reason Code
    snprintf(leak.text, MAX_LEAK_STR_LEN - 1, "DEAUTH (Reason: %d)",
             reason_code);
    leak.retained_len = strnlen(leak.text, MAX_LEAK_STR_LEN - 1);

    // Fire directly to the UI, completely bypassing the Data parser
    if (leakQueue != NULL) {
      leak_isr_attempts++;
      pcap_cooldown_total++; // cumulative: bypass candidate accepted (waterfall
                             // z)
      if (xQueueSendFromISR(leakQueue, &leak, NULL) != pdTRUE)
        leak_isr_dropped++;
      else
        pcap_upstream_total++; // cumulative: bypass leak accounted for display
                               // parity
    }

    // --- DEAUTH FLOOD TRIPWIRE ---
    // Feed this deauth to the global (transmitter-agnostic) burst detector.
    // Individual frames already shipped above as ordinary captures; on the
    // threshold crossing this emits ONE additional ALERT_DEAUTH_FLOOD record.
    {
      char flood_text[MAX_LEAK_STR_LEN] = {0};
      if (deauth_flood_feed(now_ms, flood_text, sizeof(flood_text))) {
        PacketCapture flood;
        memset(&flood, 0, sizeof(PacketCapture));

        flood.meta.timestamp = now_ms;
        flood.meta.frame_length = pkt->rx_ctrl.sig_len;
        flood.meta.channel = pkt->rx_ctrl.channel;
        flood.meta.frame_subtype = 12;
        flood.meta.is_high_value = true; // +300 retention (unchanged
                                         // is_high_value semantics)
        flood.meta.alert_kind = ALERT_DEAUTH_FLOOD;

        // Same addr1/addr2/addr3 mapping as the per-frame record above
        // (mgmt frames: DA/SA/BSSID).
        memcpy(flood.meta.dst_mac, payload + 4, 6);
        memcpy(flood.meta.src_mac, payload + 10, 6);
        memcpy(flood.meta.bssid, payload + 16, 6);

        strncpy(flood.text, flood_text, MAX_LEAK_STR_LEN - 1);
        flood.retained_len = strnlen(flood.text, MAX_LEAK_STR_LEN - 1);

        if (leakQueue != NULL) {
          leak_isr_attempts++;
          pcap_cooldown_total++; // cumulative: bypass candidate accepted
                                 // (waterfall z)
          if (xQueueSendFromISR(leakQueue, &flood, NULL) != pdTRUE)
            leak_isr_dropped++;
          else
            pcap_upstream_total++; // cumulative: bypass leak accounted for
                                   // display parity
        }
      }
    }

    return;
  }

  // ==========================================
  // 3. LEAKY PCAP CLEARTEXT EXTRACTOR
  // ==========================================
  if (currentRadioMode == RADIO_PCAP) { // <-- THE CRITICAL GATE
    // 1. TALLY ABSOLUTE RF VOLUME (Before the gate!)
    capture_bytes_tick += pkt->rx_ctrl.sig_len;

    bool is_protected = (payload[1] & 0x40) != 0;

    if (!is_protected) {
      // ==========================================
      // DYNAMIC MAC HEADER SIZING (HT Control & WDS)
      // ==========================================
      bool is_qos = (payload[0] & 0x80) != 0;
      bool to_ds = (payload[1] & 0x01) != 0;
      bool from_ds = (payload[1] & 0x02) != 0;

      // Strict check for +HTC: the Order bit (0x80) only means +HTC
      // if it is a QoS Data frame! Otherwise, it just means "Strictly Ordered".
      bool has_ht_ctrl = is_qos && ((payload[1] & 0x80) != 0);

      uint8_t header_len = 24; // Base MAC Header
      if (to_ds && from_ds) {
        header_len += 6; // Address 4 present (WDS Bridge)
      }

      // --- SAFE QOS OFFSET ---
      // Save the exact location of the QoS Control field before HT Control
      // shifts the header length!
      uint8_t qos_offset = header_len;

      if (is_qos) {
        header_len += 2; // QoS Control present
      }
      if (has_ht_ctrl) {
        header_len += 4; // HT Control present
      }
      // ==========================================

      // --- METADATA EXTRACTION ---
      uint8_t captured_subtype = (payload[0] & 0xF0) >> 4;
      uint8_t captured_direction = payload[1] & 0x03;
      uint8_t captured_channel = pkt->rx_ctrl.channel;
      uint8_t captured_protocol = 0;
      // --------------------------------

      if (len > header_len) {
        uint8_t *frame_body = payload + header_len;
        uint16_t body_len = len - header_len;

        // Zero-payload ordinary data frames (Null, QoS Null, header-only
        // data): discard before the cooldown gate so they never touch the
        // flow cache, funnel counters, queues, or persistent list.
        if (body_len <= 4)
          return;

        // --- STRIP LLC, IP, AND UDP HEADERS ---
        uint16_t captured_src_port = 0;
        uint16_t captured_dst_port = 0;
        uint16_t ether_type = 0;
        uint8_t tcp_flags = 0;

        uint8_t captured_ip_version = 0;
        uint8_t captured_src_ip[16] = {0};
        uint8_t captured_dst_ip[16] = {0};

        // =======================================================
        // THE A-MSDU BYPASS
        // =======================================================
        bool is_amsdu = false;
        if (is_qos) {
          is_amsdu = (payload[qos_offset] & 0x80) != 0;
        }

        if (is_amsdu) {
          // Do NOT chop `body_len`. Do NOT step `frame_body`.
          // Force an unknown protocol (255) so it bypasses all strict IP
          // parsers. The ENTIRE massive aggregate blob will fall straight
          // through to the Catch-All!
          captured_protocol = 255;
        }

        // 1. Skip LLC/SNAP Header (8 bytes) if present AND not an A-MSDU.
        if (!is_amsdu && body_len > 8 && frame_body[0] == 0xAA &&
            frame_body[1] == 0xAA) {
          bool is_apple = (frame_body[3] == 0x00 && frame_body[4] == 0x17 &&
                           frame_body[5] == 0xF2);
          ether_type = (frame_body[6] << 8) | frame_body[7];
          frame_body += 8;
          body_len -= 8;

          // --- APPLE AWDL SHIM BYPASS ---
          // Apple AWDL injects a 6-byte shim before the real IPv6 header (86
          // DD).
          // --- UPGRADED: APPLE AWDL SHIM BYPASS (SLIDING WINDOW) ---
          if (is_apple && body_len > 8) {
            // Apple's shim changes size. We hunt up to 16 bytes ahead for the
            // IPv6 header (86 DD).
            int shim_len = -1;
            for (int s = 0; s < 16; s++) {
              if (s + 1 < body_len && frame_body[s] == 0x86 &&
                  frame_body[s + 1] == 0xDD) {
                shim_len = s;
                break;
              }
            }

            if (shim_len != -1) {
              ether_type = 0x86DD; // Force the EtherType to IPv6

              // Step OVER the 86 DD bytes (+2) to reach the 0x60 IPv6 header.
              frame_body += (shim_len + 2);
              body_len -= (shim_len + 2);
            }
          }

          // --- 802.1Q VLAN TAG STRIPPING ---
          // If EtherType is 0x8100, the packet has a 4-byte VLAN tag injected
          // before the IP header.
          if (ether_type == 0x8100 && body_len > 4) {
            // The real EtherType is located right after the 2-byte TCI (Tag
            // Control Information)
            ether_type = (frame_body[2] << 8) | frame_body[3];
            frame_body += 4; // Step over the VLAN tag
            body_len -= 4;
          }
          // --------------------------------------

          // --- ARP BURST DETECTOR FEED ---
          // BEFORE the funnel LRU/30 s cooldown (:hash_flow covers payload
          // bytes, so repeated requests to the same target are suppressed
          // downstream) — the detector must see the repeats that build a
          // burst. Normal funnel behavior for the probe itself is unchanged.
          if (ether_type == 0x0806 && body_len >= 28) {
            uint16_t arp_htype = (frame_body[0] << 8) | frame_body[1];
            uint16_t arp_ptype = (frame_body[2] << 8) | frame_body[3];
            uint8_t opcode = (frame_body[6] << 8) | frame_body[7];

            // Ethernet/IPv4/6/4 shape, requests only, gratuitous/announcement
            // (sender_ip == target_ip) excluded — same validation as
            // parse_arp (link_layer.cpp).
            if (arp_htype == 1 && arp_ptype == 0x0800 && frame_body[4] == 6 &&
                frame_body[5] == 4 && opcode == 1 &&
                memcmp(frame_body + 14, frame_body + 24, 4) != 0) {
              char arp_alert_text[MAX_LEAK_STR_LEN] = {0};
              uint32_t arp_now_ms =
                  xTaskGetTickCountFromISR() * portTICK_PERIOD_MS;

              if (arp_scan_feed(addr2, frame_body + 14, frame_body + 24,
                                arp_now_ms, arp_alert_text,
                                sizeof(arp_alert_text))) {
                // Threshold crossed: emit the ALERT_RECON_ARP record through
                // leakQueue — the crypto-bypass shape verbatim.
                PacketCapture leak;
                memset(&leak, 0, sizeof(PacketCapture));

                leak.meta.timestamp = arp_now_ms;
                leak.meta.frame_length = pkt->rx_ctrl.sig_len;
                leak.meta.channel = pkt->rx_ctrl.channel;
                leak.meta.frame_subtype = captured_subtype;
                leak.meta.is_high_value = true; // +300 retention (unchanged
                                                // is_high_value semantics)
                leak.meta.alert_kind = ALERT_RECON_ARP;

                // DS-aware 802.11 address mapping — same four-way form as the
                // cleartext funnel and crypto branch.
                if (to_ds && !from_ds) {
                  memcpy(leak.meta.src_mac, payload + 10, 6); // addr2 = SA
                  memcpy(leak.meta.dst_mac, mac3, 6);         // addr3 = DA
                  memcpy(leak.meta.bssid, payload + 4, 6);    // addr1 = BSSID
                } else if (from_ds && !to_ds) {
                  memcpy(leak.meta.src_mac, mac3, 6);        // addr3 = SA
                  memcpy(leak.meta.dst_mac, payload + 4, 6); // addr1 = DA
                  memcpy(leak.meta.bssid, payload + 10, 6);  // addr2 = BSSID
                } else if (to_ds && from_ds) {
                  memcpy(leak.meta.src_mac, payload + 24, 6); // addr4 = SA (WDS)
                  memcpy(leak.meta.dst_mac, mac3, 6);         // addr3 = DA
                  // bssid left zeroed: no three-address BSSID in WDS
                } else {
                  memcpy(leak.meta.src_mac, payload + 10, 6); // addr2 = SA
                  memcpy(leak.meta.dst_mac, payload + 4, 6);  // addr1 = DA
                  memcpy(leak.meta.bssid, mac3, 6);           // addr3 = BSSID
                }

                strncpy(leak.text, arp_alert_text, MAX_LEAK_STR_LEN - 1);
                leak.retained_len = strnlen(leak.text, MAX_LEAK_STR_LEN - 1);

                if (leakQueue != NULL) {
                  leak_isr_attempts++;
                  pcap_cooldown_total++; // cumulative: bypass candidate
                                         // accepted (waterfall z)
                  if (xQueueSendFromISR(leakQueue, &leak, NULL) != pdTRUE)
                    leak_isr_dropped++;
                  else
                    pcap_upstream_total++; // cumulative: bypass leak accounted
                                           // for display parity
                }
              }
            }
          }

        }

        // 2. Check for IPv4 (First nibble is 4)
        if (!is_amsdu && body_len > 20 && (frame_body[0] & 0xF0) == 0x40) {
          captured_ip_version = 4;
          // --- Read Logical IP Length to strip Wi-Fi FCS/Padding ---
          uint16_t ip_total_len = (frame_body[2] << 8) | frame_body[3];
          // Safety check: ensure IP length isn't larger than our physical
          // capture
          if (ip_total_len < body_len) {
            body_len = ip_total_len;
          }
          // --------------------------------------------------------------
          // IPv4 Source IP is at offset 12, Destination IP is at offset 16
          memcpy(captured_src_ip, &frame_body[12], 4);
          memcpy(captured_dst_ip, &frame_body[16], 4);

          uint8_t ip_header_len = (frame_body[0] & 0x0F) * 4;

          // 3. Check Protocol field (Byte 9) for UDP (17)
          if (frame_body[9] == 17 && body_len > (ip_header_len + 8)) {
            captured_protocol = 17;
            uint8_t *udp_header = frame_body + ip_header_len;
            captured_src_port = (udp_header[0] << 8) | udp_header[1];
            captured_dst_port = (udp_header[2] << 8) | udp_header[3];

            frame_body += (ip_header_len + 8);
            body_len -= (ip_header_len + 8);
          }
          // 4. Check Protocol field for TCP (6)
          else if (frame_body[9] == 6 && body_len > (ip_header_len + 20)) {
            captured_protocol = 6;
            uint8_t *tcp_header = frame_body + ip_header_len;
            captured_src_port = (tcp_header[0] << 8) | tcp_header[1];
            captured_dst_port = (tcp_header[2] << 8) | tcp_header[3];
            tcp_flags = tcp_header[13];

            uint8_t tcp_header_len = ((tcp_header[12] & 0xF0) >> 4) * 4;
            if (body_len > (ip_header_len + tcp_header_len)) {
              frame_body += (ip_header_len + tcp_header_len);
              body_len -= (ip_header_len + tcp_header_len);
            } else {
              body_len = 0; // Prevent underflow if no payload
            }
          }
          // --- ICMPv4 (1) and Unknown Protocol Catch-All ---
          else if (frame_body[9] == 1 && body_len > ip_header_len) {
            captured_protocol = 1; // ICMPv4
            frame_body += ip_header_len;
            body_len -= ip_header_len;
          } else {
            // Unknown protocol (e.g. IGMP, GRE).
            // Strip the IP header so payload catch-alls don't print garbage!
            if (body_len > ip_header_len) {
              frame_body += ip_header_len;
              body_len -= ip_header_len;
            } else {
              body_len = 0;
            }
          }
        }
        // 2.5 Check for IPv6 (First nibble is 6)
        else if (!is_amsdu && body_len > 40 && (frame_body[0] & 0xF0) == 0x60) {
          captured_ip_version = 6;

          // IPv6 Source IP is at offset 8, Destination IP is at offset 24
          memcpy(captured_src_ip, &frame_body[8], 16);
          memcpy(captured_dst_ip, &frame_body[24], 16);

          uint8_t next_header =
              frame_body[6]; // IPv6 uses "Next Header" instead of Protocol
          uint8_t ip_header_len = 40; // Fixed size for base IPv6 header

          // ==========================================
          // EXTENSION HEADER HOPPER (Hop-by-Hop)
          // Apple injects Hop-by-Hop (0) into mDNS and ICMPv6 multicasts.
          // ==========================================
          if (next_header == 0 && body_len > ip_header_len + 8) {
            // The first byte of the extension is the TRUE protocol (e.g., 17
            // for UDP)
            uint8_t inner_header = frame_body[ip_header_len];

            // Length is calculated as (Byte[1] + 1) * 8
            uint8_t ext_len_modifier = frame_body[ip_header_len + 1];
            uint16_t total_ext_len = (ext_len_modifier + 1) * 8;

            // Commit BOTH the advanced boundary and the inner protocol
            // only if the complete extension fits within the capture;
            // otherwise the truncated extension is treated as unknown.
            if (body_len > ip_header_len + total_ext_len) {
              ip_header_len += total_ext_len;
              next_header = inner_header;
            }
          }
          // ==========================================
          if (next_header == 17 && body_len > (ip_header_len + 8)) {
            captured_protocol = 17; // UDP
            uint8_t *udp_header = frame_body + ip_header_len;
            captured_src_port = (udp_header[0] << 8) | udp_header[1];
            captured_dst_port = (udp_header[2] << 8) | udp_header[3];

            frame_body += (ip_header_len + 8);
            body_len -= (ip_header_len + 8);
          } else if (next_header == 6 && body_len > (ip_header_len + 20)) {
            captured_protocol = 6; // TCP
            uint8_t *tcp_header = frame_body + ip_header_len;
            captured_src_port = (tcp_header[0] << 8) | tcp_header[1];
            captured_dst_port = (tcp_header[2] << 8) | tcp_header[3];
            tcp_flags = tcp_header[13];

            uint8_t tcp_header_len = ((tcp_header[12] & 0xF0) >> 4) * 4;
            if (body_len > (ip_header_len + tcp_header_len)) {
              frame_body += (ip_header_len + tcp_header_len);
              body_len -= (ip_header_len + tcp_header_len);
            } else {
              body_len = 0; // Truncated TCP header (incl. options): no
                            // application payload
            }
          } else if (next_header == 58 && body_len > ip_header_len) {
            // --- ICMPv6 (58) ---
            captured_protocol = 58; // ICMPv6
            frame_body += ip_header_len;
            body_len -= ip_header_len;
          } else {
            // Unknown protocol or contains extension headers. Just strip the
            // fixed IP header.
            if (body_len > ip_header_len) {
              frame_body += ip_header_len;
              body_len -= ip_header_len;
            } else {
              body_len = 0;
            }
          }
        }

        // =========================================================
        // TCP/443 PAYLOAD HANDOFF DIAGNOSTIC
        // =========================================================
        /*
        if (captured_protocol == 6 &&
            (captured_src_port == 443 || captured_dst_port == 443)) {

            Serial.printf(
                "[SNIFF-TCP443] src=%u dst=%u flags=0x%02X "
                "payload_len=%u ether=0x%04X ip_ver=%u\n",
                captured_src_port,
                captured_dst_port,
                tcp_flags,
                body_len,
                ether_type,
                captured_ip_version
            );

            if (body_len > 0 && frame_body != nullptr) {
                Serial.print("[SNIFF-TCP443] payload first32: ");

                uint16_t dump_len =
                    min((uint16_t)32, body_len);

                for (uint16_t i = 0; i < dump_len; i++) {
                    Serial.printf("%02X ", frame_body[i]);
                }

                Serial.println();
            }
        }
        */

        // =========================================================
        // 3. THE HIGH-SPEED ISR FUNNEL (LRU Cache & Deduplication)
        // =========================================================
        leak_funnel_seen++;
        // 1. Generate the fast integer hash of the flow
        uint32_t current_hash = hash_flow(frame_body, body_len,
                                          captured_src_port, captured_dst_port);

        uint32_t now_ms = millis();
        bool should_process = false;
        int cache_idx = -1;
        int oldest_idx = 0;
        uint32_t oldest_time = 0xFFFFFFFF;

        // 2. Scan the LRU Cache
        for (int i = 0; i < MAX_ACTIVE_FLOWS; i++) {
          // Found an existing flow
          if (flow_cache[i].flow_hash == current_hash) {
            cache_idx = i;
            break;
          }
          // Keep track of the stalest record in case we need to evict
          if (flow_cache[i].last_seen_ms < oldest_time) {
            oldest_time = flow_cache[i].last_seen_ms;
            oldest_idx = i;
          }
        }

        if (cache_idx != -1) {
          // Existing Flow: Update stats and check the 30-second cooldown
          flow_cache[cache_idx].count++;
          flow_cache[cache_idx].last_seen_ms = now_ms;

          if (now_ms - flow_cache[cache_idx].last_printed_ms >
              LIVE_DUMP_COOLDOWN_MS) {
            should_process = true;
            flow_cache[cache_idx].last_printed_ms = now_ms;
          } else {
            leak_funnel_suppressed++;
            static uint32_t suppressed = 0;
            suppressed++;
            if (suppressed % 20 == 1) {
              // Serial.printf("[PCAP-DEDUP] Cooldown suppressed repeat
              // (hash=0x%08X, total=%u)\n", current_hash, suppressed);
            }
          }
        } else {
          // New Flow: Evict the oldest record and claim the slot
          cache_idx = oldest_idx;
          flow_cache[cache_idx].flow_hash = current_hash;
          flow_cache[cache_idx].first_seen_ms = now_ms;
          flow_cache[cache_idx].last_seen_ms = now_ms;
          flow_cache[cache_idx].last_printed_ms = now_ms;
          flow_cache[cache_idx].count = 1;
          should_process = true;
        }

        // =========================================================
        // 4. SHIP RAW BYTES TO CORE 1
        // =========================================================

        if (should_process) {

          // =========================================================
          // BUILD TRANSIENT FULL-PAYLOAD TRANSPORT EVENT
          // =========================================================

          uint16_t copy_len = body_len;

          if (copy_len > MAX_LIVE_CAPTURE) {
            copy_len = MAX_LIVE_CAPTURE;
          }

          // The '&' reference lets the compiler treat the heap memory exactly
          // like a local object!
          LiveCaptureEvent &live_evt = *ptr_isr_evt;
          memset(&live_evt, 0, sizeof(LiveCaptureEvent));

          live_evt.meta.timestamp = now_ms;
          live_evt.meta.frame_length = pkt->rx_ctrl.sig_len;
          live_evt.meta.flow_hash = current_hash;
          live_evt.meta.flow_count = flow_cache[cache_idx].count;

          live_evt.meta.src_port = captured_src_port;
          live_evt.meta.dst_port = captured_dst_port;
          live_evt.raw_len = copy_len;
          live_evt.meta.ether_type = ether_type;

          live_evt.meta.ip_version = captured_ip_version;
          live_evt.meta.protocol = captured_protocol;
          live_evt.meta.tcp_flags = tcp_flags;
          live_evt.meta.channel = captured_channel;
          live_evt.meta.direction = captured_direction;
          live_evt.meta.frame_subtype = captured_subtype;

          // DS-aware 802.11 address mapping (mirrors Smart Endpoint
          // Identification below). addr1=payload+4, addr2=payload+10,
          // addr3=mac3=payload+16; addr4 (WDS) at payload+24.
          // 01 STA->AP: addr1=BSSID addr2=SA addr3=DA
          // 10 AP->STA: addr1=DA   addr2=BSSID addr3=SA
          // 00 IBSS:    addr1=DA   addr2=SA    addr3=BSSID
          // 11 WDS: addr4=SA, addr3=DA; no 3-addr BSSID convention,
          //         so bssid stays zeroed (existing absent-value form).
          if (to_ds && !from_ds) {
            memcpy(live_evt.meta.src_mac, payload + 10, 6); // addr2 = SA
            memcpy(live_evt.meta.dst_mac, mac3, 6);         // addr3 = DA
            memcpy(live_evt.meta.bssid, payload + 4, 6);    // addr1 = BSSID
          } else if (from_ds && !to_ds) {
            memcpy(live_evt.meta.src_mac, mac3, 6);        // addr3 = SA
            memcpy(live_evt.meta.dst_mac, payload + 4, 6); // addr1 = DA
            memcpy(live_evt.meta.bssid, payload + 10, 6);  // addr2 = BSSID
          } else if (to_ds && from_ds) {
            memcpy(live_evt.meta.src_mac, payload + 24, 6); // addr4 = SA (WDS)
            memcpy(live_evt.meta.dst_mac, mac3, 6);         // addr3 = DA
            // bssid left zeroed: no three-address BSSID in WDS
          } else {
            memcpy(live_evt.meta.src_mac, payload + 10, 6); // addr2 = SA
            memcpy(live_evt.meta.dst_mac, payload + 4, 6);  // addr1 = DA
            memcpy(live_evt.meta.bssid, mac3, 6);           // addr3 = BSSID
          }

          memcpy(live_evt.meta.src_ip, captured_src_ip, 16);
          memcpy(live_evt.meta.dst_ip, captured_dst_ip, 16);

          if (copy_len > 0) {
            memcpy(live_evt.raw_payload, frame_body, copy_len);
          }

          // =========================================================
          // TCP/443 DIAGNOSTIC
          // =========================================================
          /*
          if (captured_protocol == 6 &&
              (captured_src_port == 443 || captured_dst_port == 443)) {

              Serial.printf(
                  "[CALLBACK-TCP443] "
                  "src=%u dst=%u flags=0x%02X "
                  "body_len=%u copy_len=%u sig_len=%u\n",
                  captured_src_port,
                  captured_dst_port,
                  tcp_flags,
                  body_len,
                  copy_len,
                  pkt->rx_ctrl.sig_len
              );

              if (copy_len > 0) {
                  Serial.print("[CALLBACK-TCP443] first32: ");

                  uint16_t dump_len = min((uint16_t)32, copy_len);

                  for (uint16_t i = 0; i < dump_len; i++) {
                      Serial.printf("%02X ", live_evt.raw_payload[i]);
                  }

                  Serial.println();
              }
          }
          */

          // =========================================================
          // SHIP FULL PAYLOAD TO CORE 1
          // =========================================================

          if (liveDumpQueue != NULL) {
            ui_total_arrived++;
            pcap_cooldown_total++; // cumulative: passed the cooldown gate

            if (xQueueSendFromISR(liveDumpQueue, &live_evt, NULL) != pdTRUE) {

              debug_dropped_packets++;
              ui_dropped_packets++;
              live_dump_dropped++;
            } else {
              leak_funnel_shipped++; // shipped = successful liveDumpQueue
                                     // enqueue (y counterpart of z above)
              pcap_upstream_total++; // cumulative: successful liveDumpQueue
                                     // enqueue
            }
          }

        } // closes if (should_process)

      } // <-- THIS closes if (len > header_len)
    } // <-- THIS closes if (!is_protected)
    else {
      // ==========================================
      // INSECURE ENCRYPTION DETECTION (TKIP/WEP)
      // ==========================================

      // --- UPGRADED: STRICT HEADER SIZING ---
      bool is_qos = (payload[0] & 0x80) != 0;
      bool to_ds = (payload[1] & 0x01) != 0;
      bool from_ds = (payload[1] & 0x02) != 0;

      // The +HTC bit ONLY dictates a 4-byte shift if it is a QoS Data frame!
      bool has_ht_ctrl = is_qos && ((payload[1] & 0x80) != 0);

      uint8_t header_len = 24; // Base MAC Header
      if (to_ds && from_ds)
        header_len += 6; // Address 4 present (WDS Bridge)

      // --- SAFE QOS OFFSET (mirrors the plaintext extractor above) ---
      // Save the exact location of the QoS Control field before HT Control
      // shifts the header length!
      uint8_t qos_offset = header_len;

      if (is_qos)
        header_len += 2; // QoS Control present
      if (has_ht_ctrl)
        header_len += 4; // HT Control present
      // ---------------------------------------

      // Null Data (subtype 4) and QoS Null (subtype 12) frames carry no data
      // payload, so they cannot constitute meaningful insecure-encryption
      // findings. Skip the IV evaluation for them (the plaintext zero-payload
      // filter lives in the opposite !is_protected branch and cannot cover
      // these).
      bool is_null_frame =
          ((payload[0] & 0xF0) >> 4) == 4 || ((payload[0] & 0xF0) >> 4) == 12;

      if (!is_null_frame && len > header_len + 4) {
        uint8_t *iv_ptr = payload + header_len;

        bool is_ext_iv = (iv_ptr[3] & 0x20) != 0;
        bool is_valid_key_id = (iv_ptr[3] & 0x1F) == 0;

        char tid_str[16] = {0};
        if (is_qos) {
          uint8_t tid = payload[qos_offset] & 0x0F;
          snprintf(tid_str, sizeof(tid_str), "[TID:%d] ", tid);
        }

        bool triggered = false;
        char temp_text[MAX_LEAK_STR_LEN] = {0};

        // ONLY evaluate if we mathematically proved it is a valid IV header
        // structure
        if (is_valid_key_id) {
          if (is_ext_iv) {
            // CCMP strictly reserves Byte 2 as 0x00.
            // TKIP uses it as a Dummy Byte, mathematically computed as: (TSC1 |
            // 0x20) & 0x7F
            if (iv_ptr[2] != 0x00) {
              // THE SILVER BULLET: Verify the IEEE TKIP RFC math
              if (iv_ptr[2] == ((iv_ptr[1] | 0x20) & 0x7F)) {
                snprintf(temp_text, MAX_LEAK_STR_LEN,
                         "%sWPA/TKIP Encryption Detected (INSECURE)", tid_str);
                triggered = true;
              }
            }
          } else {
            // WEP signature: KeyID is valid, but it is NOT an Extended IV.
            snprintf(temp_text, MAX_LEAK_STR_LEN,
                     "%sWEP Encryption Detected (INSECURE)", tid_str);
            triggered = true;
          }
        }

        // Apply the LRU cache deduplication
        if (triggered) {
          uint32_t now_ms = xTaskGetTickCountFromISR() * portTICK_PERIOD_MS;

          if (should_alert_crypto(payload + 10, payload + 4, now_ms)) {

            PacketCapture leak;
            memset(&leak, 0, sizeof(PacketCapture));

            leak.meta.timestamp = now_ms;
            leak.meta.frame_length = pkt->rx_ctrl.sig_len;
            leak.meta.flow_hash = (payload[9] << 24) | (payload[8] << 16) |
                                  (payload[15] << 8) | payload[14];
            leak.meta.frame_subtype = (payload[0] & 0xF0) >> 4;
            leak.meta.direction = payload[1] & 0x03;
            leak.meta.channel = pkt->rx_ctrl.channel;

            // DS-aware 802.11 address mapping — same four-way form
            // as the cleartext funnel (capture.cpp). addr1=+4,
            // addr2=+10, addr3=mac3=+16, addr4=+24 (present: this
            // branch runs only under len > header_len + 4, and
            // header_len includes the +6 WDS address field).
            if (to_ds && !from_ds) {
              memcpy(leak.meta.src_mac, payload + 10, 6); // addr2 = SA
              memcpy(leak.meta.dst_mac, mac3, 6);         // addr3 = DA
              memcpy(leak.meta.bssid, payload + 4, 6);    // addr1 = BSSID
            } else if (from_ds && !to_ds) {
              memcpy(leak.meta.src_mac, mac3, 6);        // addr3 = SA
              memcpy(leak.meta.dst_mac, payload + 4, 6); // addr1 = DA
              memcpy(leak.meta.bssid, payload + 10, 6);  // addr2 = BSSID
            } else if (to_ds && from_ds) {
              memcpy(leak.meta.src_mac, payload + 24, 6); // addr4 = SA (WDS)
              memcpy(leak.meta.dst_mac, mac3, 6);         // addr3 = DA
              // bssid left zeroed: no three-address BSSID in WDS
            } else {
              memcpy(leak.meta.src_mac, payload + 10, 6); // addr2 = SA
              memcpy(leak.meta.dst_mac, payload + 4, 6);  // addr1 = DA
              memcpy(leak.meta.bssid, mac3, 6);           // addr3 = BSSID
            }

            strncpy(leak.text, temp_text, MAX_LEAK_STR_LEN - 1);
            leak.retained_len = strnlen(leak.text, MAX_LEAK_STR_LEN - 1);

            if (leakQueue != NULL) {
              leak_isr_attempts++;
              pcap_cooldown_total++; // cumulative: bypass candidate accepted
                                     // (waterfall z)

              if (xQueueSendFromISR(leakQueue, &leak, NULL) != pdTRUE) {
                leak_isr_dropped++;
              } else {
                pcap_upstream_total++; // cumulative: bypass leak accounted for
                                       // display parity
              }
            }
          }
        }
      }
    }
  }
  // ==========================================

  // 2. The Target AP Lock Gate
  if (target_locked) {
    bool belongs_to_target = false;

    // --- THE UNIVERSAL FOXHUNT EXCEPTION ---
    if (is_foxhunting &&
        (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP)) {
      if (memcmp(addr1, foxhunt_target_mac, 6) == 0 ||
          memcmp(addr2, foxhunt_target_mac, 6) == 0 ||
          memcmp(mac3, foxhunt_target_mac, 6) == 0) {
        belongs_to_target = true;
      }
    }

    // Legacy AP Scanner Lock
    if (memcmp(addr1, target_bssid, 6) == 0)
      belongs_to_target = true;
    else if (memcmp(addr2, target_bssid, 6) == 0)
      belongs_to_target = true;
    else if (memcmp(mac3, target_bssid, 6) == 0)
      belongs_to_target = true;

    if (!belongs_to_target)
      return; // The Ruthless Drop
  }

  // 3. Extract DS Flags to determine traffic direction
  uint8_t ds_flags = payload[1] & 0x03;
  bool to_ds = (ds_flags & 0x01);   // Bit 0: Client -> AP (Upload)
  bool from_ds = (ds_flags & 0x02); // Bit 1: AP -> Client (Download)

  // 4. Smart Endpoint Identification
  uint8_t *client_mac = addr2; // Default to Transmitter (mac2)

  if (from_ds && !to_ds) {
    client_mac = addr1; // mac1
  } else if (to_ds && !from_ds) {
    client_mac = addr2; // mac2
  } else if (to_ds && from_ds && len >= 30) {
    // WDS: addr4 is the true source endpoint; addr2 is the transmitting bridge.
    client_mac = payload + 24;
  }

  // 5. Handle Broadcasts and Multicasts
  bool is_broadcast = (client_mac[0] == 0xFF);
  bool is_ipv4_multicast =
      (client_mac[0] == 0x01 && client_mac[1] == 0x00 && client_mac[2] == 0x5E);
  bool is_ipv6_multicast = (client_mac[0] == 0x33 && client_mac[1] == 0x33);
  bool is_stp_multicast =
      (client_mac[0] == 0x01 && client_mac[1] == 0x80 && client_mac[2] == 0xC2);

  if (is_broadcast || is_ipv4_multicast || is_ipv6_multicast ||
      is_stp_multicast) {
    client_mac = mac3;
  }

  // 6. Target Exclusion Gate
  if (target_locked && memcmp(client_mac, target_bssid, 6) == 0)
    return;

  // 7. Update the deduplication buffer
  bool is_tx = (client_mac == addr2); // mac2

  // WiFi client foxhunt — uses correctly derived client_mac:
  if (is_foxhunting && currentRadioMode == RADIO_WIFI) {
    if (memcmp(client_mac, foxhunt_target_mac, 6) == 0) {
      updateFoxhuntSignal(pkt->rx_ctrl.rssi);
    }
  }

  for (int i = 0; i < liveMacCount; i++) {
    if (memcmp((void *)liveData[i].mac, client_mac, 6) == 0) {
      liveData[i].packets += 1;
      liveData[i].sum_bytes += len;
      liveData[i].sum_sq_bytes += ((uint64_t)len * len);

      // Pure Window Stretching
      // Track the absolute min/max for this 2-second window without ever
      // deleting history. Only updates when the target is transmitting.
      if (is_tx) {
        liveData[i].rssi = pkt->rx_ctrl.rssi;

        if (liveData[i].rssi_min == 0 ||
            pkt->rx_ctrl.rssi < liveData[i].rssi_min) {
          liveData[i].rssi_min = pkt->rx_ctrl.rssi;
        }
        if (liveData[i].rssi_max == -100 ||
            pkt->rx_ctrl.rssi > liveData[i].rssi_max) {
          liveData[i].rssi_max = pkt->rx_ctrl.rssi;
        }
      }

      uint8_t current_rate = getBitrateMbps(pkt);
      if (current_rate > liveData[i].rate) {
        liveData[i].rate = current_rate;
      }
      liveData[i].last_seen = millis();
      if (is_tx)
        liveData[i].tx_bytes += len;
      else
        liveData[i].rx_bytes += len;

      return;
    }
  }

  // If we made it here, it's a completely new MAC address!
  if (liveMacCount < MAX_MACS) {
    memcpy((void *)liveData[liveMacCount].mac, client_mac, 6);

    // Seed the first packet's math
    liveData[liveMacCount].packets = 1;
    liveData[liveMacCount].sum_bytes = len;
    liveData[liveMacCount].sum_sq_bytes = ((uint64_t)len * len);
    liveData[liveMacCount].rssi = pkt->rx_ctrl.rssi;
    liveData[liveMacCount].rate = getBitrateMbps(pkt);
    unsigned long now = millis();
    liveData[liveMacCount].first_seen = now;
    liveData[liveMacCount].last_seen = now;

    // Dynamic Initializer
    // Seed the bounds directly to the first packet if it's a physical
    // transmission. Otherwise, use the safe defaults so they stretch correctly
    // later.
    if (is_tx) {
      liveData[liveMacCount].rssi_min = pkt->rx_ctrl.rssi;
      liveData[liveMacCount].rssi_max = pkt->rx_ctrl.rssi;
    } else {
      liveData[liveMacCount].rssi_min = 0;
      liveData[liveMacCount].rssi_max = -100;
    }

    // Route the first packet to TX or RX
    if (is_tx) {
      liveData[liveMacCount].tx_bytes = len;
      liveData[liveMacCount].rx_bytes = 0;
    } else {
      liveData[liveMacCount].tx_bytes = 0;
      liveData[liveMacCount].rx_bytes = len;
    }

    liveData[liveMacCount].vendorFound = false;

    // --- ADD THESE 3 LINES ---
    liveData[liveMacCount].needs_lookup =
        true; // Tell Core 1 to check the SD card
    strncpy((char *)liveData[liveMacCount].vendor, "Resolving...", 27);
    liveData[liveMacCount].vendor[27] = '\0';
    // -------------------------

    liveMacCount++; // Advance the tracker
  } else {
    // If the buffer is full, dump the size into the overflow bucket
    liveOtherBytes += len;
  }
}
static bool is_lldp_multicast(const uint8_t *mac) {
  return mac && mac[0] == 0x01 && mac[1] == 0x80 && mac[2] == 0xC2 &&
         mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0x0E;
}
static bool is_cdp_multicast(const uint8_t *mac) {
  // 01:00:0C:CC:CC:CC is the dedicated Cisco CDP/VTP multicast address
  return mac && mac[0] == 0x01 && mac[1] == 0x00 && mac[2] == 0x0C &&
         mac[3] == 0xCC && mac[4] == 0xCC && mac[5] == 0xCC;
}
void processLiveDumpQueue() {
  if (liveDumpQueue == NULL)
    return;

  // Throttle: at most one warning per 3 s (matches the DIAG cadence).
  // Unsigned subtraction is wraparound-safe.
  static uint32_t last_queue_warn_ms = 0;
  uint32_t now_ms = millis();

  UBaseType_t waiting = uxQueueMessagesWaiting(liveDumpQueue);
  if (waiting >= LIVE_DUMP_QUEUE_DEPTH - 2 &&
      now_ms - last_queue_warn_ms > 3000) {
    last_queue_warn_ms = now_ms;
    Serial.printf("WARNING: Queue backing up! (%u/%u waiting)\n",
                  (unsigned)waiting, (unsigned)LIVE_DUMP_QUEUE_DEPTH);
  }

  LiveCaptureEvent &live_evt = *ptr_core1_evt;
  int packets_processed = 0;
  // uint32_t start_time = micros(); // disabled with the benchmark print
  static char temp_text[MAX_LEAK_STR_LEN];
  static char eapol_text[MAX_LEAK_STR_LEN];

  // Check count BEFORE pulling from the queue (short-circuit order matters).
  while (packets_processed < 5 &&
         xQueueReceive(liveDumpQueue, &live_evt, 0) == pdTRUE) {
    packets_processed++;
    live_dump_consumed++;

    memset(temp_text, 0, sizeof(temp_text));
    bool custom_extracted = false;
    memset(eapol_text, 0, sizeof(eapol_text));
    bool eapol_detected = false;

    // Early semantic classification: QoS Null (802.11 DATA subtype 12).
    // These frames carry no data payload; their nonzero frame_length is
    // frame-level overhead (FCS etc.). Classify them explicitly so they do
    // not enter the payload/protocol parsers. The only producer for this
    // queue is the plaintext funnel, which admits DATA-type frames only
    // (deauths and EAPOL never reach here), so subtype 12 unambiguously
    // identifies QoS Null.
    if (live_evt.meta.frame_subtype == 12) {
      snprintf(temp_text, MAX_LEAK_STR_LEN,
               "0B QoS Null (no data payload)");
      custom_extracted = true;
    }

    if (live_evt.meta.protocol == 6 || live_evt.meta.src_port == 80 ||
        live_evt.meta.dst_port == 80) {

      /*
      Serial.printf(
          "[HTTPDBG] eth=0x%04X ip=%u proto=%u "
          "src=%u dst=%u flags=0x%02X raw_len=%u | ",
          live_evt.meta.ether_type,
          live_evt.meta.ip_version,
          live_evt.meta.protocol,
          live_evt.meta.src_port,
          live_evt.meta.dst_port,
          live_evt.meta.tcp_flags,
          live_evt.raw_len
      );
      */

      // for (int i = 0; i < 32 && i < live_evt.raw_len; i++) {
      //     uint8_t c = live_evt.raw_payload[i];
      //
      //     if (c >= 32 && c <= 126)
      //         Serial.printf("%c", c);
      //     else
      //         Serial.printf(".");
      // }
      //
      // Serial.println();
    }

    // =========================================================
    // --- STRICT PROTOCOL PARSERS ---
    // =========================================================
    // =========================================================
    // --- 0.0 UPNP / SSDP RESPONSE BYPASS (UDP Ephemeral) ---
    // =========================================================
    // Reinstated: Guarded strictly by UDP (Protocol 17) to prevent
    // colliding with standard TCP web traffic!
    if (live_evt.meta.protocol == 17 && live_evt.raw_len > 15 &&
        memcmp(live_evt.raw_payload, "HTTP/1.", 7) == 0) {

      custom_extracted = parse_ssdp(live_evt.raw_payload, live_evt.raw_len,
                                    temp_text, MAX_LEAK_STR_LEN);

      // Unicast SSDP replies are pure gold. Elevate immediately!
      if (custom_extracted) {
        live_evt.meta.is_high_value = true;
      }
    }
    // The entire chain is guarded so the SSDP bypass isn't overwritten
    if (!custom_extracted) {
      // Bare TCP control frames: classify by flags BEFORE any port-based
      // application parser can claim them.
      if (live_evt.meta.protocol == 6 && live_evt.raw_len == 0 &&
          (live_evt.meta.tcp_flags & 0x02)) {
        snprintf(temp_text, MAX_LEAK_STR_LEN, "TCP SYN (Port %d)",
                 live_evt.meta.dst_port);
        custom_extracted = true;
      } else if (live_evt.meta.protocol == 6 && live_evt.raw_len == 0 &&
                 (live_evt.meta.tcp_flags & 0x04)) {
        snprintf(temp_text, MAX_LEAK_STR_LEN, "TCP RST (Port %d)",
                 live_evt.meta.dst_port);
        custom_extracted = true;
      } else if (live_evt.meta.ether_type == 0x0806) {
        custom_extracted = parse_arp(live_evt.raw_payload, live_evt.raw_len,
                                     temp_text, MAX_LEAK_STR_LEN);
      } else if (live_evt.meta.ether_type == 0x888E) {

        eapol_detected = parse_eapol(live_evt.raw_payload, live_evt.raw_len,
                                     eapol_text, MAX_LEAK_STR_LEN);

        // Preserve the existing M1/M2/M3/M4 detection exactly.
        if (eapol_detected &&
            (strstr(eapol_text, "M1") || strstr(eapol_text, "M2") ||
             strstr(eapol_text, "M3") || strstr(eapol_text, "M4"))) {

          live_evt.meta.is_high_value = false;
        }

        // Deliberately do NOT set custom_extracted here.
        // The packet should continue into the deeper/catch-all
        // payload inspection below.
      } else if (is_cdp_multicast(live_evt.meta.dst_mac)) {
        custom_extracted = parse_cdp(live_evt.raw_payload, live_evt.raw_len,
                                     temp_text, MAX_LEAK_STR_LEN);
        if (custom_extracted) {
          live_evt.meta.is_high_value = true;
        }
      } else if (live_evt.meta.ether_type == 0x88CC ||
                 is_lldp_multicast(live_evt.meta.dst_mac)) {
        custom_extracted = parse_lldp(live_evt.raw_payload, live_evt.raw_len,
                                      temp_text, MAX_LEAK_STR_LEN);
        if (custom_extracted) {
          live_evt.meta.is_high_value = true;
        }
      } else if (live_evt.meta.dst_port == 67 || live_evt.meta.src_port == 67 ||
                 live_evt.meta.dst_port == 68 || live_evt.meta.src_port == 68) {
        custom_extracted = parse_dhcp_v4(live_evt.raw_payload, live_evt.raw_len,
                                         temp_text, MAX_LEAK_STR_LEN);
      } else if (live_evt.meta.dst_port == 546 ||
                 live_evt.meta.src_port == 546 ||
                 live_evt.meta.dst_port == 547 ||
                 live_evt.meta.src_port == 547) {
        custom_extracted = parse_dhcp_v6(live_evt.raw_payload, live_evt.raw_len,
                                         temp_text, MAX_LEAK_STR_LEN);
      } else if (live_evt.meta.dst_port == 137 ||
                 live_evt.meta.src_port == 137) {
        custom_extracted = parse_netbios(live_evt.raw_payload, live_evt.raw_len,
                                         temp_text, MAX_LEAK_STR_LEN);
      } else if (live_evt.meta.dst_port == 138 ||
                 live_evt.meta.src_port == 138) {
        custom_extracted = parse_nbds(live_evt.raw_payload, live_evt.raw_len,
                                      temp_text, MAX_LEAK_STR_LEN);
      } else if (live_evt.meta.dst_port == 53 || live_evt.meta.src_port == 53 ||
                 live_evt.meta.dst_port == 5353 ||
                 live_evt.meta.src_port == 5353) {
        custom_extracted = parse_dns_mdns(
            live_evt.raw_payload, live_evt.raw_len,
            live_evt.meta.dst_port == 5353 || live_evt.meta.src_port == 5353,
            temp_text, MAX_LEAK_STR_LEN);
      } else if (live_evt.meta.dst_port == 80 || live_evt.meta.src_port == 80) {
        custom_extracted =
            parse_http_host(live_evt.raw_payload, live_evt.raw_len, temp_text,
                            MAX_LEAK_STR_LEN);
        if (custom_extracted && strstr(temp_text, "[Auth: Basic "))
          live_evt.meta.is_high_value = true;
      } else if (live_evt.meta.dst_port == 3702 ||
                 live_evt.meta.src_port == 3702) {
        custom_extracted =
            parse_ws_discovery(live_evt.raw_payload, live_evt.raw_len,
                               temp_text, MAX_LEAK_STR_LEN);
        if (custom_extracted && strstr(temp_text, "[URL: "))
          live_evt.meta.is_high_value = true;
      } else if (live_evt.meta.dst_port == 631 ||
                 live_evt.meta.src_port == 631) {
        custom_extracted = parse_ipp(live_evt.raw_payload, live_evt.raw_len,
                                     temp_text, MAX_LEAK_STR_LEN);
        // is_high_value intentionally remains false.
      } else if (live_evt.meta.dst_port == 514 ||
                 live_evt.meta.src_port == 514) {
        custom_extracted = parse_syslog(live_evt.raw_payload, live_evt.raw_len,
                                        temp_text, MAX_LEAK_STR_LEN);
      } else if (live_evt.meta.dst_port == 554 ||
                 live_evt.meta.src_port == 554) {
        custom_extracted = parse_rtsp(live_evt.raw_payload, live_evt.raw_len,
                                      temp_text, MAX_LEAK_STR_LEN);
      } else if (live_evt.meta.dst_port == 21 || live_evt.meta.src_port == 21) {
        custom_extracted = parse_ftp(live_evt.raw_payload, live_evt.raw_len,
                                     temp_text, MAX_LEAK_STR_LEN);
        if (custom_extracted)
          live_evt.meta.is_high_value = true;
      } else if (live_evt.meta.dst_port == 23 || live_evt.meta.src_port == 23) {
        custom_extracted = parse_telnet(live_evt.raw_payload, live_evt.raw_len,
                                        temp_text, MAX_LEAK_STR_LEN);
        if (custom_extracted)
          live_evt.meta.is_high_value = true;
      } else if (live_evt.meta.dst_port == 22 || live_evt.meta.src_port == 22) {
        custom_extracted = parse_ssh(live_evt.raw_payload, live_evt.raw_len,
                                     temp_text, MAX_LEAK_STR_LEN);
      } else if (live_evt.meta.dst_port == 69 || live_evt.meta.src_port == 69) {
        custom_extracted = parse_tftp(live_evt.raw_payload, live_evt.raw_len,
                                      temp_text, MAX_LEAK_STR_LEN);

        if (custom_extracted)
          live_evt.meta.is_high_value = true;
      } else if (live_evt.meta.dst_port == 3389 ||
                 live_evt.meta.src_port == 3389) {
        custom_extracted = parse_rdp(live_evt.raw_payload, live_evt.raw_len,
                                     temp_text, MAX_LEAK_STR_LEN);
        if (custom_extracted)
          live_evt.meta.is_high_value = true;
      } else if (live_evt.meta.dst_port == 25 || live_evt.meta.src_port == 25 ||
                 live_evt.meta.dst_port == 587 ||
                 live_evt.meta.src_port == 587) {
        custom_extracted = parse_smtp(live_evt.raw_payload, live_evt.raw_len,
                                      temp_text, MAX_LEAK_STR_LEN);
        if (custom_extracted)
          live_evt.meta.is_high_value = true;
      } else if (live_evt.meta.dst_port == 445 ||
                 live_evt.meta.src_port == 445) {
        custom_extracted = parse_smb(live_evt.raw_payload, live_evt.raw_len,
                                     temp_text, MAX_LEAK_STR_LEN);
        if (custom_extracted)
          live_evt.meta.is_high_value = true;
      } else if (live_evt.meta.dst_port == 1900 ||
                 live_evt.meta.src_port == 1900) {
        custom_extracted = parse_ssdp(live_evt.raw_payload, live_evt.raw_len,
                                      temp_text, MAX_LEAK_STR_LEN);
      } else if (live_evt.meta.dst_port == 5355 ||
                 live_evt.meta.src_port == 5355) {
        custom_extracted = parse_llmnr(live_evt.raw_payload, live_evt.raw_len,
                                       temp_text, MAX_LEAK_STR_LEN);
      } else if (live_evt.meta.dst_port == 17500 ||
                 live_evt.meta.src_port == 17500) {
        custom_extracted = parse_dropbox(live_evt.raw_payload, live_evt.raw_len,
                                         temp_text, MAX_LEAK_STR_LEN);
      } else if (live_evt.meta.dst_port == 161 ||
                 live_evt.meta.src_port == 161 ||
                 live_evt.meta.dst_port == 162 ||
                 live_evt.meta.src_port == 162) {
        custom_extracted = parse_snmp(live_evt.raw_payload, live_evt.raw_len,
                                      temp_text, MAX_LEAK_STR_LEN);
      } else if (live_evt.meta.dst_port == 1080 ||
                 live_evt.meta.src_port == 1080 ||
                 live_evt.meta.dst_port == 9050 ||
                 live_evt.meta.src_port == 9050) {
        custom_extracted = parse_socks(live_evt.raw_payload, live_evt.raw_len,
                                       temp_text, MAX_LEAK_STR_LEN);
      } else if (live_evt.meta.protocol == 1) {
        if (!parse_icmpv4(live_evt.raw_payload, live_evt.raw_len, temp_text,
                          MAX_LEAK_STR_LEN)) {
          snprintf(temp_text, MAX_LEAK_STR_LEN, "ICMPv4: Malformed");
        }
        custom_extracted = true;
      }
    }

    // =========================================================
    // --- DEEP PARSERS & SIGNATURES ---
    // =========================================================
    if (!custom_extracted && live_evt.raw_len > 0) {
      const uint8_t *p = live_evt.raw_payload;
      uint16_t len = live_evt.raw_len;

      // ICMPv6
      if (!custom_extracted && live_evt.meta.ip_version == 6 &&
          live_evt.meta.protocol == 58) {
        if (parse_icmpv6(p, len, temp_text, MAX_LEAK_STR_LEN,
                         live_evt.meta.is_high_value)) {
          custom_extracted = true;
        }
      }

      // MQTT
      if (!custom_extracted && live_evt.meta.protocol == 6 &&
          (live_evt.meta.src_port == 1883 || live_evt.meta.dst_port == 1883)) {
        if (parse_mqtt(p, len, temp_text, MAX_LEAK_STR_LEN,
                       live_evt.meta.is_high_value)) {
          custom_extracted = true;
        }
      }
      // CoAP
      if (!custom_extracted &&
          (live_evt.meta.src_port == 5683 || live_evt.meta.dst_port == 5683)) {

        if (parse_coap(p, len, temp_text, MAX_LEAK_STR_LEN)) {
          custom_extracted = true;
          // Leave is_high_value false for ordinary CoAP traffic.
        }
      }

      // TLS Diagnostic Walker
      if (!custom_extracted && live_evt.meta.protocol == 6 &&
          (live_evt.meta.src_port == 443 || live_evt.meta.dst_port == 443) &&
          len > 0) {

        uint16_t offset = 0;
        bool found_tls = false;

        // ---------------------------------------------------------
        // 1. Walk TLS records that begin at this TCP payload boundary
        // ---------------------------------------------------------
        while (offset + 5 <= len) {
          uint8_t rec_type = p[offset];
          uint16_t rec_version = ((uint16_t)p[offset + 1] << 8) | p[offset + 2];
          uint16_t rec_len = ((uint16_t)p[offset + 3] << 8) | p[offset + 4];

          if (rec_type >= 0x14 && rec_type <= 0x17 &&
              (rec_version == 0x0301 || rec_version == 0x0302 ||
               rec_version == 0x0303)) {

            found_tls = true;

            // TLS record debug dump disabled (hot-path serial spam)
            // Serial.printf(
            //     "\n[TLS-RECORD] offset=%u type=%02X version=%04X len=%u\n",
            //     offset, rec_type, rec_version, rec_len
            // );
            //
            // if (rec_type == 0x16 && offset + 5 < len) {
            //     uint8_t hs_type = p[offset + 5];
            //     const char* hs_str = "Unknown";
            //
            //     if (hs_type == 0x01) hs_str = "ClientHello";
            //     else if (hs_type == 0x02) hs_str = "ServerHello";
            //     else if (hs_type == 0x0B) hs_str = "Certificate";
            //     else if (hs_type == 0x0E) hs_str = "ServerHelloDone";
            //     else if (hs_type == 0x10) hs_str = "ClientKeyExchange";
            //
            //     Serial.printf(
            //         "  -> [TLS-HS] type=%02X %s\n",
            //         hs_type, hs_str
            //     );
            //
            //     if (hs_type == 0x0B &&
            //         rec_len > len - offset - 5) {
            //         Serial.printf(
            //             "  -> [TLS-FRAG] Warning: Certificate record extends
            //             beyond this TCP segment!\n"
            //         );
            //     }
            // }

            // Subtraction-safe boundary check
            if (rec_len > len - offset - 5)
              break;

            offset += 5 + rec_len;
          } else {
            break;
          }
        }

        // ---------------------------------------------------------
        // 2. Parse information from recognized TLS records
        // ---------------------------------------------------------
        if (found_tls) {
          custom_extracted = parse_tls_sni(p, len, temp_text, MAX_LEAK_STR_LEN);

          if (!custom_extracted) {
            custom_extracted =
                parse_tls_cert(p, len, temp_text, MAX_LEAK_STR_LEN);

            if (custom_extracted)
              live_evt.meta.is_high_value = true;
          }

          if (!custom_extracted) {
            snprintf(temp_text, MAX_LEAK_STR_LEN,
                     "TLS Encrypted Traffic (Port %u)",
                     live_evt.meta.dst_port == 443 ? live_evt.meta.src_port
                                                   : live_evt.meta.dst_port);

            custom_extracted = true;
          }
        }

        // ---------------------------------------------------------
        // 3. IMPORTANT: Raw certificate scan for non-header segments
        // ---------------------------------------------------------
        if (!custom_extracted) {
          custom_extracted =
              parse_tls_cert(p, len, temp_text, MAX_LEAK_STR_LEN);

          if (custom_extracted)
            live_evt.meta.is_high_value = true;
        }
      }

      // Other structured deep extractors
      if (!custom_extracted) {
        if (len >= 8 && p[4] == 0x21 && p[5] == 0x12 && p[6] == 0xA4 &&
            p[7] == 0x42) {
          snprintf(temp_text, MAX_LEAK_STR_LEN,
                   "STUN: Live VoIP/WebRTC Stream");
          custom_extracted = true;
          live_evt.meta.is_high_value = true;
        } else if ((len >= 4 &&
                    (memcmp(p, "GET ", 4) == 0 || memcmp(p, "PUT ", 4) == 0)) ||
                   (len >= 5 && (memcmp(p, "POST ", 5) == 0 ||
                                 memcmp(p, "HEAD ", 5) == 0))) {

          custom_extracted =
              parse_http_host(p, len, temp_text, MAX_LEAK_STR_LEN);

          if (custom_extracted) {
            if (strstr(temp_text, "[Auth: Basic ")) {
              live_evt.meta.is_high_value = true;
            }
          } else {
            snprintf(temp_text, MAX_LEAK_STR_LEN, "HTTP Request (Hidden Port)");
            custom_extracted = true;
          }
        }

        else if (len >= 20 && p[0] == 0x13 &&
                 memcmp(&p[1], "BitTorrent protocol", 19) == 0) {

          snprintf(temp_text, MAX_LEAK_STR_LEN, "P2P: BitTorrent Handshake");
          custom_extracted = true;
          live_evt.meta.is_high_value = true;
        }

        else if (len == 148 && p[0] == 0x01 && p[1] == 0x00 && p[2] == 0x00 &&
                 p[3] == 0x00) {

          snprintf(temp_text, MAX_LEAK_STR_LEN, "VPN: WireGuard Handshake");
          custom_extracted = true;
          live_evt.meta.is_high_value = true;
        }
      }

      if (!custom_extracted) {
        if (parse_ephemeral_upnp(p, len, temp_text, MAX_LEAK_STR_LEN)) {
          custom_extracted = true;
          live_evt.meta.is_high_value = true;
        }
      }
    }

    // =========================================================
    // --- STATIC PORT FINGERPRINTS ---
    // =========================================================
    if (!custom_extracted) {
      if (live_evt.meta.dst_port == 3544 || live_evt.meta.src_port == 3544) {
        snprintf(temp_text, MAX_LEAK_STR_LEN, "Teredo: Windows IPv6 Tunnel");
        custom_extracted = true;
      } else if (live_evt.meta.dst_port == 5350 ||
                 live_evt.meta.src_port == 5350) {
        snprintf(temp_text, MAX_LEAK_STR_LEN, "PCP: Port Control Protocol");
        custom_extracted = true;
      } else if (live_evt.meta.dst_port == 5351 ||
                 live_evt.meta.src_port == 5351) {
        snprintf(temp_text, MAX_LEAK_STR_LEN, "NAT-PMP: Apple Port Mapping");
        custom_extracted = true;
      } else if (live_evt.meta.dst_port == 1883 ||
                 live_evt.meta.src_port == 1883) {
        snprintf(temp_text, MAX_LEAK_STR_LEN, "MQTT (IoT Telemetry/PubSub)");
        custom_extracted = true;
        // No automatic high_value elevation here so generic telemetry stays
        // normal
      } else if (live_evt.meta.dst_port == 5683 ||
                 live_evt.meta.src_port == 5683) {
        snprintf(temp_text, MAX_LEAK_STR_LEN,
                 "CoAP (IoT Constrained App Protocol)");
        custom_extracted = true;
        // is_high_value intentionally remains false.
      }
    }

    // =========================================================
    // --- EAPOL FALLBACK ---
    // If no deeper payload extraction succeeded, preserve the
    // normal EAPOL classification.
    // =========================================================
    if (!custom_extracted && eapol_detected) {
      strncpy(temp_text, eapol_text, MAX_LEAK_STR_LEN - 1);
      temp_text[MAX_LEAK_STR_LEN - 1] = '\0';
      custom_extracted = true;
    }

    // =========================================================
    // --- CATCH-ALL FOR UNKNOWN CLEARTEXT ---
    // =========================================================
    if (!custom_extracted && live_evt.raw_len > 0) {
      if (extract_printable_runs(live_evt.raw_payload, live_evt.raw_len,
                                 temp_text, MAX_LEAK_STR_LEN, 4, false, "|")) {
        custom_extracted = true;
      } else {
        // [FALLTHROUGH] hex dump disabled (hot-path serial spam)
        // Serial.printf("[FALLTHROUGH] ip_ver=%u proto=%u src=%u dst=%u
        // eth=0x%04X len=%u | first16: ",
        //               live_evt.meta.ip_version, live_evt.meta.protocol,
        //               live_evt.meta.src_port, live_evt.meta.dst_port,
        //               live_evt.meta.ether_type, live_evt.raw_len);
        // for (int b = 0; b < 16 && b < live_evt.raw_len; b++) {
        //     Serial.printf("%02X ", live_evt.raw_payload[b]);
        // }
        // Serial.println();
      }
    }

    // ==========================================
    // --- UI ROUTING ---
    // ==========================================
    if (custom_extracted) {

      // =========================================================
      // Create the compact persistent/UI object ONLY after parsing
      // =========================================================
      PacketCapture pcap;
      memset(&pcap, 0, sizeof(PacketCapture));

      // Copy packet metadata from the full-payload transport event
      pcap.meta = live_evt.meta;

      // =========================================================
      // Copy parsed text into persistent storage.
      // MAX_LEAK_STR_LEN includes the terminating NUL.
      // =========================================================
      size_t text_len = strnlen(temp_text, MAX_LEAK_STR_LEN - 1);

      pcap.retained_len = (uint16_t)text_len; // <--- INJECT THIS LINE

      memcpy(pcap.text, temp_text, text_len);
      pcap.text[text_len] = '\0';

      // =========================================================
      // High-Value Triage
      // =========================================================
      if (strcasestr(temp_text, "M-SEARCH") ||
          strcasestr(temp_text, "HTTP/1.") ||
          strcasestr(temp_text, "spotify") || strcasestr(temp_text, "cast") ||
          strcasestr(temp_text, "bearer ") || strcasestr(temp_text, "token=") ||
          strcasestr(temp_text, "password=") || strcasestr(temp_text, "pwd=") ||
          strcasestr(temp_text, "user=") || strcasestr(temp_text, "login=") ||
          strcasestr(temp_text, "login:") || strcasestr(temp_text, "/admin") ||
          strcasestr(temp_text, "rtsp://") ||
          strcasestr(temp_text, "tasmota")) {

        pcap.meta.is_high_value = true;

        // if (leakQueue != NULL) {
        //     leak_core1_attempts++;

        // if (xQueueSend(leakQueue, &pcap, 0) != pdTRUE) {
        //     leak_core1_dropped++;
        // }
        //}
      }

      // =========================================================
      // Copy final parsed text into the compact UI union
      // =========================================================
      // strncpy(pcap.text, temp_text, MAX_LEAK_STR_LEN - 1);
      // pcap.text[MAX_LEAK_STR_LEN - 1] = '\0';

      // =========================================================
      // Send compact object to the UI/history pipeline
      // =========================================================
      if (leakQueue != NULL) {
        leak_core1_attempts++;

        if (xQueueSend(leakQueue, &pcap, 0) != pdTRUE) {
          leak_core1_dropped++;
        }
      }
    }

    // if (packets_processed > 0) {
    //     uint32_t elapsed = micros() - start_time;
    //     Serial.printf("Processed %d packets in %u us\n", packets_processed,
    //     elapsed);
    // }
  }
}
void resetMonitorState() {
  pause_sniffing = true;
  current_x = 0;

  // ==========================================
  // FLUSH SHARED ARRAYS (Wi-Fi sizes cover BLE and AP too)
  // ==========================================
  memset((void *)liveData, 0, sizeof(liveData));
  liveMacCount = 0;
  liveOtherBytes = 0;
  liveBleCount = 0;
  liveApCount = 0;
  liveChannelCount = 0;

  memset(sortData, 0, sizeof(sortData));
  sortMacCount = 0;
  sortOtherBytes = 0;
  sortBleCount = 0;
  sortApCount = 0;
  sortChannelCount = 0;

  memset(sessionData, 0, sizeof(sessionData));
  sessionMacCount = 0;
  sessionOtherBytes = 0;
  sessionBleCount = 0;
  sessionApCount = 0;
  sessionChannelCount = 0;

  // Session reset: the waterfall's cumulative counters start over here too.
  // Other zero sites: switchRadioMode() and the MENU-EXIT path; the DIAG block
  // only derives window deltas.
  pcap_upstream_total = 0;
  pcap_cooldown_total = 0;
  pcap_displayed_total = 0;

  pause_sniffing = false;
}
void processPcapData() {
  if (currentLeakSort == SORT_LEAK_AGE) {
    qsort(leakHistory, MAX_LEAK_SLOTS, sizeof(LeakHistoryEntry),
          compareLeakAge);
  } else if (currentLeakSort == SORT_LEAK_LENGTH) {
    qsort(leakHistory, MAX_LEAK_SLOTS, sizeof(LeakHistoryEntry),
          compareLeakLength);
  } else if (currentLeakSort == SORT_LEAK_HITS) {
    qsort(leakHistory, MAX_LEAK_SLOTS, sizeof(LeakHistoryEntry),
          compareLeakHits);
  }
}
void logLeakToSerial(const PacketCapture &leak, const char *src_vendor,
                     const char *dst_vendor, const char *ssid) {

  // Mirror drawDeviceList()'s PCAP presentation (lists.cpp): compact length,
  // direction/subtype/protocol strings, IPv6 compression, srcIp>dstIp|age.
  // Field order and separators match the waterfall header lines so the
  // serial record reads like the on-screen one. Data, ordering, and logging
  // behavior are unchanged.
  char lenStr[8];
  uint16_t fLen = leak.meta.frame_length;
  if (fLen < 1000)
    snprintf(lenStr, sizeof(lenStr), "%dB", fLen);
  else
    snprintf(lenStr, sizeof(lenStr), "%dK", fLen / 1000);

  char portStr[24] = "";
  if (leak.meta.protocol == 6 || leak.meta.protocol == 17) {
    snprintf(portStr, sizeof(portStr), "|%d>%d", leak.meta.src_port,
             leak.meta.dst_port);
  }

  // Render correctly regardless of IP version, reusing meta.ip_version
  // as the single source of truth (same field the on-screen PCAP display
  // already keys off of).
  char srcIpStr[48], dstIpStr[48];

  if (leak.meta.ip_version == 6) {
    char srcIpRaw[48], dstIpRaw[48];
    getIpString(6, leak.meta.src_ip, srcIpRaw, sizeof(srcIpRaw));
    getIpString(6, leak.meta.dst_ip, dstIpRaw, sizeof(dstIpRaw));
    compress_ipv6(srcIpRaw, srcIpStr, sizeof(srcIpStr));
    compress_ipv6(dstIpRaw, dstIpStr, sizeof(dstIpStr));
  } else {
    getIpString(leak.meta.ip_version, leak.meta.src_ip, srcIpStr,
                sizeof(srcIpStr));
    getIpString(leak.meta.ip_version, leak.meta.dst_ip, dstIpStr,
                sizeof(dstIpStr));
  }

  // Compact last-seen age, same form as the waterfall's lastSeen field
  // (computed here rather than via the UI helper to avoid a capture->ui
  // include).
  uint32_t age_s = (millis() - leak.meta.timestamp) / 1000;
  char ageStr[8];
  if (age_s < 60)
    snprintf(ageStr, sizeof(ageStr), "%ds", (unsigned)age_s);
  else if (age_s < 3600)
    snprintf(ageStr, sizeof(ageStr), "%dm", (unsigned)(age_s / 60));
  else
    snprintf(ageStr, sizeof(ageStr), "%dh", (unsigned)(age_s / 3600));

  // Sanitize the payload text exactly like the waterfall's payload slice
  // (non-printables -> '.').
  char safePayload[MAX_LEAK_STR_LEN + 1] = {0};
  int pLen = leak.retained_len;
  if (pLen > MAX_LEAK_STR_LEN - 1)
    pLen = MAX_LEAK_STR_LEN - 1;
  memcpy(safePayload, leak.text, pLen);
  safePayload[pLen] = '\0';
  for (int pt = 0; pt < pLen; pt++) {
    if (safePayload[pt] < 32 || safePayload[pt] > 126)
      safePayload[pt] = '.';
  }

  Serial.printf(
      "🚨 CLRTXT%s: "
      "%02X%02X%02X%02X%02X%02X(%s)>%02X%02X%02X%02X%02X%02X(%s)|%s|C%u\n"
      "%02X%02X%02X%02X%02X%02X(%s)|%s|%s|%s%s\n"
      "%s>%s|age:%s\n"
      "%s\n",
      leak.meta.alert_kind == ALERT_DEAUTH_FLOOD
          ? " [DEAUTH FLOOD]"
          : (leak.meta.alert_kind == ALERT_RECON_ARP
                 ? " [RECON]"
                 : (leak.meta.is_high_value ? " [HIGH-VALUE]" : "")),
      leak.meta.src_mac[0], leak.meta.src_mac[1], leak.meta.src_mac[2],
      leak.meta.src_mac[3], leak.meta.src_mac[4], leak.meta.src_mac[5],
      src_vendor, leak.meta.dst_mac[0], leak.meta.dst_mac[1],
      leak.meta.dst_mac[2], leak.meta.dst_mac[3], leak.meta.dst_mac[4],
      leak.meta.dst_mac[5], dst_vendor, lenStr, leak.meta.channel,
      leak.meta.bssid[0], leak.meta.bssid[1], leak.meta.bssid[2],
      leak.meta.bssid[3], leak.meta.bssid[4], leak.meta.bssid[5], ssid,
      getDirectionStr(leak.meta.direction),
      getSubtypeStr(leak.meta.frame_subtype),
      getProtocolStr(leak.meta.protocol), portStr, srcIpStr, dstIpStr, ageStr,
      safePayload);
}

// ============================================================================
// Exact character-trigram Jaccard diversity (incoming-only scoring aid).
//   novelty = 1 - max over retained entries of trigramJaccard(text_in,
//   text_ret)
// Returns 256 * novelty in [0, 256]. O(20) comparisons.
//
// Scratch is TRANSIENT STACK storage (freed on return; no .bss). Exact full-
// payload comparison needs two 512-entry uint32 arrays (~4 KB), which cannot be
// static on this device. Normalization is position-preserving (ascii lowercase
// + map whitespace); the character alphabet is NOT collapsed, so this is exact
// trigram Jaccard over the full cleartext payload.
// ============================================================================

// Worst-case free stack (bytes) seen inside the diversity scorer, recorded each
// call so the caller can verify headroom. On ESP32 StackType_t is uint8_t, so
// uxTaskGetStackHighWaterMark() already returns bytes.
// NOTE: Diagnostic values (high-water, now, etc.) remain 0 until
// incoming_diversity_bonus() is first invoked by the diversity-aware eviction
// path; this may require enough distinct leak results to trigger
// persistent-history eviction.
volatile uint32_t g_div_stack_highwater = 0;

// Instantaneous loopTask stack margin at this probe point (bytes free above
// the current frame), distinct from the lifetime-minimum high-water above.
// pxTaskGetStackStart(NULL) returns the task's stack LOW address (pxStack,
// TCB member, StackType_t* with StackType_t==uint8_t on this port, stacks
// grow downward), so free = current_frame_addr - stack_start.
volatile uint32_t g_div_stack_free_now = 0;

static inline unsigned char tri_norm_char(unsigned char c) {
  if (c >= 'A' && c <= 'Z')
    c += (unsigned char)('a' - 'A');
  if (c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v')
    c = ' ';
  return c;
}

static inline uint32_t trigram_code(const char *s, int i) {
  unsigned char a = tri_norm_char((unsigned char)s[i]);
  unsigned char b = tri_norm_char((unsigned char)s[i + 1]);
  unsigned char c = tri_norm_char((unsigned char)s[i + 2]);
  return ((uint32_t)a << 16) | ((uint32_t)b << 8) | (uint32_t)c;
}

static inline int tri_text_len(const char *s) {
  int n = 0;
  while (n < MAX_LEAK_STR_LEN && s[n] != '\0')
    ++n;
  return n;
}

// In-place heapsort over uint32 (no recursion, bounded stack).
static void hsort_u32(uint32_t *a, int n) {
  for (int i = n / 2 - 1; i >= 0; --i) {
    int p = i;
    for (;;) {
      int l = 2 * p + 1, r = 2 * p + 2, m = p;
      if (l < n && a[l] > a[m])
        m = l;
      if (r < n && a[r] > a[m])
        m = r;
      if (m == p)
        break;
      uint32_t t = a[p];
      a[p] = a[m];
      a[m] = t;
      p = m;
    }
  }
  for (int i = n - 1; i > 0; --i) {
    uint32_t t = a[0];
    a[0] = a[i];
    a[i] = t;
    int p = 0;
    for (;;) {
      int l = 2 * p + 1, r = 2 * p + 2, m = p;
      if (l < i && a[l] > a[m])
        m = l;
      if (r < i && a[r] > a[m])
        m = r;
      if (m == p)
        break;
      uint32_t t2 = a[p];
      a[p] = a[m];
      a[m] = t2;
      p = m;
    }
  }
}

struct DivMatch {
  int sim256;  // max trigram Jaccard similarity, 0..256 (256 = identical sets)
  int best_j;  // retained slot index of the most-similar entry (-1 if none)
};

// Near-duplicate policy: sim256 >= DIV_NEAR_DUP_SIM256 (~0.85 Jaccard)
// marks a candidate as a near-duplicate of its nearest retained entry.
static const int DIV_NEAR_DUP_SIM256 = 218;

// A near-duplicate must beat its representative by this margin
// (retained-length + high-value points) to replace it.
static const int DIV_MATERIALLY_BETTER = 64;

// Age penalty: entries that have not been re-seen recently become
// progressively easier to evict. One penalty point per AGE_PENALTY_STEP_MS
// of staleness (based on last-seen), capped at AGE_PENALTY_MAX so age can
// never by itself outweigh the +300 high-value bonus.
static const int AGE_PENALTY_WEIGHT = 1;
static const uint32_t AGE_PENALTY_STEP_MS = 60000; // 1 minute per step
static const int AGE_PENALTY_MAX = 300;

// How strongly a retained entry's redundancy (max similarity to another
// retained entry, 0..256) counts against it during victim selection.
// 1 = a fully-redundant entry loses up to 256 protection points (~half a
// typical text length); keep <= 2 so redundancy cannot dominate the +300
// high-value bonus.
static const int REDUNDANCY_WEIGHT = 15;

static DivMatch incoming_diversity_match(const PacketCapture &incoming) {
  // Transient stack scratch, bounded to the first 128 trigrams (130 text
  // bytes) of each text — 2 x 128 x 4 = 1 KiB of stack instead of 4 KiB.
  // Longer texts are scored on their bounded prefix: near-duplicate
  // similarity is dominated by the leading protocol region, so this
  // preserves the intended Jaccard behavior for realistic inputs while
  // keeping loopTask stack usage safe (Step 7C).
  static const int DIV_TRIGRAM_BOUND = 128;

  uint32_t keys_a[DIV_TRIGRAM_BOUND];
  uint32_t keys_b[DIV_TRIGRAM_BOUND];

  // Record worst-case free stack (bytes) at this deepest point.
  g_div_stack_highwater = uxTaskGetStackHighWaterMark(NULL);

  // Instantaneous margin: distance from this frame down to the stack base.
  // (Verified: pxTaskGetStackStart returns the LOW end; local addresses sit
  // above it on a downward-growing ESP32 stack.)
  volatile uint32_t probe_anchor = 0;
  g_div_stack_free_now =
      (uint32_t)&probe_anchor - (uint32_t)pxTaskGetStackStart(NULL);

  int la = tri_text_len(incoming.text);
  int na = (la >= 3) ? (la - 2) : 0;
  if (na > DIV_TRIGRAM_BOUND)
    na = DIV_TRIGRAM_BOUND;
  for (int i = 0; i < na; ++i)
    keys_a[i] = trigram_code(incoming.text, i);
  if (na > 0)
    hsort_u32(keys_a, na);
  int ua = 0;
  for (int i = 0; i < na; ++i)
    if (i == 0 || keys_a[i] != keys_a[i - 1])
      keys_a[ua++] = keys_a[i];

  int best_inter = 0; // max similarity = best_inter / best_union
  int best_union = 0;
  int best_j = -1; // retained slot of the most-similar entry

  for (int j = 0; j < MAX_LEAK_SLOTS; ++j) {
    if (leakHistory[j].leak.meta.timestamp == 0)
      continue;

    int lb = tri_text_len(leakHistory[j].leak.text);
    int nb = (lb >= 3) ? (lb - 2) : 0;
    if (nb > DIV_TRIGRAM_BOUND)
      nb = DIV_TRIGRAM_BOUND;
    for (int i = 0; i < nb; ++i)
      keys_b[i] = trigram_code(leakHistory[j].leak.text, i);
    if (nb > 0)
      hsort_u32(keys_b, nb);
    int ub = 0;
    for (int i = 0; i < nb; ++i)
      if (i == 0 || keys_b[i] != keys_b[i - 1])
        keys_b[ub++] = keys_b[i];

    int inter = 0, x = 0, y = 0;
    while (x < ua && y < ub) {
      if (keys_a[x] == keys_b[y]) {
        ++inter;
        ++x;
        ++y;
      } else if (keys_a[x] < keys_b[y])
        ++x;
      else
        ++y;
    }

    int un = ua + ub - inter;
    if (un <= 0)
      continue;
    if (best_union == 0 || inter * best_union > best_inter * un) {
      best_inter = inter;
      best_union = un;
      best_j = j;
    }
  }

  if (best_union == 0)
    return {256, -1}; // nothing comparable -> fully novel
  return {256 - (256 * best_inter) / best_union, best_j};
}

// Existing novelty term (0..256, 256 = fully novel), derived from the match.
static inline int incoming_diversity_bonus(const PacketCapture &incoming) {
  return 256 - incoming_diversity_match(incoming).sim256;
}

// Redundancy of a RETAINED entry: its max trigram Jaccard similarity
// (0..256) to any OTHER occupied retained entry. Used to make redundant
// entries more evictable (REDUNDANCY_WEIGHT in the victim-selection score).
// Max (not average) is the correct measure: an entry is redundant if it has
// a near-twin, regardless of its similarity to the rest of the set.
static int retained_redundancy_score(const PacketCapture &leak, int self_idx) {
  // Same 2 x 128 x 4 = 1 KiB stack-scratch pattern as
  // incoming_diversity_match(); identical bounded 130-byte prefix.
  static const int DIV_TRIGRAM_BOUND = 128;
  uint32_t keys_a[DIV_TRIGRAM_BOUND];
  uint32_t keys_b[DIV_TRIGRAM_BOUND];

  // Same stack probes as the incoming scorer so headroom stays observable
  // from this (equally deep) frame.
  g_div_stack_highwater = uxTaskGetStackHighWaterMark(NULL);
  volatile uint32_t probe_anchor = 0;
  g_div_stack_free_now =
      (uint32_t)&probe_anchor - (uint32_t)pxTaskGetStackStart(NULL);

  // Build the reference set once (the entry being scored).
  int la = tri_text_len(leak.text);
  int na = (la >= 3) ? (la - 2) : 0;
  if (na > DIV_TRIGRAM_BOUND)
    na = DIV_TRIGRAM_BOUND;
  for (int i = 0; i < na; ++i)
    keys_a[i] = trigram_code(leak.text, i);
  if (na > 0)
    hsort_u32(keys_a, na);
  int ua = 0;
  for (int i = 0; i < na; ++i)
    if (i == 0 || keys_a[i] != keys_a[i - 1])
      keys_a[ua++] = keys_a[i];

  int best_inter = 0;
  int best_union = 0;

  // Early out: fewer than 2 occupied entries -> nothing to be redundant with.
  int occupied = 0;
  for (int j = 0; j < MAX_LEAK_SLOTS && occupied < 2; ++j)
    if (leakHistory[j].leak.meta.timestamp != 0)
      occupied++;
  if (occupied < 2)
    return 0;

  for (int j = 0; j < MAX_LEAK_SLOTS; ++j) {
    if (j == self_idx || leakHistory[j].leak.meta.timestamp == 0)
      continue;

    int lb = tri_text_len(leakHistory[j].leak.text);
    int nb = (lb >= 3) ? (lb - 2) : 0;
    if (nb > DIV_TRIGRAM_BOUND)
      nb = DIV_TRIGRAM_BOUND;
    for (int i = 0; i < nb; ++i)
      keys_b[i] = trigram_code(leakHistory[j].leak.text, i);
    if (nb > 0)
      hsort_u32(keys_b, nb);
    int ub = 0;
    for (int i = 0; i < nb; ++i)
      if (i == 0 || keys_b[i] != keys_b[i - 1])
        keys_b[ub++] = keys_b[i];

    int inter = 0, x = 0, y = 0;
    while (x < ua && y < ub) {
      if (keys_a[x] == keys_b[y]) {
        ++inter;
        ++x;
        ++y;
      } else if (keys_a[x] < keys_b[y])
        ++x;
      else
        ++y;
    }

    int un = ua + ub - inter;
    if (un <= 0)
      continue;
    if (best_union == 0 || inter * best_union > best_inter * un) {
      best_inter = inter;
      best_union = un;
      if (best_union > 0 && best_inter == best_union)
        return 256; // identical sets: cannot do better
    }
  }

  if (best_union == 0)
    return 0;
  return (256 * best_inter) / best_union;
}

void processLeakQueue() {
  if (leakQueue == NULL)
    return;

  PacketCapture incomingLeak;
  bool ui_needs_update = false;

  // Bounded batch (mirrors processLiveDumpQueue's 5-per-call pattern): a
  // backlog accumulated during a ~230 ms waterfall redraw is drained over
  // successive loop() iterations instead of monopolizing one iteration with
  // a burst of blocking CLRTXT Serial output.
  int packets_processed = 0;
  while (packets_processed < 5 &&
         xQueueReceive(leakQueue, &incomingLeak, 0) == pdTRUE) {
    packets_processed++;

    // ==========================================
    // 0. TOKEN EXPANSION
    //    Run outside the ISR
    // ==========================================
    if (strcmp(incomingLeak.text, "ICMPV6_NS") == 0) {

      char src_str[40] = {0};
      char tgt_str[40] = {0};

      getIpString(6, incomingLeak.meta.src_ip, src_str, sizeof(src_str));

      getIpString(6, incomingLeak.meta.dst_ip, tgt_str, sizeof(tgt_str));

      snprintf(incomingLeak.text, sizeof(incomingLeak.text),
               "ICMPv6 ND: Who has %s? Tell %s", tgt_str, src_str);
    }

    // ==========================================
    // 1. TERMINAL HISTORY DEDUPLICATION
    //
    //    This is intentionally independent from
    //    persistent leakHistory eviction.
    // ==========================================
    bool foundTerminalMatch = false;
    int matchIndex = -1;

    for (int i = 0; i < MAX_TERMINAL_LINES; i++) {

      if (terminal_history[i].meta.timestamp > 0 &&
          memcmp(terminal_history[i].meta.src_mac, incomingLeak.meta.src_mac,
                 6) == 0 &&
          strcmp(terminal_history[i].text, incomingLeak.text) == 0) {

        foundTerminalMatch = true;
        matchIndex = i;
        break;
      }
    }

    if (foundTerminalMatch) {

      // Refresh last-seen timestamp
      terminal_history[matchIndex].meta.timestamp = incomingLeak.meta.timestamp;

      // Move the refreshed entry to the front
      if (matchIndex > 0) {

        PacketCapture tempCap = terminal_history[matchIndex];

        uint32_t tempFirst = terminal_first_seen[matchIndex];

        for (int t = matchIndex; t > 0; t--) {
          terminal_history[t] = terminal_history[t - 1];

          terminal_first_seen[t] = terminal_first_seen[t - 1];
        }

        terminal_history[0] = tempCap;
        terminal_first_seen[0] = tempFirst;
      }

      ui_needs_update = true;

    } else {

      // New terminal entry.
      // Shift existing entries toward the back.
      for (int t = MAX_TERMINAL_LINES - 1; t > 0; t--) {

        terminal_history[t] = terminal_history[t - 1];

        terminal_first_seen[t] = terminal_first_seen[t - 1];
      }

      terminal_history[0] = incomingLeak;
      terminal_first_seen[0] = incomingLeak.meta.timestamp;

      ui_needs_update = true;
    }

    // ==========================================
    // 2. PERSISTENT LIST DEDUPLICATION
    // ==========================================
    bool isDuplicate = false;

    for (int i = 0; i < MAX_LEAK_SLOTS; i++) {

      if (leakHistory[i].leak.meta.timestamp > 0 &&
          memcmp(leakHistory[i].leak.meta.src_mac, incomingLeak.meta.src_mac,
                 6) == 0 &&
          strcmp(leakHistory[i].leak.text, incomingLeak.text) == 0) {

        // Existing persistent entry.
        // Do NOT run the eviction engine.
        // [xN] = receptions matching this entry's persistent identity
        // (source MAC + displayed text), including payload variants whose
        // raw bytes differ but parse to the same displayed text.
        leakHistory[i].hitCount++;

        // Refresh last-seen timestamp.
        leakHistory[i].leak.meta.timestamp = incomingLeak.meta.timestamp;

        isDuplicate = true;
        ui_needs_update = true;

        break;
      }
    }

    if (!isDuplicate) {

      // ==========================================
      // 3. RESOLVE VENDORS + LOG — UNCONDITIONAL
      //    Runs for every genuinely new capture,
      //    regardless of eviction outcome.
      // ==========================================
      MacRecord tempRec;
      char resolved_src_vendor[16] = "Unknown";
      char resolved_dst_vendor[16] = "Unknown";

      memset(&tempRec, 0, sizeof(MacRecord));
      memcpy(tempRec.mac, incomingLeak.meta.src_mac, 6);
      resolveMacVendor(&tempRec);
      strncpy(resolved_src_vendor, tempRec.vendor,
              sizeof(resolved_src_vendor) - 1);
      resolved_src_vendor[sizeof(resolved_src_vendor) - 1] = '\0';

      memset(&tempRec, 0, sizeof(MacRecord));
      memcpy(tempRec.mac, incomingLeak.meta.dst_mac, 6);
      resolveMacVendor(&tempRec);
      strncpy(resolved_dst_vendor, tempRec.vendor,
              sizeof(resolved_dst_vendor) - 1);
      resolved_dst_vendor[sizeof(resolved_dst_vendor) - 1] = '\0';

      char safeSsid[33] = "Unknown";
      for (int ap = 0; ap < MAX_BSSID_CACHE; ap++) {
        if (bssidCache[ap].last_seen == 0)
          continue;
        if (memcmp(incomingLeak.meta.bssid, bssidCache[ap].bssid, 6) == 0) {
          strncpy(safeSsid, bssidCache[ap].ssid, sizeof(safeSsid) - 1);
          safeSsid[sizeof(safeSsid) - 1] = '\0';
          break;
        }
      }

      leak_displayed++;
      pcap_displayed_total++; // cumulative waterfall numerator (session total)
      logLeakToSerial(incomingLeak, resolved_src_vendor, resolved_dst_vendor,
                      safeSsid);

      // UI plumbing: latch the waterfall-footer alert banner when a dedicated
      // alert record passes (recon ARP or deauth flood). Gated on alert_kind
      // (not is_high_value, which parser triage also sets for ordinary
      // high-value captures) so only real alerts raise the banner. The latch
      // kind records WHICH alert to draw so the two banner texts can share
      // one expiry timestamp.
      if (incomingLeak.meta.alert_kind == ALERT_RECON_ARP ||
          incomingLeak.meta.alert_kind == ALERT_DEAUTH_FLOOD) {
        extern uint32_t alert_latch_until_ms;
        extern uint8_t alert_latch_kind; // AlertKind of the latched banner
        alert_latch_until_ms = millis() + 10000; // 10 s banner window
        alert_latch_kind = incomingLeak.meta.alert_kind;
      }

      // ==========================================
      // 4. SMART EVICTION ENGINE
      //    Only decides whether it also gets a
      //    permanent slot in leakHistory.
      // ==========================================
      // Shared quality score: retained length (with strlen fallback) plus the
      // high-value bonus. Used for BOTH victim selection and the
      // near-duplicate representative comparison so the definitions cannot
      // drift.
      auto score_of = [](const PacketCapture &leak) {
        int score = leak.retained_len;
        if (score == 0)
          score = strlen(leak.text);
        if (leak.meta.is_high_value)
          score += 300;
        return score;
      };

      int targetIndex = -1;

      for (int i = 0; i < MAX_LEAK_SLOTS; i++) {
        if (leakHistory[i].leak.meta.timestamp == 0) {
          targetIndex = i;
          break;
        }
      }

      if (targetIndex == -1) {
        // Near-duplicate gate: a candidate similar to a retained entry
        // (>= ~0.85 Jaccard) competes only against that representative and
        // replaces it only if materially better (length + high-value; the
        // novelty bonus is intentionally excluded here). A near-duplicate
        // that fails the margin is rejected from the persistent list.
        DivMatch dm = incoming_diversity_match(incomingLeak);

        if (dm.sim256 >= DIV_NEAR_DUP_SIM256 &&
            dm.best_j >= 0 && dm.best_j < MAX_LEAK_SLOTS) {
          int rep_score = score_of(leakHistory[dm.best_j].leak);
          int in_score = score_of(incomingLeak);
          if (in_score > rep_score + DIV_MATERIALLY_BETTER) {
            targetIndex = dm.best_j; // replace the representative in place
          }
          // else: not materially better -> candidate stays out of the list
        } else {
          // Novel candidate: existing behavior — global minimum-score victim
          // selection, then the strict admission gate with the novelty bonus.
          int victim_idx = 0;
          int min_score = INT_MAX;
          uint32_t oldest_time = UINT32_MAX;

          for (int i = 0; i < MAX_LEAK_SLOTS; i++) {
            // Age penalty from last-seen; wrap-safe unsigned subtraction.
            // Bounded so age can never by itself outweigh the high-value bonus.
            uint32_t age_ms = millis() - leakHistory[i].leak.meta.timestamp;
            int age_penalty =
                (int)((age_ms / AGE_PENALTY_STEP_MS) * AGE_PENALTY_WEIGHT);
            if (age_penalty > AGE_PENALTY_MAX)
              age_penalty = AGE_PENALTY_MAX;

            int score =
                score_of(leakHistory[i].leak) -
                REDUNDANCY_WEIGHT *
                    retained_redundancy_score(leakHistory[i].leak, i) -
                age_penalty;

            if (score < min_score) {
              min_score = score;
              victim_idx = i;
              oldest_time = leakHistory[i].first_seen;
            } else if (score == min_score) {
              if (leakHistory[i].first_seen < oldest_time) {
                victim_idx = i;
                oldest_time = leakHistory[i].first_seen;
              }
            }
          }

          int incoming_score = incomingLeak.retained_len;
          if (incoming_score == 0)
            incoming_score = strlen(incomingLeak.text);
          if (incomingLeak.meta.is_high_value)
            incoming_score += 300;
          incoming_score += 10 * incoming_diversity_bonus(incomingLeak);

          if (incoming_score > min_score) {
            targetIndex = victim_idx;
          }
        }
      }

      // ==========================================
      // 5. INSERT — GATED, using vendors already resolved above
      // ==========================================
      if (targetIndex != -1) {
        leakHistory[targetIndex].leak = incomingLeak;
        leakHistory[targetIndex].hitCount = (incomingLeak.meta.flow_count > 0)
                                                ? incomingLeak.meta.flow_count
                                                : 1;
        leakHistory[targetIndex].first_seen = incomingLeak.meta.timestamp;
        leakHistory[targetIndex].flow_hash = incomingLeak.meta.flow_hash;
        strcpy(leakHistory[targetIndex].src_vendor, resolved_src_vendor);
        strcpy(leakHistory[targetIndex].dst_vendor, resolved_dst_vendor);

        ui_needs_update = true;
      }
    }
  }

  // ==========================================
  // 8. BATCHED UI REFRESH
  // ==========================================
  if (ui_needs_update && currentState == SCREEN_DEVICE_LIST &&
      currentRadioMode == RADIO_PCAP) {

    processPcapData();
    drawDeviceList();
  }
}

// --- PCAP QSORT COMPARATORS ---

int compareLeakAge(const void *a, const void *b) {
  LeakHistoryEntry *lA = (LeakHistoryEntry *)a;
  LeakHistoryEntry *lB = (LeakHistoryEntry *)b;

  // Push empty slots to the bottom
  if (lA->leak.meta.timestamp == 0 && lB->leak.meta.timestamp == 0)
    return 0;
  if (lA->leak.meta.timestamp == 0)
    return 1;
  if (lB->leak.meta.timestamp == 0)
    return -1;

  if (sort_descending)
    return (lB->leak.meta.timestamp > lA->leak.meta.timestamp)   ? 1
           : (lB->leak.meta.timestamp < lA->leak.meta.timestamp) ? -1
                                                                 : 0;
  return (lA->leak.meta.timestamp > lB->leak.meta.timestamp)   ? 1
         : (lA->leak.meta.timestamp < lB->leak.meta.timestamp) ? -1
                                                               : 0;
}

int compareLeakLength(const void *a, const void *b) {
  LeakHistoryEntry *lA = (LeakHistoryEntry *)a;
  LeakHistoryEntry *lB = (LeakHistoryEntry *)b;

  if (lA->leak.meta.timestamp == 0 && lB->leak.meta.timestamp == 0)
    return 0;
  if (lA->leak.meta.timestamp == 0)
    return 1;
  if (lB->leak.meta.timestamp == 0)
    return -1;

  if (sort_descending)
    return (lB->leak.meta.frame_length > lA->leak.meta.frame_length)   ? 1
           : (lB->leak.meta.frame_length < lA->leak.meta.frame_length) ? -1
                                                                       : 0;
  return (lA->leak.meta.frame_length > lB->leak.meta.frame_length)   ? 1
         : (lA->leak.meta.frame_length < lB->leak.meta.frame_length) ? -1
                                                                     : 0;
}

int compareLeakHits(const void *a, const void *b) {
  LeakHistoryEntry *lA = (LeakHistoryEntry *)a;
  LeakHistoryEntry *lB = (LeakHistoryEntry *)b;

  if (lA->leak.meta.timestamp == 0 && lB->leak.meta.timestamp == 0)
    return 0;
  if (lA->leak.meta.timestamp == 0)
    return 1;
  if (lB->leak.meta.timestamp == 0)
    return -1;

  if (sort_descending)
    return (lB->hitCount > lA->hitCount)   ? 1
           : (lB->hitCount < lA->hitCount) ? -1
                                           : 0;
  return (lA->hitCount > lB->hitCount)   ? 1
         : (lA->hitCount < lB->hitCount) ? -1
                                         : 0;
}
