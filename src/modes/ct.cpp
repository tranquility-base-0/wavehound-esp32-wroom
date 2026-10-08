#include "ct.h"
#include "core/radio.h"
#include "capture/capture.h" // sniffer_callback: CT BLE burst Wi-Fi restore reattach
#include "modes/ap_scanner.h"
#include "osint/osint.h"

// Compile-time switches for the TEMPORARY CT serial diagnostics only.
// Each 0 = compiled out (image-size budget); 1 = restores the byte-
// identical diagnostic output. CT behavior, state, timing, and SRAM
// layout are identical in both settings — the gated code is Core-1,
// post-fence, serial-only. Image budget note (2026-10-01): the app0
// partition is 0x140000 = 1,310,720 B; with all four at 0 the image is
// 1,309,056 B (1,664 B headroom); the full set was 1,310,992 B (272 B
// overflow). Current enablement: SEED + TRIG + PERSIST.
#define CT_DIAG_SEED     1   // [CT-SEED] seed + re-seed-after-commit proof
#define CT_DIAG_TRIG     1   // [CT-TRIG] channel crossings (POP/CHURN/TURN)
#define CT_DIAG_PERSIST  1   // [CT-PERSIST] promotions/evictions
#define CT_DIAG_STEPS    0   // [CT-STEP3/4.1/4.2/5] window telemetry
#define CT_DIAG_TIMING   0   // [CT-TIMING] TEMPORARY: prints the F1 derivation
                            // at every ct_timing_apply() run. Measurement-only.
                            // Remove after diagnosis.

// CT alternating BLE burst (display-only side channel). When 1, every CT
// window close on the chart screen is followed by a bounded passive NimBLE
// scan; the observed advertisement count renders as a second waterfall lane.
// CT_BLE_BURST_SEC is in SECONDS — NimBLE-Arduino 1.4.1 multiplies the scan
// duration by 1000 internally (ms would scan ~33 minutes).
//
// Lifecycle (hardware-validated by the A/B/C/D + mode-4 diagnostic campaign,
// 2026-10): BLE is fully initialized before each scan and fully shut down
// (NimBLEDevice::deinit(false)) after it, so the BT controller/coexistence
// subsystem is NEVER enabled during the Wi-Fi OFF -> STA transition.
// Hardware results of that lifecycle: no `wifi:timeout when WiFi un-init,
// type=4`, no recurring per-burst heap retention (the old controller-
// enabled lifecycle lost ~50 B/burst), reliable cold reinit every cycle
// (init ~190 ms), and normal hit counts. A/B evidence: with the controller
// enabled across Wi-Fi OFF/STA the retention + timeout appear even with no
// scan; with it deinit'd (D-arm, mode 4) neither appears.
#define CT_BLE_BURST     1
#define CT_BLE_BURST_SEC 2

// ---- Step 3 observation accumulator (Core-0 feeder) ----
//
// Ownership model: ctState.acc is appended to by Core 0 (RX context) and
// structurally stamped by Core 1 (window close) under the established
// pause_sniffing + delay(10) fence (F10 discipline). Appends are short,
// bounded, and idempotent for duplicates, so occasional missed observations
// during a Core-1 fence are acceptable by design — CT accumulates set
// membership over repeated beacon/probe-response observations, so this is
// not an event-loss-sensitive queue.
//
// ---- Step 4 per-window touched masks ----
// Two file-local masks record WHICH accumulator slots were observed during
// the CURRENT window (new insertions AND duplicate observations both mark
// their bit — the mask is the window's observation set, not the newly-
// discovered set). Core 0 sets bits inside the gated feeder; Core 1
// snapshots + clears them under the F10 fence at window close. Storage
// cost: 8 + 4 = 12 B file-local static. acc itself is never cleared.
static uint64_t ct_touch_bssid_mask = 0; // bit i = acc.bssid[i] seen this window
static uint32_t ct_touch_ssid_mask = 0;  // bit i = acc.ssid[i] seen this window

// Cumulative per-SEGMENT confirmation masks: OR of every valid window's
// touch masks since the last commit (Core-1-maintained at the close, from
// the window snapshots — no new cross-core state). Identities carried in
// acc across a commit but never RE-observed in the new segment have no bit
// here and are excluded from persistence evidence. Cleared at commit (after
// the persistence pass consumed them) and on CT session reset.
static uint64_t ct_seg_bmask = 0;        // bit i = acc.bssid[i] observed this segment
static uint32_t ct_seg_smask = 0;        // bit i = acc.ssid[i] observed this segment

// Step 4.1 temporal-derivative scratch (file-local, Core-1-owned, reset on CT
// exit/re-entry like the touch masks — no CTState growth, no new primitives).
// prev_* = immediately preceding VALID window's values; *_have flags gate the
// first and second window so no fabricated derivative is reported.
static uint8_t ct_prev_b = 0, ct_prev_s = 0;      // previous window populations
static int8_t  ct_prev_d_b = 0, ct_prev_d_s = 0;  // previous first differences
static bool ct_have_prev = false, ct_have_prev_d = false;

// ---- Step 4.2: environment baseline + bounded envelope ----
// File-local Core-1 scratch. The baseline describes the CURRENT segment only
// (not the session); it is reset on CT exit/re-entry and at every segment
// commit (ct_reset_segment_stats). All fixed-point math is Q8.8 unless noted.
//   sum_b/sum_s/n_obs      — exact integer running mean over VALID windows
//   sum_b2/sum_s2          — running sums of squares (population variance)
//   ct_min/max_*           — bounded envelope over VALID windows (descriptive
//                            only; never a segmentation trigger)
//   ct_obs_count           — per-window qualifying-observation counter from the
//                            Core-0 feeder; DIAGNOSTIC descriptor only (it
//                            cannot distinguish "empty RF" from "nothing
//                            qualifying on air"). NOT a validity test.
// Horizon-bounded baselines (alpha = 1/32, one shared clock): population
// mean (Q8.8) and variance (Q8.16) as EWMAs, seeded with the EXACT first
// valid sample. Variance is excursion-gated (Huber-style; see the evidence
// section) so sigma describes regime noise, never the transitions.
static uint16_t ct_ewma_mu_b_q8 = 0, ct_ewma_mu_s_q8 = 0;
static uint32_t ct_ewma_var_b_q16 = 0, ct_ewma_var_s_q16 = 0;
static uint8_t ct_min_b = 0, ct_max_b = 0, ct_min_s = 0, ct_max_s = 0;
static uint16_t ct_obs_count = 0;
static bool ct_have_obs = false;

// Step-5 follow-up instrumentation: observation-quality counters.
//   ct_rej_count  — per-window count of REJECTED genuinely-new identity
//                   insertions (table full). Immune to saturation by
//                   construction: it measures the untracked world.
//   ct_chans_mask — per-window channels-visited mask, maintained by Core 1
//                   (Core-1 context) by watching current_ch_idx transitions
//                   every loop tick. A window with cov < configured-set did
//                   not cover a full sweep (hopper stalled / screen state) —
//                   a coverage
//                   gap, not an environment reading.
static uint16_t ct_rej_count = 0;
static uint16_t ct_chans_mask = 0;
static uint8_t ct_last_ch = 0xFF; // 0xFF = no channel recorded yet

// ---- Step 5: segmentation evidence (3 LIVE channels) ----
// LIVE quorum: POPULATION + CHURN + TURNOVER (2-of-3). The old RETENTION
// channel was retired from the quorum and its machinery (sums, EWMA,
// persistence, and the hist[]-identity-overlap diagnostic) has been deleted
// along with the historical identity arrays it consumed.
// All file-local Core-1 scratch; updated only for VALID windows (window that
// closes while pause_sniffing == false), inside the F10 fence.
//
// Churn channel: EWMA of ABSOLUTE deltas (m_B = EWMA|ΔB|). Evidence
// is EXCESS churn over the segment's own normal churn magnitude, so a
// sustained walking regime self-quietens once m adapts.
// Horizon baseline for churn: EWMA of |dB|, |dS| (Q8.8), seeded with the
// first delta (window 2), evidence from window 3 — same clock as mu/var.
static uint16_t ct_ewma_m_ab_b_q8 = 0, ct_ewma_m_ab_s_q8 = 0;
//
// Turnover channel (identity dynamics, adjacent-window) — LIVE channel:
//   turnover = popcount(cur & ~prev)   new SSIDs      (tracked stream)
//            + popcount(prev & ~cur)   vanished SSIDs (tracked stream)
//            + rejected inserts        untracked-stream arrivals
// ct_prev_smask = previous valid window's SSID mask — the bit->SSID mapping
// is stable for the lifetime of acc, so mask algebra IS identity algebra.
// No ABSTAIN case: a previous valid window suffices (empty->populated IS
// turnover). Adjacent-window semantics mean a post-commit re-learn of the
// SAME environment produces ~no turnover (the prev mask tracks it), so
// there is no artificial post-commit spike. The rejected term is
// FLUX-WEIGHTED (frames x unseen identities; rejected identities are not
// recorded, so each later frame re-attempts — rej <= 2*obs).
static uint32_t ct_prev_smask = 0;
static uint32_t ct_ewma_m_turn_q8 = 0; // EWMA of turnover (Q8.8, u32: turnover
                                       // can exceed 255 counts via rej)
//
// Common EWMA (Q8.8) + persistence per channel. A channel "is triggering"
// when persistence >= CT_N_MIN — the persistence state IS the trigger state
// (no separate latch). LIVE quorum = 2-of-3 over {population, churn,
// turnover}.
static uint16_t ct_ewma_pop = 0, ct_ewma_churn = 0, ct_ewma_turn = 0;
static uint8_t ct_persist_pop = 0, ct_persist_churn = 0, ct_persist_turn = 0;
//
// Provisional E/T classification of the OPEN segment (false=E_n, true=T_n).
// Description of volatility only: changes never reset statistics or evidence.
static bool ct_prov_is_t = false;
//
// ---- Per-window byte traffic (environment-history metric) ----
// Core 0 sums every received frame's sig_len into ct_window_bytes while
// RADIO_CT is active (same interpretation as the ApRecord traffic
// accounting). Core 1 snapshots + clears it under the window-close fence and
// folds it into horizon EWMAs: mean in KiB Q8.8 (bytes >> 2) and variance in
// KiB Q8.16 (u64 — raw-byte residuals overflow u32). Same alpha = 1/32,
// seeded exactly on the segment's first valid window, excursion-gated like
// the population variance so transitions are never laundered into the
// byte-dispersion statistic.
uint32_t ct_window_bytes = 0;                    // Core-0 written (see ct.h)
static uint32_t ct_ewma_byte_mean_q8kib = 0;     // KiB Q8.8
static uint64_t ct_ewma_byte_var_q16kib = 0;     // KiB^2 Q8.16
//
// ---- Probe presence (persistent-device evidence) ----
// Core 0 marks the probe-tracker slot that recorded each accepted probe
// request during the current window (see capture.cpp decision gate). Core 1
// snapshots + clears it at commit; identities are re-read from probeList
// under the fence and immediately copied into CT-owned state — the slot
// index never becomes a persistent reference.
uint64_t ct_probe_hit_mask = 0;                  // Core-0 written (see ct.h)

// Fixed-point constants (Q8.8 unless noted). Initial tunables from the
// audited design — measurable from [CT-STEP*] traces, not sacred.
static const uint16_t CT_C1_Q8 = 512;             // population threshold floor C1 = 2
static const uint8_t CT_C2S_NUM = 5, CT_C2S_DEN = 4; // threshold slope: 1.25*sigma
static const uint16_t CT_SIGMA_T_Q8 = 384;        // provisional-T sigma >= 1.5 counts
static const uint8_t CT_BASE_SHIFT = 5;           // baseline EWMA alpha = 1/32
static const uint16_t CT_VAR_FLOOR_Q8 = 256;      // variance gate floor: 1.0 count
static const uint16_t CT_K3 = 3;                  // churn normalization K3
static const uint16_t CT_K5 = 3;                  // turnover normalization K5 (trace-tunable)
static const uint16_t CT_TURN_N_MAX_Q8 = 8192;    // turnover evidence clamp (32.0 Q8.8)
static const uint8_t CT_N_MIN = 3;                // persistence length (windows)
// RC2 defensive gate: a second environment shorter than this many valid
// windows does not qualify as persistence evidence (the MAC stays pending,
// merge/refresh path). Quorum-committed envs are always >= 5 windows, so
// this only bites degenerate boundaries (e.g. SELECT CH 1-window envs).
static const uint8_t CT_PROMOTE_MIN_WIN = 2;

// Integer square roots (no floating-point state). The 64-bit variant serves
// the byte-variance EWMA (KiB^2 Q8.16); raw-byte residuals would overflow
// 32-bit squares.
static uint16_t ct_isqrt32(uint32_t v) {
  uint32_t res = 0, bit = 1UL << 30;
  while (bit > v) bit >>= 2;
  while (bit) {
    if (v >= res + bit) { v -= res + bit; res = (res >> 1) + bit; }
    else res >>= 1;
    bit >>= 2;
  }
  return (uint16_t)res;
}
static uint32_t ct_isqrt64(uint64_t v) {
  uint64_t res = 0, bit = 1ULL << 62;
  while (bit > v) bit >>= 2;
  while (bit) {
    if (v >= res + bit) { v -= res + bit; res = (res >> 1) + bit; }
    else res >>= 1;
    bit >>= 2;
  }
  return (uint32_t)res;
}

// Common evidence update: EWMA (alpha = 1/8, Q8.8) + consecutive-above-
// threshold persistence. Returns true exactly when this update moves the
// channel across the trigger boundary (persistence reaches CT_N_MIN from
// below) — used by the temporary [CT-TRIG] diagnostic only; the quorum
// still reads the persistence state itself.
static inline bool ct_evidence_update(uint16_t &ewma, uint8_t &persist,
                                      uint16_t n_q8) {
  ewma = (uint16_t)(((uint32_t)ewma * 7 + n_q8) >> 3);
  if (ewma > 256) { // ewma > 1.0
    if (persist < 255) persist++;
    return persist == CT_N_MIN; // crossing (also fires again after a drop+re-rise)
  }
  persist = 0;
  return false;
}

// Per-segment statistical/evidence reset. Called at CT exit/re-entry and at
// every segment commit (the accumulator/segment identity space is reset in
// both cases, so SSID bit indices and all baselines lose meaning).
static void ct_reset_segment_stats() {
  ct_ewma_mu_b_q8 = 0; ct_ewma_mu_s_q8 = 0;
  ct_ewma_var_b_q16 = 0; ct_ewma_var_s_q16 = 0;
  ct_ewma_byte_mean_q8kib = 0; ct_ewma_byte_var_q16kib = 0;
  ct_min_b = 0; ct_max_b = 0; ct_min_s = 0; ct_max_s = 0;
  ct_have_obs = false;
  ct_ewma_m_ab_b_q8 = 0; ct_ewma_m_ab_s_q8 = 0;
  ct_prev_smask = 0;
  ct_ewma_m_turn_q8 = 0;
  ct_ewma_pop = 0; ct_ewma_churn = 0; ct_ewma_turn = 0;
  ct_persist_pop = 0; ct_persist_churn = 0;
  ct_persist_turn = 0;
  ct_prov_is_t = false;
  // Derivatives must not bridge a segment boundary either.
  ct_prev_b = 0; ct_prev_s = 0;
  ct_prev_d_b = 0; ct_prev_d_s = 0;
  ct_have_prev = false; ct_have_prev_d = false;
}

void ct_observe_bssid(const uint8_t *bssid, const char *ssid) {
  if (pause_sniffing)
    return;

  // Diagnostic observation counter: one increment per qualifying observation.
  // Same stream, same gating, same function as the identity inserts below —
  // no second capture path. Cleared by Core 1 under the fence at window close.
  ct_obs_count++;

  CtEnvironment &a = ctState.acc;

  // --- BSSID insert: exact 6-byte identity, linear scan, no hashing ---
  int bssid_idx = -1; // matched slot, or the newly claimed slot
  for (uint8_t i = 0; i < a.n_bssid; i++) {
    if (memcmp(a.bssid[i], bssid, 6) == 0) {
      bssid_idx = i;
      break;
    }
  }
  if (bssid_idx < 0) {
    if (a.n_bssid < MAX_CT_BSSIDS) {
      memcpy(a.bssid[a.n_bssid], bssid, 6);
      bssid_idx = a.n_bssid;
      a.n_bssid++;
    } else {
      // Sticky: only a genuinely new identity that failed to insert sets it.
      a.flags |= CT_FLAG_BSSID_TRUNC;
      ct_rej_count++;
    }
  }
  if (bssid_idx >= 0)
    ct_touch_bssid_mask |= (uint64_t)1 << bssid_idx; // duplicates mark too

  // --- SSID insert: CT-local copy of the caller's bytes ---
  int ssid_idx = -1;
  for (uint8_t i = 0; i < a.n_ssid; i++) {
    if (strcmp(a.ssid[i], ssid) == 0) {
      ssid_idx = i;
      break;
    }
  }
  if (ssid_idx < 0) {
    if (a.n_ssid < MAX_CT_SSIDS) {
      strncpy(a.ssid[a.n_ssid], ssid, 32);
      a.ssid[a.n_ssid][32] = '\0';
      ssid_idx = a.n_ssid;
      a.n_ssid++;
    } else {
      a.flags |= CT_FLAG_SSID_TRUNC;
      ct_rej_count++;
    }
  }
  if (ssid_idx >= 0)
    ct_touch_ssid_mask |= (uint32_t)1 << ssid_idx; // duplicates mark too

  // Timestamps = observation stamps (NOT window-close stamps). first_seen==0
  // is the empty-accumulator sentinel: acc is memset on mode entry and at
  // every commit, and millis() is nonzero long before RADIO_CT is reachable.
  uint32_t now = millis();
  if (a.first_seen == 0)
    a.first_seen = now;
  a.last_seen = now;
}

// ---- Window close + segmentation (Core 1, every loop tick) ----
//
// Fixed-duration Wi-Fi observation windows while RADIO_CT is active. On
// expiry, under the F10 fence: validity decision, three-channel evidence,
// 2-of-3 quorum, and (on quorum) segment commit. acc is the persistent
// uncommitted record of the open (provisional) segment.
//
// Window-timing state is file-local Core-1 scratch (the last_queue_warn_ms
// pattern): no new persistent SRAM, no CTState layout change.
static uint32_t ct_window_start_ms = 0;
static uint32_t ct_last_hop_ms = 0;   // millis() of the last counted transition
static bool ct_window_running = false;

// ---- F1 timing foundation (CT-local, Core-1 owned) ----
// The CT statistical window is an integer number of complete sweeps with a
// ~5000 ms target; the dwell is derived per selection (>= 300 ms floor) so
// that every selected channel receives exactly k identical dwell slots per
// window. The window CLOSES on complete-sweep boundaries (hop transitions
// counted by the per-tick channel watcher below), not on a free-running
// wall clock; a wall-clock failsafe covers hopper stalls (CT hopping stops
// off the chart screen, and CT is always capture-paused there, so a
// failsafe close is discarded by the existing paused-window validity rule).
// With a single selected channel the hop index never changes, so that case
// falls back to the plain wall clock (every window is trivially complete).
static const uint32_t CT_TIMING_TARGET_MS = 5000;
static const uint16_t CT_TIMING_DWELL_FLOOR_MS = 300;
static const uint32_t CT_WINDOW_FAILSAFE_MS = 2000;
uint16_t ct_dwell_ms = CT_TIMING_DWELL_FLOOR_MS;  // derived dwell (hopper reads)
static uint16_t ct_timing_sweeps = 1;    // k: complete sweeps per window
static uint32_t ct_window_ms = CT_TIMING_TARGET_MS; // k * N * dwell
static uint16_t ct_window_hops = 0;      // k * N; 0 = wall-clock close (N==1)
static uint16_t ct_hop_transitions = 0;  // hops since the window opened

// Boundary-deferred SELECT CH: stashed by the UI, applied at the next
// complete-window close (an environment boundary under the close fence).
static uint8_t ct_reselect_chans[NUM_CHANNELS];
static uint8_t ct_reselect_count = 0;
static bool ct_reselect_pending = false;

// Typed CT waterfall render slots: set at every window close (CT_RTYPE_WIFI,
// valid or invalid, so the visible timeline stays uniformly time-based) and
// after each BLE burst (CT_RTYPE_BLE). Consumed by the main loop via
// ct_take_render_slot(); bounded at CT_RENDERQ_MAX with silent drop on a
// third push (same bounded/fail-safe philosophy as the rest of CT state).
// The old boolean could not queue two phases: the Core-1 loop is blocked
// inside the BLE burst, so the second set was idempotent and the BLE phase
// had no chart slot of its own.
static uint8_t ct_renderq[CT_RENDERQ_MAX];
static uint8_t ct_renderq_n = 0;
static uint8_t ct_last_slot = CT_RTYPE_NONE;

// CT BLE burst accounting: incremented per advertisement callback while the
// burst is live (radio.cpp, NimBLE host context). ct_ble_last_hits holds the
// completed burst's total for the chart's BLE-lane column.
volatile bool     ct_ble_burst_active = false;
volatile uint32_t ct_ble_burst_hits = 0;
static uint32_t   ct_ble_last_hits = 0;
static uint32_t   ct_render_wbytes = 0;  // completed-window bytes (chart reads)

// Pure F1 integer derivation (single source of truth for CT and the non-CT
// Wi-Fi-family hopper): k = max(1, floor(T/(N*floor_dwell)));
// dwell = round(T/(k*N)) >= floor by construction.
// Design (2026-10-06, restored): the statistical window stays ~5 s; sweeps
// pack k revisits per window so every channel receives the SAME number of
// visits per window, with the visit count maximized s.t. dwell >= 300 ms.
// The visible waterfall is paced separately (~5 s per column), so sweep
// length no longer sets the visible time scale.
static void ct_derive_timing(uint16_t n, uint16_t *k_out, uint16_t *dwell_out) {
  uint16_t k = (uint16_t)(CT_TIMING_TARGET_MS / ((uint32_t)n * CT_TIMING_DWELL_FLOOR_MS));
  if (k < 1) k = 1;
  // Round-to-nearest dwell; k*n*300 <= target by construction of k, so the
  // rounded dwell is >= the 300 ms floor. Window deviation from the target
  // is < 0.5 ms per dwell slot (<= 16 slots => < 0.2%).
  uint32_t d = (CT_TIMING_TARGET_MS + ((uint32_t)k * n) / 2) / ((uint32_t)k * n);
  if (d < CT_TIMING_DWELL_FLOOR_MS) d = CT_TIMING_DWELL_FLOOR_MS; // defensive
  *k_out = k;
  *dwell_out = (uint16_t)d;
}

void ct_timing_apply() {
  uint16_t n = (hop_count > 0) ? hop_count : (uint16_t)NUM_CHANNELS;
  uint16_t k, d;
  ct_derive_timing(n, &k, &d);
  ct_dwell_ms = d;
  ct_timing_sweeps = k;
  ct_window_ms = (uint32_t)k * n * d;
  ct_window_hops = (n >= 2) ? (uint16_t)(k * n) : 0;
#if CT_DIAG_TIMING
  Serial.printf("[CT-TIMING] N=%u k=%u dwell=%u window=%u hops=%u\n",
                (unsigned)n, (unsigned)ct_timing_sweeps,
                (unsigned)ct_dwell_ms, (unsigned)ct_window_ms,
                (unsigned)ct_window_hops);
#endif
}

void ct_request_reselect(const uint8_t *chans, uint8_t cnt) {
  if (chans == nullptr || cnt == 0 || cnt > NUM_CHANNELS) return;
  memcpy(ct_reselect_chans, chans, cnt);
  ct_reselect_count = cnt;
  ct_reselect_pending = true;
}

// F1-derived dwell for a set of n channels: the system-wide hopper rule for
// every Wi-Fi-family mode (CT, WIFI, NETWORKS, CHANNELS, PCAP) so one sweep
// is ~5 s regardless of N. Public so diagnostics report the same value the
// hopper will use.
uint16_t ct_derived_dwell(uint16_t n) {
  uint16_t k, d;
  ct_derive_timing(n, &k, &d);
  return d;
}

uint16_t ct_hop_interval() {
  // System-wide F1 rule: every Wi-Fi-family hopping mode derives its dwell
  // (sweep ~ 5 s). BLE keeps the fixed HOP_INTERVAL; locked modes never hop.
  // CT additionally persists its derivation in ct_dwell_ms (statistical
  // window state) and must match the shared helper — it does by construction.
  if (currentRadioMode == RADIO_CT) return ct_dwell_ms;
  if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP ||
      currentRadioMode == RADIO_CHANNELS || currentRadioMode == RADIO_PCAP) {
    uint16_t n = (hop_count > 0) ? hop_count : (uint16_t)NUM_CHANNELS;
    return ct_derived_dwell(n);
  }
  return (uint16_t)HOP_INTERVAL;
}

static void ct_renderq_push(uint8_t type) {
  if (ct_renderq_n < CT_RENDERQ_MAX) ct_renderq[ct_renderq_n++] = type;
}

uint8_t ct_take_render_slot() {
  // Return-and-clear of the oldest queued render slot. CT runs on the single
  // Core-1 loop context (producers inside processCtData(), consumer in
  // loop()), so FIFO access is atomic by construction.
  if (ct_renderq_n == 0) return CT_RTYPE_NONE;
  uint8_t t = ct_renderq[0];
  ct_renderq[0] = ct_renderq[1];
  ct_renderq_n--;
  ct_last_slot = t;
  return t;
}

uint8_t ct_last_render_slot() { return ct_last_slot; }

uint32_t ct_last_burst_hits() { return ct_ble_last_hits; }

uint32_t ct_window_render_bytes() { return ct_render_wbytes; }

#if CT_BLE_BURST
// ---- CT BLE burst (display-only side channel) ----
// Runs strictly AFTER a Wi-Fi window has closed and all of its accounting /
// validity / segmentation work is done, while the capture fence is still
// held (pause_sniffing == true inside the close): nothing can reach the CT
// accumulators for the whole BLE -> Wi-Fi-off -> Wi-Fi-on transition. The
// radio timeline is time-division, not coexistence: promiscuous capture is
// stopped first, one blocking bounded passive scan runs on the existing
// NimBLE configuration (BLE freshly cold-initialized each cycle and fully
// deinit'd after it — see the lifecycle note at the CT_BLE_BURST gate),
// then Wi-Fi STA/promiscuous is restored. This deliberately bypasses
// switchRadioMode() (which would union-wipe CT state); CT keeps mode
// ownership the entire time.
//
// Timing safety: the burst blocks the single Core-1 loop, so
// processCtData() is never re-entered mid-burst, the hopper cannot fire,
// and no failsafe is armed. The close tail re-anchors ct_window_start_ms /
// ct_last_hop_ms with post-burst millis() AFTER this returns, so the
// existing failsafe (measured from the last hop transition) never sees the
// burst. No timing machinery is touched.
static bool ct_ble_burst(uint32_t *hits_out) {
  *hits_out = 0;
  // Display-only: skip off-screen. Off the chart screen the data has no
  // consumer and every cycle would only churn the radio and block menus.
  if (currentState != SCREEN_CHART) return false;

  uint32_t hits = 0; // total advertisement callbacks during this burst

  // Teardown/scan order (hardware-validated): stop promiscuous capture
  // FIRST (frees the antenna lock and gives the BLE scan exclusive radio
  // access, matching the ordinary RADIO_BLE entry ordering,
  // radio.cpp:421-422), then run the whole BLE lifecycle BEFORE
  // WiFi.mode(WIFI_OFF) so the BT controller is deinit'd — never merely
  // idle-enabled — for the entire Wi-Fi OFF -> STA transition below.
  esp_wifi_set_promiscuous(false);
  ct_ble_burst_hits = 0;
  ct_ble_burst_active = true;
  ble_init_only(); // fresh BLEDevice::init each cycle (ble_initialized is
                   // false after the previous burst's ble_shutdown())
  hits = ble_radio_burst(CT_BLE_BURST_SEC); // blocking; SECONDS
  ble_shutdown(); // supported composite NimBLEDevice::deinit(false) + lockstep
  WiFi.mode(WIFI_OFF);
  ct_ble_burst_active = false;

  // Wi-Fi restore, in switchRadioMode()'s STA/promiscuous order, plus two
  // things switchRadioMode() gets away with skipping only because it relies
  // on an immediate hop: an explicit re-tune to the CURRENT hop slot (the
  // next CT dwell must be on the parked channel, and WiFi.mode() resets the
  // radio) and a sniffer_callback reattach (WiFi.mode() can clobber it).
  // Hopper state (hop_channels / hop_pos / hop_count) is untouched: parking
  // on the channel the hopper currently represents preserves sweep phase
  // exactly. That channel is hop_channels[hop_pos] ONLY for a custom SELECT
  // CH set (hop_count > 0); in the default full CHANNELS[] sweep
  // hop_channels[] is the 0 = unused-slot sentinel (radio.cpp:38) and the
  // parked channel is CHANNELS[current_ch_idx] (the hopper's own
  // selection, radio.cpp:495-498). Passing the 0 sentinel to
  // esp_wifi_set_channel() fails with ESP_ERR_INVALID_ARG and leaves the
  // driver on the WIFI_STA default (channel 1) for the residual dwell.
  uint8_t park_ch = (hop_count > 0)
                        ? hop_channels[hop_pos]
                        : CHANNELS[current_ch_idx];
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  // Guard park_ch: 0 is never a legal channel, so skip the call rather than
  // force another INVALID_ARG.
  if (park_ch) (void)esp_wifi_set_channel(park_ch, WIFI_SECOND_CHAN_NONE);
  (void)esp_wifi_set_promiscuous(true);
  (void)esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);

  *hits_out = hits;
  return true;
}
#endif // CT_BLE_BURST

// Commit the open segment: copy the accumulator into the next history slot
// with its final provisional E/T class, advance the global segment index,
// and reset the accumulator plus ALL per-segment statistical/evidence state.
// Must run inside the F10 fence.
// ===========================================================================
// ---- Persistent-device machinery (Core 1, commit time, fence held) ----
// All inputs are read ONCE under the pause fence and immediately copied into
// CT-owned state. No persistent record ever references a probeList slot,
// ssidPool node, or bssidCache entry. Evidence sources at commit:
//   AP:   the committed acc BSSID set (exact identities, dedup'd live)
//   probe: ct_probe_hit_mask bits -> probeList[slot] re-read under the fence
// A MAC observed in a second distinct committed environment promotes
// immediately from the pending pool into the persistent table.
// ===========================================================================

// Minimal sanity: skip identities that cannot be a device (multicast I/G bit,
// all-zero, broadcast). The probe path's own randomization gate upstream
// already filters most junk; this is the persistence-layer guard.
static bool ct_persist_mac_sane(const uint8_t *mac) {
  static const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  if ((mac[0] & 0x01) != 0) return false;          // multicast/group bit
  for (uint8_t i = 0; i < 6; i++)
    if (mac[i] != 0) return (memcmp(mac, bcast, 6) != 0);
  return false;                                    // all-zero
}

static CtPersistDevice *ct_persist_find(const uint8_t *mac) {
  for (uint8_t i = 0; i < ctState.persist.count; i++)
    if (memcmp(ctState.persist.dev[i].mac, mac, 6) == 0)
      return &ctState.persist.dev[i];
  return nullptr;
}

static int ct_pend_find(const uint8_t *mac) {
  for (uint8_t i = 0; i < ctState.pend.count; i++)
    if (memcmp(ctState.pend.e[i].mac, mac, 6) == 0)
      return (int)i;
  return -1;
}

// env_seen[] insert-once semantics. env_count counts ALL distinct envs
// (saturating u8); exact dedup is only possible against the stored first 8 —
// once the list is full, revisits of unstored env ids increment the count
// again (documented bounded limitation; ENV_OVERFLOW marks it).
static void ct_persist_env_insert(CtPersistDevice &d, uint16_t env) {
  uint8_t stored = (d.env_count < 8) ? d.env_count : 8;
  for (uint8_t i = 0; i < stored; i++)
    if (d.env_seen[i] == env) return;              // already counted
  if (stored < 8)
    d.env_seen[stored] = env;
  else
    d.flags |= CT_PFLAG_ENV_OVF;
  if (d.env_count < 255) d.env_count++;
}

// ssid_hist policy: slot 0 = first SSID ever (frozen once written); slots
// 1..3 = latest distinct SSIDs in recency order (dedup against all 4 slots,
// oldest rolled out by memmove). Empty slots ('\0') render as none.
static void ct_persist_ssid_note(CtPersistDevice &d, const char *ssid) {
  if (ssid == nullptr || ssid[0] == '\0') return;
  for (uint8_t i = 0; i < CT_PERSIST_SSIDS; i++)
    if (d.ssid_hist[i][0] != '\0' && strcmp(d.ssid_hist[i], ssid) == 0)
      return;                                      // duplicate
  if (d.ssid_hist[0][0] == '\0') {
    strncpy(d.ssid_hist[0], ssid, 32);
    d.ssid_hist[0][32] = '\0';
    return;                                        // first ever — frozen slot
  }
  memmove(d.ssid_hist[1], d.ssid_hist[2], 33);
  memmove(d.ssid_hist[2], d.ssid_hist[3], 33);
  strncpy(d.ssid_hist[3], ssid, 32);
  d.ssid_hist[3][32] = '\0';
}

// Walk a probe tracker SSID chain (arrival-ordered; the tail is the most
// recent SSID) and feed it to the record's SSID policy. Fence-held read.
static void ct_persist_ssid_from_chain(CtPersistDevice &d, int probe_slot) {
  if (probe_slot < 0) return;
  int node = probeList[probe_slot].first_ssid_idx;
  int guard = 0;
  while (node != -1 && guard++ < TOTAL_SSID_POOL) {
    if (ssidPool[node].text[0] != '\0')
      ct_persist_ssid_note(d, ssidPool[node].text);
    node = ssidPool[node].next_node_idx;
  }
}

// Opportunistic AP enrichment (optional by design, never evidence): the
// bssidCache copy becomes the record's first-known SSID only while the
// record has none at all. Fence-held read of the 16-entry cache.
static void ct_persist_ap_enrich(CtPersistDevice &d, const uint8_t *bssid) {
  if (d.ssid_hist[0][0] != '\0') return;
  for (int i = 0; i < MAX_BSSID_CACHE; i++) {
    if (bssidCache[i].last_seen == 0) continue;
    if (memcmp(bssidCache[i].bssid, bssid, 6) == 0) {
      if (bssidCache[i].ssid[0] != '\0')
        ct_persist_ssid_note(d, bssidCache[i].ssid);
      return;
    }
  }
}

// Country copy (AP evidence only): scan liveApData for the BSSID and copy
// its 802.11d country IE bytes. Cache eviction leaves the field empty.
static void ct_persist_copy_country(CtPersistDevice &d, const uint8_t *bssid) {
  if (d.country[0] != '\0') return;                // already known
  for (int i = 0; i < MAX_AP_RECORDS; i++) {
    if (memcmp((const void *)liveApData[i].bssid, bssid, 6) != 0) continue;
    if (liveApData[i].country[0] != '\0') {
      d.country[0] = liveApData[i].country[0];
      d.country[1] = liveApData[i].country[1];
      d.country[2] = liveApData[i].country[2];
    }
    return;
  }
}

// Vendor copy (probe evidence only): probeList vendors are resolved by the
// existing mechanism (Tag 221 at frame time, or the Core-1 SD worker).
// Placeholders ("Resolving...") are NOT copied — an unresolved device keeps
// an empty vendor and its OUI for later resolution. AP rows have no vendor
// source in CT-reachable state; they carry OUI only.
static void ct_persist_copy_vendor(CtPersistDevice &d, int probe_slot) {
  if (probe_slot < 0 || d.vendor[0] != '\0') return;
  const char *v = probeList[probe_slot].vendor;
  if (v[0] == '\0' || strcmp(v, "Resolving...") == 0) return;
  strncpy(d.vendor, v, sizeof(d.vendor) - 1);
  d.vendor[sizeof(d.vendor) - 1] = '\0';
}

static void ct_pend_remove(int idx) {
  ctState.pend.e[idx] = ctState.pend.e[ctState.pend.count - 1];
  ctState.pend.count--;
}

// One evidence event for one exact MAC in committed environment `env`.
static void ct_persist_observe(const uint8_t *mac, bool is_ap, int probe_slot,
                               uint32_t src_first, uint32_t src_last,
                               uint16_t env, uint16_t win) {
  if (!ct_persist_mac_sane(mac)) return;
  uint8_t fl = is_ap ? CT_PFLAG_AP : CT_PFLAG_PROBE;

  // --- already persistent: refresh owned state ---
  CtPersistDevice *row = ct_persist_find(mac);
  if (row != nullptr) {
    ct_persist_env_insert(*row, env);
    if (src_first < row->first_seen) row->first_seen = src_first; // earliest known
    if (src_last > row->last_seen) row->last_seen = src_last;
    row->flags |= fl;
    if (!is_ap) ct_persist_ssid_from_chain(*row, probe_slot);
    else        ct_persist_ap_enrich(*row, mac);
    ct_persist_copy_vendor(*row, probe_slot);
    if (is_ap) ct_persist_copy_country(*row, mac);
    return;
  }

  // --- pending: promote on a second distinct environment ---
  int pi = ct_pend_find(mac);
  if (pi >= 0) {
    CtPendMac &p = ctState.pend.e[pi];
    if (p.first_env_id == env || win < CT_PROMOTE_MIN_WIN) {
      // Same-env merge, OR second environment shorter than the promotion
      // gate (RC2): a 0/1-window environment is not persistence evidence.
      // Either way the MAC stays pending for a later, longer environment.
      p.flags |= fl;
      if (src_first < p.first_seen) p.first_seen = src_first;
      return;
    }
    // PROMOTE: second distinct committed environment.
    if (ctState.persist.count >= CT_PERSIST_DEVICES) {
      // Table full: evict the least-recently-seen row (LRU by last_seen;
      // ties -> lowest index). Deterministic, bounded, false-negative-only.
      uint8_t vic = 0;
      for (uint8_t i = 1; i < ctState.persist.count; i++)
        if (ctState.persist.dev[i].last_seen < ctState.persist.dev[vic].last_seen)
          vic = i;
#if CT_DIAG_PERSIST
      Serial.printf("[CT-PERSIST] win=%u evict-row idx=%u\n", (unsigned)win,
                    (unsigned)vic);
#endif
      ctState.persist.dev[vic] = ctState.persist.dev[ctState.persist.count - 1];
      ctState.persist.count--;
    }
    CtPersistDevice &d = ctState.persist.dev[ctState.persist.count++];
    memset(&d, 0, sizeof(CtPersistDevice));
    memcpy(d.mac, mac, 6);
    memcpy(d.oui, mac, 3);
    d.first_seen = (src_first < p.first_seen) ? src_first : p.first_seen;
    d.last_seen = src_last;
    d.env_seen[0] = p.first_env_id;
    d.env_seen[1] = env;
    d.env_count = 2;
    d.flags = p.flags | fl;
    if (!is_ap) {
      ct_persist_ssid_from_chain(d, probe_slot);
      ct_persist_copy_vendor(d, probe_slot);
    } else {
      ct_persist_ap_enrich(d, mac);
      ct_persist_copy_country(d, mac);
    }
    uint16_t promo_first_env = p.first_env_id;
    ct_pend_remove(pi);
#if CT_DIAG_PERSIST
    Serial.printf("[CT-PERSIST] win=%u promo mac=%02X%02X%02X%02X%02X%02X envs=E%u,E%u\n",
                  (unsigned)win, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                  (unsigned)promo_first_env, (unsigned)env);
#endif
    return;
  }

  // --- first evidence ever: enter the pending pool ---
  if (ctState.pend.count >= CT_PEND_SLOTS) {
    // Pool full: evict the entry from the OLDEST environment (smallest
    // first_env_id; ties -> lowest index). Deterministic; loses only a
    // seen-once record (false-negative-only).
    uint8_t vic = 0;
    for (uint8_t i = 1; i < ctState.pend.count; i++)
      if (ctState.pend.e[i].first_env_id < ctState.pend.e[vic].first_env_id)
        vic = i;
    ctState.pend.e[vic] = ctState.pend.e[ctState.pend.count - 1];
    ctState.pend.count--;
  }
  CtPendMac &p = ctState.pend.e[ctState.pend.count++];
  p.first_seen = src_first;
  p.first_env_id = env;
  memcpy(p.mac, mac, 6);
  p.flags = fl;
}

// Master persistence pass at commit of environment `env`. Runs under the
// pause fence: Core-0 writers (probe tracker, acc feeder) are quiesced, so
// probeList reads are stable for the duration.
static void ct_persist_commit(uint16_t env, uint16_t win) {
  // AP evidence: the committed environment's exact BSSID set, filtered to
  // slots CONFIRMED by observation in this segment (cumulative mask). With
  // identity carry across commits, acc may hold slots from the previous
  // environment that were never re-observed — those are NOT evidence for
  // this environment. Per-BSSID stamps do not exist in acc, so the
  // environment-level stamps are the closest available observation times
  // (documented semantics).
  for (uint8_t i = 0; i < ctState.acc.n_bssid; i++) {
    if (((ct_seg_bmask >> i) & 1ULL) == 0) continue; // carried, never re-observed
    ct_persist_observe(ctState.acc.bssid[i], true, -1,
                       ctState.acc.first_seen, ctState.acc.last_seen, env, win);
  }
  // Probe evidence: snapshot + clear the hit mask, then resolve each bit's
  // identity from the tracker under the fence.
  uint64_t hits = ct_probe_hit_mask;
  ct_probe_hit_mask = 0;
  while (hits) {
    int s = (int)__builtin_ctzll(hits);
    hits &= hits - 1;
    if (s >= MAX_PROBE_SLOTS) continue;
    ct_persist_observe(probeList[s].mac, false, s,
                       probeList[s].first_seen, probeList[s].last_seen,
                       env, win);
  }
}

static void ct_commit_segment() {
  uint8_t next = (ctState.current_idx + 1) % MAX_CT_ENVIRONMENTS;
  CtEnvRecord &dst = ctState.hist[next];
  // ---- Immutable environment metrics snapshot (the committing window is
  // included: its absorption happened before the quorum check) ----
  dst.first_seen = ctState.acc.first_seen;
  dst.last_seen = ctState.acc.last_seen;           // duration = last - first
  dst.byte_mean_q8kib = ct_ewma_byte_mean_q8kib;
  dst.byte_std_q8kib = ct_isqrt64(ct_ewma_byte_var_q16kib);
  dst.mu_b_q8 = ct_ewma_mu_b_q8;
  dst.sig_b_q8 = ct_isqrt32(ct_ewma_var_b_q16);
  dst.mu_s_q8 = ct_ewma_mu_s_q8;
  dst.sig_s_q8 = ct_isqrt32(ct_ewma_var_s_q16);
  dst.env_id = ctState.env_seq;
  dst.window_count = ctState.acc.window_count;
  dst.flags = (ctState.acc.flags & (CT_FLAG_BSSID_TRUNC | CT_FLAG_SSID_TRUNC)) |
              (ct_prov_is_t ? CT_FLAG_CLASS_T : 0);
  dst.reserved = 0;
  ctState.current_idx = next;
  // ---- Persistence pass (fence still held; consumes the cumulative masks) ----
  ct_persist_commit(dst.env_id, dst.window_count);
  ctState.env_seq++;
  // ---- Identity carry (RC1) + selective segment-scratch reset ----
  // The identity arrays (bssid[]/ssid[]/n_bssid/n_ssid) are deliberately
  // PRESERVED across the commit: they are the previous environment's
  // successfully stored identities, and carrying them (a) eliminates the
  // post-commit refill transient that masqueraded as turnover in stationary
  // dense environments, and (b) re-scopes rejected-insert counting to
  // identities genuinely absent from the previous environment. Only the
  // segment-local scratch fields are reset, explicitly field-by-field.
  // acc.env_id is never read (commit stamps dst from env_seq); acc.reserved
  // is unused. Persistence evidence has already been filtered to slots
  // confirmed by the cumulative masks, which are consumed above and cleared
  // here.
  ct_seg_bmask = 0;
  ct_seg_smask = 0;
  ctState.acc.first_seen = 0;   // empty-accumulator sentinel (chart + feeder)
  ctState.acc.last_seen = 0;
  ctState.acc.window_count = 0;
  ctState.acc.flags = 0;        // truncation bits are per-segment confidence
  ctState.acc.reserved = 0;
  ct_reset_segment_stats();
}

// Defined below, before processCtData(): measurement-domain reset used by
// ct_flush_reselect() (forward-declared here because it sits after the
// flush helper's definition point).
static void ct_segment_fresh_reset();

// Apply a pending boundary-deferred SELECT CH set (measurement-domain
// boundary). The single authoritative reselect-application sequence, shared
// by the window-close tail and the CT resume path:
//   radio_apply_channel_set(new set)  -> hop list/pos/hardware channel
//   ct_timing_apply()                 -> re-derive k / dwell / window
//   ct_segment_fresh_reset()          -> a set change is a MEASUREMENT-DOMAIN
//                                        change, not an RF-environment
//                                        transition: the open segment is
//                                        silently discarded (no env record,
//                                        no env_seq increment, no persistence
//                                        pass, no RC1 carry) and a fresh
//                                        segmentation baseline is established
//                                        — exactly as fresh CT entry would
//                                        leave it
//   re-anchor the channel watcher     -> seed the new set's coverage bit
//                                        without counting a spurious hop
// Safe to call while the capture fence is held (pause_sniffing true): both
// call sites guarantee that — the close tail by construction, the resume
// path before scanAction() reopens the gate. No-op when nothing is pending.
// Returns true when a pending set was applied.
bool ct_flush_reselect() {
  if (!ct_reselect_pending) return false;
  radio_apply_channel_set(ct_reselect_chans, ct_reselect_count);
  ct_timing_apply(); // re-derive k / dwell / window for the new set
  ct_segment_fresh_reset();
  // Re-anchor the watcher: the radio now sits on the new set's first
  // channel; seed its coverage bit without counting a spurious hop.
  ct_last_ch = current_ch_idx;
  ct_chans_mask |= (uint16_t)1 << current_ch_idx;
  ct_reselect_pending = false;
  return true;
}

// A channel-set change is a new RF MEASUREMENT DOMAIN, not an RF-environment
// transition. The RF-segmentation subset of a fresh CT entry: discard the
// open segment entirely — including the RC1 carried identity set (it belongs
// to the old sampling domain and must not occupy the new domain's bounded
// identity slots) — and re-establish a clean baseline, WITHOUT manufacturing
// an environment record, touching env_seq, or generating persistence
// evidence (normal RC1 carry/evidence filtering applies only to ordinary
// segment commits). Deliberately NOT part of this reset (continuity across
// a domain change): persistence table, pending pool, env_seq, committed
// environment history, probe tracker/ssidPool, BLE/render state, channel/
// hopper/timing state. The full CT entry/session reset in processCtData()'s
// non-CT branch additionally clears lifecycle state and is preserved as-is.
static void ct_segment_fresh_reset() {
  memset(&ctState.acc, 0, sizeof(CtEnvironment));

  ct_seg_bmask = 0;
  ct_seg_smask = 0;
  ct_touch_bssid_mask = 0;
  ct_touch_ssid_mask = 0;
  ct_obs_count = 0;
  ct_rej_count = 0;
  ct_window_bytes = 0;

  ct_reset_segment_stats();
}

void processCtData() {
  if (currentRadioMode != RADIO_CT) {
    // Re-arm for the next CT entry. Safe to clear the touched masks here
    // WITHOUT the fence: the feeder call site is RADIO_CT-gated, so no
    // Core-0 writer can be active in a non-CT mode (switchRadioMode's own
    // fence already drained any in-flight write before the mode flipped).
    // Without this, stale bits from a pre-exit window would leak into the
    // first window after re-entry.
    ct_touch_bssid_mask = 0;
    ct_touch_ssid_mask = 0;
    ct_seg_bmask = 0;         // no confirmed identities survive a session
    ct_seg_smask = 0;
    ct_obs_count = 0;
    ct_rej_count = 0;
    ct_chans_mask = 0;
    ct_last_ch = 0xFF;
    ct_window_bytes = 0;      // Core-0 scratch: stale pre-exit bytes would
    ct_probe_hit_mask = 0;    // leak into the first window after re-entry
    ct_reset_segment_stats();
    ct_window_running = false;
    ct_hop_transitions = 0;   // no stale hop count may pre-load the next session
    ct_renderq_n = 0;         // queued render slots die with the session
    ct_ble_last_hits = 0;     // a stale burst total must not bleed into the next
    ct_render_wbytes = 0;     // same for the completed-window byte snapshot
    ct_reselect_pending = false; // a queued set change dies with the session
    return;
  }

  // Per-tick channel-coverage tracking (Core-1 context): record every channel
  // the radio lands on during the open window. A closed window whose mask
  // covers fewer than the configured channel set did not observe a full
  // sweep. The transition count is also the F1 hop-clock: a window closes
  // after exactly k*N complete dwell slots (one complete sweep, k times).
  if (current_ch_idx != ct_last_ch) {
    ct_last_ch = current_ch_idx;
    ct_chans_mask |= (uint16_t)1 << current_ch_idx;
    ct_hop_transitions++;
    ct_last_hop_ms = millis();
  }

  if (!ct_window_running) {
    ct_window_start_ms = millis();
    ct_last_hop_ms = millis();
    ct_window_running = true;
    ct_hop_transitions = 0;
    return;
  }

  // F1 window close: complete-sweep boundary (k*N hop transitions), not a
  // free-running wall clock. With one selected channel the hop index never
  // changes (ct_window_hops == 0), so that case closes on the derived wall
  // clock -- every window there is trivially complete.
  uint32_t win_elapsed = millis() - ct_window_start_ms;
  bool win_boundary = (ct_window_hops == 0)
      ? (win_elapsed >= ct_window_ms)
      : (ct_hop_transitions >= ct_window_hops);
  // Failsafe: CT hopping stalls off the chart screen (menu / list screens)
  // and CT is always capture-paused there, so a late close is discarded by
  // the existing paused-window validity rule -- the same discard semantics
  // the old wall-clock close had for menu-visit windows.
  // The stall is measured from the LAST OBSERVED CHANNEL TRANSITION, not
  // from window age: a long blocking operation mid-window (e.g. an SD mac
  // vendor lookup) pauses transitions without ending the session, and an
  // age-based failsafe closed the window mid-sweep, permanently shifting
  // the sweep phase (waterfall columns drifting onto mid-set channels).
  // Normal transition gaps are ~dwell (<= 556 ms), so only a genuine
  // multi-second stall with no fires trips this.
  bool win_failsafe =
      (millis() - ct_last_hop_ms >= ct_window_ms + CT_WINDOW_FAILSAFE_MS);
  if (!win_boundary && !win_failsafe)
    return;

  // Validity is decided BEFORE the fence is raised: a window that closes
  // while the receiver is paused (menu open etc.) is unobservable and
  // contributes nothing. An UNPAUSED window — including one with zero
  // qualifying observations — is a valid RF observation ([0,0] is real).
  bool was_paused = pause_sniffing;
  bool valid = !was_paused;

  // Window expired — structural work under the established fence.
  pause_sniffing = true;
  delay(10);

  // Consume the window's touched masks (snapshot + clear for the next window).
  uint64_t bmask = ct_touch_bssid_mask;
  uint32_t smask = ct_touch_ssid_mask;
  ct_touch_bssid_mask = 0;
  ct_touch_ssid_mask = 0;
  uint16_t obs = ct_obs_count;
  ct_obs_count = 0;
  uint16_t rej = ct_rej_count;
  ct_rej_count = 0;
  uint16_t chans = ct_chans_mask;
  ct_chans_mask = 0;
  uint8_t cov = (uint8_t)__builtin_popcount(chans);
  // Coverage denominator: the configured observation set, not the physical
  // band (F1 guarantees complete sweeps of that set within every window).
  uint8_t cov_max = (hop_count > 0) ? hop_count : (uint8_t)NUM_CHANNELS;
  // Byte-traffic snapshot: unconditional (mirrors the mask snapshots). The
  // RX callback is gated on pause_sniffing, so a paused window contributes
  // no bytes. A window that closes INVALID discards its snapshot: the EWMA
  // fold below runs only for valid windows, so the few bytes observed
  // during the unpaused part of an invalid window vanish — the same
  // discard-invalid convention as every other CT statistic (obs, rej,
  // channels). Valid-window accounting is unaffected.
  uint32_t wbytes = ct_window_bytes;
  ct_window_bytes = 0;
  // Completed-window byte total for the CT Wi-Fi waterfall lane. The lane
  // renders ONE column per statistical window (slot-paced), consumed in the
  // same loop iteration as this roll — so a per-tick delta of the now-zeroed
  // accumulator cannot see the window mass. The chart reads this snapshot on
  // the CT_RTYPE_WIFI slot instead. Zero for invalid windows: unobservable
  // time contributes no bar (blank column, the existing zero convention).
  ct_render_wbytes = valid ? wbytes : 0;

  if (valid) {
    ctState.acc.window_count++;
    uint16_t win = ctState.acc.window_count; // snapshot (commit resets acc)

    // Cumulative segment confirmation: this window's observed identities
    // (valid windows only — invalid windows are unobservable time). These
    // bits, not bare acc membership, are what persistence evidence requires.
    ct_seg_bmask |= bmask;
    ct_seg_smask |= smask;

    uint8_t nb = ctState.acc.n_bssid;
    uint8_t ns = ctState.acc.n_ssid;
    uint8_t fl = ctState.acc.flags;

    uint8_t cur_b = (uint8_t)__builtin_popcountll(bmask);
    uint8_t cur_s = (uint8_t)__builtin_popcount(smask);

    // ---- Step 4.1: temporal feature-vector deltas (descriptive) ----
    // Compared against the previous VALID window; paused windows never
    // update ct_prev_*, so no phantom churn bridges a pause.
    int d_b = 0, d_s = 0;
    bool have_d = ct_have_prev;
    if (have_d) {
      d_b = (int)cur_b - ct_prev_b;
      d_s = (int)cur_s - ct_prev_s;
    }
    int dd_b = 0, dd_s = 0;
    bool have_dd = ct_have_prev_d;
    if (have_dd) {
      dd_b = d_b - ct_prev_d_b;
      dd_s = d_s - ct_prev_d_s;
    }
    if (ct_have_prev) {
      ct_prev_d_b = (int8_t)d_b;
      ct_prev_d_s = (int8_t)d_s;
      ct_have_prev_d = true;
    }
    ct_prev_b = cur_b;
    ct_prev_s = cur_s;
    ct_have_prev = true;

    // ---- Retention-vs-hist overlap diagnostic REMOVED ----
    // The old retention channel (and its [CT-STEP4] overlap print) was the
    // only consumer of the historical identity arrays; both were deleted
    // together with those arrays when environment history became compact
    // CtEnvRecord metrics and persistence moved to CT-owned state.

    // Valid windows already absorbed by the baselines = win - 1
    // (window_count was incremented above; identical lifecycle to the
    // former ct_n_obs counter — reset with the segment, post-increment).
    uint16_t n_pre = (uint16_t)(win - 1);

    // Per-channel trigger-crossing flags for the [CT-TRIG] diagnostic:
    // true exactly on the window where persistence reaches N_MIN from below.
    bool cross_pop = false, cross_churn = false, cross_turn = false;

    // ---- Channel 1: POPULATION [B, S] — horizon-bounded baselines ----
    // mu: EWMA (alpha = 1/32), seeded with the EXACT first valid sample
    // (never EWMA-from-zero). var: EWMA of squared residuals vs the
    // post-update mu, Q8.16, excursion-gated (Huber-style): updated only
    // when n_pre < 4 (cold-start warm-up) or |resid| <= 3*sigma + 1 count,
    // so sigma describes regime noise and never learns the transitions.
    // Evidence: D = max(|dB|,|dS|) vs the PRE-update baseline, normalized
    // by the absolute-noise threshold thr = C1 + 1.25*sigma (the CV ratio
    // is ill-conditioned exactly during mean collapses). Evidence starts
    // at the 3rd valid window (uniform cold start).
    uint16_t sig_b_q8 = 0, sig_s_q8 = 0;
    if (n_pre == 0) {
      ct_ewma_mu_b_q8 = (uint16_t)(cur_b * 256); // exact seed
      ct_ewma_mu_s_q8 = (uint16_t)(cur_s * 256);
      ct_ewma_var_b_q16 = 0;
      ct_ewma_var_s_q16 = 0;
#if CT_DIAG_SEED
      Serial.printf("[CT-SEED] win=%u mu=%u/%u\n", (unsigned)win,
                    (unsigned)cur_b, (unsigned)cur_s);
#endif
    } else {
      sig_b_q8 = ct_isqrt32(ct_ewma_var_b_q16); // Q8.8 (var is Q8.16)
      sig_s_q8 = ct_isqrt32(ct_ewma_var_s_q16);
      uint32_t db_q8 = (cur_b * 256 > ct_ewma_mu_b_q8)
                           ? cur_b * 256 - ct_ewma_mu_b_q8
                           : ct_ewma_mu_b_q8 - cur_b * 256;
      uint32_t ds_q8 = (cur_s * 256 > ct_ewma_mu_s_q8)
                           ? cur_s * 256 - ct_ewma_mu_s_q8
                           : ct_ewma_mu_s_q8 - cur_s * 256;
      uint32_t d_pop_q8 = (db_q8 > ds_q8) ? db_q8 : ds_q8;
      if (n_pre >= 2) {
        uint16_t sig_q8 = (sig_b_q8 > sig_s_q8) ? sig_b_q8 : sig_s_q8;
        // thr = C1 + 1.25*sigma (Q8.8); thr >= 512, so the evidence
        // division yields <= (12288 << 8)/512 = 6144 — fits uint16_t.
        uint32_t thr_q8 = CT_C1_Q8 + ((uint32_t)sig_q8 * CT_C2S_NUM) / CT_C2S_DEN;
        uint16_t n_pop_q8 = (uint16_t)((d_pop_q8 << 8) / thr_q8);
        cross_pop = ct_evidence_update(ct_ewma_pop, ct_persist_pop, n_pop_q8);
        // Provisional E/T (volatility description ONLY; never resets
        // statistics, evidence, or creates a boundary): absolute noise
        // scale, replacing the ill-conditioned CV ratio.
        ct_prov_is_t = (sig_q8 >= CT_SIGMA_T_Q8);
      }
      // Absorb the window AFTER evidence (baselines track, pre-update).
      ct_ewma_mu_b_q8 = (uint16_t)((int32_t)ct_ewma_mu_b_q8 +
          (((int32_t)cur_b * 256 - (int32_t)ct_ewma_mu_b_q8) >> CT_BASE_SHIFT));
      ct_ewma_mu_s_q8 = (uint16_t)((int32_t)ct_ewma_mu_s_q8 +
          (((int32_t)cur_s * 256 - (int32_t)ct_ewma_mu_s_q8) >> CT_BASE_SHIFT));
      // Variance update, excursion-gated. |resid| <= 48<<8 = 12288, so
      // resid^2 <= 1.51e8 fits int32_t and var (Q8.16) fits uint32_t.
      int32_t rb_q8 = (int32_t)cur_b * 256 - (int32_t)ct_ewma_mu_b_q8;
      int32_t rs_q8 = (int32_t)cur_s * 256 - (int32_t)ct_ewma_mu_s_q8;
      int32_t gate_b = (int32_t)3 * sig_b_q8 + CT_VAR_FLOOR_Q8;
      int32_t gate_s = (int32_t)3 * sig_s_q8 + CT_VAR_FLOOR_Q8;
      if (n_pre < 4 || (rb_q8 <= gate_b && -rb_q8 <= gate_b))
        ct_ewma_var_b_q16 +=
            ((uint32_t)((int32_t)rb_q8 * rb_q8) >> CT_BASE_SHIFT) -
            (ct_ewma_var_b_q16 >> CT_BASE_SHIFT);
      if (n_pre < 4 || (rs_q8 <= gate_s && -rs_q8 <= gate_s))
        ct_ewma_var_s_q16 +=
            ((uint32_t)((int32_t)rs_q8 * rs_q8) >> CT_BASE_SHIFT) -
            (ct_ewma_var_s_q16 >> CT_BASE_SHIFT);
    }

    // ---- Channel 2: CHURN [ΔB, ΔS] ----
    // Excess absolute churn over the horizon EWMA of |Δ| (m adapts, so a
    // sustained walking regime self-quietens). m is seeded with the first
    // delta (window 2) and updated AFTER evidence; churn evidence starts
    // at the 3rd valid window of a segment (uniform cold start).
    if (have_d) {
      uint32_t ab_b = (d_b >= 0) ? d_b : -d_b;
      uint32_t ab_s = (d_s >= 0) ? d_s : -d_s;
      if (n_pre >= 2) {
        uint32_t ex_b_q8 = (ab_b * 256 > ct_ewma_m_ab_b_q8)
                               ? ab_b * 256 - ct_ewma_m_ab_b_q8 : 0;
        uint32_t ex_s_q8 = (ab_s * 256 > ct_ewma_m_ab_s_q8)
                               ? ab_s * 256 - ct_ewma_m_ab_s_q8 : 0;
        uint32_t scale_b = (uint32_t)CT_K3 * (ct_ewma_m_ab_b_q8 < 256
                                                  ? 256 : ct_ewma_m_ab_b_q8);
        uint32_t scale_s = (uint32_t)CT_K3 * (ct_ewma_m_ab_s_q8 < 256
                                                  ? 256 : ct_ewma_m_ab_s_q8);
        uint32_t n1_q8 = (ex_b_q8 << 8) / scale_b;
        uint32_t n2_q8 = (ex_s_q8 << 8) / scale_s;
        uint16_t n_churn_q8 = (n1_q8 > n2_q8) ? (uint16_t)n1_q8 : (uint16_t)n2_q8;
        cross_churn = ct_evidence_update(ct_ewma_churn, ct_persist_churn,
                                         n_churn_q8);
        // Absorb after evidence (same horizon clock).
        ct_ewma_m_ab_b_q8 = (uint16_t)((int32_t)ct_ewma_m_ab_b_q8 +
            (((int32_t)ab_b * 256 - (int32_t)ct_ewma_m_ab_b_q8) >> CT_BASE_SHIFT));
        ct_ewma_m_ab_s_q8 = (uint16_t)((int32_t)ct_ewma_m_ab_s_q8 +
            (((int32_t)ab_s * 256 - (int32_t)ct_ewma_m_ab_s_q8) >> CT_BASE_SHIFT));
      } else { // n_pre == 1 (have_d implies window 2): seed with first |Δ|
        ct_ewma_m_ab_b_q8 = (uint16_t)(ab_b * 256);
        ct_ewma_m_ab_s_q8 = (uint16_t)(ab_s * 256);
      }
    }

    // ---- Channel 3: SSID IDENTITY RETENTION — RETIRED ----
    // Deleted with the horizon redesign's successor steps: retention was
    // removed from the quorum when turnover (below) became the third live
    // channel, and its sums/EWMA/persistence were removed together with the
    // historical identity arrays it was the last consumer of.

    // ---- Channel 3 (LIVE): SSID IDENTITY TURNOVER ----
    // Adjacent-window identity dynamics over the touch masks (the bit->SSID
    // mapping is stable for acc's lifetime — identities are carried across
    // commits, so a slot index keeps referring to the same identity) plus
    // rejected inserts. With identity carry, a rejected insert means an
    // identity genuinely absent from the carried previous-environment set
    // (novelty), not a bounded-set artifact: in a stationary environment the
    // overflow tail's retries are steady-state and self-quiet in the m
    // baseline, while a real dense->dense-different transition keeps
    // producing novel rejects. Consumes ct_prev_smask BEFORE it is
    // overwritten below. Needs only a previous valid window — there is no
    // ABSTAIN case, so a zero-RF -> populated transition is visible here
    // (the regime the retention channel was mathematically unable to fire
    // on). Baseline is the horizon EWMA (same clock as mu/var), seeded
    // with the first turnover (window 2); evidence starts at the 3rd valid
    // window — the same cold start as churn.
    if (n_pre >= 1) {
      uint32_t new_id = (uint32_t)__builtin_popcount(smask & ~ct_prev_smask);
      uint32_t van_id = (uint32_t)__builtin_popcount(ct_prev_smask & ~smask);
      uint32_t turnover = new_id + van_id + (uint32_t)rej;
      if (n_pre >= 2) {
        // Excess over the pre-update EWMA baseline (m adapts, so the onset
        // fires and the sustained regime self-quietens). The clamp is
        // applied before the << 8 so the shift cannot overflow: if the
        // excess already exceeds 32*scale, evidence is at the clamp.
        uint32_t ex_turn_q8 =
            (turnover * 256 > ct_ewma_m_turn_q8)
                ? turnover * 256 - ct_ewma_m_turn_q8 : 0;
        uint32_t scale = (uint32_t)CT_K5 *
                         (ct_ewma_m_turn_q8 < 256 ? 256 : ct_ewma_m_turn_q8);
        uint32_t n_turn_q8;
        if (ex_turn_q8 > ((uint32_t)(CT_TURN_N_MAX_Q8 >> 8)) * scale)
          n_turn_q8 = CT_TURN_N_MAX_Q8;
        else
          n_turn_q8 = (ex_turn_q8 << 8) / scale;
        cross_turn = ct_evidence_update(ct_ewma_turn, ct_persist_turn,
                                        (uint16_t)n_turn_q8);
        // Absorb after evidence (same horizon clock).
        ct_ewma_m_turn_q8 = ct_ewma_m_turn_q8 +
            (((int32_t)(turnover * 256) - (int32_t)ct_ewma_m_turn_q8) >>
             CT_BASE_SHIFT);
      } else { // n_pre == 1: seed with the first turnover (window 2)
        ct_ewma_m_turn_q8 = turnover * 256; // u32: turnover may exceed 255
      }
    }
    ct_prev_smask = smask;

    // ---- Per-window byte traffic (environment-history metric) ----
    // Fold ONLY valid windows into the horizon EWMAs (paused windows
    // contribute nothing, matching every other CT statistic). Same horizon
    // clock: alpha = 1/32, exact seed on the segment's first valid window,
    // excursion-gated variance so transitions are never laundered into the
    // byte-dispersion statistic. Units: KiB Q8.8 (bytes >> 2); raw-byte
    // residuals overflow u32, hence the u64 variance and 64-bit isqrt.
    uint32_t kb_q8 = wbytes >> 2; // bytes -> KiB Q8.8
    if (n_pre == 0) {             // exact seed (first valid window)
      ct_ewma_byte_mean_q8kib = kb_q8;
      ct_ewma_byte_var_q16kib = 0;
    } else {
      ct_ewma_byte_mean_q8kib += (int32_t)(((int32_t)kb_q8 -
          (int32_t)ct_ewma_byte_mean_q8kib) >> CT_BASE_SHIFT);
      int32_t rb_byte = (int32_t)kb_q8 - (int32_t)ct_ewma_byte_mean_q8kib;
      int32_t gate_byte = (int32_t)3 * ct_isqrt64(ct_ewma_byte_var_q16kib) +
                          CT_VAR_FLOOR_Q8;
      if (n_pre < 4 || (rb_byte <= gate_byte && -rb_byte <= gate_byte)) {
        // var += (resid^2 - var) / 32 — signed delta. Both operands are
        // non-negative, but the difference is negative whenever the
        // variance is decaying (new squared residual below the running
        // variance); the previous unsigned form underflowed u64 and
        // corrupted the variance on exactly those windows. delta is
        // bounded below by -(var >> 5), so the sum cannot go negative.
        int64_t r2_q16 = (int64_t)rb_byte * rb_byte;
        int64_t delta = (r2_q16 >> CT_BASE_SHIFT) -
                        (int64_t)(ct_ewma_byte_var_q16kib >> CT_BASE_SHIFT);
        ct_ewma_byte_var_q16kib =
            (uint64_t)((int64_t)ct_ewma_byte_var_q16kib + delta);
      }
    }

    // ---- Envelope statistics absorb the window (diagnostic range display)
    // ---- Population mean/variance are absorbed inside the channel block
    // above (horizon EWMAs, post-evidence).
    if (!ct_have_obs) {
      ct_min_b = cur_b; ct_max_b = cur_b;
      ct_min_s = cur_s; ct_max_s = cur_s;
      ct_have_obs = true;
    } else {
      if (cur_b < ct_min_b) ct_min_b = cur_b;
      if (cur_b > ct_max_b) ct_max_b = cur_b;
      if (cur_s < ct_min_s) ct_min_s = cur_s;
      if (cur_s > ct_max_s) ct_max_s = cur_s;
    }
    // ct_n_obs++ removed — n_pre derives from acc.window_count now.

    // Snapshots for the post-fence diagnostics (pre-commit segment state).
#if CT_DIAG_STEPS || CT_DIAG_TRIG
    uint16_t snap_mub = ct_ewma_mu_b_q8, snap_mus = ct_ewma_mu_s_q8;
    uint16_t snap_sgb = sig_b_q8, snap_sgs = sig_s_q8; // horizon sigma
    uint8_t snap_mnb = ct_min_b, snap_mxb = ct_max_b;
    uint8_t snap_mns = ct_min_s, snap_mxs = ct_max_s;
    bool snap_have = ct_have_obs;
    uint16_t snap_ep = ct_ewma_pop, snap_ec = ct_ewma_churn;
    uint16_t snap_et = ct_ewma_turn;
    uint8_t snap_pp = ct_persist_pop, snap_pc = ct_persist_churn;
    uint8_t snap_pt = ct_persist_turn;
    uint32_t snap_bmean = ct_ewma_byte_mean_q8kib;
    bool snap_t = ct_prov_is_t;
#endif // CT_DIAG_STEPS || CT_DIAG_TRIG

    // ---- 2-of-3 LIVE quorum: {population, churn, turnover} ----
    // Retention persistence is deliberately excluded (diagnostic only).
    uint8_t trig = (ct_persist_pop >= CT_N_MIN) + (ct_persist_churn >= CT_N_MIN) +
                   (ct_persist_turn >= CT_N_MIN);
    if (trig >= 2)
      ct_commit_segment(); // closes segment, advances env_seq, resets scratch

    // ---- TEMPORARY Step-3/4/4.1/4.2/5 diagnostics (Core 1 only) ----
    // Post-fence, snapshot-driven; remove as segmentation stabilizes.
#if CT_DIAG_STEPS
    Serial.printf("[CT-STEP3] window=%u bssid=%u ssid=%u trunc=%s%s\n",
                  (unsigned)win, (unsigned)nb, (unsigned)ns,
                  (fl & CT_FLAG_BSSID_TRUNC) ? "B" : "-",
                  (fl & CT_FLAG_SSID_TRUNC) ? "S" : "-");
    // [CT-STEP4] (retention overlap) removed with the retention machinery.
    {
      char db[8], ddb[8], ds[8], dds[8];
      if (have_d) { snprintf(db, sizeof(db), "%+d", d_b); snprintf(ds, sizeof(ds), "%+d", d_s); }
      else { snprintf(db, sizeof(db), "n/a"); snprintf(ds, sizeof(ds), "n/a"); }
      if (have_dd) { snprintf(ddb, sizeof(ddb), "%+d", dd_b); snprintf(dds, sizeof(dds), "%+d", dd_s); }
      else { snprintf(ddb, sizeof(ddb), "n/a"); snprintf(dds, sizeof(dds), "n/a"); }
      Serial.printf("[CT-STEP4.1] win=%u B=%u d=%s dd=%s | S=%u d=%s dd=%s\n",
                    (unsigned)win, (unsigned)cur_b, db, ddb, (unsigned)cur_s, ds, dds);
    }
    {
      char mb[12], ms[12], rb[16], rs[16], thr[12];
      if (snap_have) {
        snprintf(mb, sizeof(mb), "%u.%02u", (unsigned)(snap_mub >> 8),
                 (unsigned)(((snap_mub & 0xFF) * 100) >> 8));
        snprintf(ms, sizeof(ms), "%u.%02u", (unsigned)(snap_mus >> 8),
                 (unsigned)(((snap_mus & 0xFF) * 100) >> 8));
        snprintf(rb, sizeof(rb), "%u-%u", (unsigned)snap_mnb, (unsigned)snap_mxb);
        snprintf(rs, sizeof(rs), "%u-%u", (unsigned)snap_mns, (unsigned)snap_mxs);
        uint16_t sg = (snap_sgb > snap_sgs) ? snap_sgb : snap_sgs;
        uint32_t tq = CT_C1_Q8 + ((uint32_t)sg * CT_C2S_NUM) / CT_C2S_DEN;
        snprintf(thr, sizeof(thr), "%u.%02u", (unsigned)(tq >> 8),
                 (unsigned)(((tq & 0xFF) * 100) >> 8));
      } else {
        snprintf(mb, sizeof(mb), "n/a"); snprintf(ms, sizeof(ms), "n/a");
        snprintf(rb, sizeof(rb), "n/a"); snprintf(rs, sizeof(rs), "n/a");
        snprintf(thr, sizeof(thr), "n/a");
      }
      Serial.printf("[CT-STEP4.2] win=%u valid=Y obs=%u rej=%u cov=%u/%u mean=%s range=%s/%s thr=%s bytes=%u.%02uKiB\n",
                    (unsigned)win, (unsigned)obs, (unsigned)rej, (unsigned)cov,
                    (unsigned)cov_max, mb, rb, rs, thr,
                    (unsigned)(snap_bmean >> 8),
                    (unsigned)(((snap_bmean & 0xFF) * 100) >> 8));
    }
    Serial.printf(
        "[CT-STEP5] win=%u class=%c ewma=%u/%u/%u persist=%u/%u/%u\n",
        (unsigned)win, snap_t ? 'T' : 'E', (unsigned)(snap_ep >> 2),
        (unsigned)(snap_ec >> 2),
        (unsigned)(snap_et >> 2), (unsigned)snap_pp, (unsigned)snap_pc,
        (unsigned)snap_pt);
#endif // CT_DIAG_STEPS
    // One line per channel that crossed persistence >= N_MIN on THIS window
    // (transition-only; repeated triggers while staying above are silent).
    // Diagnostic only — the 2-of-3 quorum remains the sole commit criterion.
#if CT_DIAG_TRIG
    if (cross_pop)
      Serial.printf("[CT-TRIG] win=%u channel=POP ewma=%u.%02u persist=%u\n",
                    (unsigned)win, (unsigned)(snap_ep >> 8),
                    (unsigned)(((snap_ep & 0xFF) * 100) >> 8), (unsigned)snap_pp);
    if (cross_churn)
      Serial.printf("[CT-TRIG] win=%u channel=CHURN ewma=%u.%02u persist=%u\n",
                    (unsigned)win, (unsigned)(snap_ec >> 8),
                    (unsigned)(((snap_ec & 0xFF) * 100) >> 8), (unsigned)snap_pc);
    if (cross_turn)
      Serial.printf("[CT-TRIG] win=%u channel=TURN ewma=%u.%02u persist=%u\n",
                    (unsigned)win, (unsigned)(snap_et >> 8),
                    (unsigned)(((snap_et & 0xFF) * 100) >> 8), (unsigned)snap_pt);
#endif // CT_DIAG_TRIG
    // ---- END TEMPORARY ----
  } else {
    // Invalid (paused) window: contributes nothing — no statistics, no
    // evidence, no classification change, no commit, no window_count.
#if CT_DIAG_STEPS
    Serial.printf("[CT-STEP4.2] win=%u valid=N obs=0 rej=%u cov=%u/%u mean=n/a range=n/a/n/a\n",
                  (unsigned)(ctState.acc.window_count + 1), (unsigned)rej,
                  (unsigned)cov, (unsigned)cov_max);
#endif // CT_DIAG_STEPS
    // ---- END TEMPORARY ----
  }

  // ---- Boundary-deferred SELECT CH apply (environment boundary) ----
  // The capture fence is still up here: the safe point to rewrite the radio
  // hop set. The current environment is closed with the normal commit
  // mechanism (a set change IS an environment boundary); if no valid window
  // ever folded into it (e.g. the quorum already committed during this
  // window's fold, or nothing was observed), there is nothing to commit —
  // clear the open statistics instead. The persist table, pending pool, and
  // environment history are deliberately untouched: this is an environment
  // boundary, not a session reset. (Applied via the shared helper, which is
  // also invoked by the CT resume path for selections made while paused.)
  ct_flush_reselect();
  ct_hop_transitions = 0;
  // Window complete (valid or invalid): enqueue exactly one Wi-Fi waterfall
  // column. The chart plots the completed window's byte snapshot
  // (ct_render_wbytes) on this slot; no metric special-casing needed.
  ct_renderq_push(CT_RTYPE_WIFI);
#if CT_BLE_BURST
  // BLE burst — strictly after ALL Wi-Fi window work (validity, commit,
  // evidence, reselect) and still under the capture fence. On success it
  // contributes exactly one BLE render slot; skipped bursts contribute
  // nothing (no fabricated BLE data slot). The fence restore and the
  // post-close timing re-anchor below run AFTER the burst, so the next
  // window starts fresh from post-burst time.
  {
    uint32_t burst_hits = 0;
    if (ct_ble_burst(&burst_hits)) {
      ct_ble_last_hits = burst_hits;
      ct_renderq_push(CT_RTYPE_BLE);
    }
  }
#endif
  pause_sniffing = was_paused; // RESTORE: do not clear a menu-held pause
  ct_window_start_ms = millis();
  ct_last_hop_ms = millis();
}
