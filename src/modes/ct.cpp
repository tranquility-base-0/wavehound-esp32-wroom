#include "ct.h"
#include "core/radio.h"

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
static uint16_t ct_sum_b = 0, ct_sum_s = 0, ct_n_obs = 0;
static uint32_t ct_sum_b2 = 0, ct_sum_s2 = 0;
static uint8_t ct_min_b = 0, ct_max_b = 0, ct_min_s = 0, ct_max_s = 0;
static uint16_t ct_obs_count = 0;
static bool ct_have_obs = false;

// Step-5 follow-up instrumentation: observation-quality counters.
//   ct_rej_count  — per-window count of REJECTED genuinely-new identity
//                   insertions (table full). Immune to saturation by
//                   construction: it measures the untracked world.
//   ct_chans_mask — per-window channels-visited mask, maintained by Core 1
//                   (Core-1 context) by watching current_ch_idx transitions
//                   every loop tick. A window with cov < 13 did not cover a
//                   full sweep (hopper stalled / screen state) — a coverage
//                   gap, not an environment reading.
static uint16_t ct_rej_count = 0;
static uint16_t ct_chans_mask = 0;
static uint8_t ct_last_ch = 0xFF; // 0xFF = no channel recorded yet

// ---- Step 5: segmentation evidence (3 LIVE channels + 1 diagnostic) ----
// LIVE quorum: POPULATION + CHURN + TURNOVER (2-of-3). RETENTION is
// computed as a diagnostic only (see below).
// All file-local Core-1 scratch; updated only for VALID windows (window that
// closes while pause_sniffing == false), inside the F10 fence.
//
// Churn channel: running means of ABSOLUTE deltas (m_B = mean|ΔB|). Evidence
// is EXCESS churn over the segment's own normal churn magnitude, so a
// sustained walking regime self-quietens once m adapts.
static uint32_t ct_sum_ab_b = 0, ct_sum_ab_s = 0;
//
// Retention channel: R = shared/prev_count in Q8.8, from the touch masks
// (ct_prev_smask = previous valid window's SSID mask — the bit->SSID mapping
// is stable for the lifetime of acc, so mask intersection IS identity
// intersection; no strings are stored or compared here). Divergence is
// DIRECTIONAL: only low retention (μ_R − R) is transition evidence.
static uint32_t ct_prev_smask = 0;
static uint32_t ct_sum_r = 0, ct_sum_r2 = 0; // Q8.8, Q8.16 respectively
static uint16_t ct_n_ret = 0;                // non-ABSTAIN retention observations
// DIAGNOSTIC-ONLY since the turnover step: retention is excluded from the
// quorum; its evidence machinery is kept temporarily for on-device
// comparison and will be deleted after turnover is hardware-verified.
//
// Turnover channel (identity dynamics, adjacent-window) — LIVE channel:
//   turnover = popcount(cur & ~prev)   new SSIDs      (tracked stream)
//            + popcount(prev & ~cur)   vanished SSIDs (tracked stream)
//            + rejected inserts        untracked-stream arrivals
// No ABSTAIN case: a previous valid window suffices (empty->populated IS
// turnover). Adjacent-window semantics mean a post-commit re-learn of the
// SAME environment produces ~no turnover (the prev mask tracks it), so
// there is no artificial post-commit spike. The rejected term is
// FLUX-WEIGHTED (frames x unseen identities; rejected identities are not
// recorded, so each later frame re-attempts — rej <= 2*obs).
static uint32_t ct_sum_turn = 0; // running Σ turnover (counts per window)
//
// Common EWMA (Q8.8) + persistence per channel. A channel "is triggering"
// when persistence >= CT_N_MIN — the persistence state IS the trigger state
// (no separate latch). LIVE quorum = 2-of-3 over {population, churn,
// turnover}; retention's persistence state is diagnostic only.
static uint16_t ct_ewma_pop = 0, ct_ewma_churn = 0, ct_ewma_ret = 0;
static uint16_t ct_ewma_turn = 0;
static uint8_t ct_persist_pop = 0, ct_persist_churn = 0, ct_persist_ret = 0;
static uint8_t ct_persist_turn = 0;
//
// Provisional E/T classification of the OPEN segment (false=E_n, true=T_n).
// Description of volatility only: changes never reset statistics or evidence.
static bool ct_prov_is_t = false;

// Fixed-point constants (Q8.8 unless noted). Initial tunables from the
// audited design — measurable from [CT-STEP*] traces, not sacred.
static const uint16_t CT_CV_MAX_Q8 = 384;         // CV_MAX = 1.5
static const uint16_t CT_CV_T_Q8 = 179;           // provisional-T CV threshold 0.7
static const uint16_t CT_C1_Q8 = 512;             // population threshold floor C1 = 2
static const uint16_t CT_C2_Q8 = 1024;            // population CV scaling C2 = 4
static const uint16_t CT_K3 = 3;                  // churn normalization K3
static const uint16_t CT_K4 = 3;                  // retention K4 (diagnostic channel)
static const uint16_t CT_K5 = 3;                  // turnover normalization K5 (trace-tunable)
static const uint16_t CT_TURN_N_MAX_Q8 = 8192;    // turnover evidence clamp (32.0 Q8.8)
static const uint16_t CT_SIGMA_R_FLOOR_Q8 = 26;   // sigma_floor = 0.1 (25.6 -> 26)
static const uint8_t CT_N_MIN = 3;                // persistence length (windows)

// Integer square root (no floating-point state).
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
  ct_sum_b = 0; ct_sum_s = 0; ct_n_obs = 0;
  ct_sum_b2 = 0; ct_sum_s2 = 0;
  ct_min_b = 0; ct_max_b = 0; ct_min_s = 0; ct_max_s = 0;
  ct_have_obs = false;
  ct_sum_ab_b = 0; ct_sum_ab_s = 0;
  ct_prev_smask = 0; ct_sum_r = 0; ct_sum_r2 = 0; ct_n_ret = 0;
  ct_sum_turn = 0;
  ct_ewma_pop = 0; ct_ewma_churn = 0; ct_ewma_ret = 0; ct_ewma_turn = 0;
  ct_persist_pop = 0; ct_persist_churn = 0; ct_persist_ret = 0;
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
static bool ct_window_running = false;

// Commit the open segment: copy the accumulator into the next history slot
// with its final provisional E/T class, advance the global segment index,
// and reset the accumulator plus ALL per-segment statistical/evidence state.
// Must run inside the F10 fence.
static void ct_commit_segment() {
  uint8_t next = (ctState.current_idx + 1) % MAX_CT_ENVIRONMENTS;
  CtEnvironment &dst = ctState.hist[next];
  dst = ctState.acc; // identities, first/last_seen, window_count, n_*, trunc flags
  dst.env_id = ctState.env_seq;
  dst.flags = (dst.flags & ~CT_FLAG_CLASS_T) | (ct_prov_is_t ? CT_FLAG_CLASS_T : 0);
  ctState.current_idx = next;
  ctState.env_seq++;
  memset(&ctState.acc, 0, sizeof(CtEnvironment));
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
    ct_obs_count = 0;
    ct_rej_count = 0;
    ct_chans_mask = 0;
    ct_last_ch = 0xFF;
    ct_reset_segment_stats();
    ct_window_running = false;
    return;
  }

  // Per-tick channel-coverage tracking (Core-1 context): record every channel
  // the radio lands on during the open window. A closed window whose mask
  // covers fewer than 13 channels did not observe a full sweep.
  if (current_ch_idx != ct_last_ch) {
    ct_last_ch = current_ch_idx;
    ct_chans_mask |= (uint16_t)1 << current_ch_idx;
  }

  if (!ct_window_running) {
    ct_window_start_ms = millis();
    ct_window_running = true;
    return;
  }

  if (millis() - ct_window_start_ms < CT_WIFI_WINDOW_MS)
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

  if (valid) {
    ctState.acc.window_count++;
    uint16_t win = ctState.acc.window_count; // snapshot (commit resets acc)

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

    // ---- Retention vs committed environment (Step-4 diagnostic) ----
    // Read-only vs hist[]; intersection vs the committed identity sets.
    const CtEnvironment &committed = ctState.hist[ctState.current_idx];
    bool have_committed = (committed.first_seen != 0);
    int b_inter = 0, s_inter = 0;
    if (have_committed) {
      for (uint8_t i = 0; i < nb; i++) {
        if (!(bmask & ((uint64_t)1 << i)))
          continue;
        for (uint8_t j = 0; j < committed.n_bssid; j++) {
          if (memcmp(ctState.acc.bssid[i], committed.bssid[j], 6) == 0) {
            b_inter++;
            break;
          }
        }
      }
      for (uint8_t i = 0; i < ns; i++) {
        if (!(smask & ((uint32_t)1 << i)))
          continue;
        for (uint8_t j = 0; j < committed.n_ssid; j++) {
          if (strcmp(ctState.acc.ssid[i], committed.ssid[j]) == 0) {
            s_inter++;
            break;
          }
        }
      }
    }

    uint16_t n_pre = ct_n_obs; // valid windows already in the population stats

    // Per-channel trigger-crossing flags for the [CT-TRIG] diagnostic:
    // true exactly on the window where persistence reaches N_MIN from below.
    bool cross_pop = false, cross_churn = false, cross_ret = false,
         cross_turn = false;

    // ---- Channel 1: POPULATION [B, S] ----
    // Evidence is measured against the pre-update baseline (the running mean
    // established BEFORE this window), then the baseline absorbs the window.
    // Variance: E[x^2] - E[x]^2 with per-term integer division (no overflow:
    // sum_b2/n and (sum_b/n)^2 are both <= 48^2).
    uint16_t cv_seg_q8 = 0;
    if (n_pre >= 1) {
      uint32_t mu_b_q8 = ((uint32_t)ct_sum_b * 256) / n_pre;
      uint32_t mu_s_q8 = ((uint32_t)ct_sum_s * 256) / n_pre;
      uint32_t db_q8 = (cur_b * 256 > mu_b_q8) ? cur_b * 256 - mu_b_q8
                                               : mu_b_q8 - cur_b * 256;
      uint32_t ds_q8 = (cur_s * 256 > mu_s_q8) ? cur_s * 256 - mu_s_q8
                                               : mu_s_q8 - cur_s * 256;
      uint32_t d_pop_q8 = (db_q8 > ds_q8) ? db_q8 : ds_q8;

      if (n_pre >= 2) {
        int32_t var_b = (int32_t)(ct_sum_b2 / n_pre) -
                        (int32_t)((ct_sum_b / n_pre) * (ct_sum_b / n_pre));
        int32_t var_s = (int32_t)(ct_sum_s2 / n_pre) -
                        (int32_t)((ct_sum_s / n_pre) * (ct_sum_s / n_pre));
        if (var_b < 0) var_b = 0; // integer-truncation guard
        if (var_s < 0) var_s = 0;
        uint16_t sig_b_q8 = (uint16_t)ct_isqrt32((uint32_t)var_b) << 8;
        uint16_t sig_s_q8 = (uint16_t)ct_isqrt32((uint32_t)var_s) << 8;
        uint16_t cv_b_q8, cv_s_q8;
        if (mu_b_q8 == 0)
          cv_b_q8 = (sig_b_q8 > 0) ? CT_CV_MAX_Q8 : 0; // case C / case B
        else
          cv_b_q8 = (sig_b_q8 * 256) / mu_b_q8;
        if (cv_b_q8 > CT_CV_MAX_Q8) cv_b_q8 = CT_CV_MAX_Q8;
        if (mu_s_q8 == 0)
          cv_s_q8 = (sig_s_q8 > 0) ? CT_CV_MAX_Q8 : 0;
        else
          cv_s_q8 = (sig_s_q8 * 256) / mu_s_q8;
        if (cv_s_q8 > CT_CV_MAX_Q8) cv_s_q8 = CT_CV_MAX_Q8;
        cv_seg_q8 = (cv_b_q8 > cv_s_q8) ? cv_b_q8 : cv_s_q8;

        // threshold = C1 + C2*CV_seg  (Q8.8: C2*CV = CV << 2 for C2 = 4)
        uint32_t thr_q8 = CT_C1_Q8 + ((uint32_t)cv_seg_q8 << 2);
        uint16_t n_pop_q8 = (uint16_t)((d_pop_q8 << 8) / thr_q8);
        cross_pop = ct_evidence_update(ct_ewma_pop, ct_persist_pop, n_pop_q8);

        // ---- Provisional E/T classification (volatility description ONLY;
        // never resets statistics, evidence, or creates a boundary) ----
        ct_prov_is_t = (cv_seg_q8 >= CT_CV_T_Q8);
      }
    }

    // ---- Channel 2: CHURN [ΔB, ΔS] ----
    // Excess absolute churn over the segment's own mean |Δ| (m adapts, so a
    // sustained walking regime self-quietens). m uses windows 2..k-1, so
    // churn evidence starts at the 3rd valid window of a segment.
    if (have_d) {
      uint32_t ab_b = (d_b >= 0) ? d_b : -d_b;
      uint32_t ab_s = (d_s >= 0) ? d_s : -d_s;
      if (n_pre >= 2) { // n_pre valid windows existed; churn count = n_pre-1
        uint32_t m_b_q8 = (ct_sum_ab_b * 256) / (n_pre - 1);
        uint32_t m_s_q8 = (ct_sum_ab_s * 256) / (n_pre - 1);
        uint32_t ex_b_q8 = (ab_b * 256 > m_b_q8) ? ab_b * 256 - m_b_q8 : 0;
        uint32_t ex_s_q8 = (ab_s * 256 > m_s_q8) ? ab_s * 256 - m_s_q8 : 0;
        uint32_t scale_b = (uint32_t)CT_K3 * (m_b_q8 < 256 ? 256 : m_b_q8);
        uint32_t scale_s = (uint32_t)CT_K3 * (m_s_q8 < 256 ? 256 : m_s_q8);
        uint32_t n1_q8 = (ex_b_q8 << 8) / scale_b;
        uint32_t n2_q8 = (ex_s_q8 << 8) / scale_s;
        uint16_t n_churn_q8 = (n1_q8 > n2_q8) ? (uint16_t)n1_q8 : (uint16_t)n2_q8;
        cross_churn = ct_evidence_update(ct_ewma_churn, ct_persist_churn, n_churn_q8);
      }
      ct_sum_ab_b += ab_b;
      ct_sum_ab_s += ab_s;
    }

    // ---- Channel 3: SSID IDENTITY RETENTION ----
    // Bit->SSID mapping is stable for acc's lifetime, so mask intersection
    // IS identity intersection (no strings stored/compared here). The
    // previous mask must be consumed BEFORE it is overwritten, and it is
    // only meaningful if a previous VALID window exists (n_pre >= 1).
    if (n_pre >= 1) {
      uint16_t prev_cnt = (uint16_t)__builtin_popcount(ct_prev_smask);
      if (prev_cnt > 0) {
        uint16_t shared = (uint16_t)__builtin_popcount(smask & ct_prev_smask);
        uint16_t r_q8 = (uint16_t)(((uint32_t)shared << 8) / prev_cnt); // <= 256
        if (ct_n_ret >= 2) { // mu_R / sigma_R defined from the 3rd retention obs
          uint32_t mu_r_q8 = ct_sum_r / ct_n_ret;
          int32_t var_r = (int32_t)(ct_sum_r2 / ct_n_ret) -
                          (int32_t)((ct_sum_r / ct_n_ret) * (ct_sum_r / ct_n_ret));
          if (var_r < 0) var_r = 0;
          uint16_t sig_r_q8 = ct_isqrt32((uint32_t)var_r); // Q8.8 (var was Q8.16)
          uint16_t sig_eff = (sig_r_q8 > CT_SIGMA_R_FLOOR_Q8) ? sig_r_q8
                                                              : CT_SIGMA_R_FLOOR_Q8;
          // Directional: only LOW retention is transition evidence.
          uint32_t excess_q8 = (mu_r_q8 > r_q8) ? mu_r_q8 - r_q8 : 0;
          uint16_t n_ret_ev_q8 =
              (uint16_t)(((uint32_t)excess_q8 << 8) / ((uint32_t)CT_K4 * sig_eff));
          cross_ret = ct_evidence_update(ct_ewma_ret, ct_persist_ret, n_ret_ev_q8);
        }
        ct_sum_r += r_q8;
        ct_sum_r2 += (uint32_t)r_q8 * r_q8;
        ct_n_ret++;
      }
      // prev_count == 0 -> ABSTAIN: no vote, evidence state frozen.
    }

    // ---- Channel 3 (LIVE): SSID IDENTITY TURNOVER ----
    // Adjacent-window identity dynamics over the touch masks (the bit->SSID
    // mapping is stable for acc's lifetime) plus the untracked-stream
    // arrivals (rejected inserts). Consumes ct_prev_smask BEFORE it is
    // overwritten below. Needs only a previous valid window — there is no
    // ABSTAIN case, so a zero-RF -> populated transition is visible here
    // (the regime the retention channel was mathematically unable to fire
    // on). Running mean uses windows 2..k-1, so turnover evidence starts at
    // the 3rd valid window of a segment — the same cold start as churn.
    if (n_pre >= 1) {
      uint32_t new_id = (uint32_t)__builtin_popcount(smask & ~ct_prev_smask);
      uint32_t van_id = (uint32_t)__builtin_popcount(ct_prev_smask & ~smask);
      uint32_t turnover = new_id + van_id + (uint32_t)rej;
      if (n_pre >= 2) { // mean over windows 2..k-1 (no div-by-zero at k=2)
        uint32_t m_turn_q8 = ((uint32_t)ct_sum_turn * 256) / (n_pre - 1);
        uint32_t ex_turn_q8 =
            (turnover * 256 > m_turn_q8) ? turnover * 256 - m_turn_q8 : 0;
        uint32_t scale = (uint32_t)CT_K5 * (m_turn_q8 < 256 ? 256 : m_turn_q8);
        uint32_t n_turn_q8 = (ex_turn_q8 << 8) / scale;
        if (n_turn_q8 > CT_TURN_N_MAX_Q8)
          n_turn_q8 = CT_TURN_N_MAX_Q8; // rej is unbounded per window; clamp
        cross_turn = ct_evidence_update(ct_ewma_turn, ct_persist_turn,
                                        (uint16_t)n_turn_q8);
      }
      ct_sum_turn += turnover;
    }
    ct_prev_smask = smask;

    // ---- Population statistics absorb the window (after evidence) ----
    ct_sum_b += cur_b;
    ct_sum_s += cur_s;
    ct_sum_b2 += (uint32_t)cur_b * cur_b;
    ct_sum_s2 += (uint32_t)cur_s * cur_s;
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
    ct_n_obs++;

    // Snapshots for the post-fence diagnostics (pre-commit segment state).
    uint16_t snap_n = ct_n_obs, snap_sb = ct_sum_b, snap_ss = ct_sum_s;
    uint8_t snap_mnb = ct_min_b, snap_mxb = ct_max_b;
    uint8_t snap_mns = ct_min_s, snap_mxs = ct_max_s;
    bool snap_have = ct_have_obs;
    uint16_t snap_ep = ct_ewma_pop, snap_ec = ct_ewma_churn, snap_er = ct_ewma_ret;
    uint16_t snap_et = ct_ewma_turn;
    uint8_t snap_pp = ct_persist_pop, snap_pc = ct_persist_churn,
            snap_pr = ct_persist_ret;
    uint8_t snap_pt = ct_persist_turn;
    bool snap_t = ct_prov_is_t;

    // ---- 2-of-3 LIVE quorum: {population, churn, turnover} ----
    // Retention persistence is deliberately excluded (diagnostic only).
    uint8_t trig = (ct_persist_pop >= CT_N_MIN) + (ct_persist_churn >= CT_N_MIN) +
                   (ct_persist_turn >= CT_N_MIN);
    if (trig >= 2)
      ct_commit_segment(); // closes segment, advances env_seq, resets scratch

    // ---- TEMPORARY Step-3/4/4.1/4.2/5 diagnostics (Core 1 only) ----
    // Post-fence, snapshot-driven; remove as segmentation stabilizes.
    Serial.printf("[CT-STEP3] window=%u bssid=%u ssid=%u trunc=%s%s\n",
                  (unsigned)win, (unsigned)nb, (unsigned)ns,
                  (fl & CT_FLAG_BSSID_TRUNC) ? "B" : "-",
                  (fl & CT_FLAG_SSID_TRUNC) ? "S" : "-");
    if (have_committed) {
      char bret[12], sret[12];
      if (committed.n_bssid > 0)
        snprintf(bret, sizeof(bret), "%u%%", (unsigned)(b_inter * 100 / committed.n_bssid));
      else
        snprintf(bret, sizeof(bret), "n/a");
      if (committed.n_ssid > 0)
        snprintf(sret, sizeof(sret), "%u%%", (unsigned)(s_inter * 100 / committed.n_ssid));
      else
        snprintf(sret, sizeof(sret), "n/a");
      Serial.printf("[CT-STEP4] win=%u Bret=%s (%u/%u) Sret=%s (%u/%u)\n",
                    (unsigned)win, bret,
                    (unsigned)b_inter, (unsigned)committed.n_bssid,
                    sret, (unsigned)s_inter, (unsigned)committed.n_ssid);
    }
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
      char mb[12], ms[12], rb[16], rs[16];
      if (snap_have) {
        snprintf(mb, sizeof(mb), "%u/%u", (unsigned)(snap_sb / snap_n),
                 (unsigned)(snap_ss / snap_n));
        snprintf(rb, sizeof(rb), "%u-%u", (unsigned)snap_mnb, (unsigned)snap_mxb);
        snprintf(rs, sizeof(rs), "%u-%u", (unsigned)snap_mns, (unsigned)snap_mxs);
      } else {
        snprintf(mb, sizeof(mb), "n/a"); snprintf(ms, sizeof(ms), "n/a");
        snprintf(rb, sizeof(rb), "n/a"); snprintf(rs, sizeof(rs), "n/a");
      }
      Serial.printf("[CT-STEP4.2] win=%u valid=Y obs=%u rej=%u cov=%u/13 mean=%s range=%s/%s\n",
                    (unsigned)win, (unsigned)obs, (unsigned)rej, (unsigned)cov,
                    mb, rb, rs);
    }
    Serial.printf(
        "[CT-STEP5] win=%u class=%c ewma=%u/%u/%u/%u persist=%u/%u/%u/%u\n",
        (unsigned)win, snap_t ? 'T' : 'E', (unsigned)(snap_ep >> 2),
        (unsigned)(snap_ec >> 2), (unsigned)(snap_er >> 2),
        (unsigned)(snap_et >> 2), (unsigned)snap_pp, (unsigned)snap_pc,
        (unsigned)snap_pr, (unsigned)snap_pt);
    // One line per channel that crossed persistence >= N_MIN on THIS window
    // (transition-only; repeated triggers while staying above are silent).
    // Diagnostic only — the 2-of-3 quorum remains the sole commit criterion.
    if (cross_pop)
      Serial.printf("[CT-TRIG] win=%u channel=POP ewma=%u.%02u persist=%u\n",
                    (unsigned)win, (unsigned)(snap_ep >> 8),
                    (unsigned)(((snap_ep & 0xFF) * 100) >> 8), (unsigned)snap_pp);
    if (cross_churn)
      Serial.printf("[CT-TRIG] win=%u channel=CHURN ewma=%u.%02u persist=%u\n",
                    (unsigned)win, (unsigned)(snap_ec >> 8),
                    (unsigned)(((snap_ec & 0xFF) * 100) >> 8), (unsigned)snap_pc);
    if (cross_ret)
      Serial.printf("[CT-TRIG] win=%u channel=RET ewma=%u.%02u persist=%u\n",
                    (unsigned)win, (unsigned)(snap_er >> 8),
                    (unsigned)(((snap_er & 0xFF) * 100) >> 8), (unsigned)snap_pr);
    if (cross_turn)
      Serial.printf("[CT-TRIG] win=%u channel=TURN ewma=%u.%02u persist=%u\n",
                    (unsigned)win, (unsigned)(snap_et >> 8),
                    (unsigned)(((snap_et & 0xFF) * 100) >> 8), (unsigned)snap_pt);
    // ---- END TEMPORARY ----
  } else {
    // Invalid (paused) window: contributes nothing — no statistics, no
    // evidence, no classification change, no commit, no window_count.
    Serial.printf("[CT-STEP4.2] win=%u valid=N obs=0 rej=%u cov=%u/13 mean=n/a range=n/a/n/a\n",
                  (unsigned)(ctState.acc.window_count + 1), (unsigned)rej,
                  (unsigned)cov);
    // ---- END TEMPORARY ----
  }

  pause_sniffing = was_paused; // RESTORE: do not clear a menu-held pause
  ct_window_start_ms = millis();
}
