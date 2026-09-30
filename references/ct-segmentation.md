# CT (Chase Tail / Counter-surveillance) — implementation state

Last updated: 2026-09-29 (Step 5 three-channel segmentation + commit IMPLEMENTED in ct.cpp; built host-side pending user paste; nothing committed).

## Accepted implementation

- Data structures (Step 1): `src/core/wavehound_state.h` — `MAX_CT_BSSIDS 48 / MAX_CT_SSIDS 32 / MAX_CT_ENVIRONMENTS 8`; `CtEnvironment` = 1,360 B; `CTState` = 12,248 B (union headroom 2,552 B; boundary still `MacRecord[185]` = 14,800; static SRAM delta 0). `acc` member added by explicit approval: sole uncommitted accumulator; commit copies acc -> next hist slot. `static_assert(sizeof(CTState) <= sizeof(MacRecord)*MAX_MACS)` guards placement.
- Mode shell (Step 2): `RADIO_CT` enum appended; CT reuses the Wi-Fi antenna-init branch in `switchRadioMode` (RADIO_PCAP deliberately excluded — PCAP inherits prior radio state); CT in hopper + EXIT promiscuous restore; cycle PCAP -> CT -> WIFI; chart banner `CH: NN | CT SWEEP`, footer `SORT: N/A`.
- Observation (Step 3): `CT_WIFI_WINDOW_MS = 5000` (radio.h). Core-0 feeder `ct_observe_bssid()` called from the mode-agnostic passive SSID scraper (capture.cpp ~:839) — once per qualifying beacon/probe-response (fc 0x80/0x50, valid Tag-0 SSID), RADIO_CT-gated. Exact 6-byte BSSID inserts, CT-local SSID copies, sticky truncation flags only on failed insert of genuinely new identity. Timestamps = observation stamps (first_seen on first observation; first_seen==0 = empty accumulator — note: after Step-5 commits this sentinel also gates the Step-4 "committed exists" test, so a committed-from-empty-acc record would read as uncommitted; handle if it ever matters).
- Window masks (Step 4): `ct_touch_bssid_mask` (u64) / `ct_touch_ssid_mask` (u32) = the CURRENT window's observation set (duplicates mark bits too; failed inserts mark nothing — no slot, no bit).
- Temporal derivatives (Step 4.1): F_t = [B_t, S_t] from mask popcounts (NEVER acc.n_* — cumulative); signed d/dd, `n/a` until windows 2/3. Walking result: constant speed does NOT give dd≈0 — Δ/Δ² are descriptive only, never triggers.
- Baseline + envelope (Step 4.2): exact integer running mean (sum/n, no smoothing constant), min/max envelope (descriptive only), `ct_obs_count` diagnostic counter (one increment per feeder call).

## Step 5 — three-channel segmentation (IMPLEMENTED, ct.cpp)

Validity (REVISED from 4.2 — the obs>0 rule was wrong for segmentation): a window is a **valid segmentation observation iff it closes while `pause_sniffing == false`** (`was_paused` read BEFORE raising the fence). An unpaused `[0,0]` window is a legitimate RF observation (rural-highway regime) and fully participates; `ct_obs_count` is a diagnostic descriptor only — it cannot distinguish "empty RF" from "nothing qualifying on air" (both give 0, and in truly empty air an all-frames counter is also 0; the only provably muted state is the menu pause). Paused windows: skip EVERYTHING — no stats, no EWMA, no persistence, no E/T change, no commit, no window_count increment (window_count now counts valid windows only — a deliberate Step-3 semantics revision).

All fixed-point math is Q8.8 (256 = 1.0); integer isqrt helper (no FP state). Evidence is measured against the PRE-UPDATE baseline (mean established before this window), then the baseline absorbs the window. Variance via `Σx²/n − (Σx/n)²` (per-term integer division — never `(Σx)²` which overflows u32 at session scales); negative truncation clamp. Per-dimension statistics only — never pool B with S.

- **Population `[B,S]`**: `D = max(|B−μ_B|, |S−μ_S|)` count units; `CV_d = σ_d/μ_d` clamped to 1.5, with zero-mean conventions (μ>0 normal; μ=0∧σ=0 → CV=0 → floor threshold, maximally sensitive; μ=0∧σ>0 → CV_MAX — unreachable with exact integer mean but kept defensively); `thr = C1 + C2·CV_seg`, C1=2, C2=4. Evidence from the 2nd valid window.
- **Churn `[ΔB,ΔS]`**: NO CV (μ_Δ≈0 diverges). Baseline = running mean of ABSOLUTE deltas m_d; divergence = max(0, |Δ|−m_d) (EXCESS churn — sustained walking self-quietens once m adapts; a naive |Δ| detector would commit the whole journey); `n = excess/(K3·max(m,1))`, K3=3; scale floor 1 count prevents hypersensitivity at σ→0. Evidence from the 3rd valid window (m needs ≥1 sample). Signed Δ/Δ² stay descriptive.
- **Retention `R`** (Q8.8): `shared = popcount(smask & ct_prev_smask)` — pure mask intersection, NO strings stored/compared (bit→SSID mapping stable for acc's lifetime); `R = shared/prev_count` where prev_count = popcount(previous valid window's mask); prev_count==0 → **ABSTAIN = frozen channel state** (no μ_R/σ_R update, no divergence, no EWMA/persistence change — a no-vote, NOT R=0); prev>0 & cur=0 → R=0, a hard change vote. Divergence DIRECTIONAL: `max(0, μ_R−R)` only (high retention is stability, never evidence); σ_R from ΣR/ΣR² (Q8.16→isqrt→Q8.8) floored at 26 (=0.1: 25.6→26, the documented constant). Evidence from the 3rd non-abstain observation.
- **Common mechanism**: `ewma = (7·ewma + n)/8` (exact α=1/8, unsigned — no sign hazard); `persist++` iff `ewma > 256` else 0; channel triggering iff `persist ≥ N_MIN` (N_MIN=3) — the persistence state IS the trigger (no latch). `ct_evidence_update()` returns true exactly on the N_MIN−1→N_MIN crossing, feeding the temporary `[CT-TRIG]` diagnostic only.
- **Quorum**: `Σ(persist_i ≥ N_MIN) ≥ 2` evaluated per valid window → `ct_commit_segment()` (inside the fence): `acc` struct-copied to `hist[(current_idx+1)%8]` with `env_id = env_seq` + class bit `CT_FLAG_CLASS_T` (0x04, approved) from the final provisional class; current_idx/env_seq advance; `memset(acc)`; `ct_reset_segment_stats()` resets ALL per-segment scratch (population, churn, retention, EWMAs, persistence, class, prev_smask, derivatives — Δ never bridges a boundary). Ring-full overwrites oldest; env_seq keeps global order. New segment always starts provisional E; E/T alternation is an empirical expectation, never enforced.
- **Provisional E/T**: T iff `CV_seg ≥ 0.7` (179 in Q8.8), live-updated; volatility description only — never resets stats/evidence and never creates a boundary.
- New scratch ≈ 39 B file-local (churn sums 8, retention sums 10, prev_smask 4, EWMA 6, persistence 3, class 1, population Σ² 8 — Σ² was required by "existing variance machinery" which did not exist; flagged). All reset at CT exit/re-entry AND at every commit.
- Trigger state must never survive an acc reset (bit indices are meaningless across it) — prev_smask and derivatives are in the same reset set for this reason.

## Known open items

1. **Thin-margin absorption**: the exact running mean chases a sustained shift on the same timescale as persistence (worked example: commit fired at window 9 of a zero-regime, ~1 window of margin). If traces show absorption winning (persist never reaching N_MIN), the fix is a slower baseline (EWMA-μ or frozen-at-start μ) — a constants/one-line change, designed for, not yet needed.
2. EWMA hysteresis: deliberately absent; add a deadband only if traces show persist chattering at the boundary (0 SRAM — a comparison constant).
3. Churn-scale as a second E/T input: deferred to traces.
4. Committed-from-empty-acc edge (first_seen=0 reads as uncommitted): handle only if it ever occurs.
5. `window_count` in committed records now counts valid windows only.

## Diagnostic inventory (all TEMPORARY, Core-1 only, post-fence, snapshot-driven so a same-window commit can't print post-reset values)

`[CT-STEP3]` counts+trunc; `[CT-STEP4]` retention vs committed; `[CT-STEP4.1]` d/dd; `[CT-STEP4.2]` validity+mean+range (valid now = unpaused); `[CT-STEP5]` class + ewma/persist triple; `[CT-TRIG]` one line per channel crossing N_MIN this window (transition-only). When consolidating, preserve each line's distinct information (the user gates on losing information).
