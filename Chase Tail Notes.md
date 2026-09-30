# Chase Tail Notes

_RF environment segmentation for the Wavehound counter-surveillance mode._
_Status of this document: rewritten 2026-09-30 after the horizon-bounded
baseline redesign. Supersedes the v0.1 CYT brainstorm (wavehoundCYTbrainstorm),
whose implementation plan has been largely executed — see "Where we are" below._

---

## 1. Purpose

**CT ("Chase Tail") is a counter-surveillance mode.** Its objective is to
detect devices that persist across *changing RF environments* — the classic
signature of something (or someone) deliberately co-locating with the carrier.

It is explicitly **not** a geolocation or movement-estimation mode. "Environments"
are RF-identity neighborhoods, not places; geography is an incidental human
interpretation of a segmentation that is actually over identity sets.

The two questions CT answers:

1. **Did the RF environment change?** (segmentation)
2. **What persisted across the change?** (device persistence — the payload)

## 2. Architecture at a glance

```
Core 0 (RX context)                Core 1 (main loop)
---------------------              ----------------------------
sniffer callback                   RADIO_CT window clock (5 s)
  -> ct_observe_bssid()  --------> window close under pause fence (F10)
     inserts identities into       validity = !was_paused
     acc (48 BSSID / 32 SSID)      evidence channels (per window)
     marks touch masks             2-of-3 quorum -> commit
     counts rejected inserts       acc -> hist[E_next] (ring of 8)
     per-tick channel mask         [CT-*] diagnostics
```

- **acc**: the open (uncommitted) segment's identity accumulator. Saturates
  at 48 BSSIDs / 32 SSIDs; `trunc` flags record saturation.
- **hist[8]**: committed environments (ring), each with its identity sets,
  first/last seen, window count, and provisional E/T class.
- **Union budget**: CTState = 12,248 B inside the 14,800 B SessionBuffer slot
  (frozen layout; static-asserted).
- **Touch masks** (bit per accumulator slot) give per-window identity sets
  without copying strings; the bit->identity mapping is stable for acc's
  lifetime, so mask intersection IS identity intersection.
- **Rejected inserts**: when the tables are full, each genuinely-new identity
  that fails to insert increments a counter. This is the *only* sensor that
  sees the untracked world once saturated — it is flux-weighted (frames, not
  distinct identities, `rej <= 2*obs`).

## 3. Segmentation strategy (conceptual)

### 3.1 What an environment is

A segment is a bounded time epoch over which the RF identity neighborhood is
deemed stable. It is described by:

- the identity sets accumulated in `acc` (and their saturation state),
- horizon-bounded statistics of the per-window observation counts,
- first/last seen times and window count,
- a provisional volatility class (E = quiet, T = volatile).

Environments are enumerated E0, E1, ... by commit order and kept in an 8-slot
ring. A commit copies `acc` into the next slot, clears the accumulator, and
re-seeds all statistics — the next segment starts from a clean, seeded state.

### 3.2 The three live evidence channels

Each channel answers a *different* question; quorum requires two to agree,
which is what makes independent testimony rather than one signal read twice:

| Channel | Question | Signal | Divergence measure |
|---|---|---|---|
| POPULATION | "is the observed *level* of identities normal?" | B, S = touched slots per window | `D = max(|B−μ_B|, |S−μ_S|)` vs threshold `thr = 2 + 1.25σ` |
| CHURN | "is the *count flux* abnormal?" | per-window absolute deltas |ΔB|, |ΔS| | excess over horizon mean m |
| TURNOVER | "are *identities themselves* being swapped in/out?" | mask popcounts (new + vanished) + rejected inserts | excess over horizon mean m |

Retention (fraction of the previous window's SSIDs still present) is retained
as a **diagnostic only** — it is algebraically two views of the same identity
dynamics turnover measures, cannot fire at R=0, and is blind when the tables
are saturated. Its machinery is still in the code pending deletion.

**The co-moving bubble.** In steady transit (bus, train), the tracked identity
set often collapses to 1-2 *co-moving* identities (personal hotspots on the
vehicle) while the traversed world streams past *unsampled* — visible only as
rejected inserts. This is why turnover includes `rej`: in a saturated
accumulator it is the sole sensor of the traversed environment. Sustained
`rej > 0` with a frozen tracked set is the signature of motion through new
territory; `rej = 0` in motion (empty highway) is correctly *not* an event —
no environments are being traversed.

### 3.3 Horizon-bounded baselines (the 2026-09-30 redesign)

The original segment-total running means had four hardware-confirmed defects:
young-segment absorption (transitions eaten in 2-3 windows), old-segment
threshold inflation (whole-trip variance shielded mid-scale changes
indefinitely), quorum coincidence failure, and one-sided blindness to flux
drops. All share one root: statistics computed over the *entire segment*.

The fix: every baseline is an **EWMA on one shared clock** (α = 1/32,
τ ≈ 32 windows ≈ 160 s):

- **μ (population)**: EWMA of B and S, **seeded with the exact first valid
  sample** (seeding is load-bearing — an EWMA-from-zero start poisons
  evidence for ~20 windows).
- **σ (population noise)**: EWMA of squared residuals vs the post-update μ,
  Q8.16, **excursion-gated** (Huber-style): variance is updated only when
  `n_pre < 4` (cold-start warm-up) or `|resid| <= 3σ + 1 count`. Steps are
  learned by μ, never laundered into σ — without the gate, a step's own
  residual inflates the threshold within one window and self-shields the
  transition; with it, σ describes regime noise only.
- **m (churn, turnover)**: EWMAs of |Δ| and of turnover, seeded with the
  first observation.

The threshold is **absolute-noise**, not relative: `thr = 2 + 1.25σ`. The
former CV-based (σ/μ) threshold is ill-conditioned exactly when μ moves —
stale σ over a fresh small μ pins the threshold at its clamp — and, worse,
it made evidence for a fixed relative transition grow linearly with
population density. CT's semantics are absolute-count: environments are
distinguished by absolute identity content, measured with an absolute
instrument. C1 = 2 is the deliberate small-signal floor (fade-jitter
immunity at bubble scales).

Evidence is measured against the **pre-update** baseline each window, then
the window is absorbed — the detector always compares against what the world
looked like before this window arrived.

### 3.4 Evidence pipeline and commit

```
per-window divergence -> normalized evidence (Q8.8, clamped 32.0)
  -> channel EWMA (alpha = 1/8, frozen since Step 5)
  -> persistence counter (increment while EWMA > 1.0, reset otherwise)
  -> channel "triggering" when persistence >= 3
  -> commit when 2-of-3 {POPULATION, CHURN, TURNOVER} are triggering
  -> commit: acc -> hist, acc cleared, ALL baselines re-seeded
```

There is no artificial post-commit spike: baselines re-seed from the new
segment's first observations, so a re-learned environment produces ~no
evidence. Persistent-device detection is a *later, separate* layer built on
committed-environment identity overlap plus probe/BLE device-stream
association — it deliberately does not use adjacent-window retention.

### 3.5 Known open items (deliberate, sequenced)

1. **Downward flux blindness** — `excess = max(0, x − m)` is one-sided; a
   flux *drop* (city -> empty highway) yields exactly zero evidence at any
   clock rate, and even a two-sided formula caps drop evidence at 1/K.
   Separate future pass; must be designed against stop-and-go oscillation.
2. **Quorum coincidence** — across every hardware trace, exactly one channel
   sustains per event (POP on steps, TURN on onsets; their 3-window
   persistence intervals have not overlapped). The committed 2-of-3 quorum is
   now the binding constraint on committing; candidate fixes (time-extended
   quorum, leaky persistence) are the *next* experiment after baseline
   behavior is field-verified.
3. **Saturation blindness** — at `trunc=B` the BSSID count stops tracking
   true population (accumulator full); rej covers the untracked world, but
   the population channel is partially blind. Unchanged from inception.
4. **Zero-observation commit edge** — a commit on a window with no
   observations stamps `first_seen = 0` on the copied environment. Dormant.

## 4. Trigger logic — technical details

All arithmetic is fixed-point, integer-only, no floats.

### 4.1 Representations

- Counts and means: **Q8.8** (value × 256). μ, m, evidence, thresholds.
- Variance: **Q8.16** (value² × 65,536); σ = `isqrt(var_q16)` directly
  (isqrt of Q8.16 yields Q8.8 — no shift). Bounds: |resid| ≤ 48·256 = 12,288,
  resid² ≤ 1.51e8 fits int32; var fits uint32.
- Evidence: Q8.8, clamped to 8192 (= 32.0) where the input is unbounded
  (turnover via rej). Population and churn are naturally bounded.

### 4.2 Per-window update (valid windows only; paused windows contribute nothing)

Order matters — evidence is always computed against **pre-update** baselines:

```
1. POPULATION evidence   D = max(|B−μ_B|, |S−μ_S|)
                         thr = 512 + (σ_max·5)/4          [Q8.8; ≥ 512]
                         n_pop = (D<<8)/thr
                         evidence_update(pop EWMA, persist, n_pop)
2. CHURN evidence        ex = max(0, |ΔB|·256 − m_ab_B) (likewise S; take max)
                         scale = 3 · max(m_ab, 256)
                         n_churn = (ex<<8)/scale
3. TURNOVER evidence     turnover = new + vanished + rej   [mask popcounts + rej]
                         ex = max(0, turnover·256 − m_turn)
                         scale = 3 · max(m_turn, 256)
                         if ex > 32·scale: n = 8192        [clamp pre-shift]
                         else: n = (ex<<8)/scale
4. Absorb (after evidence):
                         μ += (x·256 − μ) >> 5             [exact seed at n_pre=0]
                         var: gated update                 [n_pre<4 or |r|≤3σ+256]
                                var += (r²>>5) − (var>>5)
                         m_ab += (|Δ|·256 − m_ab) >> 5     [seed at n_pre=1]
                         m_turn += (turnover·256 − m_turn) >> 5
5. evidence_update:      e = (7·e + n)>>8... (i.e. (7·e + n)/8)
                         persist++ while e > 256; else persist = 0
6. Quorum:               persist_pop + persist_churn + persist_turn >= 2 -> commit
```

### 4.3 Cold start (uniform)

- Window 1 (n_pre = 0): μ seeded exactly, var = 0, **no evidence**.
  `[CT-SEED]` prints the seed values.
- Window 2 (n_pre = 1): churn/turnover baselines seeded with their first
  observation; still no evidence.
- Window 3+ (n_pre ≥ 2): all three channels vote. One rule, one gate.

### 4.4 Constants (all trace-tunables, none sacred)

| Constant | Value | Meaning |
|---|---|---|
| CT_BASE_SHIFT | 5 | baseline EWMA α = 1/32 (horizon ≈ 160 s) |
| CT_C1_Q8 | 512 | threshold floor C1 = 2 counts |
| CT_C2S_NUM/DEN | 5/4 | threshold slope 1.25·σ |
| CT_SIGMA_T_Q8 | 384 | E/T class boundary (σ ≥ 1.5 counts → T) |
| CT_VAR_FLOOR_Q8 | 256 | variance gate floor (1.0 count) |
| CT_K3, CT_K5 | 3 | churn / turnover normalization K |
| CT_TURN_N_MAX_Q8 | 8192 | turnover evidence clamp (32.0) |
| CT_N_MIN | 3 | persistence length |
| (evidence EWMA) | 1/8 | smoothing before persistence (frozen since Step 5) |

Derived detection properties: a step with initial evidence n₀ = D/thr
produces peak channel EWMA ≈ 0.65·n₀ (α=1/32), so triggering needs n₀ ≳ 1.6;
detection latency for moderate steps is ~10-20 windows (EWMA lag + persist-3);
baseline absorption time (~32 windows) exceeds persistence time by ~10×, so
the trigger race is decidable by construction.

## 5. Where we are in testing

### Hardware-verified to date (six+ trace campaigns, previous builds)

- **Stationary apartment** (2.3 h segment): healthy reference; rej = 0 for
  hours; no spurious activity. Confirmed false-positive resistance.
- **City bus, multiple rounds**: discovered accumulator saturation blindness
  (led to the rej counter); exposed the co-moving bubble; first hardware
  trigger (dense→sparse, POP channel); steady-motion silence (led to
  turnover); flux-drop blindness quantified.
- **Smeared old segment** (224 windows, never committed): demonstrated
  old-segment threshold inflation — a sustained B=1→6 return was provably
  invisible (n ≈ 0.66 forever). Motivated the horizon redesign.
- **Sparse country / rural highway**: rej = 0 while moving is *correct*
  (no identity flux in empty space); confirmed rej measures
  density×traversal, not motion.

### Current build (horizon-bounded baselines) — flashed, early validation

- **Stationary enterprise office**: verified — horizon μ converges and holds
  (mean=4.00), thr rests on the C1 floor (2.00, σ ≈ 0), class=E, turnover
  idle, all persist 0, heap stable. The no-false-positive half of the
  validation is confirmed on hardware for the new model.
- **Pending**: a boarding/dense-transition trace. The simulation predicts the
  first hardware **commit**: TURN crossing ~11 windows into the onset, POP
  following as μ lags the collapse, quorum met ~window 20 (~55 s); `[CT-SEED]`
  should print at window 1 and again after the commit (re-seed proof).
  Sparse-country quiet is the other regression to watch.

### Diagnostics inventory (temporary, removal as things stabilize)

- `[CT-STEP3]` accumulator fill + trunc flags
- `[CT-STEP4]` overlap vs committed environment (diagnostic)
- `[CT-STEP4.1]` per-window B/S with Δ and Δ²
- `[CT-STEP4.2]` obs/rej/cov/13, horizon μ, envelope range, **thr**; valid=N
  variant for paused windows
- `[CT-STEP5]` class + per-channel EWMA (raw>>2) + persistence (P/C/R/T)
- `[CT-TRIG]` transition-only crossing lines per channel (POP/CHURN/RET/TURN)
- `[CT-SEED]` one-shot per segment: seeding values (verifies re-seed after commit)

## 6. Frozen decisions

- Windowing: fixed 5 s Wi-Fi windows; validity = `!was_paused` (zero-count
  windows are real observations); F10 pause fence for all structural work.
- Identity model: acc = 48 BSSID / 32 SSID slots, frozen layout; touch masks
  as per-window identity sets; rejected inserts as the untracked-world sensor.
- Turnover definition (adjacent-window, no ever-mask); flux-weighted rej.
- Evidence EWMA (1/8), persistence semantics (N_MIN = 3), 2-of-3 quorum,
  commit semantics (acc → hist ring, full statistical reset).
- The assistant never flashes, commits, or pushes unprompted; per-commit
  identity `Tranquility Base <tranquil_base@proton.me>`.
