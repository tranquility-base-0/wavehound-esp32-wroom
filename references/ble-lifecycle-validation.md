# BLE timer lifecycle — Stage 1 validation record

**Historical record — initial Stage 1 (guard-only, uninstrumented) build and soak.**
This document covers the FIRST controlled flash and soak only. It is superseded for
current status by `references/ble-crash-fix-revisit-guide.md` (2026-10-12), which is
the authoritative handoff and records the later `CT_DIAG_BLE_GUARD=1` diagnostic build
and soak as a separate artifact run — different hashes, do not conflate the two
firmware images or their evidence. The follow-up plan below was written BEFORE the
diagnostic build and soak occurred; that run has since been completed and is
documented in the revisit guide, not here.

Last updated: 2026-10-11 (Stage 1 controlled flash + initial soak; run observed, not instrumented).

## Scope

Documentation-only record of the first controlled device validation of the Stage 1
BLE timer-lifecycle patch (branch `fix/ble-timer-lifecycle`, commit
`6e3bfcc5478a844fedc40b3832156a5313d99bdc`). The authoritative mechanism/lifecycle
analysis (crash causal chain, hunk-by-hunk rationale, FreeRTOS v10.4.3 timer-deletion
semantics, `&ble_hs_timer.ev` = 0x3ffc5f28 attribution) is maintained separately and
is NOT duplicated here. Nothing in this record claims the timer race has been
eliminated — the run below is encouraging preliminary runtime evidence only.

## Build identity (observed, hash-verified)

- Branch `fix/ble-timer-lifecycle`, HEAD `6e3bfcc5478a844fedc40b3832156a5313d99bdc`
  (parent `bcacd72`). Working tree clean at time of build/flash.
- NimBLE-Arduino pinned 1.4.3, libdeps tree patched in place by the idempotent hook
  (7 hunks, Hunk 4 withheld by design).
- Variant: guard-only. `CT_DIAG_BLE_GUARD` is NOT defined in this build (no
  `wh_guard_rejects` symbol, no `[CT-BLE-GUARD]` diagnostic string in the ELF).
- Artifacts (SHA-256, independently computed from the archive and matched byte-for-byte
  against the live `.pio/build/esp32dev/` images):
  - `firmware.elf` `e2ea1b6bd0d34ec5dd74d0fc716ddffad580138103b5cfc60a5db5a700a562cf`
  - `firmware.bin` `77dda5153811b6fa33526ac741d98c35504a42286821082db72927287e2c2ada` (1,262,480 B)
  - `firmware.map` `0dfb79d89130a3b2408191cbffee83019d53f3edce7cf892921adac4b777b22a`
- App-partition budget: 1,262,480 B of 1,310,720 B limit → 48,240 B remaining headroom.
- Archived under `.pio/archive/stage1-build-6e3bfcc/`; the pre-Stage-1 images are
  preserved under `.pio/archive/pre-stage1-build-6e3bfcc/` (pre-Stage-1 ELF
  `7527d0fba0f3efcd49a3d7a4347ea5768fa24bf4019c245061cf627bf997b6d9` — this is the
  build whose content class matches the crash-era archive ELF
  `fw-bcacd72-20261009T015722Z.elf`, which retains its own hash
  `52ec92e5c8a73dc3aee7802c50493282bf168d9f875da352d475298450bfcbb2` and must not be
  substituted for the Stage 1 ELF).

## Flash method and verification (observed)

- The archived Stage 1 `firmware.bin` was flashed at offset `0x10000` (app partition)
  using esptool 4.9.0 at 115200 baud — direct artifact flash, no rebuild, so the
  flashed image is hash-identical to the archived BIN above.
- esptool reported `Hash of data verified`, then reset the device.

## Test conditions (partially observed — limitations noted)

- Run duration: several hours; the exact duration and wall-clock boundaries were NOT
  recorded.
- Primary operation in CT (Chase Tail) mode, including repeated BLE scan/burst cycles
  (the regime that produced the original crashes).
- Transitions to Wi-Fi and BLE modes occurred during the run; exact mode-transition
  timings were NOT recorded.
- No `[CT-BLE-GUARD]` diagnostics were available in this build (guard-only variant);
  the guard-rejection counter was not observable at runtime.

## Observed outcome

- No crash, reset, or Guru Meditation output was observed during the run. The
  original failure signature (Core 0 `InstrFetchProhibited`, `PC=0`, `EXCVADDR=0`,
  `A2=A10=0x3ffc5f28`) did not recur.

## Interpretation (explicitly NOT proven)

- A multi-hour CT-heavy run without a recurrence of the PC=0 signature is consistent
  with the Stage 1 protections working as designed, but it is NOT proof of race
  elimination. The original crashes were intermittent across repeated BLE
  scan/burst/teardown cycles; soak coverage, exact cycle counts, and per-transition
  evidence were not recorded this run, so exposure depth is unquantified.

## Limitations

1. Uninstrumented run: no soak duration, cycle count, or transition log recorded.
2. Guard-only build: the `wh_guard_rejects` counter (the patch's own diagnostic that
   would directly show near-miss teardown callbacks being rejected) was compiled out;
   absence of crashes cannot be distinguished from absence of near-misses.
3. Single run; no controlled repetition.
4. No stress beyond the normal CT/Wi-Fi/BLE operating regime.

## Follow-up plan (proposed, not yet authorized)

- Record soak duration and mode-transition timeline (device-monitor log review) for
  the next run.
- Build with `-DCT_DIAG_BLE_GUARD=1` (via build_flags only) for an instrumented soak
  so `wh_guard_rejects` deltas are visible; guard-only and diagnostic builds stay
  separate artifacts with separate hashes.
- Decide the recurrence criterion in advance: a new `PC=0` with
  `A2=A10=0x3ffc5f28` through the host-task or timer-daemon dispatch path would mean
  the Stage 1 protections failed to close the race; any different signature is to be
  investigated as a potentially separate fault.
