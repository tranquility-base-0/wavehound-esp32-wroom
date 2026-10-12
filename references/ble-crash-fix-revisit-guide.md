# Wavehound BLE Timer Lifecycle Crash — Frozen, PROVISIONALLY FIXED

**Last updated:** 2026-10-12
**Repository:** `~/Projects/maker/wavehound`
**Branch:** `fix/ble-timer-lifecycle`
**HEAD:** `6e3bfcc`
**Status:** Provisionally fixed. Further investigation deferred until release validation unless new evidence warrants reopening.

**Document authority note:** This guide is the authoritative current handoff.
`references/ble-lifecycle-validation.md` is the EARLIER (2026-10-11) historical record
of the initial guard-only Stage 1 build and its uninstrumented soak — a distinct
firmware artifact (BIN `77dda515…`, 1,262,480 B) from this guide's later
`CT_DIAG_BLE_GUARD=1` diagnostic build (BIN `6971e65a…`, 1,262,576 B). Do not conflate
the two runs, their hashes, or their evidence; consult the validation record for the
first flash's history only.

## 1. Executive summary for the next agent

Wavehound's Chase Tail (CT) mode previously crashed intermittently during BLE lifecycle transitions. The observed failure was an ESP32 `InstrFetchProhibited` exception with `PC=0`, consistent with a null function-pointer invocation.

A source-level investigation identified a credible root cause in the interaction between NimBLE callout deinitialization and asynchronous FreeRTOS software-timer deletion. The Stage 1 patch addresses the identified failure path by preserving callback state during callout deinitialization, rejecting callbacks associated with invalidated timer handles, guarding host-timer expiry during selected lifecycle states, and preserving the default NimBLE event queue across lifecycle transitions.

The patch is committed as `6e3bfcc` on `fix/ble-timer-lifecycle` and has since been merged into `main` as merge commit `153393f` (the race is still NOT conclusively proven eliminated; release validation remains deferred). The instrumented diagnostic build was successfully compiled, archived, flashed, and verified. Two post-fix, multi-hour soaks have been reported crash-free. The instrumented soak produced no `[CT-BLE-GUARD]` messages.

**Decision:** Stop active investigation and move on to other repository work. Return to this issue before release, or sooner if new evidence suggests a regression.

**Do not claim that the race has been conclusively eliminated.** The original root-cause analysis is source-supported, but the baseline crash captures were not all decoded against the exact ELF corresponding to the flashed baseline image. Post-fix soaks were not logged, the baseline burst count remains unknown, and the diagnostic counter cannot detect every relevant interleaving.

### Instructions to a future agent

1. Read this document before investigating or changing BLE lifecycle code.
2. Inspect the current repository state and verify the actual HEAD before relying on the commit and artifact identities below.
3. Do not repeat the entire investigation simply because validation is incomplete. The current stopping decision is deliberate.
4. Do not modify the lifecycle patch, rebuild, flash, push, or commit without the user's authorization.
5. If a new crash occurs, preserve its full panic dump and identify the exact firmware image before drawing conclusions.
6. Distinguish **FACT**, **INFERENCE**, and **UNKNOWN** throughout any renewed investigation.

## 2. Evidence terminology

* **FACT:** Directly established by source, a captured log, a verified artifact, or a documented command result.
* **INFERENCE:** A reasoned explanation consistent with the available evidence, but not conclusively demonstrated.
* **UNKNOWN:** Requires further evidence or measurement.

A source-level fact about the archived pristine library is not automatically proof of what the flashed firmware executed. Keep binary provenance explicit.

## 3. Environment and symptom

**Hardware and software**

* ESP32-WROOM-class board; observed chip `ESP32-D0WD-V3`, revision 3.1.
* 4 MB flash, dual-core ESP32 at 240 MHz.
* PlatformIO environment: `esp32dev`.
* NimBLE-Arduino 1.4.3.
* ESP-IDF 4.4.7 / FreeRTOS Kernel V10.4.3 in the investigated build environment.

**Observed failure**

* Exception: `InstrFetchProhibited`.
* `PC=0x00000000`.
* `EXCCAUSE=0x14`.
* `A10=0x3ffc5f28`, matching the address of `ble_hs_timer.ev` in the decoded ELF.
* `ble_hs_timer` was located at `0x3ffc5f20`, with `ev` at offset `+8`.
* The original failure typically appeared within approximately ten minutes of entering CT mode.

**Timing evidence**

Two baseline crashes occurred 3.74 s and 3.76 s after the last short-gap `[DIAG]` print, approximately 0.18 s before the loop unblocked. The crashes occurred around the end of `ct_ble_burst`, which performs `ble_init_only`, a roughly two-second `ble_radio_burst`, then `ble_shutdown` and Wi-Fi restoration.

**INFERENCE:** This timing is consistent with BLE teardown in `ble_shutdown`, but the Wi-Fi restore duration is not fixed by the cited source. Timing alone does not establish the exact instruction interleaving.

## 4. Root-cause analysis

### 4.1 Asynchronous timer deletion and callout clearing

**FACT — original library behavior**

In the investigated non-mempool implementation of `npl_os_freertos.c`:

* `callout_deinit` calls `xTimerDelete(co->handle, portMAX_DELAY)`.
* FreeRTOS timer deletion is asynchronous. A successful return means the delete command was enqueued, not that the timer has finished all pending callback execution.
* The original deinitializer then clears the callout structure with `memset`, including `handle`, `evq`, and `ev.fn`.
* `os_callout_timer_cb` enqueues `&co->ev` if `co->evq` is non-NULL; otherwise it directly calls `co->ev.fn(&co->ev)`.

The FreeRTOS timer daemon can execute expired callbacks before processing pending timer commands. The investigated timer implementation also has paths where START/RESET processing can invoke a callback inline when the expiry has already passed.

Consequently, a callback can overlap callout deinitialization and observe partially or completely cleared state.

### 4.2 Failure routes

**Route A — event queued before the callout is cleared**

1. The timer callback places `&co->ev` on the event queue.
2. Callout deinitialization clears the callout, including `ev.fn`.
3. The host task subsequently dispatches the queued event.
4. Dispatch invokes the now-null callback.

The archived decode identifies the indirect call at `0x400eb2a0` in the host-task loop, with return address `0x400eb2a3`. The observed `A8=0x800eb2a3` and `A10=0x3ffc5f28` are consistent with this route.

**Route C — timer callback runs inline after callout clearing**

1. Callout deinitialization clears `evq` and `ev.fn`.
2. The timer daemon processes a straddling START/RESET operation.
3. The callback observes `evq == NULL` and directly calls `ev.fn`.
4. The null function pointer causes the exception.

The archived decode identifies the indirect call at `0x400e00f6` in `os_callout_timer_cb`, with return address `0x400e00f9`.

**Route B — late event put into a newly initialized queue**

This route was considered but ruled out as an explanation for the observed `PC=0` signature: `callout_init` in `ble_hs.c` restores the callback before the new host task exists. This conclusion is limited to the analyzed interleaving.

### 4.3 Additional source observations

* The timer daemon is priority 1 and unpinned in the investigated configuration.
* `callout_reset` clamps a zero-tick request to one tick, making very short re-arms possible.
* **INFERENCE:** Short re-arms may help explain recurrence of Route C; this has not been experimentally established.
* Six known captures were classified before the baseline log's third panic was noticed: four Route A and two Route C.

### 4.4 Binary-provenance caveat

The route decodes came from:

`.pio/archive/fw-bcacd72-20261009T015722Z.elf`

That ELF has a SHA-256 prefix of `52ec92e5…`.

The flashed baseline image had a different ELF hash prefix: `7527d0fba0f3efcd…`. The archived ELF and flashed ELF differ in `.flash.text` size (839,319 versus 839,211 bytes), likely due to an uncommitted `chart.cpp` edit.

The 09:56 crash's `A8=0x800eb2a3` and `A10=0x3ffc5f28` corroborate the Route A decode, but do not prove it conclusively. A decode against the exact flashed ELF was not completed; that ELF may have been lost after a revert.

The Route C `A8` value from a rebuild is **UNKNOWN**. `0x800e00f9` is the expected return address based on the archived decode, not a verified decode of the flashed baseline binary.

Do not silently treat these artifacts as interchangeable.

## 5. Stage 1 fix

Commit: `6e3bfcc5478a844fedc40b3832156a5313d99bdc`
Parent: `bcacd72…`
Branch: `fix/ble-timer-lifecycle`

The exact patch is in the repository's commit diff and is applied to the installed NimBLE-Arduino library by the PlatformIO patch hook.

### 5.1 Changes

1. **Callout deinitialization:** Replace the full-structure `memset` with `co->handle = NULL`, preserving the event callback and queue fields.
2. **Timer callback guard:** Reject a callback when `timer != co->handle`.
3. **Host timer expiry fence:** `ble_hs_timer_exp` returns if `ble_hs_enabled_state != ON` or `ble_hs_sync_state == BRINGUP`.
4. **Persistent default event queue:** `g_eventq_dflt` is retained across NimBLE lifecycle transitions. Initialization drains stale events rather than freeing and recreating the queue; deinitialization no longer destroys it.
5. **Optional diagnostic counter:** `wh_guard_rejects` counts handle-mismatch rejections. A delta-only `[CT-BLE-GUARD]` message is printed from `ct.cpp` when the compile-time diagnostic macro is enabled.

The temporary macro was enabled only through a `platformio.ini` build-flag edit. It was subsequently removed, and `platformio.ini` has no remaining diff.

### 5.2 Patch-hook behavior

The `extra_scripts` hook patches the installed library under `.pio/libdeps/esp32dev/NimBLE-Arduino`, which is not tracked by Git.

The hook accepts pristine NimBLE-Arduino 1.4.3 or the already-patched version, and aborts if the source matches neither expected state.

During the diagnostic build, it reported **seven expected hunks already present, zero newly applied**.

The original proposed Hunk 4—a stop-only `resched` change in `ble_hs_stop.c`—was dropped as redundant. `ble_hs_stop.c` was not changed.

### 5.3 Why the fix is expected to help

**INFERENCE:** Route A should now retain a valid callback, allowing the real `ble_hs_timer_exp` handler to execute the lifecycle fence. Route C should no longer see a cleared callback and should either enqueue the event or be rejected by the timer-handle guard.

These changes structurally address the identified failure path. They do not establish that every possible NimBLE teardown race has been eliminated.

## 6. Known residual concerns

These are reasons to retain release-validation work, not reasons to resume speculative development now.

### 6.1 Late or phantom timer expiry

A late event can potentially be enqueued into a subsequent lifecycle.

* In `OFF` and `BRINGUP`, the expiry fence suppresses the timer action.
* In `GOOD`, a stale expiry may cause an otherwise benign timer pass.
* In `BAD`, the expiry may call `ble_hs_reset`, potentially aborting an active scan while self-healing the host state.

The number of copies is not source-bounded to exactly one; each queued copy can produce at most one event dispatch.

### 6.2 Host-task exit

The `host_task` exit path uses shared `host_task_h` state with `vTaskDelete`. This is a separate, low-likelihood hazard that has not been patched or proven to cause the original crash.

### 6.3 Persistent queue and event lifetime

* A full-queue put from task context can block the daemon until a subsequent initialization drain.
* From an ISR, a failed put may leave `queued` stuck, an upstream issue.
* Queue length is `BLE_TOTAL_EV_COUNT`; the value 32 has not been verified for this configuration.
* The drain clears `queued` on popped events. That is safe for the static event storage identified in CT.
* An exhaustive audit of event-queue put sites for non-CT modes was not completed. If a heap-allocated event can enter the persistent queue and outlive its owner, the drain could create a use-after-free.

These are identified audit gaps, not demonstrated failures in the current firmware.

## 7. Validation record

### 7.1 Baseline

Log:

`logs/device-monitor-261011-093208.log`

* Unpatched image hash prefix: `7527d0fba0f3efcd…`
* Capture period: October 11, 2026, 09:32:08–12:06:23 (approximately 2 h 34 min).
* Three panics and three boots.
* Two crashes classified: 09:42:29 (Route C) and 09:56:52 (Route A).
* Third panic: **UNCLASSIFIED**.

An earlier estimate suggested roughly 0.8% crashes per burst, based on two crashes in about 250 bursts, with an approximate 95% range of 0.1–3%. The actual burst count has not been established. If the true count were around 600, the point estimate would instead be about 0.5%.

Do not use the earlier rate as a measured baseline until the burst count is verified.

### 7.2 Stage 1 soak

Several hours of use, mostly in CT mode, with some Wi-Fi/BLE switching. No crash observed.

This run was unlogged and its exact duration and transition count are unknown. Treat it as anecdotal supporting evidence.

### 7.3 Instrumented soak

The diagnostic firmware was built with `CT_DIAG_BLE_GUARD=1`.

**Verified diagnostic artifacts**

Directory:

`.pio/archive/stage1-diag-build-6e3bfcc/`

| Artifact       |         Size | SHA-256                                                            |
| -------------- | -----------: | ------------------------------------------------------------------ |
| `firmware.elf` | 11,497,936 B | `90f2f37692bb72c21c63183444afd530a227f1e85033a54224ed4eb2c0466137` |
| `firmware.bin` |  1,262,576 B | `6971e65a3e27a600ef31d7a8fcbddd799e8253b1e6c1d904d1a8c85331d6419b` |
| `firmware.map` | 11,743,677 B | `2387fb79a623bb766275a7ae5ba15294742d8a8e682f301d7343ff773b2e9e65` |

The archived artifacts matched the build outputs. The original Stage 1 archive hashes were also verified unchanged.

`esptool.py image_info` reported a valid ESP32 image with valid checksum and validation hash. The diagnostic BIN was flashed at `0x10000`; esptool reported `Hash of data verified` and performed a hard reset.

**Observed runtime result:** Several hours in CT mode, with no crash and no `[CT-BLE-GUARD]` output. The soak was unlogged, and the exact duration, mode-switch activity, and serial-monitor continuity are unknown.

### 7.4 Interpret the silent counter correctly

The diagnostic counter is not a general detector for the original race.

* It increments only when `os_callout_timer_cb` observes `timer != co->handle`.
* A Route A callback can pass the handle guard before deinitialization invalidates the handle, enqueue its event, and subsequently encounter a stale dispatch. That route can remain invisible to the counter.
* There is no heartbeat or positive control proving that the diagnostic print path was active throughout the soak.

Therefore, **zero guard reports are weak evidence only**. They do not establish that no race occurred.

## 8. Repository and workflow state at the end of the diagnostic run

**Historical snapshot.** This section records the repository state at the end of the
diagnostic workflow (2026-10-12, on branch `fix/ble-timer-lifecycle`, HEAD `6e3bfcc`).
It is NOT a description of the current repository state: Stage 1 was subsequently
merged into `main` as merge commit `153393f`, and later work may have changed the
tree further. Always verify the live branch, HEAD, and working tree before relying on
any historical repository-state detail in this document.

At the end of the diagnostic workflow:

* Branch: `fix/ble-timer-lifecycle`.
* HEAD: `6e3bfcc`.
* `platformio.ini` restored; no tracked diff.
* Working tree shows only these untracked items:

  * `logs/`
  * `references/ble-lifecycle-validation.md`
* Both untracked items must be preserved. Do not stage, overwrite, or delete them without authorization.
* Diagnostic artifacts are archived separately from the original Stage 1 artifacts.
* No diagnostic source changes were committed.
* No additional firmware build or flash is authorized merely by this handoff.

The temporary diagnostic flag was removed after the diagnostic artifacts were archived. Do not infer the contents of a future build from the archived image or current build directory alone; inspect the active configuration and patch-hook output.

## 9. Deferred release-validation plan

Do not interrupt ordinary development to complete these tasks. Revisit them before release or earlier if new evidence appears.

### 9.1 Recover the baseline crash rate

Count the long gaps between `[DIAG] Free Heap` messages in the baseline log. Each CT cycle is expected to contain one approximately 3.9-second gap:

```sh
grep -a '\[DIAG\] Free Heap' LOG |
awk '{
    split($1,t,":");
    s=t[1]*3600+t[2]*60+t[3];
    if (NR>1) {
        g=s-p;
        if (g>=3.5 && g<=4.4) long++;
    }
    p=s
}
END { print long }'
```

Replace `LOG` with the actual path. Validate the timestamp format and inspect the output before accepting it as a burst count. Do not assume every qualifying gap corresponds to exactly one burst without checking the logging behavior.

### 9.2 Classify the third baseline panic

```sh
grep -a -E 'Guru Meditation|PC +:|A2 +:|A6 +:|A10 +:' \
    logs/device-monitor-261011-093208.log
```

Review the surrounding log context and preserve the original capture. Do not classify the panic from register fragments alone if the full dump is available.

### 9.3 Optional improved diagnostic build

If quantitative validation resumes, a Stage 2 diagnostic build could add a heartbeat **inside the same compile-time diagnostic gate**, printing on the first CT BLE burst after boot and every 256 bursts thereafter:

```text
[CT-BLE-GUARD] hb bursts=<n> total=<rejects>
```

This would establish that the diagnostic path is alive and make counter silence more interpretable. It would still not detect Route A.

Optionally record the application ELF SHA using `esp_app_get_elf_sha256` if available in the current IDF 4.4 configuration.

Any diagnostic rebuild must follow the established process:

1. Verify the repository and branch state.
2. Make only the temporary authorized build-flag change.
3. Confirm the patch hook's output and inspect the diagnostic symbol/string.
4. Record BIN/ELF/MAP sizes and SHA-256 hashes.
5. Archive artifacts without overwriting existing directories.
6. Verify archived copies and the original Stage 1 archive.
7. Restore `platformio.ini` and confirm the diff is empty.
8. Obtain separate authorization before flashing or running device tests.

### 9.4 Quantitative soak sizing

Once a defensible baseline crash rate \(r\) is measured, use a predeclared test duration rather than treating an arbitrary crash-free interval as proof.

Under an independent, equal-risk-per-burst model, approximately \(3/n\) is the one-sided 95% upper bound on the crash probability after zero failures in \(n\) trials (the rule of three).

The following approximations use the earlier *unverified* rates solely for planning:

| Assumed baseline rate | About \(9/r\) clean bursts | About \(30/r\) clean bursts |
| --------------------- | -------------------------: | --------------------------: |
| 0.8%                  |               1,200 bursts |                3,900 bursts |
| 0.5%                  |               1,800 bursts |                6,000 bursts |

At approximately 6.9 seconds per burst, those correspond to roughly 2.3–2.9 hours and 7.5–11.5 hours, respectively. These are planning estimates, not a guarantee that the statistical assumptions hold.

Keep test conditions comparable when estimating the baseline and assessing the patch. A stress test is most informative when its workload and failure opportunities are characterized.

### 9.5 Assess new failures by signature

If a post-patch panic occurs:

1. Preserve the full panic dump, including the `ELF file SHA256` line.
2. Identify the exact firmware artifact that was flashed. The panic's ELF SHA identifies a build, not necessarily the currently flashed partition.
3. Verify that the patch hook applied or recognized all expected changes.
4. Decode against the exact ELF corresponding to that build.
5. Compare the PC, exception cause, and relevant registers with the original captures.

`PC=0`, `EXCCAUSE=0x14`, and `A10=0x3ffc5f28`, together with a matching host-task or timer-callback call site, would strongly warrant reopening this investigation. A different signature may indicate a separate bug; do not automatically attribute it to the timer race.

Before any renewed work, verify that the build actually includes the fix:

```sh
grep -n 'timer != co->handle' \
  .pio/libdeps/esp32dev/NimBLE-Arduino/src/nimble/nimble/porting/npl/freertos/src/npl_os_freertos.c
```

Also verify the exact NimBLE-Arduino version, patch-hook output, branch, and flashed artifact. A build from a branch that lacks the hook may reproduce the original failure.

### 9.6 Other optional work

* Fresh-clone build to verify that the patch hook applies all expected hunks from pristine NimBLE-Arduino 1.4.3.
* Exhaustive event-queue put-site and event-lifetime audit across non-CT modes.
* Revisit the host-task exit concern if new evidence implicates it.
* Decode against the exact flashed baseline ELF if that artifact can be recovered.

These tasks are deferred, not prerequisites for returning to normal repository development.

## 10. Recovery references and environment

* Repository: `~/Projects/maker/wavehound`.
* Baseline commit on `main`: `bcacd72…`.
* Recovery directory: `~/Projects/maker/wavehound-recovery-20261009`.
* The recovery directory contains a pristine NimBLE 1.4.3 clone and prior `objdump`/`addr2line` outputs.
* Toolchain: `~/.platformio/packages/toolchain-xtensa-esp32/bin/xtensa-esp32-elf-*`.
* Shell: Fish.
* An earlier audit document, `references/ble-lifecycle.md` in the Hermes skill store, had pending corrections; whether those corrections were applied is UNKNOWN.
* The shared Claude Docs report at `claude.ai/code/artifact/89a3de98-6b60-4276-8abe-be79fda42e7c` is stale: it contains an incorrect `esp_timer` premise and incorrect host-task attribution. Do not rely on it as authoritative evidence.

## 11. Final disposition

The original crash has a credible, source-supported root cause. The Stage 1 patch directly addresses the identified null-callback failure path, the diagnostic firmware was successfully flashed and verified, and two reported multi-hour soaks have been crash-free.

That is sufficient to justify freezing the fix and moving on to other repository issues. It is **not** sufficient to claim exhaustive lifecycle safety or release validation.

Keep the patch stable. Preserve the artifacts and evidence. Reopen only for new evidence, a justified engineering concern, or the planned release-validation pass.

**No flashing, pushing, or committing without the user's explicit authorization.**
