"""BLE timer lifecycle patch hook (stage 1) — NimBLE-Arduino 1.4.3.

Idempotent extra_script (post: slot, same as lto_link.py): runs after
platform setup and BEFORE compilation, applies the canonical BLE-timer
lifecycle diff to the installed NimBLE-Arduino library in .pio/libdeps.

Accepted state per file: pristine (patch is applied) or already-patched
(re-run is a no-op). Anything else — wrong library version, drifted anchor,
hand-edited content, missing library directory — ABORTS the build loudly,
naming the file and hunk. It never skips or fuzzy-matches.

Hunk 4 (ble_hs_stop.c:197 ble_hs_timer_resched -> ble_hs_timer_stop) is
INTENTIONALLY NOT in this patch set (see references/ble-lifecycle.md,
Hunk 4 decision block): no PC=0-class failure exists that Hunks 3+6+fence
do not already close.

Testing override: set WAVEHOUND_NIMBLE_DIR to a copy of the library tree.
"""
import os
import sys

REQUIRED_VERSION = "1.4.3"
LIB_NAME = "NimBLE-Arduino"

# (relative file, hunk name, pristine anchor, patched anchor, replacement)
HUNKS = [
    # --- Hunk 1a: add ble_hs_timer_stop after ble_hs_timer_reset ---
    (
        "src/nimble/nimble/host/src/ble_hs.c",
        "1a: ble_hs_timer_stop after ble_hs_timer_reset",
        "    } else {\n"
        "        rc = ble_npl_callout_reset(&ble_hs_timer, ticks);\n"
        "        BLE_HS_DBG_ASSERT_EVAL(rc == 0);\n"
        "    }\n"
        "}\n",
        "    } else {\n"
        "        rc = ble_npl_callout_reset(&ble_hs_timer, ticks);\n"
        "        BLE_HS_DBG_ASSERT_EVAL(rc == 0);\n"
        "    }\n"
        "}\n"
        "\n"
        "void\n"
        "ble_hs_timer_stop(void)\n"
        "{\n"
        "    ble_npl_callout_stop(&ble_hs_timer);\n"
        "}\n",
        None,
    ),
    # --- Hunk 1b: fence inside ble_hs_timer_exp ---
    (
        "src/nimble/nimble/host/src/ble_hs.c",
        "1b: ble_hs_timer_exp state fence",
        "ble_hs_timer_exp(struct ble_npl_event *ev)\n"
        "{\n"
        "    int32_t ticks_until_next;\n",
        "ble_hs_timer_exp(struct ble_npl_event *ev)\n"
        "{\n"
        "    int32_t ticks_until_next;\n"
        "\n"
        "    if (ble_hs_enabled_state != BLE_HS_ENABLED_STATE_ON ||\n"
        "        ble_hs_sync_state == BLE_HS_SYNC_STATE_BRINGUP) {\n"
        "        return;\n"
        "    }\n",
        None,
    ),
    # --- Hunk 2: declaration in ble_hs_priv.h ---
    (
        "src/nimble/nimble/host/src/ble_hs_priv.h",
        "2: ble_hs_timer_stop declaration",
        "void ble_hs_timer_resched(void);\n",
        "void ble_hs_timer_resched(void);\n"
        "void ble_hs_timer_stop(void);\n",
        None,
    ),
    # --- Hunk 6 + counter: os_callout_timer_cb guard (guard-only when the
    #     CT_DIAG_BLE_GUARD macro is undefined) ---
    (
        "src/nimble/porting/npl/freertos/src/npl_os_freertos.c",
        "6: os_callout_timer_cb handle guard (+ gated counter)",
        "#else\n"
        "static void\n"
        "os_callout_timer_cb(TimerHandle_t timer)\n"
        "{\n"
        "    struct ble_npl_callout *co;\n"
        "\n"
        "    co = pvTimerGetTimerID(timer);\n"
        "    assert(co);\n"
        "\n"
        "    if (co->evq) {\n",
        "#else\n"
        "#if CT_DIAG_BLE_GUARD\n"
        "uint32_t wh_guard_rejects; /* C linkage; read by ct.cpp via extern \"C\" */\n"
        "#endif\n"
        "static void\n"
        "os_callout_timer_cb(TimerHandle_t timer)\n"
        "{\n"
        "    struct ble_npl_callout *co;\n"
        "\n"
        "    co = pvTimerGetTimerID(timer);\n"
        "    assert(co);\n"
        "\n"
        "    if (timer != co->handle) {\n"
        "#if CT_DIAG_BLE_GUARD\n"
        "        __atomic_fetch_add(&wh_guard_rejects, 1, __ATOMIC_RELAXED);\n"
        "#endif\n"
        "        return;\n"
        "    }\n"
        "\n"
        "    if (co->evq) {\n",
        None,
    ),
    # --- Hunk 3: callout_deinit keeps the callout struct alive ---
    (
        "src/nimble/porting/npl/freertos/src/npl_os_freertos.c",
        "3: callout_deinit keeps fn/evq, clears only the handle",
        "    xTimerDelete(co->handle, portMAX_DELAY);\n"
        "    ble_npl_event_deinit(&co->ev);\n"
        "#endif\n"
        "    memset(co, 0, sizeof(struct ble_npl_callout));\n",
        "    xTimerDelete(co->handle, portMAX_DELAY);\n"
        "    ble_npl_event_deinit(&co->ev);\n"
        "#endif\n"
        "    co->handle = NULL;\n",
        None,
    ),
    # --- Hunk 5a: persistent event queue + discard-only startup drain ---
    (
        "src/nimble/porting/nimble/src/nimble_port.c",
        "5a: persistent event queue + discard-only drain (esp_nimble_init)",
        "    /* Initialize default event queue */\n"
        "    ble_npl_eventq_init(&g_eventq_dflt);\n",
        "    /* Initialize default event queue (persists across lifecycles) */\n"
        "    if (g_eventq_dflt.q) {\n"
        "        struct ble_npl_event *ev;\n"
        "        while ((ev = ble_npl_eventq_get(&g_eventq_dflt, 0)) != NULL) {\n"
        "            (void)ev; /* discard-only startup drain: never dispatched */\n"
        "        }\n"
        "    } else {\n"
        "        ble_npl_eventq_init(&g_eventq_dflt);\n"
        "    }\n",
        None,
    ),
    # --- Hunk 5b: remove eventq_deinit (esp_nimble_deinit) ---
    (
        "src/nimble/porting/nimble/src/nimble_port.c",
        "5b: remove eventq_deinit (esp_nimble_deinit)",
        "    ble_npl_eventq_deinit(&g_eventq_dflt);\n"
        "#endif\n"
        "    ble_hs_deinit();\n",
        "    /* BLE timer lifecycle (stage 1): the default event queue persists\n"
        "     * across lifecycles; it is drained at esp_nimble_init. */\n"
        "#endif\n"
        "    ble_hs_deinit();\n",
        None,
    ),
]


def _fail(msg, env):
    print("NIMBLE-TIMER-PATCH FATAL: %s" % msg)
    if env is not None:
        env.Exit(1)
    sys.exit(1)


def main(env=None):
    override = os.environ.get("WAVEHOUND_NIMBLE_DIR")
    if override:
        libdir = override
    elif env is not None:
        libdir = env.subst("$PROJECT_LIBDEPS_DIR/$PIOENV/%s" % LIB_NAME)
    else:
        libdir = os.path.join(
            os.environ.get("PLATFORMIO_LIBDEPS_DIR", "/workspace/.pio/libdeps"),
            "esp32dev", LIB_NAME,
        )

    props = os.path.join(libdir, "library.properties")
    if not os.path.isfile(props):
        _fail("NimBLE-Arduino library not found at %s (missing "
              "library.properties). Aborting, never skipping." % libdir, env)
    version = None
    with open(props) as fh:
        for line in fh:
            if line.strip().startswith("version="):
                version = line.strip().split("=", 1)[1].strip()
                break
    if version != REQUIRED_VERSION:
        _fail("NimBLE-Arduino version is %r, expected exactly %s. Aborting."
              % (version, REQUIRED_VERSION), env)

    by_file = {}
    for rel, name, pre, post, _ in HUNKS:
        by_file.setdefault(rel, []).append((name, pre, post))

    applied, noop = [], []
    for rel, hunks in sorted(by_file.items()):
        path = os.path.join(libdir, rel)
        if not os.path.isfile(path):
            _fail("expected library file missing: %s" % path, env)
        with open(path) as fh:
            text = fh.read()
        for name, pre, post in hunks:
            # NOTE: patched anchors may CONTAIN their pristine anchors (an
            # insertion hunk's post text is a superset of its pre text), so
            # the patched state MUST be checked first.
            n_post, n_pre = text.count(post), text.count(pre)
            if n_post == 1:
                noop.append("%s :: %s" % (rel, name))
            elif n_post == 0 and n_pre == 1:
                text = text.replace(pre, post)
                applied.append("%s :: %s" % (rel, name))
            elif n_post == 0 and n_pre == 0:
                _fail("anchor not found (neither pristine nor patched) in "
                      "%s for hunk %s — the tree does not match pristine "
                      "NimBLE-Arduino %s. Aborting." % (rel, name, REQUIRED_VERSION),
                      env)
            else:
                _fail("ambiguous anchor state in %s for hunk %s "
                      "(pre=%d post=%d). Aborting." % (rel, name, n_pre, n_post), env)
        with open(path, "w") as fh:
            fh.write(text)

    print("NIMBLE-TIMER-PATCH: %d hunk(s) applied, %d already present (no-op)"
          % (len(applied), len(noop)))
    for line in applied:
        print("  applied: %s" % line)
    for line in noop:
        print("  no-op:   %s" % line)


try:
    Import("env")  # PlatformIO SCons context
except NameError:
    env = None

main(env)
