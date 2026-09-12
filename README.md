# Wavehound

A packet-capture and clear-text analysis sniffer for the ESP32, with an on-device
display. It captures 802.11 traffic, parses L2/L3 protocols in place, and surfaces
the clear text that ordinary network chatter exposes — DNS/mDNS, DHCP, NetBIOS, ARP,
TLS metadata, and more — alongside vendor (OUI) resolution and a persistent
"notable finds" list.

## Overview

Wavehound runs on an ESP32 with an ILI9488 TFT. Capture, parsing, classification,
and display all happen on-device. The serial monitor is the complete, authoritative
log; the on-screen views are deliberately small, curated windows into it.

## Hardware and build

_pending — board, wiring, PlatformIO, flash procedure, and the 460800 baud serial rate._

## Operating modes

_pending — WiFi, BLE, AP scan, channel scan, foxhunt, and PCAP promiscuous capture._

## The capture pipeline

_pending — capture → filter → 30-second cooldown → queue → parse → dedup → display._

## Capture counters and display views

The header at the top of the real-time screen shows three cumulative numbers, for
example `100/239/251`. They form a funnel — the intended relationship is
x ≤ y ≤ z — and all three reset only on a session/mode reset, not per interval:

- **x — leaks logged/displayed.** Distinct leak results that made it through
  processing and were written to the serial log (a unique source-MAC + text
  pairing). It is *not* the number of rows drawn on the LCD, despite the "made it
  to screen" phrasing used during development.
- **y — successfully enqueued.** Events actually placed into a queue, including
  the deauth and crypto/WEP-TKIP bypass paths.
- **z — accepted into the pipeline.** Events that passed their applicable
  acceptance/cooldown gate and proceeded toward queueing, again including the
  bypass paths. A queue-full event therefore counts toward z but not y; the gap
  y-to-z measures frames accepted but never enqueued.

The point worth settling early: the first number can reach 100+ per cycle while the
screen can only ever show a handful of rows. That is expected and healthy. Every
distinct leak flows into three separate places, and only the serial log keeps all of
them:

1. **Serial monitor — keeps everything.** Each distinct leak prints one CLRTXT line.
   Nothing is lost here; this is the complete record.

2. **Real-time waterfall — keeps the most recent 5.** It is a rolling window: each
   new distinct leak pushes the oldest one off the bottom. Over a busy cycle it
   scrolls through 100+ distinct leaks, but at any instant only the latest five are
   visible.

3. **Persistent (sniff) list — keeps at most 20, by score.** Entries are retained by
   a score (text length plus a high-value bonus). Of the 100+ distinct leaks in a
   busy cycle, only about 20 earn or keep a slot; the rest are never inserted or are
   later evicted by a higher-value newcomer.

So nothing is silently dropped from the pipeline: every distinct leak is
serial-printed. The two on-screen views are small and curated — a live "tail" of
five and a "best-of" list of twenty — while serial remains the authoritative mirror.

## The [xN] repeat count

_pending — [xN] is the number of times the exact full-payload frame represented by a
row was received, including copies suppressed by the 30-second cooldown._

## Probe request tracking

When a device scans for networks, it broadcasts probe request frames announcing
the network names (SSIDs) it is looking for. These frames reveal a device's
history — every network it has previously joined — which makes them rich
identification evidence. Wavehound tracks this in its probe tracker view.

### Randomized MACs

Modern phones and laptops randomize the transmitter MAC address in probe
requests (the locally-administered bit is set on the address), rotating to a
new identity periodically so the same phone appears as many different "devices".
Wavehound detects this (`mac[0] & 0x02`) and applies two rules:

- A physical (non-randomized) MAC always passes, and its vendor is resolved
  from the OUI database.
- A randomized MAC passes only if the probe carries a real, printable SSID —
  a randomized probe for a wildcard (hidden-network) sweep carries no useful
  identity, so it is not tracked.

For randomized MACs, the vendor shown is *inferred* from Vendor Specific
information elements (IE tag 221) in the probe itself when present (e.g.
"Apple~IE"); otherwise it falls to SD-card OUI resolution of the transient
address, which for randomized MACs usually resolves to the chip maker rather
than the phone brand.

### IE-based device fingerprinting (hardware hash)

Every tracked probe builds a 32-bit fingerprint from the probe's information
elements:

- The **tag numbers** of every IE present are hashed in order, capturing the
  structural skeleton of the frame (which capabilities the chipset advertises).
- The **complete payload bytes** of three relatively stable IEs are also
  hashed: tag 45 (HT Capabilities), tag 127 (Extended Capabilities), and
  tag 221 (Vendor Specific).

This is best understood as an *implementation fingerprint* rather than a true
hardware identity: it fingerprints the chipset/driver's IE composition. It is
strict equality — a device that omits or reorders an information element
between probes can produce different hashes for the same radio, so it is one
signal, not proof.

### PNL (Preferred Network List) evidence

Each tracked device accumulates two forms of "where has this device been"
evidence:

- **Exact SSID history** — the real strings, deduplicated, in a per-device
  list (up to 15 entries, drawn from a shared 150-slot pool).
- **A 64-bit bitmap** (`pnl_hash`) — each SSID folds to one bit via a djb2
  hash mod 64. This is cheap and mergeable, but lossy: two different SSIDs
  collide into the same bit about 1 time in 64, so the bitmap is a hint, not
  proof. Wildcard probes (`<Wld>` for broadcast sweeps, `<Nul>` for
  blank/hidden names) are recorded but deliberately excluded from the bitmap.

### Smart endpoint identification (correlation)

Because a rotating MAC makes one phone look like five, the tracker runs a
background correlation pass (every ~5 s) that tries to merge records that are
probably the same physical device — this is the "Smart Endpoint
Identification" logic. Two records are compared with:

1. **Hardware gate** — the IE fingerprints (above) must match exactly.
   Mismatched fingerprints are never merged.
2. **Network evidence** — the two devices' PNL bitmaps are compared. An
   identical non-empty bitmap scores +50; a subset/superset relationship
   scores +30, but only when both devices have actually probed networks and
   the exact SSID histories share at least one real network name (empty
   bitmaps and bitmap-only coincidences score nothing).
3. **Spatial evidence** — instantaneous RSSI within 5 dB scores +40;
   more than 15 dB apart subtracts 50.

A merge needs a total of 70+ points. On a merge, the newer MAC and
timestamps are adopted, hit counters and MAC-rotation counts accumulate, and
the exact SSID lists are unioned — so a device that has rotated MACs twice
shows one row with 3 rotations and the combined network history, instead of
three separate entries.

What correlation cannot do: it cannot merge a rotated MAC whose fingerprint
changed between probes (the hard gate rejects it), and it cannot rescue two
devices with identical chipsets that probe identical networks at similar
signal strength — those are genuinely ambiguous from the air.

## Serial output

_pending — CLRTXT lines and the [DIAG] / [PROF] diagnostic lines._

## Supported protocols

_pending — DHCP, DNS/mDNS, ARP, ICMP, EAPOL, CDP/LLDP, NetBIOS, SSDP/UPnP, HTTP,
MQTT, SNMP, TLS SNI, and others._

## Known limitations

_pending — stateless packet-by-packet parsing, the 64-flow cache, TCP-boundary and
ASN.1 length limits, ECH._

## Glossary

_pending — Seen, Suppressed, Shipped, Arrived, Queue Drops, and the other counter
terms._
