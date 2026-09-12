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

The header at the top of the real-time screen shows three numbers, for example
`100/239/251`:

- **First number — distinct leaks logged this session.** This counts genuinely new
  leaks (a unique source-MAC + text pairing) that were written to the serial log.
  It is *not* the number of rows drawn on the LCD, despite the "made it to screen"
  phrasing used during development.
- **Second number — frames enqueued** to the capture queue (the "Shipped" count).
- **Third number — frames attempted** (the "arrived" count, of which some were
  dropped because the queue was full).

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
