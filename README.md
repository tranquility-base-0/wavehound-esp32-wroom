# Wavehound

A packet-capture and clear-text analysis sniffer for the ESP32, with an on-device
display. It captures 802.11 traffic, parses L2/L3 protocols in place, and surfaces
the clear text that ordinary network chatter exposes — DNS/mDNS, DHCP, NetBIOS, ARP,
TLS metadata, and more — alongside vendor (OUI) resolution and a persistent
"notable finds" list.

Wavehound is passive and observation-oriented. It listens to traffic that is
already on the air and logs what it sees; it does not decrypt encrypted
communications and does not interfere with the networks it observes.

## Overview

Wavehound runs on an ESP32 with an ILI9488 TFT. Capture, parsing, classification,
and display all happen on-device. The serial monitor is the complete, authoritative
log; the on-screen views are deliberately small, curated windows into it.

## Hardware

Wavehound currently targets commodity ESP32 development hardware with a 3.5"
ILI9488 touch display and a microSD card for the OUI database — the class of
widely available all-in-one ESP32 boards often called "cheap yellow displays".

Building from source uses PlatformIO:

    pio run -e esp32dev          # build
    pio run -e esp32dev -t upload  # flash

The serial monitor runs at 460800 baud.

_detailed BOM, pinout, and wiring guide — pending_

## Buying a pre-built Wavehound

A small-batch pre-built version is planned. Store link: _placeholder_.

## Operating modes

- **WIFI** — live 2.4 GHz channel-hopping capture with clear-text leak display,
  device list, and foxhunt (locate a selected device by signal strength).
- **BLE** — Bluetooth Low Energy device scanning and listing.
- **NETWORKS** — access-point discovery and per-AP view.
- **CHANNELS** — per-channel activity metering.
- **PCAP** — promiscuous packet capture to SD card.
- **CHASE TAIL** — see below.
- **SETTINGS** — device configuration.

## Chase Tail

CHASE TAIL is Wavehound's countersurveillance mode — an implementation of the
well-known "chasing your tail" concept: detecting devices that persist across
*changing RF environments*, the classic signature of something deliberately
co-locating with the carrier. Wavehound segments the RF environment into
committed "environments" (E0, E1, …), then watches for device identities —
BSSIDs, SSIDs, probe-request traffic — that keep reappearing across distinct
environments. Detection is statistical and works over identity sets, not
geography. It is Wi-Fi-based; BLE device correlation is a planned extension,
not current behavior.

## Documentation

- `manual` — technical documentation: how the capture pipeline, counters,
  probe-request tracking, channel timing, and Chase Tail logic work under
  the hood.
- `Chase Tail Notes.md` — Chase Tail design history and engineering notes.

## License

The Wavehound firmware is open-source software, intended to be released under
the Apache License 2.0 (full license text to be added with the first public
release).

The Wavehound name and logo are the identity of this project and are not
covered by the software license: permission to use the source code does not
grant permission to present derivative products as official Wavehound devices.

Wavehound builds on third-party open components, including NimBLE-Arduino
(Apache-2.0), SdFat (MIT), TFT_eSPI (permissive/MIT-derived), and the Ubuntu
Mono typeface (Ubuntu Font Licence 1.0). Full attribution will be collected
in a NOTICE file.