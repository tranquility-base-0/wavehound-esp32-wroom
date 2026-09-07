#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <TFT_eSPI.h>
#include <SPI.h>
#include "SdFat.h"
#include <NimBLEDevice.h>
#include <ctype.h>
#include <string.h>
#include <algorithm>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include "tag221Lookup.h"
#include "UbuntuMono_Regular11pt7b.h"
#include "UbuntuMono_Regular9pt7b.h"
#include "UbuntuMono_Regular8pt7b.h"
#include "UbuntuMono_B9pt7b.h"
#include "UbuntuMono_RI9pt7b.h"
#include <cmath>
#include <atomic> // Add this to your includes
#include "waveHoundSprites.h"
#include "parsers/parser_common.h"
#include "parsers/dns.h"
#include "parsers/discovery.h"
#include "parsers/link_layer.h"
#include "parsers/application.h"
#include "parsers/web.h"
#include "parsers/structured.h"
#include "core/wavehound_state.h"
#include "core/radio.h"
#include "osint/vendor.h"





BssidCacheEntry bssidCache[MAX_BSSID_CACHE];

// Define the protocols so the math knows how to handle the physics

// ==========================================
// OSINT PROBE TRACKER GLOBALS
// ==========================================

ProbeSortMode currentProbeSortMode = PROBE_SORT_HITS;
bool probe_sort_descending = true;

/**
 * Universal Log-Distance Path Loss Calculator
 * * @param rssi        The received signal strength (e.g., -75)
 * @param txPower     The broadcasted TX power in dBm (0 if unknown)
 * @param protocol    The RadioProtocol enum (BLE, Wi-Fi 2.4, Wi-Fi 5)
 * @param customLoss  (Optional) Override the path loss exponent. Default 0.0 uses standard presets.
 * @return            Estimated distance in meters
 */

int ap_current_page = 0;
const int APS_PER_PAGE = 6; // Number of APs that fit safely between the header and footer

int target_rssi = 0;


// ==========================================
// WAVE HOUND PCAP & LIVE DUMP GLOBALS
// ==========================================
// ------------------------------------------
// CORE 0 CACHES
// ------------------------------------------




uint32_t leak_hash_history[32] = {0};
uint8_t  leak_hash_idx = 0;

// ------------------------------------------
// DUAL-CORE MESSAGE QUEUES & UNIFIED STRUCT
// ------------------------------------------
// Shared metadata — single source of truth




// --- TRANSIENT HEAP POINTERS ---
LiveCaptureEvent* ptr_isr_evt = nullptr;
LiveCaptureEvent* ptr_core1_evt = nullptr;





QueueHandle_t liveDumpQueue = NULL;
QueueHandle_t leakQueue = NULL;
uint8_t leak_current_page = 0;


LeakSortMode currentLeakSort = SORT_LEAK_AGE; // Default

// ==========================================
// PCAP WATERFALL GLOBALS
// ==========================================
volatile uint32_t capture_bytes_tick = 0;
uint32_t capture_bytes_render = 0;
PacketCapture terminal_history[MAX_TERMINAL_LINES];
uint16_t terminal_hits[MAX_TERMINAL_LINES] = {0};
uint32_t terminal_first_seen[MAX_TERMINAL_LINES] = {0};

volatile uint32_t debug_dropped_packets = 0;
volatile uint32_t ui_total_arrived = 0;
volatile uint32_t ui_dropped_packets = 0;

// ISR-side (Core 0) — deauth + crypto/WEP interceptors
volatile uint32_t leak_isr_attempts = 0;
volatile uint32_t leak_isr_dropped  = 0;
// ISR-side PCAP funnel diagnostics
volatile uint32_t leak_funnel_seen       = 0;
volatile uint32_t leak_funnel_suppressed = 0;
volatile uint32_t leak_funnel_shipped    = 0;
volatile uint32_t live_dump_dropped      = 0;
// Core 1 — processLiveDumpQueue() repush after parsing
uint32_t leak_core1_attempts = 0;
uint32_t leak_core1_dropped  = 0;
// ------------------------------------------
// FORMATTING HELPERS
// ------------------------------------------








// ==========================================
// ABSOLUTE WATERFALL GLOBALS
// ==========================================
uint32_t traffic_history[240] = {0}; // 480 width / 2px increments = 240 columns
uint32_t absolute_max_traffic = 10;  // Seeded to prevent divide-by-zero
// ==========================================
// FOXHUNT STATE GLOBALS
// ==========================================
bool is_selecting_target = false; 
bool is_foxhunting = false;
uint8_t foxhunt_target_mac[6] = {0};
char foxhunt_target_vendor[28] = "Unknown";

// Foxhunt Math & Alert State
float smoothed_rssi = -100.0f;
int baseline_rssi = -100;
int last_displayed_rssi = -999;  // Sentinel: forces redraw on first frame.
                                  // Must differ from -100.0f initial smoothed_rssi
                                  // so updater redraws before first packet arrives.
int last_drawn_min = 0;          // NEW: Sentinel for bounds redraw
int last_drawn_max = 0;          // NEW: Sentinel for bounds redraw

// Cached spatial bounds — written from Core 1 only,
// read from Core 0 ISR via updateFoxhuntSignal. Avoids sessionData
// scan inside ISR callback path.
volatile int8_t foxhunt_rssi_min = -100;
volatile int8_t foxhunt_rssi_max = -100;
volatile bool foxhunt_bounds_seeded = false;

// --- Forward Declarations for OSINT Probe Tracker ---
int addSsidToPool(const char* ssid, int head_idx, bool &already_exists, bool &added, uint8_t current_count);
void processProbeRequestShared(uint8_t* mac, const char* ssid, const char* known_vendor = "", int8_t rssi = -100, uint32_t hw_hash = 0);


UIState currentState = SCREEN_CHART;






// Fixed, static memory blocks
ProbeRecordShared probeList[MAX_PROBE_SLOTS];
SSIDNode ssidPool[TOTAL_SSID_POOL];

int probe_current_page = 0; 
const int PROBES_PER_PAGE = 5;

// ==========================================
// BLUETOOTH DATA STRUCTURE
// ==========================================

// 1. Define this enum above the struct so it exists in memory first


// 2. The perfectly aligned struct


// Perfectly aligned with your drawDeviceList() function!

// NimBLE Global Scanner Pointer
BLEScan* pBLEScan;



// Still exactly 80 bytes!




int total_sniffed_probes = 0;
int device_current_page = 0;
const int DEVICES_PER_PAGE = 13; // 9pt font with 18px line spacing fits 13 devices perfectly

std::atomic<bool> pause_sniffing{false};
bool useLogScale = false;

bool sort_descending = true; // Default to loudest devices first

uint16_t calData[5] = { 288, 3501, 301, 3244, 7 };
TFT_eSPI tft = TFT_eSPI();


const int HEADER_HEIGHT = 108; 
const int CHART_BOTTOM = 298;
const int chart_start_y = HEADER_HEIGHT + 53;

int current_x = 0;


//Should be 80 bytes





BeaconEntry beaconDict[MAX_BEACON_DICT];
uint8_t beaconDictCount = 0;

// ==========================================
// OUI RAM CACHE (Ring Buffer)
// ==========================================


// ==========================================
// 1. LIVE BUFFER (Shared RAM)
// ==========================================


// ==========================================
// 2. SORT BUFFER (Shared RAM)
// ==========================================


// ==========================================
// 3. SESSION BUFFER (Shared RAM)
// ==========================================


bool force_ui_refresh = false;

// Color utility fn
constexpr uint16_t hex24to565(uint32_t hex24) {
  return ((((hex24 >> 16) & 0xFF) & 0xF8) << 8) |
  ((((hex24 >> 8) & 0xFF) & 0xFC) << 3) |
  (((hex24) & 0xFF) >> 3);
}

// 8-color array using standard web hex codes!
uint16_t colors[9] = {
  hex24to565(0x7CD9CA), // [0] Mint Green
  hex24to565(0xFF00FF), // [1] Magenta
  hex24to565(0xD9D680), // [2] Pale Yellow
  hex24to565(0xB75BE2), // [3] Purple
  hex24to565(0x87E370), // [4] Bright Green
  hex24to565(0xD1C9CA), // [5] Light Gray
  hex24to565(0xDA815E), // [6] Rust/Orange  
  hex24to565(0x889FD7), // [7] Periwinkle Blue
  TFT_DARKGREY          // [8] "Other" category (unchanged)
  //hex24to565(0xE07EB6), // [6] Pink
};

// FNV-1a 32-bit Hash


// ==========================================
// PHY RATE TO MBPS TRANSLATOR
// ==========================================


bool isSameDevice(int idxA, int idxB) {
    // GATE 1: HARDWARE (Strict pass/fail)
    if (probeList[idxA].hardware_hash != probeList[idxB].hardware_hash) {
        return false; 
    }

    int confidence_score = 0;

    // GATE 2: BEHAVIORAL (Scoring)
    uint64_t hashA = probeList[idxA].pnl_hash;
    uint64_t hashB = probeList[idxB].pnl_hash;
    
    if (hashA == hashB && hashA != 0) {
        confidence_score += 50; // Exact match of non-empty networks
    } else if ((hashA & hashB) == hashB || (hashA & hashB) == hashA) {
        confidence_score += 30; // Perfect subset match
    }

    // GATE 3: SPATIAL (Scoring)
    int rssi_delta = abs(probeList[idxA].rssi - probeList[idxB].rssi);
    if (rssi_delta <= 5) {
        confidence_score += 40; // Physically occupying the same space
    } else if (rssi_delta > 15) {
        confidence_score -= 50; // Physics dictate these are likely different locations
    }

    // THE VERDICT
    return (confidence_score >= 70);
}

uint8_t getSsidBitIndex(const char* ssid) {
    unsigned long hash = 5381; // Standard djb2 seed
    int c;
    while ((c = *ssid++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash % 64; // Constrain to exactly 64 bits
}

void ingestBeacon(uint8_t* bssid, const char* ssid, int8_t rssi) {
    // Skip hidden networks — no useful cross-reference value
    if (ssid == nullptr || strlen(ssid) == 0) return;
    
    // Search for existing entry
    for (int i = 0; i < beaconDictCount; i++) {
        if (memcmp(beaconDict[i].bssid, bssid, 6) == 0) {
            // Update existing
            beaconDict[i].rssi = rssi;
            beaconDict[i].last_seen = millis();
            return;
        }
    }
    
    // New entry
    if (beaconDictCount < MAX_BEACON_DICT) {
        memcpy(beaconDict[beaconDictCount].bssid, bssid, 6);
        strncpy(beaconDict[beaconDictCount].ssid, ssid, 32);
        beaconDict[beaconDictCount].ssid[32] = '\0';
        beaconDict[beaconDictCount].rssi = rssi;
        beaconDict[beaconDictCount].last_seen = millis();
        beaconDictCount++;
    }
    // No eviction needed — beacon SSIDs are stable,
    // so a full dictionary means you've already catalogued
    // everything in the local airspace
}

// Returns the number of SSIDs in a probe record's list
// that have a known beacon in the dictionary
int crossReferenceProbeToBeacons(int probe_idx, 
                                  uint8_t* matched_bssid_out,
                                  int8_t* ap_rssi_out) {
    int matches = 0;
    int best_match_rssi_diff = 999;
    
    // Walk the probe record's SSID linked list
    int node = probeList[probe_idx].first_ssid_idx;
    
    while (node != -1) {
        const char* probed_ssid = ssidPool[node].text;
        
        // Skip wildcard entries
        if (strcmp(probed_ssid, "<Wld>") == 0 || 
            strcmp(probed_ssid, "<Nul>") == 0) {
            node = ssidPool[node].next_node_idx;
            continue;
        }
        
        // Search the beacon dictionary for this SSID
        for (int i = 0; i < beaconDictCount; i++) {
            if (strcmp(beaconDict[i].ssid, probed_ssid) == 0) {
                matches++;
                
                // Find the AP whose RSSI is closest to the probe RSSI
                // (same physical space = similar signal strength)
                int rssi_diff = abs(probeList[probe_idx].rssi - 
                                    beaconDict[i].rssi);
                if (rssi_diff < best_match_rssi_diff) {
                    best_match_rssi_diff = rssi_diff;
                    if (matched_bssid_out) 
                        memcpy(matched_bssid_out, beaconDict[i].bssid, 6);
                    if (ap_rssi_out) 
                        *ap_rssi_out = beaconDict[i].rssi;
                }
            }
        }
        
        node = ssidPool[node].next_node_idx;
    }
    
    return matches;
}

void updateFoxhuntSignal(int packet_rssi) {
  // 1. Set dynamic tuning parameters
  float current_alpha = 0.2; // Default for WiFi/AP

  if (currentRadioMode == RADIO_BLE) {
    current_alpha = 0.55;
  }

  // 2. Initialize or smooth the signal safely
  if (smoothed_rssi == -100.0f) {
    smoothed_rssi = (float)packet_rssi;
  } else {
    smoothed_rssi = (current_alpha * (float)packet_rssi) +
                    ((1.0f - current_alpha) * smoothed_rssi);
  }

  // ==========================================
  // 3. REAL-TIME TACTICAL STRETCHING
  // Mode-agnostic: Works for Wi-Fi, AP, and BLE
  // ==========================================
  
  // Stretch the floor (Triggering on 0 for Wi-Fi and -100 for BLE sentinels)
  if (foxhunt_rssi_min == 0 || foxhunt_rssi_min == -100 || packet_rssi < foxhunt_rssi_min) {
      foxhunt_rssi_min = packet_rssi;
  }
  
  // Stretch the ceiling 
  if (foxhunt_rssi_max == -100 || packet_rssi > foxhunt_rssi_max) {
      foxhunt_rssi_max = packet_rssi;
      foxhunt_bounds_seeded = true;
  }
}

// ==========================================
// CLEARTEXT EXTRACTOR (OSINT UPGRADED)
// ==========================================


// ==========================================
// PROTOCOL TRANSLATORS (NetBIOS, mDNS, Cast)
// ==========================================

// Returns a human-readable label for the NetBIOS suffix byte.
// Shortened slightly from the Python version to prevent text wrapping on the ILI9488 TFT.


// Decodes the A-P string, populates the display name, and returns the suffix byte.
// decodedName buffer should be at least 17 bytes (16 chars + null terminator).


// ---------------------------------------------------------
// NETBIOS (NBNS) PARSER (Port 137)
// Decodes A-P encoded names and identifies the service type
// ---------------------------------------------------------


// ---------------------------------------------------------
// NETBIOS DATAGRAM (NBDS) PARSER (Port 138)
// Extracts cleartext hostnames, domains, and workgroups 
// from SMB Browser / Mailslot packets
// ---------------------------------------------------------




// ---------------------------------------------------------
// SANITIZED ASCII COPY HELPER
// ---------------------------------------------------------


// ---------------------------------------------------------
// LIGHTWEIGHT IPv6 FORMATTER (TFT-Friendly Notation)
// ---------------------------------------------------------


// ---------------------------------------------------------
// HARDENED DNS NAME DECODER
// ---------------------------------------------------------


// ---------------------------------------------------------
// DHCPv4 (IPv4) PARSER
// Extracts Message Type, Primary DNS, and highest-value text 
// Priority: FQDN > Hostname > Domain > Vendor > Fallback ASCII
// ---------------------------------------------------------



// ---------------------------------------------------------
// DHCPv6 (IPv6) PARSER
// Extracts Message Type and highest-value text (FQDN > Vendor > ASCII)
// ---------------------------------------------------------




static inline uint16_t read_u16(const uint8_t* p, uint16_t len, int offset) {
    if (offset < 0 || offset + 1 >= len) return 0;
    return (p[offset] << 8) | p[offset + 1];
}

// Compresses a fully-expanded IPv6 address string (8 groups, e.g.
// "fe80:0000:0000:0000:1cee:da6a:322a:dd7a") into standard compressed
// form (e.g. "fe80::1cee:da6a:322a:dd7a") per RFC 5952: collapses only
// the single longest run of consecutive all-zero groups (length >= 2),
// and strips leading zeros within each remaining group.
// `full` and `out` must be different buffers.




// --- Memory-Safe HTTP Header Helper ---


// --- The Upgraded Parser ---


// --- Helper: Trim Whitespace ---
// Strips leading and trailing whitespace/newlines from extracted XML values


// --- Memory-Safe XML Value Extractor ---


// --- The WS-Discovery Parser ---


// ============================================================================
// UPGRADED X.509 CERTIFICATE & IDENTITY EXTRACTOR
// ============================================================================
// Scans raw TLS Handshakes / A-MSDU blobs for ASN.1 DER structures.
// Extracts Subject (Target Server), Issuer (CA), Geographic Location, 
// SANs, URLs, Emails, and Establishment Dates.
// ============================================================================


// ==========================================
// UPGRADED TLS SNI PARSER (Client Hello)
// ==========================================


// ============================================================================
// MEMORY-SAFE IPP (INTERNET PRINTING PROTOCOL) PARSER
// ============================================================================
// Walks strict TLV structures: Tag -> NameLen -> Name -> ValLen -> Value
// Rejects malformed structures. Extracts user and document names securely.
// ============================================================================


// ============================================================================
// MEMORY-SAFE SYSLOG PARSER
// Extracts a single-line syslog message while validating an optional PRI.
// ============================================================================
















// --- Helper: Decode Variable Length Integer ---


// --- Helper: Memory-Safe String Extractor ---


// --- Helper: Topic Validator (Operates on RAW bytes) ---


// --- MQTT Type 1: CONNECT ---


// --- MQTT Type 3: PUBLISH ---


// --- Main Entry: MQTT Framing Validation ---


// ============================================================================
// MEMORY-SAFE CoAP (CONSTRAINED APPLICATION PROTOCOL) PARSER
// ============================================================================
// Validates the fixed CoAP header and walks the variable-length option
// encoding safely.
//
// Extracts:
//   - Message type
//   - Request/response code
//   - URI-Path
//   - URI-Query
//   - Content-Format
//   - Observe
//   - Printable payload data
//
// CoAP RFC 7252:
//   Byte 0: Ver | Type | TKL
//   Byte 1: Code
//   Byte 2-3: Message ID
//   Byte 4+: Token
//   Then: Options
//   0xFF: Payload Marker
//
// Designed for packet-level parsing. It does not perform TCP/DTLS
// reassembly or decryption.
// ============================================================================



// ---------------------------------------------------------
// SSDP VERBOSE / SAFE PARSER
//
// Handles:
//   M-SEARCH * HTTP/1.1
//   NOTIFY * HTTP/1.1
//   HTTP/1.1 200 OK
//
// Extracts useful SSDP/UPnP headers while keeping the
// resulting string bounded by max_len.
// ---------------------------------------------------------







// ---------------------------------------------------------
// LLMNR PARSER (Port 5355)
// Extracts Windows local network name resolution queries
// ---------------------------------------------------------


// ---------------------------------------------------------
// LLMNR PARSER (Port 5355)
// Extracts Windows local network name resolution queries
// ---------------------------------------------------------
// --- Memory-Safe LLDP Parser ---




// --- Memory-Safe CDP (Cisco Discovery Protocol) Parser ---


// ============================================================================
// PRODUCTION-GRADE SOCKS4 / SOCKS4a / SOCKS5 PARSER
// ============================================================================
// Handles:
//   SOCKS4  request / response
//   SOCKS4a domain-name requests
//   SOCKS5 method negotiation
//   SOCKS5 username/password method negotiation
//   SOCKS5 CONNECT / BIND / UDP ASSOCIATE
//   SOCKS5 IPv4 / IPv6 / domain destinations
//   SOCKS5 replies
//
// Security / robustness:
//   - No reads occur before explicit length validation
//   - All variable-length fields are subtraction-bounded
//   - No password contents are extracted
//   - Output construction is strictly bounded
//   - Rejects malformed/truncated structures
// ============================================================================



// ---------------------------------------------------------
// TINY JSON EXTRACTOR (No dynamic memory required)
// ---------------------------------------------------------


// ---------------------------------------------------------
// DROPBOX LAN SYNC PARSER (Port 17500)
// Extracts version, namespaces, displayname, and host_int
// ---------------------------------------------------------


// ---------------------------------------------------------
// SNMP PARSER (Ports 161, 162)
// Extracts cleartext community strings from SNMPv1/v2c
// ---------------------------------------------------------


// ---------------------------------------------------------
// GENERIC JSON CATCH-ALL
// Tries to extract useful data from unknown proprietary JSON UDP protocols
// ---------------------------------------------------------
// Finds "outer_key": { ... }, then searches for inner_key strictly inside that
// object's span (via brace matching), mirroring Python's data['body']['deviceInfo']['model'].


// Approximates what json.loads() gives you for free: rejects binary garbage that
// happens to contain '{'/'}' bytes, while still tolerating a missing final '}'
// from mid-capture truncation (unlike json.loads, which would just discard that too).




// ---------------------------------------------------------
// ARP PARSER
// Extracts IPv4 <-> MAC mappings
//
// ARP packet layout:
//   0-1   Hardware Type
//   2-3   Protocol Type
//   4     Hardware Address Length
//   5     Protocol Address Length
//   6-7   Opcode
//   8-13  Sender Hardware Address (SHA)
//   14-17 Sender Protocol Address (SPA)
//   18-23 Target Hardware Address (THA)
//   24-27 Target Protocol Address (TPA)
// ---------------------------------------------------------




// ==========================================
// LIGHTWEIGHT ICMPv4 PARSER (OSINT Upgraded)
// ==========================================


// ---------------------------------------------------------
// ICMPv6 DNSSL / DNS SEARCH LIST DECODER
//
// Decodes the Domain Names field of an ICMPv6 Neighbor
// Discovery DNSSL option (ND option type 31).
//
// Input:
//   data     = beginning of Domain Names field
//   data_len = number of bytes available
//
// Output:
//   "domain1,domain2,domain3"
//
// Returns number of characters written, or -1 on malformed
// input.
// ---------------------------------------------------------


// ---------------------------------------------------------
// ICMPv6 / NDP PARSER
//
// Extracts high-value IPv6 control-plane information:
//   - Echo Request / Reply
//   - Destination Unreachable
//   - Packet Too Big
//   - Time Exceeded
//   - Parameter Problem
//   - Router Solicitation
//   - Router Advertisement
//   - Neighbor Solicitation
//   - Neighbor Advertisement
//   - Redirect
//
// NDP options:
//   1  = Source Link-Layer Address
//   2  = Target Link-Layer Address
//   3  = Prefix Information
//   5  = MTU
//   24 = Route Information
//   25 = RDNSS
//   31 = DNSSL
//
// ICMPv6 payload begins at byte 0.
// ---------------------------------------------------------

// ---------------------------------------------------------
// ICMPv6 MESSAGE TYPE NAME
// ---------------------------------------------------------



// ---------------------------------------------------------
// ICMPv6 CODE NAME
// ---------------------------------------------------------



// ---------------------------------------------------------
// APPEND TEXT SAFELY
// ---------------------------------------------------------


// ---------------------------------------------------------
// ICMPv6 PARSER
// ---------------------------------------------------------


// ==========================================
// TKIP/WEP RATE LIMITER (ISR SAFE)
// ==========================================
// Returns true if we should push this alert to the queue
bool should_alert_crypto(const uint8_t* mac_a, const uint8_t* mac_b, uint32_t current_ms) {
    
    // --- THE MAC NORMALIZATION FIX ---
    // Always store the numerically smaller MAC first. 
    // This collapses AP->STA and STA->AP into a single bidirectional conversation slot.
    const uint8_t* lo = (memcmp(mac_a, mac_b, 6) <= 0) ? mac_a : mac_b;
    const uint8_t* hi = (lo == mac_a) ? mac_b : mac_a;

    int oldest_idx = 0;
    uint32_t oldest_time = 0xFFFFFFFF;

    // 1. Scan the cache for a match AND track the oldest slot simultaneously
    for (int i = 0; i < ALERT_CACHE_SIZE; i++) {
        
        // Match found using the normalized MACs!
        if (memcmp(crypto_cache[i].mac_src, lo, 6) == 0 &&
            memcmp(crypto_cache[i].mac_dst, hi, 6) == 0) {
            
            if (current_ms - crypto_cache[i].last_alert_ms > SEC_COOLDOWN_MS) {
                crypto_cache[i].last_alert_ms = current_ms;
                return true;
            }
            return false; // Still in cooldown
        }

        // --- THE LRU EVICTION FIX ---
        // Keep track of the stalest entry in case we need to evict.
        if (crypto_cache[i].last_alert_ms < oldest_time) {
            oldest_time = crypto_cache[i].last_alert_ms;
            oldest_idx = i;
        }
    }
    
    // 2. New flow: Overwrite the genuinely oldest slot (True LRU)
    memcpy(crypto_cache[oldest_idx].mac_src, lo, 6);
    memcpy(crypto_cache[oldest_idx].mac_dst, hi, 6);
    crypto_cache[oldest_idx].last_alert_ms = current_ms;
    
    return true;
}

void drawTelemetryHeader() {
    // 1. Snapshot the volatile variables
    uint32_t current_total = ui_total_arrived;
    uint32_t current_drops = ui_dropped_packets;

    // 2. Reset the counters for the next 3-second window
    ui_total_arrived = 0;
    ui_dropped_packets = 0;

    // 3. Calculate how many successfully entered the queue
    uint32_t current_processed = 0;
    if (current_total > current_drops) {
        current_processed = current_total - current_drops;
    }

    // 4. MATCH THE "OTHER" BANNER STYLING
    tft.setFreeFont(&UbuntuMono_Regular9pt7b);
    tft.setTextDatum(TL_DATUM); 
    tft.setTextColor(COLOR_HOT_CHEST, TFT_BLACK);
    
    // 5. Erase the old numbers (Aligned to the OTHER wipe zone, but slightly wider)
    tft.fillRect(285, 0, 135, 20, TFT_BLACK); 
    
    // 6. Format with strict 3-digit padding to prevent text jitter
    char stat_text[32];
    snprintf(stat_text, sizeof(stat_text), "Pkts:%3u/%3u", current_processed, current_total);
    
    // 7. Draw the string exactly where OTHER goes
    tft.drawString(stat_text, 285, 1);
}







// --- The Smart Endpoint Wi-Fi Sniffer Callback ---
void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (pause_sniffing) return;
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint16_t len = pkt->rx_ctrl.sig_len;
  uint8_t* payload = pkt->payload;

  if (len < 24) return; // Safety check ensures bytes 22 and 23 exist!

  // Extract MAC addresses immediately since we need them for both modes
  uint8_t* addr1 = payload + 4;  // Receiver
  uint8_t* addr2 = payload + 10; // Transmitter
  uint8_t* mac3 = payload + 16;  // BSSID / Source / Dest

  // ==========================================
  // DIRECT FOXHUNT ISR FEEDER (GLOBAL)
  // ==========================================
  if (is_foxhunting) {
      // Pre-calculate to keep the ISR blazing fast
      bool target_is_tx = (memcmp(addr2, foxhunt_target_mac, 6) == 0);

      if (currentRadioMode == RADIO_AP || currentRadioMode == RADIO_WIFI) {
          
          // THE PHYSICS FIX (Signal Strength)
          // ONLY feed the math engine if our target is the physical transmitter.
          // Because we require an AP lock first, the channel is already frozen.
          // We don't need any dynamic channel-locking logic here!
          if (target_is_tx) {
              updateFoxhuntSignal(pkt->rx_ctrl.rssi);
          }
      }
  }
  // ==========================================

  // ==========================================
  // NEW: MODE-AGNOSTIC PASSIVE SSID SCRAPER 
  // Runs in ALL modes to silently maintain the BSSID Cache
  // ==========================================
  uint16_t fc = payload[0] | (payload[1] << 8);
  
  // Check if Beacon (0x80) or Probe Response (0x50)
  if ((fc & 0xFF) == 0x80 || (fc & 0xFF) == 0x50) {
      // Address 3 (mac3) is the BSSID in these frames
      int offset = 36; // Skip MAC header (24 bytes) + Fixed Mgmt Params (12 bytes)
      
      if (offset + 1 < len && payload[offset] == 0x00) { // Tag 0 is SSID
          uint8_t ssid_len = payload[offset + 1];
          
          if (ssid_len > 0 && ssid_len <= 32 && (offset + 2 + ssid_len) <= len) {
              int target_idx = -1;
              int oldest_idx = 0;
              uint32_t oldest_time = 0xFFFFFFFF;
              
              for (int i = 0; i < MAX_BSSID_CACHE; i++) {
                  if (memcmp(bssidCache[i].bssid, mac3, 6) == 0) {
                      target_idx = i;
                      break;
                  }
                  if (bssidCache[i].last_seen < oldest_time) {
                      oldest_time = bssidCache[i].last_seen;
                      oldest_idx = i;
                  }
              }
              
              if (target_idx == -1) target_idx = oldest_idx;
              
              memcpy(bssidCache[target_idx].bssid, mac3, 6);
              memcpy(bssidCache[target_idx].ssid, &payload[offset + 2], ssid_len);
              bssidCache[target_idx].ssid[ssid_len] = '\0';
              bssidCache[target_idx].last_seen = millis();
          }
      }
  }
  // ==========================================

  // ==========================================
  // BYPASS: AP WATERFALL MODE FUNNEL
  // ==========================================
  if (currentRadioMode == RADIO_AP) {
    
    // PART 1: THE DICTIONARY (Catch Beacons to learn SSIDs)
    if (type == WIFI_PKT_MGMT) {
      uint8_t subtype = (payload[0] >> 4) & 0x0F;
      
      // Subtype 8 is a Beacon Frame
      if (subtype == 8) { 
        int ap_index = -1;
        for (int i = 0; i < liveApCount; i++) {
          if (memcmp((void*)liveApData[i].bssid, addr2, 6) == 0) {
            ap_index = i;
            break;
          }
        }
        
        if (ap_index == -1) {
          if (liveApCount < MAX_AP_RECORDS) {
            // Space available, claim the next slot
            ap_index = liveApCount;
            liveApCount++;
          } else {
            // ==========================================
            // THE STALE & WEAK HYBRID EVICTION
            // ==========================================
            unsigned long now = millis();
            int stalest_idx = 0;
            int weakest_idx = 0;
            unsigned long oldest_time = 0xFFFFFFFF;
            int lowest_rssi = 127; // Max possible int8_t

            for (int i = 0; i < MAX_AP_RECORDS; i++) {
              if (liveApData[i].last_seen < oldest_time) {
                oldest_time = liveApData[i].last_seen;
                stalest_idx = i;
              }
              if (liveApData[i].rssi < lowest_rssi) {
                lowest_rssi = liveApData[i].rssi;
                weakest_idx = i;
              }
            }

            // 1. The Ghost Hunt (Evict if silent for > 60 seconds)
            if ((now - oldest_time) > 60000) {
              ap_index = stalest_idx;
            }
            // 2. The Weakest Link (Evict if new AP is stronger than our worst AP)
            else if (pkt->rx_ctrl.rssi > lowest_rssi) {
              ap_index = weakest_idx;
            }
          }

          // If we successfully claimed a slot (either a new one or an evicted one)
          if (ap_index != -1) {
            
            // --- NEW: EVICTION SAFETY INIT ---
            // Explicitly clear the country memory before the IE walk so 
            // the new AP doesn't inherit a stale code from the previous occupant.
            liveApData[ap_index].country[0] = '\0';
            liveApData[ap_index].country[1] = '\0';
            liveApData[ap_index].country[2] = '\0';
            // ---------------------------------

            // ==========================================
            // THE BEACON DECODER (Extract True Channel & SSID)
            // ==========================================
            uint8_t true_channel = CHANNELS[current_ch_idx]; // Fallback to current hopper
            char extracted_ssid[32] = "<HIDDEN>"; // Default to hidden
            
            // Beacons have a 24-byte MAC Header + 12-byte Fixed Parameters = 36 bytes before Tags begin.
            int offset = 36; 
            
            while (offset < len - 4) { // Loop through tags, stopping before the 4-byte FCS checksum
              uint8_t tag_num = payload[offset];
              uint8_t tag_len = payload[offset + 1];
              
              if (offset + 2 + tag_len > len) break; // Memory safety bounds check
              
              // Tag 0: SSID
              if (tag_num == 0) {
                if (tag_len > 0 && tag_len <= 31) {
                  memcpy(extracted_ssid, payload + offset + 2, tag_len);
                  extracted_ssid[tag_len] = '\0'; // Null terminate
                }
              }
              // Tag 3: DS Parameter Set (Current Channel)
              else if (tag_num == 3 && tag_len == 1) {
                true_channel = payload[offset + 2];
              }
              // --- NEW: TAG 7 COUNTRY CODE PARSER ---
              else if (tag_num == 7 && tag_len >= 2) {
                uint8_t c0 = payload[offset + 2];
                uint8_t c1 = payload[offset + 3];
                
                // Sanity check: valid ISO country codes are uppercase ASCII letters
                if (c0 >= 'A' && c0 <= 'Z' && c1 >= 'A' && c1 <= 'Z') {
                    liveApData[ap_index].country[0] = c0;
                    liveApData[ap_index].country[1] = c1;
                    liveApData[ap_index].country[2] = '\0';
                }
              }
              // --------------------------------------
              offset += 2 + tag_len; // Jump to the next tag
            }
            ingestBeacon(addr2, extracted_ssid, pkt->rx_ctrl.rssi);

            // ==========================================
            // POPULATE THE AP RECORD
            // ==========================================
            memcpy((void*)liveApData[ap_index].bssid, addr2, 6);
            
            unsigned long now = millis();
            liveApData[ap_index].first_seen = now;
            liveApData[ap_index].last_seen = now;
            liveApData[ap_index].packets = 0;
            liveApData[ap_index].sum_bytes = 0;
            liveApData[ap_index].sum_sq_bytes = 0;
            liveApData[ap_index].tx_bytes = 0;
            liveApData[ap_index].rx_bytes = 0;
            liveApData[ap_index].max_rate = 0;
            liveApData[ap_index].rssi = pkt->rx_ctrl.rssi;
            liveApData[ap_index].rssi_min = pkt->rx_ctrl.rssi;
            liveApData[ap_index].rssi_max = pkt->rx_ctrl.rssi;
            liveApData[ap_index].channel = true_channel; // <--- INJECT THE TRUE CHANNEL
            
            // ssid is char ssid[26] — trimmed from 28 to accommodate rssi_min/rssi_max
            strncpy((char*)liveApData[ap_index].ssid, extracted_ssid, sizeof(liveApData[ap_index].ssid));
            
            // ADD THIS LINE: Force null termination to prevent runaway memory reads
            liveApData[ap_index].ssid[sizeof(liveApData[ap_index].ssid) - 1] = '\0';

            // ==========================================
            // NEW: O(N) CLONE DETECTION ON DISCOVERY
            // ==========================================
            liveApData[ap_index].has_clone = false;

            if (strlen((char*)liveApData[ap_index].ssid) > 0 && 
                strcmp((char*)liveApData[ap_index].ssid, "<HIDDEN>") != 0 && 
                strcmp((char*)liveApData[ap_index].ssid, "<UNKNOWN>") != 0) {
                
                for (int i = 0; i < liveApCount; i++) {
                    // Skip self-comparison (crucial if ap_index claimed an evicted slot)
                    if (i == ap_index) continue;

                    if (strcmp((char*)liveApData[i].ssid, (char*)liveApData[ap_index].ssid) == 0) {
                        liveApData[ap_index].has_clone = true;
                        liveApData[i].has_clone = true;
                        break; 
                    }
                }
            }
            // ==========================================

          } // Closes `if (ap_index != -1)`
        } // Closes `if (ap_index == -1)`

        // If the AP made it into the array, update metadata but IGNORE TRAFFIC MATH!
        if (ap_index != -1) {
          liveApData[ap_index].last_seen = millis();
          liveApData[ap_index].rssi = pkt->rx_ctrl.rssi; 
          if (pkt->rx_ctrl.rssi < liveApData[ap_index].rssi_min) {
              liveApData[ap_index].rssi_min = pkt->rx_ctrl.rssi;
          }
          // rssi_max == 0 means uninitialized — same sentinel logic as MacRecord
          if (pkt->rx_ctrl.rssi > liveApData[ap_index].rssi_max || 
              liveApData[ap_index].rssi_max == 0) {
              liveApData[ap_index].rssi_max = pkt->rx_ctrl.rssi;
          }
          // --- TRAFFIC COUNTERS INTENTIONALLY DELETED HERE ---
          // We only want WIFI_PKT_DATA frames (handled below) to trigger the math engine!

          uint8_t current_rate = getBitrateMbps(pkt);
          if (current_rate > liveApData[ap_index].max_rate) {
              liveApData[ap_index].max_rate = current_rate;
          }
        }
      }
    }

    // PART 2: THE COUNTER (Catch Data frames to measure volume)
    else if (type == WIFI_PKT_DATA) {
      for (int i = 0; i < liveApCount; i++) {
        bool is_tx = (memcmp((void*)liveApData[i].bssid, addr2, 6) == 0);
        bool is_rx = (memcmp((void*)liveApData[i].bssid, addr1, 6) == 0);
        
        if (is_tx || is_rx) {
          liveApData[i].packets += 1;
          liveApData[i].sum_bytes += len;
          liveApData[i].sum_sq_bytes += ((uint64_t)len * len);
          liveApData[i].rssi = pkt->rx_ctrl.rssi;
          liveApData[i].last_seen = millis();
          
          // Max Rate Trap: Only update if the new packet is faster!
          uint8_t current_rate = getBitrateMbps(pkt);
          if (current_rate > liveApData[i].max_rate) {
              liveApData[i].max_rate = current_rate;
          }

          // Route the traffic
          if (is_tx) liveApData[i].tx_bytes += len;
          else       liveApData[i].rx_bytes += len;
          
          break; 
        }
      }
    }
    
    return; // Returns cleanly from RADIO_AP mode
  }

  // ==========================================
  // BYPASS: CHANNEL SPECTRUM MODE
  // ==========================================
  if (currentRadioMode == RADIO_CHANNELS) {
    uint8_t ch = CHANNELS[current_ch_idx];
    int idx = -1; 

    // 1. Search for the active channel in our existing array
    for (int i = 0; i < liveChannelCount; i++) {
        if (liveChannelData[i].channel == ch) {
            idx = i;
            break;
        }
    }

    // 2. If it's a completely new channel, claim the next available slot
    if (idx == -1) {
        if (liveChannelCount < MAX_CHANNEL_RECORDS) {
            idx = liveChannelCount;
            liveChannelData[idx].channel = ch;
            unsigned long now = millis();
            liveChannelData[idx].first_seen = now;
            liveChannelData[idx].last_seen = now;
            
            // Seed the physics engine
            liveChannelData[idx].avg_rssi = (float)pkt->rx_ctrl.rssi;
            liveChannelData[idx].prev_rssi = (float)pkt->rx_ctrl.rssi; // Remember the very first packet
            liveChannelData[idx].ema_variance = 0.0; 
            liveChannelData[idx].ema_cov = 0.0;      
            
            liveChannelCount++; 
        } else {
            return; 
        }
    }

    // 3. Process the packet exactly as before
    liveChannelData[idx].packets += 1;
    liveChannelData[idx].sum_bytes += len;
    liveChannelData[idx].sum_sq_bytes += ((uint64_t)len * len);
    liveChannelData[idx].last_seen = millis();
    
    // --- EMA MEAN, VARIANCE, & COVARIANCE CALCULATION ---
    float alpha = 0.05; // 5% weight to new packets, 95% to history
    float current_rssi = (float)pkt->rx_ctrl.rssi;
    
    // 1. Calculate the difference from the mean for the CURRENT packet
    float diff = current_rssi - liveChannelData[idx].avg_rssi;
    
    // 2. Calculate the difference from the mean for the PREVIOUS packet
    float prev_diff = liveChannelData[idx].prev_rssi - liveChannelData[idx].avg_rssi;
    
    // 3. Update Autocovariance (Must happen before updating variance/mean)
    liveChannelData[idx].ema_cov = (1.0 - alpha) * (liveChannelData[idx].ema_cov + alpha * diff * prev_diff);
    
    // 4. Update Variance
    liveChannelData[idx].ema_variance = (1.0 - alpha) * (liveChannelData[idx].ema_variance + alpha * diff * diff);
    
    // 5. Update Mean
    liveChannelData[idx].avg_rssi += (alpha * diff);
    
    // 6. Store current RSSI into memory for the next packet's covariance check
    liveChannelData[idx].prev_rssi = current_rssi;
    
    // --- UPLINK / DOWNLINK ROUTER ---
    uint8_t ds_flags = payload[1] & 0x03;
    bool to_ds   = (ds_flags & 0x01); // Client -> AP
    bool from_ds = (ds_flags & 0x02); // AP -> Client

    bool is_uplink = false;
    if (to_ds && !from_ds) is_uplink = true;
    else if (payload[0] == 0x40) is_uplink = true; // Probe Requests

    if (is_uplink) liveChannelData[idx].rx_bytes += len; 
    else           liveChannelData[idx].tx_bytes += len; 

    return; 
  }

  // ==========================================
  // PROBE REQUEST BOUNCER (Runs only in WIFI mode)
  // ==========================================
  // Check if Frame Control byte 0 is 0x40 (Subtype 4: Probe Request)
  if (payload[0] == 0x40) {
    // ==========================================
    // THE SMART BOUNCER & IE PARSER
    // ==========================================
    bool is_randomized = (addr2[0] & 0x02) != 0;
    
    int offset = 24; 
    char final_ssid[33] = "";
    bool is_valid_ssid = false; 
    
    char ie_vendor[25] = "";    
    uint8_t highest_weight_found = 0; // Resets for every new packet
    uint32_t live_hw_hash = 5381;
    // 1. FIRST PASS: Parse the IE tags to build the profile
    while (offset < len - 4) {
      uint8_t tag_num = payload[offset];
      uint8_t tag_len = payload[offset + 1];
      
      if (offset + 2 + tag_len > len) break; // Memory safety boundary
      
      // --- BUILD THE HARDWARE HASH ---
      // 1. Always hash the tag_num (Captures the structural skeleton)
      live_hw_hash = ((live_hw_hash << 5) + live_hw_hash) + tag_num;

      // 2. Selectively hash the payload (Captures the unchangeable DNA)
      // Tag 45: HT Caps | Tag 127: Ext Caps | Tag 221: Vendor Specific
      if (tag_num == 45 || tag_num == 127 || tag_num == 221) {
          for (int p = 0; p < tag_len; p++) {
              live_hw_hash = ((live_hw_hash << 5) + live_hw_hash) + payload[offset + 2 + p];
          }
      }
      // ------------------------------------

      // Extract the SSID (Tag 0)
      if (tag_num == 0) {
        if (tag_len == 0) {
          strlcpy(final_ssid, "<Wld>", sizeof(final_ssid));
        } 
        else if (tag_len <= 32) {
          if (payload[offset + 2] == 0x00) {
            strlcpy(final_ssid, "<Nul>", sizeof(final_ssid));
          } else {
            bool has_valid_chars = false;
            for (int c = 0; c < tag_len; c++) {
              char ch = payload[offset + 2 + c];
              if (ch >= 32 && ch <= 126) {
                final_ssid[c] = ch;
                has_valid_chars = true; 
              } else {
                final_ssid[c] = '.';
              }
            }
            final_ssid[tag_len] = '\0';
            
            if (has_valid_chars) {
              is_valid_ssid = true; // Valid printable network name found!
            } else {
              strlcpy(final_ssid, "<Nul>", sizeof(final_ssid));
            }
          }
        }
      }
      
      // Extract the True Vendor via Tag 221
      else if (tag_num == 221 && tag_len >= 3) {
        // Search the compiled array from your include/tag221Lookup.h file
        for (int v = 0; v < TAG_221_COUNT; v++) {
          if (payload[offset+2] == TAG_221_DATABASE[v].oui[0] && 
              payload[offset+3] == TAG_221_DATABASE[v].oui[1] && 
              payload[offset+4] == TAG_221_DATABASE[v].oui[2]) {
                
            if (TAG_221_DATABASE[v].weight > highest_weight_found) {
              highest_weight_found = TAG_221_DATABASE[v].weight;
              snprintf(ie_vendor, sizeof(ie_vendor), "%s~IE", TAG_221_DATABASE[v].name);
            }
            break; 
          }
        }
      }
      
      offset += 2 + tag_len; 
    }

    // 2. THE DECISION GATE
    // Universal Pass: Real MACs get through.
    // Conditional Pass: Randomized MACs only get through if targeting a named network.
    if (!is_randomized || (is_randomized && is_valid_ssid)) {
      if (strlen(final_ssid) > 0) { 
        
        // ONLY pass the Tag 221 guess if the MAC is randomized!
        // If it is a physical MAC, pass an empty string so Core 1 checks the SD Card.
        if (is_randomized) {
          processProbeRequestShared(addr2, final_ssid, ie_vendor, pkt->rx_ctrl.rssi, live_hw_hash);
        } else {
          processProbeRequestShared(addr2, final_ssid, "", pkt->rx_ctrl.rssi, live_hw_hash); 
        }
        
      }
    }    
    return; // EXIT EARLY: Do not let Management frames hit the bandwidth math!
  }
  // ==========================================
  // PCAP handling:
  // ==========================================
  // 1. MASTER FRAME FILTER (Data & Deauths)
  // ==========================================
  uint8_t frame_type = payload[0] & 0x0C;
  uint8_t frame_subtype = (payload[0] & 0xF0) >> 4;

  // Allow Data frames (Type 0x08) AND Deauth frames (Type 0x00, Subtype 12)
  if (frame_type != 0x08 && !(frame_type == 0x00 && frame_subtype == 12)) return;

  // ==========================================
  // 2. INSTANT DEAUTH INTERCEPTOR
  // ==========================================
  if (frame_type == 0x00 && frame_subtype == 12) {
      uint32_t now_ms = xTaskGetTickCountFromISR() * portTICK_PERIOD_MS;
      
      // Management frame headers are strictly 24 bytes. 
      // The 2-byte Reason Code sits immediately after the header (Little-Endian).
      uint16_t reason_code = 0;
      if (len >= 26) {
          reason_code = payload[24] | (payload[25] << 8);
      }

      PacketCapture leak;
      memset(&leak, 0, sizeof(PacketCapture));
      
      leak.meta.timestamp = now_ms;
      leak.meta.frame_length = pkt->rx_ctrl.sig_len;
      leak.meta.channel = pkt->rx_ctrl.channel;
      leak.meta.frame_subtype = 12;
      leak.meta.is_high_value = true; // Deauths are always a massive red flag!
      
      // Address 1: Destination, Address 2: Source, Address 3: BSSID
      memcpy(leak.meta.dst_mac, payload + 4, 6);
      memcpy(leak.meta.src_mac, payload + 10, 6);
      memcpy(leak.meta.bssid, payload + 16, 6);

      // Create a highly visible alert using the Reason Code
      snprintf(leak.text, MAX_LEAK_STR_LEN - 1, "DEAUTH (Reason: %d)", reason_code);

      // Fire directly to the UI, completely bypassing the Data parser
      if (leakQueue != NULL) {
          leak_isr_attempts++;
          if (xQueueSendFromISR(leakQueue, &leak, NULL) != pdTRUE) leak_isr_dropped++;
      }
      // Fire directly to the UI, completely bypassing the Data parser
      //if (leakQueue != NULL) xQueueSendFromISR(leakQueue, &leak, NULL);
      // Fire directly to the UI and Logger, completely bypassing the Data parser
      //if (leakQueue != NULL) xQueueSendFromISR(leakQueue, &leak, NULL);
      //if (liveDumpQueue != NULL) xQueueSendFromISR(liveDumpQueue, &leak, NULL);
      
      return; 
  }

  // ==========================================
  // 3. LEAKY PCAP CLEARTEXT EXTRACTOR
  // ==========================================
  if (currentRadioMode == RADIO_PCAP) { // <-- THE CRITICAL GATE
      // 1. TALLY ABSOLUTE RF VOLUME (Before the gate!)
      capture_bytes_tick += pkt->rx_ctrl.sig_len;
      
      bool is_protected = (payload[1] & 0x40) != 0;
      
      if (!is_protected) {
          // ==========================================
          // DYNAMIC MAC HEADER SIZING (HT Control & WDS)
          // ==========================================
          bool is_qos = (payload[0] & 0x80) != 0;
          bool to_ds = (payload[1] & 0x01) != 0;
          bool from_ds = (payload[1] & 0x02) != 0;
          
          // FIX 1: Strict check for +HTC. The Order bit (0x80) only means +HTC 
          // if it is a QoS Data frame! Otherwise, it just means "Strictly Ordered".
          bool has_ht_ctrl = is_qos && ((payload[1] & 0x80) != 0); 
          
          uint8_t header_len = 24;          // Base MAC Header
          if (to_ds && from_ds) {
              header_len += 6;              // Address 4 present (WDS Bridge)
          }
          
          // --- SAFE QOS OFFSET ---
          // Save the exact location of the QoS Control field before HT Control shifts the header length!
          uint8_t qos_offset = header_len; 
          
          if (is_qos) {
              header_len += 2;              // QoS Control present
          }
          if (has_ht_ctrl) {
              header_len += 4;              // HT Control present
          }
          // ==========================================

          // --- METADATA EXTRACTION ---
          uint8_t captured_subtype = (payload[0] & 0xF0) >> 4;
          uint8_t captured_direction = payload[1] & 0x03; 
          uint8_t captured_channel = pkt->rx_ctrl.channel; 
          uint8_t captured_protocol = 0; 
          // --------------------------------
          
          if (len > header_len) {
              uint8_t* frame_body = payload + header_len;
              uint16_t body_len = len - header_len;
              
              // --- STRIP LLC, IP, AND UDP HEADERS ---
              uint16_t captured_src_port = 0;
              uint16_t captured_dst_port = 0;
              uint16_t ether_type = 0; 
              uint8_t tcp_flags = 0;   
              
              uint8_t captured_ip_version = 0;
              uint8_t captured_src_ip[16] = {0};
              uint8_t captured_dst_ip[16] = {0};

              // =======================================================
              // FIX 2: THE A-MSDU BYPASS
              // =======================================================
              bool is_amsdu = false;
              if (is_qos) {
                  is_amsdu = (payload[qos_offset] & 0x80) != 0;
              }

              if (is_amsdu) {
                  // Do NOT chop `body_len`. Do NOT step `frame_body`.
                  // Force an unknown protocol (255) so it bypasses all strict IP parsers.
                  // The ENTIRE massive aggregate blob will fall straight through to the Catch-All!
                  captured_protocol = 255;
              }
              
              // 1. Skip LLC/SNAP Header (8 bytes) if present AND not an A-MSDU.
              if (!is_amsdu && body_len > 8 && frame_body[0] == 0xAA && frame_body[1] == 0xAA) {
                  bool is_apple = (frame_body[3] == 0x00 && frame_body[4] == 0x17 && frame_body[5] == 0xF2);
                  ether_type = (frame_body[6] << 8) | frame_body[7]; // <--- GRAB ETHERTYPE HERE  
                  frame_body += 8;
                  body_len -= 8;

                  // --- NEW: APPLE AWDL SHIM BYPASS ---
                  // Apple AWDL injects a 6-byte shim before the real IPv6 header (86 DD).
                  // --- UPGRADED: APPLE AWDL SHIM BYPASS (SLIDING WINDOW) ---
                  if (is_apple && body_len > 8) {
                      // Apple's shim changes size. We hunt up to 16 bytes ahead for the IPv6 header (86 DD).
                      int shim_len = -1;
                      for (int s = 0; s < 16; s++) {
                          if (s + 1 < body_len && frame_body[s] == 0x86 && frame_body[s+1] == 0xDD) {
                              shim_len = s;
                              break;
                          }
                      }
                      
                      if (shim_len != -1) {
                          ether_type = 0x86DD; // Force the EtherType to IPv6
                          
                          // THE FIX: Step OVER the 86 DD bytes (+2) to reach the 0x60 IPv6 header!
                          frame_body += (shim_len + 2);
                          body_len -= (shim_len + 2);
                      }
                  }

                  // --- 802.1Q VLAN TAG STRIPPING ---
                  // If EtherType is 0x8100, the packet has a 4-byte VLAN tag injected before the IP header.
                  if (ether_type == 0x8100 && body_len > 4) {
                      // The real EtherType is located right after the 2-byte TCI (Tag Control Information)
                      ether_type = (frame_body[2] << 8) | frame_body[3];
                      frame_body += 4; // Step over the VLAN tag
                      body_len -= 4;
                  }
                  // --------------------------------------
              }

              // 2. Check for IPv4 (First nibble is 4)
              if (!is_amsdu && body_len > 20 && (frame_body[0] & 0xF0) == 0x40) {
                  captured_ip_version = 4;
                  // --- NEW: Read Logical IP Length to strip Wi-Fi FCS/Padding ---
                  uint16_t ip_total_len = (frame_body[2] << 8) | frame_body[3];
                  // Safety check: ensure IP length isn't larger than our physical capture
                  if (ip_total_len < body_len) {
                  body_len = ip_total_len; 
                  }
                  // --------------------------------------------------------------
                  // IPv4 Source IP is at offset 12, Destination IP is at offset 16
                  memcpy(captured_src_ip, &frame_body[12], 4);
                  memcpy(captured_dst_ip, &frame_body[16], 4);

                  uint8_t ip_header_len = (frame_body[0] & 0x0F) * 4;
                  
                  // 3. Check Protocol field (Byte 9) for UDP (17)
                  if (frame_body[9] == 17 && body_len > (ip_header_len + 8)) {
                      captured_protocol = 17;
                      uint8_t* udp_header = frame_body + ip_header_len;
                      captured_src_port = (udp_header[0] << 8) | udp_header[1];
                      captured_dst_port = (udp_header[2] << 8) | udp_header[3];
                      
                      frame_body += (ip_header_len + 8);
                      body_len -= (ip_header_len + 8);
                  }
                  // 4. Check Protocol field for TCP (6)
                  else if (frame_body[9] == 6 && body_len > (ip_header_len + 20)) {
                      captured_protocol = 6;
                      uint8_t* tcp_header = frame_body + ip_header_len;
                      captured_src_port = (tcp_header[0] << 8) | tcp_header[1];
                      captured_dst_port = (tcp_header[2] << 8) | tcp_header[3];
                      tcp_flags = tcp_header[13]; // <--- GRAB TCP FLAGS HERE

                      uint8_t tcp_header_len = ((tcp_header[12] & 0xF0) >> 4) * 4;
                      if (body_len > (ip_header_len + tcp_header_len)) {
                          frame_body += (ip_header_len + tcp_header_len);
                          body_len -= (ip_header_len + tcp_header_len);
                      } else {
                          body_len = 0; // Prevent underflow if no payload
                      }
                  }
                  // --- ICMPv4 (1) and Unknown Protocol Catch-All ---
                  else if (frame_body[9] == 1 && body_len > ip_header_len) {
                      captured_protocol = 1; // ICMPv4
                      frame_body += ip_header_len; 
                      body_len -= ip_header_len;
                  } else {
                      // Unknown protocol (e.g. IGMP, GRE). 
                      // Strip the IP header so payload catch-alls don't print garbage!
                      if (body_len > ip_header_len) {
                          frame_body += ip_header_len;
                          body_len -= ip_header_len;
                      } else {
                          body_len = 0;
                      }
                  }
              }
              // 2.5 Check for IPv6 (First nibble is 6)
              else if (!is_amsdu && body_len > 40 && (frame_body[0] & 0xF0) == 0x60) {
                  captured_ip_version = 6;
                  
                  // IPv6 Source IP is at offset 8, Destination IP is at offset 24
                  memcpy(captured_src_ip, &frame_body[8], 16);
                  memcpy(captured_dst_ip, &frame_body[24], 16);

                  uint8_t next_header = frame_body[6]; // IPv6 uses "Next Header" instead of Protocol
                  uint8_t ip_header_len = 40; // Fixed size for base IPv6 header

                  // ==========================================
                  // NEW: EXTENSION HEADER HOPPER (Hop-by-Hop)
                  // Apple injects Hop-by-Hop (0) into mDNS and ICMPv6 multicasts.
                  // ==========================================
                  if (next_header == 0 && body_len > ip_header_len + 8) {
                      // The first byte of the extension is the TRUE protocol (e.g., 17 for UDP)
                      next_header = frame_body[ip_header_len];
                      
                      // Length is calculated as (Byte[1] + 1) * 8
                      uint8_t ext_len_modifier = frame_body[ip_header_len + 1];
                      uint16_t total_ext_len = (ext_len_modifier + 1) * 8;
                      
                      // Safely advance the IP header boundary to step over the extension
                      if (body_len > ip_header_len + total_ext_len) {
                          ip_header_len += total_ext_len;
                      }
                  }
                  // ==========================================
                  if (next_header == 17 && body_len > (ip_header_len + 8)) {
                      captured_protocol = 17; // UDP
                      uint8_t* udp_header = frame_body + ip_header_len;
                      captured_src_port = (udp_header[0] << 8) | udp_header[1];
                      captured_dst_port = (udp_header[2] << 8) | udp_header[3];
                      
                      frame_body += (ip_header_len + 8);
                      body_len -= (ip_header_len + 8);
                  } else if (next_header == 6 && body_len > (ip_header_len + 20)) {
                      captured_protocol = 6; // TCP
                      uint8_t* tcp_header = frame_body + ip_header_len;
                      captured_src_port = (tcp_header[0] << 8) | tcp_header[1];
                      captured_dst_port = (tcp_header[2] << 8) | tcp_header[3];
                      tcp_flags = tcp_header[13]; // <--- GRAB TCP FLAGS HERE

                      uint8_t tcp_header_len = ((tcp_header[12] & 0xF0) >> 4) * 4;
                      if (body_len > (ip_header_len + tcp_header_len)) {
                          frame_body += (ip_header_len + tcp_header_len);
                          body_len -= (ip_header_len + tcp_header_len);
                      }
                  } else if (next_header == 58 && body_len > ip_header_len) {
                      // --- NEW: ICMPv6 (58) ---
                      captured_protocol = 58; // ICMPv6
                      frame_body += ip_header_len;
                      body_len -= ip_header_len;
                  } else {
                      // Unknown protocol or contains extension headers. Just strip the fixed IP header.
                      if (body_len > ip_header_len) {
                          frame_body += ip_header_len;
                          body_len -= ip_header_len;
                      } else {
                          body_len = 0;
                      }
                  }
              }

              // =========================================================
              // TCP/443 PAYLOAD HANDOFF DIAGNOSTIC
              // =========================================================
              /*
              if (captured_protocol == 6 &&
                  (captured_src_port == 443 || captured_dst_port == 443)) {

                  Serial.printf(
                      "[SNIFF-TCP443] src=%u dst=%u flags=0x%02X "
                      "payload_len=%u ether=0x%04X ip_ver=%u\n",
                      captured_src_port,
                      captured_dst_port,
                      tcp_flags,
                      body_len,
                      ether_type,
                      captured_ip_version
                  );

                  if (body_len > 0 && frame_body != nullptr) {
                      Serial.print("[SNIFF-TCP443] payload first32: ");

                      uint16_t dump_len =
                          min((uint16_t)32, body_len);

                      for (uint16_t i = 0; i < dump_len; i++) {
                          Serial.printf("%02X ", frame_body[i]);
                      }

                      Serial.println();
                  }
              }
              */

              // =========================================================
              // 3. THE HIGH-SPEED ISR FUNNEL (LRU Cache & Deduplication)
              // =========================================================
              leak_funnel_seen++;
              // 1. Generate the fast integer hash of the flow
              uint32_t current_hash = hash_flow(frame_body, body_len, captured_src_port, captured_dst_port);
              
              uint32_t now_ms = millis();
              bool should_process = false;
              int cache_idx = -1;
              int oldest_idx = 0;
              uint32_t oldest_time = 0xFFFFFFFF;

              // 2. Scan the LRU Cache
              for (int i = 0; i < MAX_ACTIVE_FLOWS; i++) {
                  // Found an existing flow
                  if (flow_cache[i].flow_hash == current_hash) {
                      cache_idx = i;
                      break;
                  }
                  // Keep track of the stalest record in case we need to evict
                  if (flow_cache[i].last_seen_ms < oldest_time) {
                      oldest_time = flow_cache[i].last_seen_ms;
                      oldest_idx = i;
                  }
              }

              if (cache_idx != -1) {
                  // Existing Flow: Update stats and check the 30-second cooldown
                  flow_cache[cache_idx].count++;
                  flow_cache[cache_idx].last_seen_ms = now_ms;
                  
                  if (now_ms - flow_cache[cache_idx].last_printed_ms > LIVE_DUMP_COOLDOWN_MS) {
                      should_process = true;
                      flow_cache[cache_idx].last_printed_ms = now_ms;
                  } else {
                      leak_funnel_suppressed++;
                      static uint32_t suppressed = 0;
                      suppressed++;
                      if (suppressed % 20 == 1) {
                          //Serial.printf("[PCAP-DEDUP] Cooldown suppressed repeat (hash=0x%08X, total=%u)\n", current_hash, suppressed);
                      }
                  }
              } else {
                  // New Flow: Evict the oldest record and claim the slot
                  cache_idx = oldest_idx;
                  flow_cache[cache_idx].flow_hash = current_hash;
                  flow_cache[cache_idx].first_seen_ms = now_ms;
                  flow_cache[cache_idx].last_seen_ms = now_ms;
                  flow_cache[cache_idx].last_printed_ms = now_ms;
                  flow_cache[cache_idx].count = 1;
                  should_process = true;
              }

              // =========================================================
              // 4. SHIP RAW BYTES TO CORE 1 
              // =========================================================
              
                            if (should_process) {

                  // =========================================================
                  // BUILD TRANSIENT FULL-PAYLOAD TRANSPORT EVENT
                  // =========================================================

                  uint16_t copy_len = body_len;

                  if (copy_len > MAX_LIVE_CAPTURE) {
                      copy_len = MAX_LIVE_CAPTURE;
                  }

                  // The '&' reference lets the compiler treat the heap memory exactly like a local object!
                  LiveCaptureEvent& live_evt = *ptr_isr_evt;
                  memset(&live_evt, 0, sizeof(LiveCaptureEvent));

                  live_evt.meta.timestamp     = now_ms;
                  live_evt.meta.frame_length  = pkt->rx_ctrl.sig_len;
                  live_evt.meta.flow_hash     = current_hash;

                  live_evt.meta.src_port      = captured_src_port;
                  live_evt.meta.dst_port      = captured_dst_port;
                  live_evt.raw_len   = copy_len;
                  live_evt.meta.ether_type    = ether_type;

                  live_evt.meta.ip_version    = captured_ip_version;
                  live_evt.meta.protocol      = captured_protocol;
                  live_evt.meta.tcp_flags     = tcp_flags;
                  live_evt.meta.channel       = captured_channel;
                  live_evt.meta.direction     = captured_direction;
                  live_evt.meta.frame_subtype = captured_subtype;

                  memcpy(live_evt.meta.bssid,   mac3,         6);
                  memcpy(live_evt.meta.src_mac, payload + 10, 6);
                  memcpy(live_evt.meta.dst_mac, payload + 4,  6);

                  memcpy(live_evt.meta.src_ip, captured_src_ip, 16);
                  memcpy(live_evt.meta.dst_ip, captured_dst_ip, 16);

                  if (copy_len > 0) {
                      memcpy(live_evt.raw_payload, frame_body, copy_len);
                  }

                  // =========================================================
                  // TCP/443 DIAGNOSTIC
                  // =========================================================
                  /*
                  if (captured_protocol == 6 &&
                      (captured_src_port == 443 || captured_dst_port == 443)) {

                      Serial.printf(
                          "[CALLBACK-TCP443] "
                          "src=%u dst=%u flags=0x%02X "
                          "body_len=%u copy_len=%u sig_len=%u\n",
                          captured_src_port,
                          captured_dst_port,
                          tcp_flags,
                          body_len,
                          copy_len,
                          pkt->rx_ctrl.sig_len
                      );

                      if (copy_len > 0) {
                          Serial.print("[CALLBACK-TCP443] first32: ");

                          uint16_t dump_len = min((uint16_t)32, copy_len);

                          for (uint16_t i = 0; i < dump_len; i++) {
                              Serial.printf("%02X ", live_evt.raw_payload[i]);
                          }

                          Serial.println();
                      }
                  }
                  */

                  // =========================================================
                  // SHIP FULL PAYLOAD TO CORE 1
                  // =========================================================

                                    if (liveDumpQueue != NULL) {
                      ui_total_arrived++;

                      if (xQueueSendFromISR(
                              liveDumpQueue,
                              &live_evt,
                              NULL) != pdTRUE) {

                          debug_dropped_packets++;
                          ui_dropped_packets++;
                          live_dump_dropped++;
                      } else {
                          leak_funnel_shipped++; // <-- IT BELONGS EXACTLY HERE
                      }
                  }

              }   // closes if (should_process)

          }       // <-- THIS closes if (len > header_len)
      }           // <-- THIS closes if (!is_protected)
      else {
          // ==========================================
          // INSECURE ENCRYPTION DETECTION (TKIP/WEP)
          // ==========================================
          
          // --- UPGRADED: STRICT HEADER SIZING ---
          bool is_qos = (payload[0] & 0x80) != 0;
          bool to_ds = (payload[1] & 0x01) != 0;
          bool from_ds = (payload[1] & 0x02) != 0;
          
          // The +HTC bit ONLY dictates a 4-byte shift if it is a QoS Data frame!
          bool has_ht_ctrl = is_qos && ((payload[1] & 0x80) != 0); 
          
          uint8_t header_len = 24;          // Base MAC Header
          if (to_ds && from_ds) header_len += 6; // Address 4 present (WDS Bridge)
          if (is_qos) header_len += 2;           // QoS Control present
          if (has_ht_ctrl) header_len += 4;      // HT Control present
          // ---------------------------------------
          
          if (len > header_len + 4) {
              uint8_t* iv_ptr = payload + header_len;
              
              bool is_ext_iv = (iv_ptr[3] & 0x20) != 0;
              bool is_valid_key_id = (iv_ptr[3] & 0x1F) == 0;
              
              char tid_str[16] = {0};
              if (is_qos) { 
                  uint8_t tid = payload[header_len - 2] & 0x0F;
                  snprintf(tid_str, sizeof(tid_str), "[TID:%d] ", tid);
              }
              
              bool triggered = false;
              char temp_text[MAX_LEAK_STR_LEN] = {0};

              // ONLY evaluate if we mathematically proved it is a valid IV header structure
              if (is_valid_key_id) {
                  if (is_ext_iv) {
                      // CCMP strictly reserves Byte 2 as 0x00. 
                      // TKIP uses it as a Dummy Byte, mathematically computed as: (TSC1 | 0x20) & 0x7F
                      if (iv_ptr[2] != 0x00) {
                          // THE SILVER BULLET: Verify the IEEE TKIP RFC math
                          if (iv_ptr[2] == ((iv_ptr[1] | 0x20) & 0x7F)) {
                              snprintf(temp_text, MAX_LEAK_STR_LEN, "%sWPA/TKIP Encryption Detected (INSECURE)", tid_str);
                              triggered = true;
                          }
                      }
                  } else {
                      // WEP signature: KeyID is valid, but it is NOT an Extended IV.
                      snprintf(temp_text, MAX_LEAK_STR_LEN, "%sWEP Encryption Detected (INSECURE)", tid_str);
                      triggered = true;
                  }
              }

              // Apply the LRU cache deduplication
              if (triggered) {
                  uint32_t now_ms = xTaskGetTickCountFromISR() * portTICK_PERIOD_MS;
                  
                  if (should_alert_crypto(payload + 10, payload + 4, now_ms)) {
                      
                      PacketCapture leak;
                      memset(&leak, 0, sizeof(PacketCapture));
                      
                      leak.meta.timestamp = now_ms;
                      leak.meta.frame_length = pkt->rx_ctrl.sig_len;
                      leak.meta.flow_hash = (payload[9] << 24) | (payload[8] << 16) | (payload[15] << 8) | payload[14];
                      leak.meta.frame_subtype = (payload[0] & 0xF0) >> 4;
                      leak.meta.direction = payload[1] & 0x03;
                      leak.meta.channel = pkt->rx_ctrl.channel;
                      
                      memcpy(leak.meta.src_mac, payload + 10, 6);
                      memcpy(leak.meta.dst_mac, payload + 4, 6);
                      memcpy(leak.meta.bssid, mac3, 6);

                      strncpy(leak.text, temp_text, MAX_LEAK_STR_LEN - 1);
                      
                      if (leakQueue != NULL) {
    leak_isr_attempts++;

    if (xQueueSendFromISR(leakQueue, &leak, NULL) != pdTRUE) {
        leak_isr_dropped++;
    }
}
                  }
              }
          } 
      } 
  }
  // ==========================================

  // 2. The Target AP Lock Gate
  if (target_locked) {
    bool belongs_to_target = false;

    // --- THE UNIVERSAL FOXHUNT EXCEPTION ---
    if (is_foxhunting && (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP)) {
        if (memcmp(addr1, foxhunt_target_mac, 6) == 0 || 
            memcmp(addr2, foxhunt_target_mac, 6) == 0 || 
            memcmp(mac3, foxhunt_target_mac, 6) == 0) {
            belongs_to_target = true;
        }
    }

    // Legacy AP Scanner Lock
    if (memcmp(addr1, target_bssid, 6) == 0) belongs_to_target = true;
    else if (memcmp(addr2, target_bssid, 6) == 0) belongs_to_target = true;
    else if (memcmp(mac3, target_bssid, 6) == 0) belongs_to_target = true;

    if (!belongs_to_target) return; // The Ruthless Drop
  }

  // 3. Extract DS Flags to determine traffic direction
  uint8_t ds_flags = payload[1] & 0x03;
  bool to_ds   = (ds_flags & 0x01); // Bit 0: Client -> AP (Upload)
  bool from_ds = (ds_flags & 0x02); // Bit 1: AP -> Client (Download)

  // 4. Smart Endpoint Identification
  uint8_t* client_mac = addr2; // Default to Transmitter (mac2)

  if (from_ds && !to_ds) {
    client_mac = addr1; // mac1
  }
  else if (to_ds && !from_ds) {
    client_mac = addr2; // mac2
  }

  // 5. Handle Broadcasts and Multicasts
  bool is_broadcast = (client_mac[0] == 0xFF);
  bool is_ipv4_multicast = (client_mac[0] == 0x01 && client_mac[1] == 0x00 && client_mac[2] == 0x5E);
  bool is_ipv6_multicast = (client_mac[0] == 0x33 && client_mac[1] == 0x33);
  bool is_stp_multicast = (client_mac[0] == 0x01 && client_mac[1] == 0x80 && client_mac[2] == 0xC2);

  if (is_broadcast || is_ipv4_multicast || is_ipv6_multicast || is_stp_multicast) {
    client_mac = mac3; 
  }

  // 6. Target Exclusion Gate
  if (target_locked && memcmp(client_mac, target_bssid, 6) == 0) return;

  // 7. Update the deduplication buffer
  bool is_tx = (client_mac == addr2); // mac2

  // WiFi client foxhunt — uses correctly derived client_mac:
  if (is_foxhunting && currentRadioMode == RADIO_WIFI) {
      if (memcmp(client_mac, foxhunt_target_mac, 6) == 0) {
          updateFoxhuntSignal(pkt->rx_ctrl.rssi);
      }
  }

  for(int i = 0; i < liveMacCount; i++) {
    if(memcmp((void*)liveData[i].mac, client_mac, 6) == 0) {
      liveData[i].packets += 1;
      liveData[i].sum_bytes += len;
      liveData[i].sum_sq_bytes += ((uint64_t)len * len);
      
      // THE FIX 1: Pure Window Stretching
      // Track the absolute min/max for this 2-second window without ever 
      // deleting history. Only updates when the target is transmitting.
      if (is_tx) {
          liveData[i].rssi = pkt->rx_ctrl.rssi;
          
          if (liveData[i].rssi_min == 0 || pkt->rx_ctrl.rssi < liveData[i].rssi_min) {
              liveData[i].rssi_min = pkt->rx_ctrl.rssi;
          }
          if (liveData[i].rssi_max == -100 || pkt->rx_ctrl.rssi > liveData[i].rssi_max) {
              liveData[i].rssi_max = pkt->rx_ctrl.rssi;
          }
      }
      
      uint8_t current_rate = getBitrateMbps(pkt);
      if (current_rate > liveData[i].rate) {
          liveData[i].rate = current_rate;
      }
      liveData[i].last_seen = millis();
      if (is_tx) liveData[i].tx_bytes += len;
      else       liveData[i].rx_bytes += len;
      
      return;
    }
  }

  // If we made it here, it's a completely new MAC address!
  if(liveMacCount < MAX_MACS) {
    memcpy((void*)liveData[liveMacCount].mac, client_mac, 6);
    
    // Seed the first packet's math
    liveData[liveMacCount].packets = 1;
    liveData[liveMacCount].sum_bytes = len;
    liveData[liveMacCount].sum_sq_bytes = ((uint64_t)len * len);
    liveData[liveMacCount].rssi = pkt->rx_ctrl.rssi;
    liveData[liveMacCount].rate = getBitrateMbps(pkt);
    unsigned long now = millis();
    liveData[liveMacCount].first_seen = now;
    liveData[liveMacCount].last_seen = now;
    
    // THE FIX 2: Dynamic Initializer
    // Seed the bounds directly to the first packet if it's a physical transmission.
    // Otherwise, use the safe defaults so they stretch correctly later.
    if (is_tx) {
        liveData[liveMacCount].rssi_min = pkt->rx_ctrl.rssi;
        liveData[liveMacCount].rssi_max = pkt->rx_ctrl.rssi;
    } else {
        liveData[liveMacCount].rssi_min = 0; 
        liveData[liveMacCount].rssi_max = -100; 
    }
    
    // Route the first packet to TX or RX
    if (is_tx) {
      liveData[liveMacCount].tx_bytes = len;
      liveData[liveMacCount].rx_bytes = 0;
    } else {
      liveData[liveMacCount].tx_bytes = 0;
      liveData[liveMacCount].rx_bytes = len;
    }
    
    liveData[liveMacCount].vendorFound = false;
    
    // --- ADD THESE 3 LINES ---
    liveData[liveMacCount].needs_lookup = true; // Tell Core 1 to check the SD card
    strncpy((char*)liveData[liveMacCount].vendor, "Resolving...", 27); 
    liveData[liveMacCount].vendor[27] = '\0';
    // -------------------------

    liveMacCount++; // Advance the tracker
  } else {
    // If the buffer is full, dump the size into the overflow bucket
    liveOtherBytes += len; 
  }
}

static bool is_lldp_multicast(const uint8_t* mac) {
    return mac && mac[0] == 0x01 && mac[1] == 0x80 && mac[2] == 0xC2 && 
           mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0x0E;
}
static bool is_cdp_multicast(const uint8_t* mac) {
    // 01:00:0C:CC:CC:CC is the dedicated Cisco CDP/VTP multicast address
    return mac && mac[0] == 0x01 && mac[1] == 0x00 && mac[2] == 0x0C && 
           mac[3] == 0xCC && mac[4] == 0xCC && mac[5] == 0xCC;
}

void processLiveDumpQueue() {
    if (liveDumpQueue == NULL) return;
    
    UBaseType_t waiting = uxQueueMessagesWaiting(liveDumpQueue);
    if (waiting >= LIVE_DUMP_QUEUE_DEPTH - 2) {
    Serial.printf(
        "WARNING: Queue backing up! (%u/%u waiting)\n",
        (unsigned)waiting,
        (unsigned)LIVE_DUMP_QUEUE_DEPTH
    );
}

    LiveCaptureEvent& live_evt = *ptr_core1_evt;
    int packets_processed = 0; 
    uint32_t start_time = micros();
    static char temp_text[MAX_LEAK_STR_LEN];
    static char eapol_text[MAX_LEAK_STR_LEN];
    
    // FIXED: Short-circuit evaluation order. Check count BEFORE pulling from the queue.
    while (packets_processed < 5 &&
       xQueueReceive(liveDumpQueue, &live_evt, 0) == pdTRUE) {
        packets_processed++;

        memset(temp_text, 0, sizeof(temp_text));
        bool custom_extracted = false;
        memset(eapol_text, 0, sizeof(eapol_text));
        bool eapol_detected = false;

        if (live_evt.meta.protocol == 6 ||
    live_evt.meta.src_port == 80 ||
    live_evt.meta.dst_port == 80) {

    /*
    Serial.printf(
        "[HTTPDBG] eth=0x%04X ip=%u proto=%u "
        "src=%u dst=%u flags=0x%02X raw_len=%u | ",
        live_evt.meta.ether_type,
        live_evt.meta.ip_version,
        live_evt.meta.protocol,
        live_evt.meta.src_port,
        live_evt.meta.dst_port,
        live_evt.meta.tcp_flags,
        live_evt.raw_len
    );
    */

    for (int i = 0; i < 32 && i < live_evt.raw_len; i++) {
        uint8_t c = live_evt.raw_payload[i];

        if (c >= 32 && c <= 126)
            Serial.printf("%c", c);
        else
            Serial.printf(".");
    }

    Serial.println();
}

        // =========================================================
        // --- STRICT PROTOCOL PARSERS ---
        // =========================================================
        // =========================================================
        // --- 0.0 UPNP / SSDP RESPONSE BYPASS (UDP Ephemeral) ---
        // =========================================================
        // Reinstated: Guarded strictly by UDP (Protocol 17) to prevent
        // colliding with standard TCP web traffic!
        if (live_evt.meta.protocol == 17 && 
            live_evt.raw_len > 15 && 
            memcmp(live_evt.raw_payload, "HTTP/1.", 7) == 0) {
            
            custom_extracted = parse_ssdp(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
            
            // Unicast SSDP replies are pure gold. Elevate immediately!
            if (custom_extracted) {
                live_evt.meta.is_high_value = true;
            }
        }
        // FIXED: The entire chain is now guarded so the SSDP bypass isn't overwritten
        if (!custom_extracted) {
            if (live_evt.meta.ether_type == 0x0806) {
                custom_extracted = parse_arp(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
            }
            else if (live_evt.meta.ether_type == 0x888E) {

    eapol_detected = parse_eapol(
        live_evt.raw_payload,
        live_evt.raw_len,
        eapol_text,
        MAX_LEAK_STR_LEN
    );

    // Preserve the existing M1/M2/M3/M4 detection exactly.
    if (eapol_detected &&
        (strstr(eapol_text, "M1") ||
         strstr(eapol_text, "M2") ||
         strstr(eapol_text, "M3") ||
         strstr(eapol_text, "M4"))) {

        live_evt.meta.is_high_value = false;
    }

    // Deliberately do NOT set custom_extracted here.
    // The packet should continue into the deeper/catch-all
    // payload inspection below.
}
            else if (is_cdp_multicast(live_evt.meta.dst_mac)) {
                custom_extracted = parse_cdp(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
                if (custom_extracted) {
                    live_evt.meta.is_high_value = true; 
                }
            }
            else if (live_evt.meta.ether_type == 0x88CC || is_lldp_multicast(live_evt.meta.dst_mac)) {
                custom_extracted = parse_lldp(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
                if (custom_extracted) {
                    live_evt.meta.is_high_value = true; 
                }
            }
            else if (live_evt.meta.dst_port == 67 || live_evt.meta.src_port == 67 ||
         live_evt.meta.dst_port == 68 || live_evt.meta.src_port == 68) {
                custom_extracted = parse_dhcp_v4(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
            }            
            else if (live_evt.meta.dst_port == 546 || live_evt.meta.src_port == 546 ||
         live_evt.meta.dst_port == 547 || live_evt.meta.src_port == 547) {
                custom_extracted = parse_dhcp_v6(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
            }
            else if (live_evt.meta.dst_port == 137 || live_evt.meta.src_port == 137) {
                custom_extracted = parse_netbios(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
            }
            else if (live_evt.meta.dst_port == 138 || live_evt.meta.src_port == 138) {
                custom_extracted = parse_nbds(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
            }
            else if (live_evt.meta.dst_port == 53 || live_evt.meta.src_port == 53 || 
                     live_evt.meta.dst_port == 5353 || live_evt.meta.src_port == 5353) {
                custom_extracted = parse_dns_mdns(live_evt.raw_payload, live_evt.raw_len, live_evt.meta.dst_port == 5353 || live_evt.meta.src_port == 5353, temp_text, MAX_LEAK_STR_LEN);
            }
            else if (live_evt.meta.dst_port == 80 ||
                     live_evt.meta.src_port == 80) {
                custom_extracted = parse_http_host(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
                if (custom_extracted && strstr(temp_text, "[Auth: Basic ")) live_evt.meta.is_high_value = true;
            }
            else if (live_evt.meta.dst_port == 3702 || live_evt.meta.src_port == 3702) {
                custom_extracted = parse_ws_discovery(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
                if (custom_extracted && strstr(temp_text, "[URL: ")) live_evt.meta.is_high_value = true;
            }
            else if (live_evt.meta.dst_port == 631 || live_evt.meta.src_port == 631) {
    custom_extracted = parse_ipp(
        live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN
    );
    // is_high_value intentionally remains false.
}
            else if (live_evt.meta.dst_port == 514 || live_evt.meta.src_port == 514) {
    custom_extracted = parse_syslog(
        live_evt.raw_payload,
        live_evt.raw_len,
        temp_text,
        MAX_LEAK_STR_LEN
    );
}
            else if (live_evt.meta.dst_port == 554 || live_evt.meta.src_port == 554) {
                custom_extracted = parse_rtsp(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
            }
            else if (live_evt.meta.dst_port == 21 || live_evt.meta.src_port == 21) {
                custom_extracted = parse_ftp(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
                if (custom_extracted) live_evt.meta.is_high_value = true;
            }
            else if (live_evt.meta.dst_port == 23 || live_evt.meta.src_port == 23) {
                custom_extracted = parse_telnet(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
                if (custom_extracted) live_evt.meta.is_high_value = true;
            }
            else if (live_evt.meta.dst_port == 22 || live_evt.meta.src_port == 22) {
                custom_extracted = parse_ssh(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
            }
            else if (live_evt.meta.dst_port == 69 || live_evt.meta.src_port == 69) {
    custom_extracted = parse_tftp(
        live_evt.raw_payload,
        live_evt.raw_len,
        temp_text,
        MAX_LEAK_STR_LEN
    );

    if (custom_extracted)
        live_evt.meta.is_high_value = true;
}
            else if (live_evt.meta.dst_port == 3389 || live_evt.meta.src_port == 3389) {
                custom_extracted = parse_rdp(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
                if (custom_extracted) live_evt.meta.is_high_value = true;
            }
            else if (live_evt.meta.dst_port == 25 || live_evt.meta.src_port == 25 || 
                     live_evt.meta.dst_port == 587 || live_evt.meta.src_port == 587) {
                custom_extracted = parse_smtp(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
                if (custom_extracted) live_evt.meta.is_high_value = true;
            }
            else if (live_evt.meta.dst_port == 445 || live_evt.meta.src_port == 445) {
                custom_extracted = parse_smb(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
                if (custom_extracted) live_evt.meta.is_high_value = true; 
            }
            else if (live_evt.meta.dst_port == 1900 || live_evt.meta.src_port == 1900) {
                custom_extracted = parse_ssdp(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
            }
            else if (live_evt.meta.dst_port == 5355 || live_evt.meta.src_port == 5355) {
                custom_extracted = parse_llmnr(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
            }
            else if (live_evt.meta.dst_port == 17500 || live_evt.meta.src_port == 17500) {
                custom_extracted = parse_dropbox(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN);
            }
            else if (live_evt.meta.dst_port == 161 || live_evt.meta.src_port == 161 ||
         live_evt.meta.dst_port == 162 || live_evt.meta.src_port == 162) {
    custom_extracted = parse_snmp(
        live_evt.raw_payload,
        live_evt.raw_len,
        temp_text,
        MAX_LEAK_STR_LEN
    );
}
else if (live_evt.meta.dst_port == 1080 || live_evt.meta.src_port == 1080 ||
         live_evt.meta.dst_port == 9050 || live_evt.meta.src_port == 9050) {
    custom_extracted = parse_socks(
        live_evt.raw_payload,
        live_evt.raw_len,
        temp_text,
        MAX_LEAK_STR_LEN
    );
}
            else if (live_evt.meta.protocol == 6 && (live_evt.meta.tcp_flags & 0x02)) { 
                snprintf(temp_text, MAX_LEAK_STR_LEN, "TCP SYN (Port %d)", live_evt.meta.dst_port); 
                custom_extracted = true; 
            } 
            else if (live_evt.meta.protocol == 6 && (live_evt.meta.tcp_flags & 0x04)) { 
                snprintf(temp_text, MAX_LEAK_STR_LEN, "TCP RST (Port %d)", live_evt.meta.dst_port); 
                custom_extracted = true; 
            } 
            else if (live_evt.meta.protocol == 1) {
                if (!parse_icmpv4(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN)) {
                    snprintf(temp_text, MAX_LEAK_STR_LEN, "ICMPv4: Malformed");
                }
                custom_extracted = true;
            }
        }

        // =========================================================
        // --- DEEP PARSERS & SIGNATURES ---
        // =========================================================
        if (!custom_extracted && live_evt.raw_len > 0) {
            const uint8_t* p = live_evt.raw_payload;
            uint16_t len = live_evt.raw_len;

            // ICMPv6
            if (!custom_extracted && live_evt.meta.ip_version == 6 && live_evt.meta.protocol == 58) {
                if (parse_icmpv6(p, len, temp_text, MAX_LEAK_STR_LEN, live_evt.meta.is_high_value)) {
                    custom_extracted = true;
                }
            }
            
            // MQTT
            if (!custom_extracted && live_evt.meta.protocol == 6 && (live_evt.meta.src_port == 1883 || live_evt.meta.dst_port == 1883)) {
                if (parse_mqtt(p, len, temp_text, MAX_LEAK_STR_LEN, live_evt.meta.is_high_value)) {
                    custom_extracted = true;
                }
            }
            // CoAP
if (!custom_extracted &&
    (live_evt.meta.src_port == 5683 || live_evt.meta.dst_port == 5683)) {

    if (parse_coap(p, len, temp_text, MAX_LEAK_STR_LEN)) {
        custom_extracted = true;
        // Leave is_high_value false for ordinary CoAP traffic.
    }
}

            // TLS Diagnostic Walker
if (!custom_extracted &&
    live_evt.meta.protocol == 6 &&
    (live_evt.meta.src_port == 443 || live_evt.meta.dst_port == 443) &&
    len > 0) {

    uint16_t offset = 0;
    bool found_tls = false;

    // ---------------------------------------------------------
    // 1. Walk TLS records that begin at this TCP payload boundary
    // ---------------------------------------------------------
    while (offset + 5 <= len) {
        uint8_t rec_type = p[offset];
        uint16_t rec_version = ((uint16_t)p[offset + 1] << 8) | p[offset + 2];
        uint16_t rec_len = ((uint16_t)p[offset + 3] << 8) | p[offset + 4];

        if (rec_type >= 0x14 && rec_type <= 0x17 &&
            (rec_version == 0x0301 ||
             rec_version == 0x0302 ||
             rec_version == 0x0303)) {

            found_tls = true;

            Serial.printf(
                "\n[TLS-RECORD] offset=%u type=%02X version=%04X len=%u\n",
                offset, rec_type, rec_version, rec_len
            );

            if (rec_type == 0x16 && offset + 5 < len) {
                uint8_t hs_type = p[offset + 5];
                const char* hs_str = "Unknown";

                if (hs_type == 0x01) hs_str = "ClientHello";
                else if (hs_type == 0x02) hs_str = "ServerHello";
                else if (hs_type == 0x0B) hs_str = "Certificate";
                else if (hs_type == 0x0E) hs_str = "ServerHelloDone";
                else if (hs_type == 0x10) hs_str = "ClientKeyExchange";

                Serial.printf(
                    "  -> [TLS-HS] type=%02X %s\n",
                    hs_type, hs_str
                );

                if (hs_type == 0x0B &&
                    rec_len > len - offset - 5) {
                    Serial.printf(
                        "  -> [TLS-FRAG] Warning: Certificate record extends beyond this TCP segment!\n"
                    );
                }
            }

            // Subtraction-safe boundary check
            if (rec_len > len - offset - 5)
                break;

            offset += 5 + rec_len;
        } else {
            break;
        }
    }

    // ---------------------------------------------------------
    // 2. Parse information from recognized TLS records
    // ---------------------------------------------------------
    if (found_tls) {
        custom_extracted =
            parse_tls_sni(p, len, temp_text, MAX_LEAK_STR_LEN);

        if (!custom_extracted) {
            custom_extracted =
                parse_tls_cert(p, len, temp_text, MAX_LEAK_STR_LEN);

            if (custom_extracted)
                live_evt.meta.is_high_value = true;
        }

        if (!custom_extracted) {
            snprintf(
                temp_text,
                MAX_LEAK_STR_LEN,
                "TLS Encrypted Traffic (Port %u)",
                live_evt.meta.dst_port == 443 ?
                    live_evt.meta.src_port :
                    live_evt.meta.dst_port
            );

            custom_extracted = true;
        }
    }

    // ---------------------------------------------------------
    // 3. IMPORTANT: Raw certificate scan for non-header segments
    // ---------------------------------------------------------
    if (!custom_extracted) {
        custom_extracted =
            parse_tls_cert(p, len, temp_text, MAX_LEAK_STR_LEN);

        if (custom_extracted)
            live_evt.meta.is_high_value = true;
    }
}

            // Other structured deep extractors
            if (!custom_extracted) {
                if (len >= 8 && p[4] == 0x21 && p[5] == 0x12 && p[6] == 0xA4 && p[7] == 0x42) {
                    snprintf(temp_text, MAX_LEAK_STR_LEN, "STUN: Live VoIP/WebRTC Stream");
                    custom_extracted = true;
                    live_evt.meta.is_high_value = true;
                }
                else if ((len >= 4 &&
          (memcmp(p, "GET ", 4) == 0 ||
           memcmp(p, "PUT ", 4) == 0)) ||
         (len >= 5 &&
          (memcmp(p, "POST ", 5) == 0 ||
           memcmp(p, "HEAD ", 5) == 0))) {

    custom_extracted =
        parse_http_host(p, len, temp_text, MAX_LEAK_STR_LEN);

    if (custom_extracted) {
        if (strstr(temp_text, "[Auth: Basic ")) {
            live_evt.meta.is_high_value = true;
        }
    } else {
        snprintf(
            temp_text,
            MAX_LEAK_STR_LEN,
            "HTTP Request (Hidden Port)"
        );
        custom_extracted = true;
    }
}

else if (len >= 20 &&
         p[0] == 0x13 &&
         memcmp(&p[1], "BitTorrent protocol", 19) == 0) {

    snprintf(
        temp_text,
        MAX_LEAK_STR_LEN,
        "P2P: BitTorrent Handshake"
    );
    custom_extracted = true;
    live_evt.meta.is_high_value = true;
}

else if (len == 148 &&
         p[0] == 0x01 &&
         p[1] == 0x00 &&
         p[2] == 0x00 &&
         p[3] == 0x00) {

    snprintf(
        temp_text,
        MAX_LEAK_STR_LEN,
        "VPN: WireGuard Handshake"
    );
    custom_extracted = true;
    live_evt.meta.is_high_value = true;
}
            }

            if (!custom_extracted) {
                if (parse_ephemeral_upnp(p, len, temp_text, MAX_LEAK_STR_LEN)) {
                    custom_extracted = true;
                    live_evt.meta.is_high_value = true;
                }
            }
        }

        // =========================================================
        // --- STATIC PORT FINGERPRINTS ---
        // =========================================================
        if (!custom_extracted) {
            if (live_evt.meta.dst_port == 3544 || live_evt.meta.src_port == 3544) {
                snprintf(temp_text, MAX_LEAK_STR_LEN, "Teredo: Windows IPv6 Tunnel");
                custom_extracted = true;
            }
            else if (live_evt.meta.dst_port == 5350 || live_evt.meta.src_port == 5350) {
                snprintf(temp_text, MAX_LEAK_STR_LEN, "PCP: Port Control Protocol");
                custom_extracted = true;
            }
            else if (live_evt.meta.dst_port == 5351 || live_evt.meta.src_port == 5351) {
                snprintf(temp_text, MAX_LEAK_STR_LEN, "NAT-PMP: Apple Port Mapping");
                custom_extracted = true;
            }
            else if (live_evt.meta.dst_port == 1883 || live_evt.meta.src_port == 1883) {
                snprintf(temp_text, MAX_LEAK_STR_LEN, "MQTT (IoT Telemetry/PubSub)");
                custom_extracted = true;
                // FIXED: Removed the automatic high_value elevation here so generic telemetry stays normal
            }
            else if (live_evt.meta.dst_port == 5683 || live_evt.meta.src_port == 5683) {
    snprintf(temp_text, MAX_LEAK_STR_LEN,
             "CoAP (IoT Constrained App Protocol)");
    custom_extracted = true;
    // is_high_value intentionally remains false.
}
        }

        // =========================================================
// --- EAPOL FALLBACK ---
// If no deeper payload extraction succeeded, preserve the
// normal EAPOL classification.
// =========================================================
if (!custom_extracted && eapol_detected) {
    strncpy(temp_text, eapol_text, MAX_LEAK_STR_LEN - 1);
    temp_text[MAX_LEAK_STR_LEN - 1] = '\0';
    custom_extracted = true;
}

        // =========================================================
        // --- CATCH-ALL FOR UNKNOWN CLEARTEXT ---
        // =========================================================
        if (!custom_extracted && live_evt.raw_len > 0) {
            if (extract_printable_runs(live_evt.raw_payload, live_evt.raw_len, temp_text, MAX_LEAK_STR_LEN, 4, false, "|")) {
                custom_extracted = true; 
            } else {
                Serial.printf("[FALLTHROUGH] ip_ver=%u proto=%u src=%u dst=%u eth=0x%04X len=%u | first16: ",
                              live_evt.meta.ip_version, live_evt.meta.protocol, live_evt.meta.src_port, live_evt.meta.dst_port,
                              live_evt.meta.ether_type, live_evt.raw_len);
                for (int b = 0; b < 16 && b < live_evt.raw_len; b++) {
                    Serial.printf("%02X ", live_evt.raw_payload[b]);
                }
                Serial.println();
            }
        }

        // ==========================================
// --- UI ROUTING ---
// ==========================================
if (custom_extracted) {

    // =========================================================
    // Create the compact persistent/UI object ONLY after parsing
    // =========================================================
    PacketCapture pcap;
    memset(&pcap, 0, sizeof(PacketCapture));

    // Copy packet metadata from the full-payload transport event
    pcap.meta = live_evt.meta;

    // =========================================================
    // Copy parsed text into persistent storage.
    // MAX_LEAK_STR_LEN includes the terminating NUL.
    // =========================================================
    size_t text_len = strnlen(temp_text, MAX_LEAK_STR_LEN - 1);

    pcap.retained_len = (uint16_t)text_len; // <--- INJECT THIS LINE

    memcpy(pcap.text, temp_text, text_len);
    pcap.text[text_len] = '\0';

    // =========================================================
    // High-Value Triage
    // =========================================================
    if (strcasestr(temp_text, "M-SEARCH") ||
        strcasestr(temp_text, "HTTP/1.") ||
        strcasestr(temp_text, "spotify") ||
        strcasestr(temp_text, "cast") ||
        strcasestr(temp_text, "bearer ") ||
        strcasestr(temp_text, "token=") ||
        strcasestr(temp_text, "password=") ||
        strcasestr(temp_text, "pwd=") ||
        strcasestr(temp_text, "user=") ||
        strcasestr(temp_text, "login=") ||
        strcasestr(temp_text, "login:") ||
        strcasestr(temp_text, "/admin") ||
        strcasestr(temp_text, "rtsp://") ||
        strcasestr(temp_text, "tasmota")) {

        pcap.meta.is_high_value = true;

       // if (leakQueue != NULL) {
       //     leak_core1_attempts++;

       // if (xQueueSend(leakQueue, &pcap, 0) != pdTRUE) {
       //     leak_core1_dropped++;
       // }
     //}
   }

    // =========================================================
    // Copy final parsed text into the compact UI union
    // =========================================================
    //strncpy(pcap.text, temp_text, MAX_LEAK_STR_LEN - 1);
    //pcap.text[MAX_LEAK_STR_LEN - 1] = '\0';

    // =========================================================
    // Send compact object to the UI/history pipeline
    // =========================================================
    if (leakQueue != NULL) {
        leak_core1_attempts++;

        if (xQueueSend(leakQueue, &pcap, 0) != pdTRUE) {
            leak_core1_dropped++;
        }
    }
}
    
    if (packets_processed > 0) {
        uint32_t elapsed = micros() - start_time;
        Serial.printf("Processed %d packets in %u us\n", packets_processed, elapsed);
    }
}
}

void resetMonitorState() {
  pause_sniffing = true;
  current_x = 0;

  // ==========================================
  // FLUSH SHARED ARRAYS (Wi-Fi sizes cover BLE and AP too)
  // ==========================================
  memset((void*)liveData, 0, sizeof(liveData));
  liveMacCount = 0;
  liveOtherBytes = 0;
  liveBleCount = 0;
  liveApCount = 0;
  liveChannelCount = 0;

  memset(sortData, 0, sizeof(sortData));
  sortMacCount = 0;
  sortOtherBytes = 0;
  sortBleCount = 0;
  sortApCount = 0;
  sortChannelCount = 0;

  memset(sessionData, 0, sizeof(sessionData));
  sessionMacCount = 0;
  sessionOtherBytes = 0;
  sessionBleCount = 0;
  sessionApCount = 0;
  sessionChannelCount = 0;

  pause_sniffing = false;
}









/**
 * Fast Binary Search for Corporate Trackers (0x16 Service Data)
 */


/**
 * Fast Binary Search for Standard Hardware Services (0x02/0x03)
 */


// --- UI Drawing Functions ---
void drawMenu() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(1);

  // HEADER
  tft.setFreeFont(&UbuntuMono_Regular11pt7b); 
  tft.setTextDatum(MC_DATUM); 
  tft.setTextColor(TFT_WHITE);
  tft.drawString("DASHBOARD SETTINGS", 240, 40); 

  tft.setFreeFont(&UbuntuMono_Regular9pt7b);

  // ==========================================
  // FOXHUNT BUTTON (Tactical Mode)
  // ==========================================
  tft.setTextDatum(MC_DATUM);

  bool foxhunt_available = false;

  // 1. BLE MODE EVALUATION
  if (currentRadioMode == RADIO_BLE) {
    if (sessionBleCount > 0) {
        foxhunt_available = true;
    }
  } 
  // 2. NETWORKS (AP) MODE EVALUATION
  else if (currentRadioMode == RADIO_AP) {
      if (sessionApCount > 0) {
          foxhunt_available = true;
      }
  } 
  // 3. WI-FI MODE EVALUATION (Isolated at the bottom)
  else if (currentRadioMode == RADIO_WIFI) {
      if (target_locked == true && sessionMacCount > 0) {
          foxhunt_available = true;
      }
  }

  if (foxhunt_available) {
      // Draw active red button
      tft.fillRoundRect(50, 90, 200, 40, 3, TFT_RED);   // Fill it red
      tft.drawRoundRect(50, 90, 200, 40, 3, TFT_WHITE); // Add the crisp border
      tft.setTextColor(TFT_WHITE);
      tft.drawString("FOXHUNT", 150, 110);
  } else {
      // Greyed out — no target locked
      uint16_t deadGrey = hex24to565(0x222222);
      tft.fillRect(50, 90, 200, 40, deadGrey);
      tft.drawRect(50, 90, 200, 40, TFT_DARKGREY);
      tft.setTextColor(TFT_DARKGREY);
      tft.drawString("FOXHUNT", 150, 110);
      
      // Hint text
      tft.setFreeFont(&UbuntuMono_Regular9pt7b);
      tft.setTextColor(hex24to565(0x444444));
      tft.drawString("(no targets yet)", 150, 125);
  }
  
  // ==========================================
  // PROBE REQUEST BUTTON (Right Column)
  // ==========================================
  uint16_t purpleColor = hex24to565(0x4A148C);
  tft.fillRect(300, 140, 150, 40, purpleColor);
  tft.drawRect(300, 140, 150, 40, TFT_WHITE);
  tft.setTextColor(TFT_WHITE);
  tft.drawString("SNIFFED PROBES", 375, 160);

  // ==========================================
  // 3. AP SCANNER / CH SELECT BUTTON (Y: 190 - 230)
  // ==========================================
  if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP || currentRadioMode == RADIO_PCAP) {
    // Active State
    tft.fillRect(50, 190, 200, 40, TFT_BLACK);
    tft.drawRect(50, 190, 200, 40, TFT_WHITE);
    tft.setTextColor(TFT_WHITE);
    
    if (currentRadioMode == RADIO_WIFI) {
        tft.drawString("SELECT AP", 150, 210);
    } else if (currentRadioMode == RADIO_AP || currentRadioMode == RADIO_PCAP) {
        if (target_locked) {
            char chStr[16];
            snprintf(chStr, sizeof(chStr), "LOCKED: CH %d", target_channel);
            tft.drawString(chStr, 150, 210);
        } else {
            tft.drawString("SELECT CH", 150, 210);
        }
    }
  } else {
    // "Cold" Abyss State
    uint16_t deadGrey = hex24to565(0x222222);      // Almost black
    tft.fillRect(50, 190, 200, 40, deadGrey);
    tft.drawRect(50, 190, 200, 40, TFT_DARKGREY);
    tft.setTextColor(TFT_DARKGREY);
    tft.drawString("SELECT AP", 150, 210);
  }

  // 4. SEEN DEVICES BUTTON
  tft.fillRect(50, 240, 200, 40, TFT_BLACK);
  tft.drawRect(50, 240, 200, 40, TFT_WHITE);
  tft.setTextColor(TFT_WHITE);
  tft.drawString("SNIFF LIST", 150, 260);

  // ==========================================
  // RADIO MODE TOGGLE
  // ==========================================
  tft.setTextColor(TFT_WHITE); // Set this once for all modes

  // 1. Draw the filled background based on the current mode
  if (currentRadioMode == RADIO_WIFI) {
    tft.fillRect(300, 190, 150, 40, TFT_BLUE);
  } 
  else if (currentRadioMode == RADIO_BLE) {
    tft.fillRect(300, 190, 150, 40, TFT_PURPLE);
  } 
  else if (currentRadioMode == RADIO_AP) {
    tft.fillRect(300, 190, 150, 40, TFT_DARKGREEN); 
  }
  else if (currentRadioMode == RADIO_CHANNELS) {
    tft.fillRect(300, 190, 150, 40, TFT_ORANGE); 
  }
  else if (currentRadioMode == RADIO_PCAP) {
    tft.fillRect(300, 190, 150, 40, TFT_MAROON); 
  }

  // 2. Draw the universal white border
  tft.drawRect(300, 190, 150, 40, TFT_WHITE);

  // 3. Draw the corresponding text label
  if (currentRadioMode == RADIO_WIFI) {
    tft.drawString("MODE: WI-FI", 375, 210);
  } 
  else if (currentRadioMode == RADIO_BLE) {
    tft.drawString("MODE: BLE", 375, 210);
  } 
  else if (currentRadioMode == RADIO_AP) {
    tft.drawString("MODE: NETWORKS", 375, 210);
  }
  else if (currentRadioMode == RADIO_CHANNELS) {
    tft.drawString("MODE: CHANNELS", 375, 210);
  }
  else if (currentRadioMode == RADIO_PCAP) {
    tft.drawString("MODE: PCAP", 375, 210);
  }

  // 5. EXIT BUTTON
  tft.fillRect(300, 240, 150, 40, TFT_RED);
  tft.drawRect(300, 240, 150, 40, TFT_WHITE);
  tft.setTextColor(TFT_WHITE);
  tft.drawString("EXIT", 375, 260);
  
  // THE FIX: Reset datum to Top-Left for the rest of the UI ONLY at the very end!
  tft.setTextDatum(TL_DATUM); 
}

void drawChartHeader() {
  // 1. Gate the horizontal separator line so it doesn't cut through the PCAP terminal
  if (currentRadioMode != RADIO_PCAP) {
    tft.drawLine(0, HEADER_HEIGHT - 8, 480, HEADER_HEIGHT - 8, COLOR_HOT_CHEST);
  }

  // MENU BUTTON
  tft.drawRoundRect(420, 1, 55, 16, 2, TFT_WHITE);
  tft.setTextColor(TFT_WHITE);
  tft.setFreeFont(&UbuntuMono_Regular9pt7b);  
  tft.setTextDatum(MC_DATUM);     
  tft.drawString("MENU", 447, 7); 
  tft.setTextDatum(TL_DATUM);     

  // BANNER
  tft.setTextWrap(false); 
  tft.setFreeFont(&UbuntuMono_Regular9pt7b);
  tft.setTextDatum(TL_DATUM);

  char bannerStr[64];

  // ==========================================
  // THE 4-STATE HEADER LOGIC
  // ==========================================
  tft.setTextColor(COLOR_HOT_CHEST); 
  if (currentRadioMode == RADIO_BLE) {
    snprintf(bannerStr, sizeof(bannerStr), "SNIFFING BLE DEVICES");
  } 
  else if (currentRadioMode == RADIO_AP) {
    if (!target_locked) {
        snprintf(bannerStr, sizeof(bannerStr), "CH: %02d | SNIFFING NETWORKS", CHANNELS[current_ch_idx]);
    } else {
        snprintf(bannerStr, sizeof(bannerStr), "CH: %02d | TARGET LOCKED", target_channel);
    }
  }
  else if (currentRadioMode == RADIO_CHANNELS) { 
    snprintf(bannerStr, sizeof(bannerStr), "CH: %02d | SNIFFING SPECTRUM", CHANNELS[current_ch_idx]);
  }
  else if (currentRadioMode == RADIO_PCAP) { 
    if (!target_locked) {
      snprintf(bannerStr, sizeof(bannerStr), "CH: %02d | PCAP (HOPPING)", CHANNELS[current_ch_idx]);
    } else {
      snprintf(bannerStr, sizeof(bannerStr), "CH: %02d | PCAP (LOCKED)", target_channel);
    }
  }
  else if (currentRadioMode == RADIO_WIFI) {    
    if (!target_locked) {
      snprintf(bannerStr, sizeof(bannerStr), "CH: %02d | FREE AIRSPACE", CHANNELS[current_ch_idx]);
    } else {
      char safe_ssid[15];
      strncpy(safe_ssid, target_ssid, 14);
      safe_ssid[14] = '\0';
      snprintf(bannerStr, sizeof(bannerStr), "CH: %02d | %s (%ddBm)", target_channel, safe_ssid, target_rssi);
    }
  }
  tft.drawString(bannerStr, 5, 1);
}

// ==========================================
// WIFI SORTING STATE
// ==========================================
enum SortMode { SORT_TOTAL, SORT_TX, SORT_RX, SORT_AVG, SORT_CV, SORT_DIST, SORT_AGE };
SortMode currentSortMode = SORT_TOTAL; // Default state

double getSortMetric(MacRecord& record, SortMode mode) {
    switch(mode) {
        case SORT_TOTAL: 
            return (double)(record.tx_bytes + record.rx_bytes);
        case SORT_TX:    
            return (double)record.tx_bytes;
        case SORT_RX:    
            return (double)record.rx_bytes;
        case SORT_AVG:   
            return (record.packets > 0) ? ((double)record.sum_bytes / record.packets) : 0.0;
        case SORT_CV: {
            if (record.packets == 0) return 0.0;
            double mean = (double)record.sum_bytes / record.packets;
            if (mean == 0) return 0.0;
            double avg_sq_sum = (double)record.sum_sq_bytes / record.packets;
            double variance = avg_sq_sum - (mean * mean);
            if (variance < 0) variance = 0;
            return (sqrt(variance) / mean) * 100.0;
        }
        case SORT_DIST:
            // Swap this to smoothedDistance to use your new EMA filter!
            return (double)record.smoothedDistance; 
        case SORT_AGE:
            // Added the missing case and using the correct timestamp variable
            return (double)record.last_seen; 
    }
    return 0.0;
}

double getSortMetric(ApRecord& record, SortMode mode) {
    switch(mode) {
        case SORT_TOTAL: 
            return (double)(record.tx_bytes + record.rx_bytes);
        case SORT_TX:    
            return (double)record.tx_bytes;
        case SORT_RX:    
            return (double)record.rx_bytes;
        case SORT_AVG:   
            return (record.packets > 0) ? ((double)record.sum_bytes / record.packets) : 0.0;
        case SORT_CV: {
            if (record.packets == 0) return 0.0;
            double mean = (double)record.sum_bytes / record.packets;
            if (mean == 0) return 0.0;
            double avg_sq_sum = (double)record.sum_sq_bytes / record.packets;
            double variance = avg_sq_sum - (mean * mean);
            if (variance < 0) variance = 0;
            return (sqrt(variance) / mean) * 100.0;
        }
        case SORT_DIST:
            return (double)record.smoothedDistance; 
        case SORT_AGE:
            return (double)record.last_seen; 
    }
    return 0.0;
}

// ==========================================
// BLE SORTING STATE
// ==========================================
enum BleSortMode { SORT_BLE_HITS, SORT_BLE_DIST, SORT_BLE_AGE };
BleSortMode currentBleSortMode = SORT_BLE_HITS; // Default state

double getBleSortMetric(BLERecord& record, BleSortMode mode) {
    switch(mode) {
        case SORT_BLE_HITS:
            return (double)record.hits;
        case SORT_BLE_DIST:
            return (double)record.smoothedDistance;
        case SORT_BLE_AGE:
            // Fixed the variable name to match your struct
            return (double)record.lastSeen; 
    }
    return 0.0;
}

// ==========================================
// PROBE REQUEST SORTING
// ==========================================

double getProbeMetric(ProbeRecordShared record, ProbeSortMode mode) {
    if (mode == PROBE_SORT_HITS) return (double)record.hits;
    if (mode == PROBE_SORT_SSIDS) return (double)record.ssid_count;
    if (mode == PROBE_SORT_AGE) return (double)record.last_seen;
    
    if (mode == PROBE_SORT_DIST) {
        // Push devices with 0.0 distance (unknown/calculating) to the bottom
        if (record.smoothedDistance <= 0.0) return 99999.0; 
        return (double)record.smoothedDistance;
    }
    return 0.0;
}

void sortProbeList() {
    for (int i = 1; i < MAX_PROBE_SLOTS; i++) {
        ProbeRecordShared key = probeList[i];
        
        // Skip moving empty slots up the list
        bool key_empty = true;
        for(int b=0; b<6; b++) if(key.mac[b]!=0) { key_empty=false; break; }
        if (key_empty) continue; 

        double key_val = getProbeMetric(key, currentProbeSortMode);
        int j = i - 1;

        if (probe_sort_descending) {
            while (j >= 0) {
                bool j_empty = true;
                for(int b=0; b<6; b++) if(probeList[j].mac[b]!=0) { j_empty=false; break; }
                
                if (j_empty || getProbeMetric(probeList[j], currentProbeSortMode) < key_val) {
                    probeList[j + 1] = probeList[j];
                    j--;
                } else break;
            }
        } else {
            while (j >= 0) {
                bool j_empty = true;
                for(int b=0; b<6; b++) if(probeList[j].mac[b]!=0) { j_empty=false; break; }
                
                if (j_empty || getProbeMetric(probeList[j], currentProbeSortMode) > key_val) {
                    probeList[j + 1] = probeList[j];
                    j--;
                } else break;
            }
        }
        probeList[j + 1] = key;
    }
}

void drawChartFooter() {
  tft.fillRect(0, 296, 480, 24, TFT_BLACK);

  tft.setFreeFont(&UbuntuMono_Regular9pt7b);
  tft.setTextColor(TFT_WHITE);
  tft.setTextDatum(MC_DATUM); 

  if (currentRadioMode != RADIO_PCAP) {
      // ==========================================
      // ZONE 1: SORT METRIC (Center X = 72)
      // ==========================================
      tft.drawRoundRect(2, 302, 141, 17, 3, TFT_WHITE); 

      char metricStr[32] = "SORT: ERR"; 
      
      if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP) {
        if (currentSortMode == SORT_TOTAL) { strcpy(metricStr, "SORT: TOTAL"); tft.setTextColor(TFT_WHITE); }
        else if (currentSortMode == SORT_TX) { strcpy(metricStr, "SORT: TX"); tft.setTextColor(TFT_CYAN); }
        else if (currentSortMode == SORT_RX) { strcpy(metricStr, "SORT: RX"); tft.setTextColor(TFT_MAGENTA); }
        else if (currentSortMode == SORT_AVG) { strcpy(metricStr, "SORT: AVG"); tft.setTextColor(TFT_YELLOW); }
        else if (currentSortMode == SORT_CV) { strcpy(metricStr, "SORT: CV%"); tft.setTextColor(TFT_ORANGE); }
        else if (currentSortMode == SORT_DIST) { strcpy(metricStr, "SORT: DIST"); tft.setTextColor(TFT_GREEN); }
        else if (currentSortMode == SORT_AGE) { strcpy(metricStr, "SORT: AGE"); tft.setTextColor(TFT_BLUE); }
      } 
      else if (currentRadioMode == RADIO_CHANNELS) {
        if (currentSortMode == SORT_TOTAL) { strcpy(metricStr, "SORT: TOTAL"); tft.setTextColor(TFT_WHITE); }
        else if (currentSortMode == SORT_TX) { strcpy(metricStr, "SORT: DN"); tft.setTextColor(TFT_CYAN); }
        else if (currentSortMode == SORT_RX) { strcpy(metricStr, "SORT: UP"); tft.setTextColor(TFT_MAGENTA); }
        else if (currentSortMode == SORT_AVG) { strcpy(metricStr, "SORT: AVG"); tft.setTextColor(TFT_YELLOW); }
        else if (currentSortMode == SORT_CV) { strcpy(metricStr, "SORT: CV%"); tft.setTextColor(TFT_ORANGE); }
        else if (currentSortMode == SORT_DIST) { strcpy(metricStr, "SORT: PWR"); tft.setTextColor(TFT_GREEN); }
        else if (currentSortMode == SORT_AGE) { strcpy(metricStr, "SORT: AGE"); tft.setTextColor(TFT_BLUE); }
      }
      else if (currentRadioMode == RADIO_BLE) {
        if (currentBleSortMode == SORT_BLE_HITS) { strcpy(metricStr, "SORT: HITS"); tft.setTextColor(TFT_WHITE); }
        else if (currentBleSortMode == SORT_BLE_DIST) { strcpy(metricStr, "SORT: DIST"); tft.setTextColor(TFT_GREEN); }
        else if (currentBleSortMode == SORT_BLE_AGE) { strcpy(metricStr, "SORT: AGE"); tft.setTextColor(TFT_BLUE); }
      }
      
      tft.drawString(metricStr, 72, 308);
      tft.setTextColor(TFT_WHITE);
      
      // ==========================================
      // ZONE 2: SORT DIRECTION (Center X = 217)
      // ==========================================
      tft.drawRoundRect(147, 302, 141, 17, 3, TFT_WHITE); 

      if (sort_descending) {
        tft.drawString("ORDER: DESC", 217, 309);
      } else {
        tft.setTextColor(TFT_GREEN); 
        tft.drawString("ORDER: ASC", 217, 309);
        tft.setTextColor(TFT_WHITE); 
      }

      // ==========================================
      // ZONE 3: SCALE MODE (Center X = 362)
      // ==========================================
      tft.drawRoundRect(292, 302, 141, 17, 3, TFT_WHITE); 

      if (useLogScale) {
        tft.setTextColor(TFT_YELLOW); 
        tft.drawString("SCALE: LOG", 362, 309);
      } else {
        tft.drawString("SCALE: LIN", 362, 309);
      }
  } else {
      // PCAP gets a clean, unified label instead of useless sort buttons
      tft.setTextColor(TFT_DARKGREY);
      // Draw the static time scale on the far left
      tft.setTextDatum(TL_DATUM);
      tft.drawString("|=2m", 10, 301); 
      
      // Draw the main status label perfectly centered
      tft.setTextDatum(MC_DATUM);
      tft.drawString("PROMISCUOUS CAPTURE MODE", 240, 309); // 240 is true center of 480px screen
      tft.setTextColor(TFT_WHITE);
  }
    
  // ==========================================
  // ZONE 4: BATTERY PLACEHOLDER
  // ==========================================
  tft.drawRect(445, 304, 22, 12, TFT_WHITE); 
  tft.fillRect(467, 307, 3, 6, TFT_WHITE);   
  tft.fillRect(447, 306, 18, 8, TFT_GREEN);  
  
  tft.setTextDatum(TL_DATUM); 
  tft.setTextColor(TFT_WHITE);
}

float calculateRfDistance(int rssi, int txPower, RadioProtocol protocol, float customLoss = 0.0) {
    // Protection against invalid/corrupt packets. 
    // Returning -1.0 prevents the EMA filter from dragging the average down to 0!
    if (rssi >= 0 || rssi < -100) return -1.0; 

    float measuredPowerAtOneMeter;
    float pathLossExponent;

    // Set baselines based on the physical frequency and protocol
    switch (protocol) {
        case RADIO_BLE_24GHZ:
            measuredPowerAtOneMeter = (txPower != 0) ? (float)txPower - 62.0 : -59.0;
            pathLossExponent = (customLoss > 0.0) ? customLoss : 3.2; // Standard indoor
            break;

        case RADIO_WIFI_24GHZ:
            // Wi-Fi transmits significantly louder than BLE standard beacons
            measuredPowerAtOneMeter = (txPower != 0) ? (float)txPower - 65.0 : -45.0;
            pathLossExponent = (customLoss > 0.0) ? customLoss : 3.0; 
            break;

        case RADIO_WIFI_5GHZ:
            // 5GHz absorbs into the environment much faster than 2.4GHz
            measuredPowerAtOneMeter = (txPower != 0) ? (float)txPower - 68.0 : -50.0;
            pathLossExponent = (customLoss > 0.0) ? customLoss : 3.8; // Heavy indoor attenuation
            break;

        default:
            return -1.0;
    }
    
    // The core Log-Distance Formula: d = 10 ^ ((A - RSSI) / 10n)
    float ratio = (measuredPowerAtOneMeter - (float)rssi) / (10.0 * pathLossExponent);
    return std::pow(10.0, ratio);
}

void drawApScanner() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(1); 

  int n = WiFi.scanComplete();
  if (n < 0) {
    ap_current_page = 0;

    tft.setFreeFont(&UbuntuMono_Regular11pt7b);
    tft.setTextDatum(MC_DATUM);
    tft.setTextColor(TFT_WHITE);
    tft.fillRect(0, 0, 480, 30, TFT_BLUE);
    tft.drawString("SCANNING ACCESS POINTS...", 240, 15);

    esp_wifi_set_promiscuous(false);
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);

    n = WiFi.scanNetworks();
  }

  tft.setFreeFont(&UbuntuMono_Regular11pt7b);
  tft.setTextDatum(MC_DATUM);
  tft.setTextColor(TFT_WHITE);
  tft.fillRect(0, 0, 480, 30, TFT_BLUE);
  
  // Build the dynamic header string using the 'n' variable
  char headerStr[64];
  snprintf(headerStr, sizeof(headerStr), "SELECT TARGET AP (%d)", n);
  tft.drawString(headerStr, 240, 15);

  tft.setFreeFont(&UbuntuMono_Regular11pt7b);
  tft.setTextDatum(TL_DATUM);
  tft.setTextColor(TFT_GREEN);
  tft.drawRect(0, 40, 480, 35, TFT_DARKGREY); 
  tft.drawString("CH:ALL (Sniff Free Airspace)", 5, 50);

  tft.setTextColor(TFT_WHITE);
  
  // ==========================================
  // LIST GENERATION
  // ==========================================
  if (n == 0) {
    tft.drawString("No networks found in airspace.", 5, 90);
  } else {
    int start_idx = ap_current_page * APS_PER_PAGE;

    if (start_idx >= n) {
      ap_current_page = 0;
      start_idx = 0;
    }

    int end_idx = start_idx + APS_PER_PAGE;
    if (end_idx > n) end_idx = n;

    int row = 0;
    for (int i = start_idx; i < end_idx; ++i) {
      int y = 80 + (row * 35); 

      // 1. Get the raw BSSID bytes and the SSID string
      uint8_t* bssid = WiFi.BSSID(i);
      String raw_ssid = WiFi.SSID(i);
      char tactical_ssid[26]; 

      // 2. Determine if this SSID is a duplicate in the airspace
      bool has_clone = false;
      if (raw_ssid.length() > 0) {
        for (int j = 0; j < n; ++j) {
          if (i != j && WiFi.SSID(j) == raw_ssid) {
            has_clone = true;
            break;
          }
        }
      }

      // 3. Construct the Tactical Suffix String
      if (raw_ssid.length() == 0) {
        snprintf(tactical_ssid, sizeof(tactical_ssid), "<HIDDEN> [%02X%02X]", bssid[4], bssid[5]);
      } else if (has_clone) {
        char temp_ssid[16]; 
        strncpy(temp_ssid, raw_ssid.c_str(), 15);
        temp_ssid[15] = '\0';
        snprintf(tactical_ssid, sizeof(tactical_ssid), "%s~%02X%02X", temp_ssid, bssid[4], bssid[5]);
      } else {
        char temp_ssid[22]; 
        strncpy(temp_ssid, raw_ssid.c_str(), 21);
        temp_ssid[21] = '\0';
        snprintf(tactical_ssid, sizeof(tactical_ssid), "%s", temp_ssid);
      }

      // 4. Calculate Distance dynamically
      float dist = calculateRfDistance(WiFi.RSSI(i), 0, RADIO_WIFI_24GHZ);

      // 5. SPLIT DRAWING LOGIC FOR PERFECT ALIGNMENT
      
      // Build the Left String (Channel & SSID)
      char leftStr[60];
      snprintf(leftStr, sizeof(leftStr), "CH:%02d %s", WiFi.channel(i), tactical_ssid);

      // Build the Right String (RSSI & Distance) with rigid width padding
      char rightStr[30];
      snprintf(rightStr, sizeof(rightStr), "%4ddBm %3.0fm", WiFi.RSSI(i), dist);

      // Paint Left Side (Flush Left at X=5)
      tft.setTextDatum(TL_DATUM);
      tft.drawString(leftStr, 5, y + 10);

      // Paint Right Side (Flush Right at X=475)
      tft.setTextDatum(TR_DATUM);
      tft.drawString(rightStr, 475, y + 10); 

      tft.drawRect(0, y, 480, 35, TFT_DARKGREY);
      row++;
    }
  }

  // ==========================================
  // FOOTER & NAVIGATION (Synced to Y=294)
  // ==========================================
  tft.setFreeFont(&UbuntuMono_Regular9pt7b);
  tft.setTextDatum(TL_DATUM); 

  // THE FIX: Pushed down from 285 to perfectly match the Probe Tracker footer
  tft.drawLine(0, 294, 480, 294, TFT_WHITE);
  
  tft.setTextColor(TFT_RED);
  tft.drawString("BACK", 215, 300);

  if (n > APS_PER_PAGE) {
    tft.setTextColor(TFT_WHITE);

    if (ap_current_page > 0) {
      tft.drawString("<- PREV", 20, 300);
    }
    
    if (((ap_current_page + 1) * APS_PER_PAGE) < n) {
      tft.drawString("NEXT ->", 360, 300);
    }
  }
}

void getAgeString(uint32_t timestamp, char* buf, size_t len) {
    if (timestamp == 0) {
        snprintf(buf, len, "00h00m");
        return;
    }
    
    // Using subtraction handles the millis() 50-day rollover safely
    uint32_t elapsed = millis() - timestamp; 
    uint32_t mins = elapsed / 60000;
    uint32_t hours = mins / 60;
    mins = mins % 60;

    // Cap at 99h to prevent layout breaking if left on for 4+ days
    if (hours > 99) {
        snprintf(buf, len, ">99h  ");
    } else {
        snprintf(buf, len, "%02luh%02lum", hours, mins);
    }
}

void cleanOsintString(char* s) {
    if (s == nullptr) return;

    // 1. Strip bulky corporate suffixes
    const char* suffixes[] = {", Inc.", " Inc.", " LLC", " Corp.", " Ltd."};
    for (int i = 0; i < 5; i++) {
        size_t suffix_len = strlen(suffixes[i]);
        char* pos;
        while ((pos = strstr(s, suffixes[i])) != nullptr) {
            // memmove safely handles overlapping memory regions.
            // We shift everything after the suffix leftward, including the '\0' terminator.
            memmove(pos, pos + suffix_len, strlen(pos + suffix_len) + 1);
        }
    }

    // 2. Crush double spaces after colons (e.g. "Apple:  Find My" -> "Apple:Find My")
    char* pos;
    while ((pos = strstr(s, ":  ")) != nullptr) {
        // Keep the ':', shift the rest of the string left by 2 bytes
        memmove(pos + 1, pos + 3, strlen(pos + 3) + 1); 
    }
    
    // 3. Crush single spaces after colons
    while ((pos = strstr(s, ": ")) != nullptr) {
        // Keep the ':', shift the rest of the string left by 1 byte
        memmove(pos + 1, pos + 2, strlen(pos + 2) + 1);
    }
}

void formatShortUnit(uint32_t bytes, char* buf, size_t len) {
    if (bytes < 1000) snprintf(buf, len, "%3luB", bytes);
    else if (bytes < 1024000) snprintf(buf, len, "%3luK", bytes / 1024);
    else if (bytes < 1048576000) snprintf(buf, len, "%3luM", bytes / 1048576);
    else snprintf(buf, len, "%3.1fG", (float)bytes / 1073741824.0);
}

void formatTotalUnit(uint32_t bytes, char* buf, size_t len) {
    if (bytes < 1000) snprintf(buf, len, "%4luB", bytes);
    else if (bytes < 1024000) snprintf(buf, len, "%4luK", bytes / 1024);
    else if (bytes < 1048576000) snprintf(buf, len, "%4luM", bytes / 1048576);
    else snprintf(buf, len, "%4.1fG", (float)bytes / 1073741824.0);
}

void drawDeviceList() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextDatum(TL_DATUM);
  tft.setTextSize(1);

  // ==========================================
  // 1. DEVICE COUNTING
  // ==========================================
  int total_devices = 0;
  
  if (currentRadioMode == RADIO_WIFI) total_devices = sessionMacCount;
  else if (currentRadioMode == RADIO_BLE) total_devices = sessionBleCount;
  else if (currentRadioMode == RADIO_AP) total_devices = sessionApCount;
  else if (currentRadioMode == RADIO_CHANNELS) total_devices = sessionChannelCount;
  else if (currentRadioMode == RADIO_PCAP) {
      for (int i = 0; i < MAX_LEAK_SLOTS; i++) {
          if (leakHistory[i].leak.meta.timestamp > 0) total_devices++;
      }
  }

  // ==========================================
  // 2. DYNAMIC PAGINATION MATH
  // ==========================================
  int start_idx = 0;
  int end_idx = 0;
  bool has_next_page = false;

  // DECLARE IN OUTER SCOPE SO RENDERER CAN SEE THEM!
  int valid_indices[MAX_LEAK_SLOTS] = {0}; 
  int valid_count = 0;

  if (currentRadioMode == RADIO_PCAP) {
      // --- 1. GATHER LOGICAL ENTRIES ---
      for (int i = 0; i < MAX_LEAK_SLOTS; i++) {
          if (leakHistory[i].leak.meta.timestamp > 0) {
              valid_indices[valid_count++] = i;
          }
      }

      // --- 2. DYNAMIC PCAP "SNUG" PACKING ---
      const int maxChars = 58;
      int page_starts[MAX_LEAK_SLOTS] = {0}; // FRIEND'S FIX: Eliminated the arbitrary 15
      int total_pages = 0;
      int test_y = 32;

      for (int v = 0; v < valid_count; v++) {
          int idx = valid_indices[v];
          int pLen = leakHistory[idx].leak.retained_len;

          // FRIEND'S FIX: Defensive clamping for the packing math
          if (pLen > MAX_LEAK_STR_LEN - 1) pLen = MAX_LEAK_STR_LEN - 1;

          // Dynamically scale up to 9 lines (512 bytes / 58 chars)
          int n_lines = (pLen > 0) ? ((pLen - 1) / maxChars) + 1 : 1;
          if (n_lines > 9) n_lines = 9;

          int item_h = 42 + (n_lines * 14) + 5; 

          if (test_y + item_h > 290) { 
              if (total_pages < MAX_LEAK_SLOTS - 1) { // Prevents out-of-bounds on page_starts
                  total_pages++;
                  page_starts[total_pages] = v; 
              }
              test_y = 32 + item_h; 
          } else {
              test_y += item_h; 
          }
      }

      if (device_current_page > total_pages) device_current_page = total_pages;
      start_idx = page_starts[device_current_page];
      end_idx = (device_current_page < total_pages) ? page_starts[device_current_page + 1] : valid_count;
      has_next_page = (device_current_page < total_pages);
      
  } else {
      // --- FIXED GRID PACKING (WIFI/AP/BLE/CHANNELS) ---
      int items_per_page = 7;
      start_idx = device_current_page * items_per_page;
      if (start_idx >= total_devices) {
          device_current_page = 0;
          start_idx = 0;
      }
      end_idx = start_idx + items_per_page;
      if (end_idx > total_devices) end_idx = total_devices;
      has_next_page = (((device_current_page + 1) * items_per_page) < total_devices);
  }

  // ==========================================
  // 3. DRAW TOP BANNER (WITH FOXHUNT OVERRIDE)
  // ==========================================
  tft.setTextColor(TFT_WHITE);
  tft.setFreeFont(&UbuntuMono_B9pt7b);
  
  if (is_selecting_target) {
    tft.fillRect(0, 0, 480, 24, TFT_RED); 
    char huntStr[64];
    const char* modeName = (currentRadioMode == RADIO_WIFI) ? "WI-FI" : (currentRadioMode == RADIO_BLE) ? "BLE" : "NETWORKS";
    snprintf(huntStr, sizeof(huntStr), " FOXHUNT TARGET (%s)", modeName);
    tft.drawString(huntStr, 5, 5);
  } else {
    uint16_t headerColor = TFT_BLUE;
    const char* modeStr = "WI-FI";
    
    if (currentRadioMode == RADIO_BLE) { headerColor = TFT_PURPLE; modeStr = "BLE"; } 
    else if (currentRadioMode == RADIO_AP) { headerColor = TFT_DARKGREEN; modeStr = "NETWORKS"; } 
    else if (currentRadioMode == RADIO_CHANNELS) { headerColor = TFT_ORANGE; modeStr = "CHANNELS"; } 
    else if (currentRadioMode == RADIO_PCAP) { headerColor = TFT_MAROON; modeStr = "PCAP LEAKS"; }
    
    tft.fillRect(0, 0, 480, 24, headerColor);
    char headerStr[64];
    snprintf(headerStr, sizeof(headerStr), " SNIFFED %s (%d)", modeStr, total_devices);
    tft.drawString(headerStr, 5, 5); 
  } 

  // ==========================================
  // 4. DYNAMIC SORT BUTTONS
  // ==========================================
  tft.setFreeFont(&UbuntuMono_Regular9pt7b);
  char metricStr[32] = "SORT:ERR";
  uint16_t metricColor = TFT_RED;
  
  if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP) {
    if (currentSortMode == SORT_TOTAL) { strcpy(metricStr, "SORT:TOTAL"); metricColor = TFT_WHITE; }
    else if (currentSortMode == SORT_TX) { strcpy(metricStr, "SORT:TX"); metricColor = TFT_CYAN; }
    else if (currentSortMode == SORT_RX) { strcpy(metricStr, "SORT:RX"); metricColor = TFT_MAGENTA; }
    else if (currentSortMode == SORT_AVG) { strcpy(metricStr, "SORT:AVG"); metricColor = TFT_YELLOW; }
    else if (currentSortMode == SORT_CV) { strcpy(metricStr, "SORT:CV%"); metricColor = TFT_ORANGE; }
    else if (currentSortMode == SORT_DIST) { strcpy(metricStr, "SORT:DIST"); metricColor = TFT_GREEN; }
    else if (currentSortMode == SORT_AGE) { strcpy(metricStr, "SORT:AGE"); metricColor = TFT_BLUE; }
  } 
  else if (currentRadioMode == RADIO_CHANNELS) {
    if (currentSortMode == SORT_TOTAL) { strcpy(metricStr, "SORT:TOTAL"); metricColor = TFT_WHITE; }
    else if (currentSortMode == SORT_TX) { strcpy(metricStr, "SORT:DN"); metricColor = TFT_CYAN; }
    else if (currentSortMode == SORT_RX) { strcpy(metricStr, "SORT:UP"); metricColor = TFT_MAGENTA; }
    else if (currentSortMode == SORT_AVG) { strcpy(metricStr, "SORT:AVG"); metricColor = TFT_YELLOW; }
    else if (currentSortMode == SORT_CV) { strcpy(metricStr, "SORT:CV%"); metricColor = TFT_ORANGE; }
    else if (currentSortMode == SORT_DIST) { strcpy(metricStr, "SORT:PWR"); metricColor = TFT_GREEN; }
  } 
  else if (currentRadioMode == RADIO_BLE) {
    if (currentBleSortMode == SORT_BLE_HITS) { strcpy(metricStr, "SORT:HITS"); metricColor = TFT_WHITE; }
    else if (currentBleSortMode == SORT_BLE_DIST) { strcpy(metricStr, "SORT:DIST"); metricColor = TFT_GREEN; }
    else if (currentBleSortMode == SORT_BLE_AGE) { strcpy(metricStr, "SORT:AGE"); metricColor = TFT_BLUE; }
  }
  else if (currentRadioMode == RADIO_PCAP) {
    if (currentLeakSort == SORT_LEAK_AGE) { strcpy(metricStr, "SORT:AGE"); metricColor = TFT_BLUE; }
    else if (currentLeakSort == SORT_LEAK_LENGTH) { strcpy(metricStr, "SORT:SIZE"); metricColor = TFT_CYAN; }
    else if (currentLeakSort == SORT_LEAK_HITS) { strcpy(metricStr, "SORT:HITS"); metricColor = TFT_WHITE; }
  }

  tft.fillRoundRect(275, 2, 130, 20, 3, TFT_BLACK); 
  tft.drawRoundRect(275, 2, 130, 20, 3, TFT_WHITE);
  tft.setTextColor(metricColor);
  tft.drawString(metricStr, 282, 4);

  tft.fillRoundRect(410, 2, 65, 20, 3, TFT_BLACK); 
  tft.drawRoundRect(410, 2, 65, 20, 3, TFT_WHITE);
  
  if (sort_descending) {
    tft.setTextColor(TFT_WHITE);
    tft.drawString("DESC", 423, 4);
  } else {
    tft.setTextColor(TFT_GREEN);
    tft.drawString("ASC", 427, 4);
  }
  
  tft.setTextColor(TFT_WHITE);

  if (total_devices == 0) {
    tft.setFreeFont(&UbuntuMono_Regular9pt7b);
    tft.drawString("No devices captured yet.", 5, 45);
  } else {
    // ==========================================
    // 5. DRAW THE UNIFIED DUAL COLUMN HEADERS
    // ==========================================
    if (currentRadioMode != RADIO_PCAP) {
        tft.setTextColor(TFT_GREEN);
        if (currentRadioMode == RADIO_WIFI) {
          tft.setFreeFont(&UbuntuMono_B9pt7b);
          tft.drawString("     VENDOR                 MAC            RSSI TOTAL", 5, 26); 
          tft.setFreeFont(&UbuntuMono_Regular9pt7b); 
          tft.drawString("Per(s) FIRST | LAST DIST Mbps  AVG    CV%    TX | RX", 5, 41);
        } 
        else if (currentRadioMode == RADIO_AP) {
          tft.setFreeFont(&UbuntuMono_B9pt7b);
          tft.drawString("     SSID                 BSSID         CC RSSI TOTAL", 5, 26);       
          tft.setFreeFont(&UbuntuMono_Regular9pt7b); 
          tft.drawString("    FIRST | LAST  DIST CH RATE  AVG  CV%    TX | RX", 5, 41);
        }
        else if (currentRadioMode == RADIO_CHANNELS) {
          tft.setFreeFont(&UbuntuMono_B9pt7b);
          tft.drawString("     CHANNEL           PWR(AVG dBm|STD)         TOTAL", 5, 26);       
          tft.setFreeFont(&UbuntuMono_Regular9pt7b); 
          tft.drawString("    FIRST | LAST         STATE   AVG  CV%    DN | UP", 5, 41);
        }
        else {
          tft.setFreeFont(&UbuntuMono_B9pt7b);
          tft.drawString("    NAME                FIRST|LAST    RSSI  DIST  HITS", 5, 26);       
          tft.setFreeFont(&UbuntuMono_Regular9pt7b); 
          tft.drawString("MAC ADDRESS        VENDOR/DIAGNOSTIC PAYLOAD", 5, 41);
        }
        tft.setTextColor(TFT_WHITE); 
        tft.drawLine(0, 57, 480, 57, TFT_WHITE); 
    }

    // ==========================================
    // 6. DRAW THE DATA ROWS
    // ==========================================
    int row = 0;
    int base_y = (currentRadioMode == RADIO_PCAP) ? 32 : 62;
    int y_spacing = 33; // Fixed spacing for all non-PCAP modes
    int dyn_y = base_y; // Dynamic tracker exclusively for PCAP mode

    for (int i = start_idx; i < end_idx; i++) {
      
      // Select the correct Y coordinate based on the mode
      int y = (currentRadioMode == RADIO_PCAP) ? dyn_y : (base_y + (row * y_spacing)); 
      
      if (currentRadioMode == RADIO_WIFI) {
        // ... [WIFI MODE LOGIC REMAINS UNCHANGED] ...
        char line1[90]; char line2[90];
        resolveMacVendor(&sessionData[i]);

        char macStr[18];
        snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                 sessionData[i].mac[0], sessionData[i].mac[1], sessionData[i].mac[2],
                 sessionData[i].mac[3], sessionData[i].mac[4], sessionData[i].mac[5]);

        char safeVendor[20]; 
        snprintf(safeVendor, sizeof(safeVendor), "%-18.18s", sessionData[i].vendor);

        double mean = 0.0; double cv_percent = 0.0;
        if (sessionData[i].packets > 0) {
            mean = (double)sessionData[i].sum_bytes / (double)sessionData[i].packets;
            double avg_sq_sum = (double)sessionData[i].sum_sq_bytes / (double)sessionData[i].packets;
            double variance = avg_sq_sum - (mean * mean);
            if (variance < 0) variance = 0; 
            double std_dev = sqrt(variance);
            if (mean > 0) cv_percent = (std_dev / mean) * 100.0;
        }

        char firstSeenStr[8], lastSeenStr[8], ageCombo[16];
        getAgeString(sessionData[i].first_seen, firstSeenStr, sizeof(firstSeenStr));
        getAgeString(sessionData[i].last_seen, lastSeenStr, sizeof(lastSeenStr));
        snprintf(ageCombo, sizeof(ageCombo), "%s|%s", firstSeenStr, lastSeenStr); 

        uint32_t total_bytes = sessionData[i].tx_bytes + sessionData[i].rx_bytes;
        char totStr[10];
        formatTotalUnit(total_bytes, totStr, sizeof(totStr));

        char txStr[6], rxStr[6], trafficCombo[12];
        formatShortUnit(sessionData[i].tx_bytes, txStr, sizeof(txStr));
        formatShortUnit(sessionData[i].rx_bytes, rxStr, sizeof(rxStr));
        snprintf(trafficCombo, sizeof(trafficCombo), "%s|%s", txStr, rxStr); 

        char avgStr[6];
        formatShortUnit((uint32_t)mean, avgStr, sizeof(avgStr));

        int keep_alive_s = 0;
        if (sessionData[i].packets > 1) {
            unsigned long duration_ms = sessionData[i].last_seen - sessionData[i].first_seen;
            keep_alive_s = (duration_ms / sessionData[i].packets) / 1000;
            if (keep_alive_s > 99) keep_alive_s = 99; 
        }

        snprintf(line1, sizeof(line1), "%3d. %-18.18s %17s %4d %-5.5s", 
                 (i + 1), safeVendor, macStr, sessionData[i].rssi, totStr);

        snprintf(line2, sizeof(line2), "  %02d  %13s %4.0fm %3d  %-5.5s %4.0f%%   %9s", 
                 keep_alive_s, ageCombo, sessionData[i].smoothedDistance, sessionData[i].rate, 
                 avgStr, cv_percent, trafficCombo);

        tft.setFreeFont(&UbuntuMono_B9pt7b);
        tft.drawString(line1, 5, y);
        tft.setTextColor(TFT_LIGHTGREY);
        tft.setFreeFont(&UbuntuMono_Regular9pt7b);
        tft.drawString(line2, 5, y + 15);
        tft.setTextColor(TFT_WHITE);      
        
      } else if (currentRadioMode == RADIO_BLE) {
        // ... [BLE MODE LOGIC REMAINS UNCHANGED] ...
        char line1[90]; 
        char safeName[20];
        
        snprintf(safeName, sizeof(safeName), "%-18.18s", sessionBleData[i].name);

        char firstSeenStr[8], lastSeenStr[8], ageCombo[16];
        getAgeString(sessionBleData[i].firstSeen, firstSeenStr, sizeof(firstSeenStr));
        getAgeString(sessionBleData[i].lastSeen, lastSeenStr, sizeof(lastSeenStr));
        snprintf(ageCombo, sizeof(ageCombo), "%s|%s", firstSeenStr, lastSeenStr); 

        const char* trackerStr = "";
        switch (sessionBleData[i].trackerType) {
            case TRACKER_APPLE_FINDMY: trackerStr = "Apple: Find My"; break;
            case TRACKER_APPLE_IBEACON: trackerStr = "Apple: iBeacon"; break;
            case TRACKER_GOOGLE_FASTPAIR: trackerStr = "Google: FastPair"; break;
            case TRACKER_SAMSUNG_SMARTTAG: trackerStr = "Samsung: SmartTag"; break;
            case TRACKER_TILE: trackerStr = "Tile Tracker"; break;
            case TRACKER_MS_SWIFTPAIR: trackerStr = "MS: Swift Pair"; break;
            case TRACKER_EDDYSTONE: trackerStr = "Eddystone"; break;
            default: trackerStr = ""; break;
        }

        const char* appStr = resolveBleAppearance(sessionBleData[i].appearanceId);
        const char* srvStr = resolveBleServiceUuid(sessionBleData[i].serviceId);
        
        char tagStr[64] = {0}; 
        
        if (strlen(trackerStr) > 0 && sessionBleData[i].namePriority != 1) {
            strlcpy(tagStr, trackerStr, sizeof(tagStr));
        }
        
        if (appStr != nullptr && appStr[0] != '\0') {
            if (tagStr[0] != '\0') strlcat(tagStr, " | ", sizeof(tagStr));
            strlcat(tagStr, appStr, sizeof(tagStr));
        }
        
        if (srvStr != nullptr && srvStr[0] != '\0') {
            if (tagStr[0] != '\0') strlcat(tagStr, " | ", sizeof(tagStr));
            strlcat(tagStr, srvStr, sizeof(tagStr));
        }

        if (tagStr[0] == '\0') {
            if (sessionBleData[i].payload[0] != '\0') {
                if (sessionBleData[i].trackerType == TRACKER_APPLE_IBEACON) {
                    snprintf(tagStr, sizeof(tagStr), "iBeacon | %s", sessionBleData[i].payload);
                } else {
                    strlcpy(tagStr, sessionBleData[i].payload, sizeof(tagStr)); 
                }
            } else {
                strlcpy(tagStr, "No Data", sizeof(tagStr)); 
            }
        }
        
        cleanOsintString(tagStr); 

        char macStr[18];
        snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X", 
                 sessionBleData[i].mac[0], sessionBleData[i].mac[1], sessionBleData[i].mac[2], 
                 sessionBleData[i].mac[3], sessionBleData[i].mac[4], sessionBleData[i].mac[5]);

        snprintf(line1, sizeof(line1), "%2d.%-18.18s %13s %4d %4.0fm %5u", 
                 (i + 1), safeName, ageCombo, sessionBleData[i].rssi, 
                 sessionBleData[i].smoothedDistance, sessionBleData[i].hits);

        char line2[90];
        snprintf(line2, sizeof(line2), "%17s  %-33.33s", macStr, tagStr);

        tft.setFreeFont(&UbuntuMono_B9pt7b);
        tft.drawString(line1, 5, y);
        tft.setTextColor(TFT_LIGHTGREY);
        tft.setFreeFont(&UbuntuMono_Regular9pt7b);
        tft.drawString(line2, 5, y + 15);
        tft.setTextColor(TFT_WHITE);

      } else if (currentRadioMode == RADIO_AP) {
        // ... [AP MODE LOGIC REMAINS UNCHANGED] ...
        char line1[90];
        char line2[90];

        bool has_clone = false;
        if (strcmp(sessionApData[i].ssid, "<HIDDEN>") != 0 && strcmp(sessionApData[i].ssid, "<UNKNOWN>") != 0) {
          for (int j = 0; j < sessionApCount; j++) {
            if (i != j && strcmp(sessionApData[i].ssid, sessionApData[j].ssid) == 0) {
              has_clone = true; break;
            }
          }
        }

        char safeSsid[20];
        if (strcmp(sessionApData[i].ssid, "<HIDDEN>") == 0 || strcmp(sessionApData[i].ssid, "<UNKNOWN>") == 0) {
           snprintf(safeSsid, sizeof(safeSsid), "%-18.18s", sessionApData[i].ssid);
        } else if (has_clone) {
           char temp_ssid[13];
           strncpy(temp_ssid, sessionApData[i].ssid, 12); temp_ssid[12] = '\0';
           snprintf(safeSsid, sizeof(safeSsid), "%s~%02X%02X", temp_ssid, sessionApData[i].bssid[4], sessionApData[i].bssid[5]);
        } else {
           snprintf(safeSsid, sizeof(safeSsid), "%-18.18s", sessionApData[i].ssid);
        }

        char bssidStr[18];
        snprintf(bssidStr, sizeof(bssidStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                 sessionApData[i].bssid[0], sessionApData[i].bssid[1], sessionApData[i].bssid[2],
                 sessionApData[i].bssid[3], sessionApData[i].bssid[4], sessionApData[i].bssid[5]);

        double mean = 0.0;
        double cv_percent = 0.0;
        if (sessionApData[i].packets > 0) {
            mean = (double)sessionApData[i].sum_bytes / (double)sessionApData[i].packets;
            double avg_sq_sum = (double)sessionApData[i].sum_sq_bytes / (double)sessionApData[i].packets;
            double variance = avg_sq_sum - (mean * mean);
            if (variance < 0) variance = 0; 
            double std_dev = sqrt(variance);
            if (mean > 0) cv_percent = (std_dev / mean) * 100.0;
        }

        char avgStr[6];
        formatShortUnit((uint32_t)mean, avgStr, sizeof(avgStr));

        char firstSeenStr[8], lastSeenStr[8], ageCombo[16];
        getAgeString(sessionApData[i].first_seen, firstSeenStr, sizeof(firstSeenStr));
        getAgeString(sessionApData[i].last_seen, lastSeenStr, sizeof(lastSeenStr));
        snprintf(ageCombo, sizeof(ageCombo), "%s|%s", firstSeenStr, lastSeenStr); 

        uint32_t total_bytes = sessionApData[i].tx_bytes + sessionApData[i].rx_bytes;
        char totStr[10];
        formatTotalUnit(total_bytes, totStr, sizeof(totStr));

        char txStr[6], rxStr[6], trafficCombo[12];
        formatShortUnit(sessionApData[i].tx_bytes, txStr, sizeof(txStr));
        formatShortUnit(sessionApData[i].rx_bytes, rxStr, sizeof(rxStr));
        snprintf(trafficCombo, sizeof(trafficCombo), "%s|%s", txStr, rxStr); 
        
        char safeCountry[3] = "--";
        if (sessionApData[i].country[0] != '\0') {
            safeCountry[0] = sessionApData[i].country[0];
            safeCountry[1] = sessionApData[i].country[1];
        }

        snprintf(line1, sizeof(line1), "%3d. %-18.18s %17s %2s %4d %-5.5s", 
                 (i + 1), safeSsid, bssidStr, safeCountry, sessionApData[i].rssi, totStr);

        snprintf(line2, sizeof(line2), "    %13s %3.0fm %02d %3uM %-4.4s %3.0f%%   %9s", 
                 ageCombo, sessionApData[i].smoothedDistance, sessionApData[i].channel, 
                 sessionApData[i].max_rate, avgStr, cv_percent, trafficCombo);

        tft.setFreeFont(&UbuntuMono_B9pt7b);
        tft.drawString(line1, 5, y);
        tft.setTextColor(TFT_LIGHTGREY);
        tft.setFreeFont(&UbuntuMono_Regular9pt7b);
        tft.drawString(line2, 5, y + 15);
        tft.setTextColor(TFT_WHITE); 
      }
      else if (currentRadioMode == RADIO_CHANNELS) {
        // ... [CHANNELS MODE LOGIC REMAINS UNCHANGED] ...
        char line1[90];
        char line2[90];

        double mean = 0.0;
        double cv_percent = 0.0;
        if (sessionChannelData[i].packets > 0) {
            mean = (double)sessionChannelData[i].sum_bytes / (double)sessionChannelData[i].packets;
            double avg_sq_sum = (double)sessionChannelData[i].sum_sq_bytes / (double)sessionChannelData[i].packets;
            double variance = avg_sq_sum - (mean * mean);
            if (variance < 0) variance = 0; 
            double std_dev = sqrt(variance);
            if (mean > 0) cv_percent = (std_dev / mean) * 100.0;
        }

        float avg_rssi = sessionChannelData[i].avg_rssi;
        double std_dev_rssi = sqrt(sessionChannelData[i].ema_variance);
        
        float rho = 0.0;
        if (sessionChannelData[i].ema_variance > 0.01) { 
            rho = sessionChannelData[i].ema_cov / sessionChannelData[i].ema_variance;
        }

        char stateStr[10];
        if (sessionChannelData[i].packets < 5) strcpy(stateStr, "CALC.."); 
        else if (rho > 0.6) strcpy(stateStr, "DRIFT");   
        else if (rho > 0.2) strcpy(stateStr, "ACTIVE");  
        else strcpy(stateStr, "STATIC");                 

        char avgStr[6];
        formatShortUnit((uint32_t)mean, avgStr, sizeof(avgStr));

        char firstSeenStr[8], lastSeenStr[8], ageCombo[16];
        getAgeString(sessionChannelData[i].first_seen, firstSeenStr, sizeof(firstSeenStr));
        getAgeString(sessionChannelData[i].last_seen, lastSeenStr, sizeof(lastSeenStr));
        snprintf(ageCombo, sizeof(ageCombo), "%s|%s", firstSeenStr, lastSeenStr); 

        uint32_t total_bytes = sessionChannelData[i].tx_bytes + sessionChannelData[i].rx_bytes;
        char totStr[10];
        formatTotalUnit(total_bytes, totStr, sizeof(totStr));

        char txStr[6], rxStr[6], trafficCombo[12];
        formatShortUnit(sessionChannelData[i].tx_bytes, txStr, sizeof(txStr)); 
        formatShortUnit(sessionChannelData[i].rx_bytes, rxStr, sizeof(rxStr)); 
        snprintf(trafficCombo, sizeof(trafficCombo), "%s|%s", txStr, rxStr); 

        char pwrStr[16];
        if (sessionChannelData[i].packets == 0) strcpy(pwrStr, "N/A");
        else snprintf(pwrStr, sizeof(pwrStr), "%3.0f|~%-2.0f", avg_rssi, std_dev_rssi);

        snprintf(line1, sizeof(line1), "%3d. CHANNEL %02d %14s %-11.11s   %-5.5s", 
                 (i + 1), sessionChannelData[i].channel, "", pwrStr, totStr);

        snprintf(line2, sizeof(line2), "    %13s %5s %-7.7s %-4.4s %3.0f%%   %9s", 
                 ageCombo, "", stateStr, avgStr, cv_percent, trafficCombo);

        tft.setFreeFont(&UbuntuMono_B9pt7b);
        tft.drawString(line1, 5, y);
        tft.setTextColor(TFT_LIGHTGREY);
        tft.setFreeFont(&UbuntuMono_Regular9pt7b);
        tft.drawString(line2, 5, y + 15);
        tft.setTextColor(TFT_WHITE); 
      }
      else if (currentRadioMode == RADIO_PCAP) {
        // Map our logical loop variable 'i' back to the real array index!
        int real_idx = valid_indices[i];
        auto& lk = leakHistory[real_idx].leak;

        // ==========================================
        // PCAP MODE - DYNAMIC 1 TO 3 LINE RENDERING
        // ==========================================
        char line1[90], line2[90], line3[90];

        char firstSeenStr[8], lastSeenStr[8], ageCombo[18];
        getAgeString(leakHistory[real_idx].first_seen, firstSeenStr, sizeof(firstSeenStr));
        getAgeString(lk.meta.timestamp, lastSeenStr, sizeof(lastSeenStr));
        snprintf(ageCombo, sizeof(ageCombo), "%s|%s", firstSeenStr, lastSeenStr); 

        char safeSsid[13] = "Unknown";
        for (int ap = 0; ap < MAX_BSSID_CACHE; ap++) {
            if (bssidCache[ap].last_seen == 0) continue; 
            if (memcmp(lk.meta.bssid, bssidCache[ap].bssid, 6) == 0) {
                strncpy(safeSsid, bssidCache[ap].ssid, 12);
                safeSsid[12] = '\0';
                break;
            }
        }
        
        char srcVend[9], dstVend[9];
        strncpy(srcVend, leakHistory[real_idx].src_vendor, 8); srcVend[8] = '\0';
        strncpy(dstVend, leakHistory[real_idx].dst_vendor, 8); dstVend[8] = '\0';
        if(strlen(srcVend) == 0) strcpy(srcVend, "Unknown");
        if(strlen(dstVend) == 0) strcpy(dstVend, "Unknown");
        for (int v = 7; v >= 0; v--) { if (srcVend[v] == ' ') srcVend[v] = '\0'; else break; }
        for (int v = 7; v >= 0; v--) { if (dstVend[v] == ' ') dstVend[v] = '\0'; else break; }

        char lenStr[8];
        uint16_t fLen = lk.meta.frame_length;
        if (fLen < 1000) snprintf(lenStr, sizeof(lenStr), "%dB", fLen);
        else snprintf(lenStr, sizeof(lenStr), "%dK", fLen / 1000);
        
        char srcIpRaw[40] = {0}, dstIpRaw[40] = {0};
getIpString(lk.meta.ip_version, lk.meta.src_ip, srcIpRaw, sizeof(srcIpRaw));
getIpString(lk.meta.ip_version, lk.meta.dst_ip, dstIpRaw, sizeof(dstIpRaw));

char srcIpStr[40] = {0}, dstIpStr[40] = {0};
if (lk.meta.ip_version == 6) {
    compress_ipv6(srcIpRaw, srcIpStr, sizeof(srcIpStr));
    compress_ipv6(dstIpRaw, dstIpStr, sizeof(dstIpStr));
} else {
    strncpy(srcIpStr, srcIpRaw, sizeof(srcIpStr) - 1);
    strncpy(dstIpStr, dstIpRaw, sizeof(dstIpStr) - 1);
}

        snprintf(line1, sizeof(line1), "[x%d]%02X%02X%02X%02X%02X%02X(%s)>%02X%02X%02X%02X%02X%02X(%s)|%s|C%d", 
                 leakHistory[real_idx].hitCount,
                 lk.meta.src_mac[0], lk.meta.src_mac[1], lk.meta.src_mac[2],
                 lk.meta.src_mac[3], lk.meta.src_mac[4], lk.meta.src_mac[5], srcVend,
                 lk.meta.dst_mac[0], lk.meta.dst_mac[1], lk.meta.dst_mac[2],
                 lk.meta.dst_mac[3], lk.meta.dst_mac[4], lk.meta.dst_mac[5], dstVend, lenStr, lk.meta.channel);

        char portStr[24] = "";
        if (lk.meta.protocol == 6 || lk.meta.protocol == 17) {
            snprintf(portStr, sizeof(portStr), "|%d>%d", lk.meta.src_port, lk.meta.dst_port);
        }
        snprintf(line2, sizeof(line2), "%02X%02X%02X%02X%02X%02X(%s)|%s|%s|%s%s", 
                 lk.meta.bssid[0], lk.meta.bssid[1], lk.meta.bssid[2],
                 lk.meta.bssid[3], lk.meta.bssid[4], lk.meta.bssid[5],
                 safeSsid, getDirectionStr(lk.meta.direction), 
                 getSubtypeStr(lk.meta.frame_subtype),
                 getProtocolStr(lk.meta.protocol), portStr);

        snprintf(line3, sizeof(line3), "%s>%s|%s", srcIpStr, dstIpStr, ageCombo);

        // --- SAFE PAYLOAD SLICING (Explicit memcpy & Clamp) ---
        int pLen = lk.retained_len; 
        if (pLen > MAX_LEAK_STR_LEN - 1) {
            pLen = MAX_LEAK_STR_LEN - 1; // Defensive boundary clamp
        }
        
        char safePayload[MAX_LEAK_STR_LEN + 1] = {0};
        size_t copyLen = pLen;
        
        memcpy(safePayload, lk.text, copyLen);
        safePayload[copyLen] = '\0'; // Guarantee NUL termination

        // Fast sanitization loop utilizing clamped pLen
        for (int pt = 0; pt < pLen; pt++) {
            if (safePayload[pt] < 32 || safePayload[pt] > 126) safePayload[pt] = '.';
        }
        
        // --- DYNAMIC PAYLOAD SLICING (Loop-Based up to 9 lines) ---
        const int maxChars = 58;
        const int maxLinesAllowed = 9;
        char pLines[9][60] = {0}; // 2D array to hold up to 9 lines of 59 chars
        int n_lines = 1;

        for (int line = 0; line < maxLinesAllowed; line++) {
            int offset = line * maxChars;
            if (offset >= pLen) {
                if (line == 0) n_lines = 1; // Guarantee at least 1 line is counted
                break;
            }
            
            n_lines = line + 1;
            int remaining = pLen - offset;
            
            if (remaining <= maxChars) {
                strncpy(pLines[line], safePayload + offset, remaining);
            } else {
                // Truncate the final allowed line with +NNN if there's more payload
                if (line == maxLinesAllowed - 1) {
                    const int textChars = 54; // Leaves room for the "+NNN" tag
                    strncpy(pLines[line], safePayload + offset, textChars);
                    snprintf(pLines[line] + textChars, sizeof(pLines[line]) - textChars, "+%d", remaining - textChars);
                } else {
                    strncpy(pLines[line], safePayload + offset, maxChars);
                }
            }
        }

        // --- RENDER DYNAMIC HEIGHT ---
        tft.setFreeFont(&UbuntuMono_Regular8pt7b);
        tft.setTextColor(TFT_CYAN);
        tft.drawString(line1, 5, y);
        tft.setTextColor(TFT_YELLOW);
        tft.drawString(line2, 5, y + 14);
        tft.setTextColor(TFT_ORANGE);
        tft.drawString(line3, 5, y + 28);
        
        tft.setTextColor(TFT_GREEN);
        
        // Dynamically print exactly as many lines as this specific packet needs
        for (int l = 0; l < n_lines; l++) {
            tft.drawString(pLines[l], 5, y + 42 + (l * 14));
        }

        int current_item_h = 42 + (n_lines * 14);
        tft.drawLine(0, y + current_item_h + 2, 480, y + current_item_h + 2, COLOR_HOT_CHEST);
        
        dyn_y += current_item_h + 5; 
        tft.setTextColor(TFT_WHITE);
      }          // closes RADIO_PCAP branch
      row++;     // <-- also missing, see note below
    }            // closes the for loop
  }              // closes the total_devices==0 / else block

  // ==========================================
  // 7. SAFE NAVIGATION FOOTER
  // ==========================================
  tft.setFreeFont(&UbuntuMono_Regular9pt7b); 
  tft.drawLine(0, 294, 480, 294, TFT_WHITE); 

  if (device_current_page > 0 && total_devices > 0) {
    tft.setTextColor(TFT_WHITE);
    tft.drawString("<- PREV", 20, 300);
  }
  
  tft.setTextColor(TFT_RED);
  tft.drawString("BACK", 215, 300); 

  if (has_next_page) {
    tft.setTextColor(TFT_WHITE);
    tft.drawString("NEXT ->", 360, 300);
  }
}

void decodeEddystoneURL(const std::string& sData, char* outBuffer, size_t maxLen) {
    // Ensure we have a valid buffer to write to
    if (maxLen == 0) return;
    outBuffer[0] = '\0'; 

    // Eddystone frame type 0x10 specifically means "URL"
    if (sData.length() < 3 || sData[0] != 0x10) {
        strlcpy(outBuffer, "Eddy: (Not URL)", maxLen);
        return;
    }

    size_t idx = 0;

    // 1. Decode the Prefix Scheme (Byte 2)
    const char* prefix = "";
    switch (sData[2]) {
        case 0x00: prefix = "http://www."; break;
        case 0x01: prefix = "https://www."; break;
        case 0x02: prefix = "http://"; break;
        case 0x03: prefix = "https://"; break;
        default:   prefix = "Unknown URI"; break;
    }

    // Write prefix to buffer safely
    while (*prefix && idx < maxLen - 1) {
        outBuffer[idx++] = *prefix++;
    }

    // 2. Decode the Body and Suffixes (Bytes 3+)
    const char* suffixes[] = {
        ".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/",
        ".com", ".org", ".edu", ".net", ".info", ".biz", ".gov"
    };

    for (size_t i = 3; i < sData.length() && idx < maxLen - 1; i++) {
        uint8_t c = sData[i];
        if (c <= 0x0D) {
            const char* suffix = suffixes[c];
            // Inject the decompressed suffix
            while (*suffix && idx < maxLen - 1) {
                outBuffer[idx++] = *suffix++;
            }
        } else {
            // Standard ASCII text
            outBuffer[idx++] = (char)c;
        }
    }
    
    // Null-terminate the final string
    outBuffer[idx] = '\0';
}






// Helper to find or allocate an SSID string in the shared pool
int addSsidToPool(const char* ssid, int head_idx, bool &already_exists, bool &added, uint8_t current_count) {
  already_exists = false;
  added = false;
  //---
  // Drop Wildcard / Hidden SSIDs if they somehow slipped through the initial filter in sniffer_callback()
  if (ssid == nullptr || strlen(ssid) == 0) {
    return head_idx; // Bail out immediately without claiming memory
  }
  //---
  int current = head_idx;
  int last = -1;

  // 1. Traverse the existing chain to check for duplicates
  while (current != -1) {
    if (strcmp(ssidPool[current].text, ssid) == 0) {
      already_exists = true;
      return head_idx;
    }
    last = current;
    current = ssidPool[current].next_node_idx;
  }

  // 2. Enforce the emergency cutoff per device
  if (current_count >= EMERGENCY_CUTOFF) {
    return head_idx; 
  }

  // 3. Find the first available slot in the global pool (Garbage Collection!)
  int new_idx = -1;
  for (int i = 0; i < TOTAL_SSID_POOL; i++) {
    if (ssidPool[i].text[0] == '\0') {
      new_idx = i;
      break;
    }
  }

  // If the pool is completely full and no slots are free, just bail out
  if (new_idx == -1) return head_idx; 

  // 4. Claim the slot
  strncpy(ssidPool[new_idx].text, ssid, 32);
  ssidPool[new_idx].text[32] = '\0'; // Ensure safe termination
  ssidPool[new_idx].next_node_idx = -1;
  added = true;

  // 5. Link it into the device's chain
  if (last == -1) {
    return new_idx; // This is the very first SSID for this device
  } else {
    ssidPool[last].next_node_idx = new_idx; // Append to the end of the chain
    return head_idx;
  }
}

void processProbeRequestShared(uint8_t* mac, const char* ssid, const char* known_vendor, int8_t rssi, uint32_t hw_hash) {
  int target_slot = -1;
  unsigned long oldest_time = 0xFFFFFFFF;
  int oldest_slot = 0;

  for (int i = 0; i < MAX_PROBE_SLOTS; i++) {
    if (memcmp(probeList[i].mac, mac, 6) == 0) {
      target_slot = i;
      break;
    }
    if (probeList[i].last_seen < oldest_time) {
      oldest_time = probeList[i].last_seen;
      oldest_slot = i;
    }
  }

  // Handle eviction/overwrite if it's a completely new device
  if (target_slot == -1) {
    target_slot = oldest_slot;

    // ==========================================
    // THE GARBAGE COLLECTOR (With Circuit Breaker)
    // ==========================================
    int current_node = probeList[target_slot].first_ssid_idx;
    int fail_safe = 0; 
    
    while (current_node != -1 && fail_safe < TOTAL_SSID_POOL) {
      int next = ssidPool[current_node].next_node_idx;
      ssidPool[current_node].text[0] = '\0'; 
      ssidPool[current_node].next_node_idx = -1; 
      current_node = next;
      fail_safe++;
    }
    // ==========================================

    // Safely claiming the slot:
    memcpy(probeList[target_slot].mac, mac, 6);
    probeList[target_slot].hits = 0;
    probeList[target_slot].ssid_count = 0;
    probeList[target_slot].first_ssid_idx = -1;
    probeList[target_slot].first_seen = millis();
    
    // --- CRITICAL MEMORY WIPE ---
    probeList[target_slot].pnl_hash = 0; 
    probeList[target_slot].mac_rotations = 1;
    // ----------------------------

    // CRITICAL: Increment generation to invalidate any in-flight SD lookups for this slot (ABA fix)
    probeList[target_slot].generation++; 
    
    // ==========================================
    // DEFER TO CORE 1 OR USE KNOWN VENDOR
    // ==========================================
    if (strlen(known_vendor) > 0) {
      // We already know who this is from Tag 221! Lock out Core 1.
      strncpy(probeList[target_slot].vendor, known_vendor, sizeof(probeList[target_slot].vendor) - 1);
      probeList[target_slot].needs_lookup = false; 
    } else {
      // We have no idea who this is. Tell Core 1 to check the SD Card.
      strncpy(probeList[target_slot].vendor, "Resolving...", sizeof(probeList[target_slot].vendor));
      probeList[target_slot].needs_lookup = true; 
    }
    // ==========================================
  }

  // 1. Standard Updates
  // In processProbeRequestShared:
  if (probeList[target_slot].hits < 65535) {
      probeList[target_slot].hits++;
  }
  probeList[target_slot].last_seen = millis();
  probeList[target_slot].rssi = rssi;
  
  // --- NEW: INJECT THE HARDWARE HASH HERE ---
  probeList[target_slot].hardware_hash = hw_hash;
  // ------------------------------------------

  // 2. EMA Physics Engine
  float rawDistance = calculateRfDistance(rssi, 0, RADIO_WIFI_24GHZ);
  if (rawDistance > 0) {
      if (probeList[target_slot].hits == 1) {
          probeList[target_slot].smoothedDistance = rawDistance; // First hit is absolute
      } else {
          probeList[target_slot].smoothedDistance = (0.2 * rawDistance) + (0.8 * probeList[target_slot].smoothedDistance);
      }
  }

  bool already_exists = false;
  bool added = false;
  
  int new_head = addSsidToPool(ssid, probeList[target_slot].first_ssid_idx, already_exists, added, probeList[target_slot].ssid_count);
  
  probeList[target_slot].first_ssid_idx = new_head;
  
  if (added) {
    probeList[target_slot].ssid_count++;
  }
  
  // 3. Update the Bloom Filter
  if (strcmp(ssid, "<Wld>") != 0 && strcmp(ssid, "<Nul>") != 0) {
      uint8_t bit_idx = getSsidBitIndex(ssid);
      probeList[target_slot].pnl_hash |= (1ULL << bit_idx);
  }
}

// --- Background Vendor Resolver (Runs safely on Core 1) ---
void processPendingVendors() {
  // ==========================================
  // 1. OSINT Probe Tracker Resolution Logic
  // ==========================================
  for (int i = 0; i < MAX_PROBE_SLOTS; i++) {
    if (probeList[i].needs_lookup) {
      MacRecord dummy;
      
      // A. Lock briefly to copy the MAC and the generation ticket
      pause_sniffing = true;
      memcpy(dummy.mac, probeList[i].mac, 6);
      uint32_t current_generation = probeList[i].generation; 
      pause_sniffing = false; // Unlock immediately! Let the radio sniff.
      
      dummy.vendorFound = false;
      resolveMacVendor(&dummy); // Slow SD Card read happens safely here
      
      // B. Lock again to write the result
      pause_sniffing = true;
      
      // CRITICAL: Did Core 0 evict this slot while we were reading?
      if (probeList[i].generation == current_generation) {
        // The generation matches! Safe to write.
        strlcpy(probeList[i].vendor, dummy.vendor, sizeof(probeList[i].vendor));
        probeList[i].needs_lookup = false; 
      }
      
      pause_sniffing = false; // Unlock
      break; // Only process one SD read per loop to prevent UI blocking
    }
  }

  // ==========================================
  // 2. Main Wi-Fi Device List Resolution
  // ==========================================
  if (currentRadioMode == RADIO_WIFI) {
    for (int i = 0; i < sessionMacCount; i++) {
      if (sessionData[i].needs_lookup) {
        MacRecord dummy;

        // A. Lock briefly to copy the MAC
        pause_sniffing = true;
        memcpy(dummy.mac, sessionData[i].mac, 6);
        pause_sniffing = false; 
        
        dummy.vendorFound = false;
        resolveMacVendor(&dummy); // Safe background lookup
        
        // B. Lock again to write the result
        pause_sniffing = true;
        
        // We use memcmp here since sessionData doesn't seem to have a generation counter yet
        if (memcmp(sessionData[i].mac, dummy.mac, 6) == 0) {
            strlcpy(sessionData[i].vendor, dummy.vendor, sizeof(sessionData[i].vendor));
            sessionData[i].needs_lookup = false; 
        }

        pause_sniffing = false;
        break; // Only process one SD read per loop
      }
    }
  }
}

void drawProbeTracker() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(1);

  // ==========================================
  // 1. DYNAMIC HEADER BANNER (Unified UI)
  // ==========================================
  sortProbeList();

  int active_probes = 0;
  for (int i = 0; i < MAX_PROBE_SLOTS; i++) {
    for (int b = 0; b < 6; b++) {
      if (probeList[i].mac[b] != 0) {
        active_probes++;
        break; 
      }
    }
  }
  total_sniffed_probes = active_probes;

  tft.setFreeFont(&UbuntuMono_B9pt7b);
  tft.setTextDatum(TL_DATUM);
  tft.setTextColor(TFT_WHITE);
  uint16_t osintHeaderColor = hex24to565(0x4A148C); 
  tft.fillRect(0, 0, 480, 24, osintHeaderColor);
  
  char headerStr[64];
  snprintf(headerStr, sizeof(headerStr), "PHYSICAL TARGETS (%d)", active_probes);
  tft.drawString(headerStr, 0, 5); 

  // --- INJECT SORT UI BUTTONS ---
  char metricStr[32];
  uint16_t metricColor = TFT_YELLOW;

  if (currentProbeSortMode == PROBE_SORT_HITS) strcpy(metricStr, "SORT:HITS");
  else if (currentProbeSortMode == PROBE_SORT_DIST) strcpy(metricStr, "SORT:DIST");
  else if (currentProbeSortMode == PROBE_SORT_SSIDS) strcpy(metricStr, "SORT:#SSIDs");
  else if (currentProbeSortMode == PROBE_SORT_AGE) strcpy(metricStr, "SORT:AGE");

  tft.fillRoundRect(275, 2, 130, 20, 3, TFT_BLACK); 
  tft.drawRoundRect(275, 2, 130, 20, 3, TFT_WHITE);
  tft.setTextColor(metricColor);
  tft.drawString(metricStr, 282, 4);

  tft.fillRoundRect(410, 2, 65, 20, 3, TFT_BLACK); 
  tft.drawRoundRect(410, 2, 65, 20, 3, TFT_WHITE);
  
  if (probe_sort_descending) {
    tft.setTextColor(TFT_WHITE);
    tft.drawString("DESC", 423, 4);
  } else {
    tft.setTextColor(TFT_GREEN);
    tft.drawString("ASC", 427, 4);
  }
  
  // ==========================================
  // 2. DUAL-LINE COLUMN HEADERS
  // ==========================================
  tft.setTextColor(TFT_GREEN);
  tft.setFreeFont(&UbuntuMono_B9pt7b);
  // --- UPDATED: Realigned spacing and injected #MAC column ---
  tft.drawString("ID VENDOR        FIRST|LAST   RSSI DIST #MAC HITS", 0, 26); 
  tft.setFreeFont(&UbuntuMono_Regular9pt7b); 
  tft.drawString("MAC ADDRESS       CAPTURED SSIDs", 0, 41); 
  tft.drawLine(0, 57, 480, 57, TFT_WHITE); 

  // ==========================================
  // 3. DATA ROWS (3-Line Data Injection)
  // ==========================================
  int start_idx = probe_current_page * PROBES_PER_PAGE;
  int end_idx = start_idx + PROBES_PER_PAGE;

  int row = 0;
  for (int i = start_idx; i < end_idx; i++) {
    bool is_slot_empty = true;
    for (int b = 0; b < 6; b++) {
      if (probeList[i].mac[b] != 0) {
        is_slot_empty = false;
        break;
      }
    }

    int y = 60 + (row * 46); 

    if (!is_slot_empty) {
      
      // --- LINE 1: Metadata ---
      if (probeList[i].mac_rotations > 1) {
          tft.setTextColor(TFT_ORANGE); 
      } else {
          tft.setTextColor(TFT_GREEN);  
      }

      bool is_randomized = (probeList[i].mac[0] & 0x02) != 0;
      char safeVendor[20];
      char rawVendor[20];
      
      if (strcmp(probeList[i].vendor, "Resolving...") == 0) {
          strcpy(rawVendor, "Resolving...");
      } else if (strstr(probeList[i].vendor, "(IE)") != nullptr) {
          strncpy(rawVendor, probeList[i].vendor, 19);
          rawVendor[19] = '\0';
      } else if (is_randomized) {
          strcpy(rawVendor, "<Randomized>");
      } else if (probeList[i].vendor[2] == ':' || strcmp(probeList[i].vendor, "Unknown") == 0 || strlen(probeList[i].vendor) == 0) {
          strcpy(rawVendor, "Unknown Device");
      } else {
          strncpy(rawVendor, probeList[i].vendor, 19);
          rawVendor[19] = '\0';
      }

      // Reduced from 15 to 13 to make room for the new #MAC column
      snprintf(safeVendor, sizeof(safeVendor), "%-13.13s", rawVendor);

      char ageCombo[16];
      char firstSeenStr[8], lastSeenStr[8];
      getAgeString(probeList[i].first_seen, firstSeenStr, sizeof(firstSeenStr));
      getAgeString(probeList[i].last_seen, lastSeenStr, sizeof(lastSeenStr));
      snprintf(ageCombo, sizeof(ageCombo), "%s|%s", firstSeenStr, lastSeenStr);

      char metaStr[80];
      // --- UPDATED: Injected mac_rotations into the Line 1 format string ---
      snprintf(metaStr, sizeof(metaStr), "%02d.%-13.13s %13s %4d %4.0fm %4d %4u",
               i + 1, safeVendor, ageCombo, probeList[i].rssi, probeList[i].smoothedDistance, probeList[i].mac_rotations, probeList[i].hits);
               
      tft.setFreeFont(&UbuntuMono_B9pt7b);
      tft.drawString(metaStr, 0, y); 

      // --- LINES 2 & 3: MAC Address & Smart SSID Word Wrapper ---
      tft.setFreeFont(&UbuntuMono_Regular8pt7b); 
      
      // Keep MAC Orange if it's a rotated device to act as a visual anchor
      if (probeList[i].mac_rotations > 1) {
          tft.setTextColor(TFT_ORANGE);
      } else {
          tft.setTextColor(TFT_WHITE);
      }
      
      // --- UPDATED: Flush left MAC address string ---
      char macStr[20];
      snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X", 
               probeList[i].mac[0], probeList[i].mac[1], probeList[i].mac[2],
               probeList[i].mac[3], probeList[i].mac[4], probeList[i].mac[5]);
      tft.drawString(macStr, 0, y + 16); 

      tft.setTextColor(TFT_WHITE);
      char line1[80] = ""; 
      char line2[100] = ""; 
      
      int true_total_ssids = 0;
      int temp_node = probeList[i].first_ssid_idx;
      while (temp_node != -1) {
          if (strlen(ssidPool[temp_node].text) > 0) {
              true_total_ssids++;
          }
          temp_node = ssidPool[temp_node].next_node_idx;
      }

      int current_node = probeList[i].first_ssid_idx;
      int ssids_drawn = 0;
      bool on_line2 = false;

      while (current_node != -1) {
        char next_str[36];
        snprintf(next_str, sizeof(next_str), "%s", ssidPool[current_node].text);
        
        if (strlen(next_str) == 0) {
            current_node = ssidPool[current_node].next_node_idx;
            continue; 
        }
        
        char addition[40];
        if (ssids_drawn == 0) snprintf(addition, sizeof(addition), "%s", next_str); 
        else snprintf(addition, sizeof(addition), "|%s", next_str);

        // --- UPDATED: Expanded Line 1 limit to 41 chars ---
        if (!on_line2) {
            if (strlen(line1) + strlen(addition) <= 41) { 
                strlcat(line1, addition, sizeof(line1));
                ssids_drawn++;
            } else {
                on_line2 = true; 
            }
        }

        if (on_line2) {
            if (strlen(line2) == 0) snprintf(addition, sizeof(addition), "%s", next_str);
            else snprintf(addition, sizeof(addition), "|%s", next_str);

            if (strlen(line2) + strlen(addition) <= 58) { 
                strlcat(line2, addition, sizeof(line2));
                ssids_drawn++;
            } else {
                break; 
            }
        }
        current_node = ssidPool[current_node].next_node_idx;
      }

      if (ssids_drawn == 0) {
        strlcat(line1, "<no SSIDs captured>", sizeof(line1));
      } else if (ssids_drawn < true_total_ssids) {
        char plusStr[8];
        snprintf(plusStr, sizeof(plusStr), "|+%d", (true_total_ssids - ssids_drawn));
        
        // --- UPDATED: Increased Line 1 safety check to 36 for the +X tag ---
        if (on_line2 || strlen(line1) > 36) { 
            strlcat(line2, plusStr, sizeof(line2));
        } else {
            strlcat(line1, plusStr, sizeof(line1));
        }
      }

      // --- UPDATED: Moved starting coordinate from 165 to 145 ---
      tft.drawString(line1, 145, y + 16);
      
      if (strlen(line2) > 0) {
        tft.drawString(line2, 0, y + 30); 
      }
      tft.drawLine(0, y + 45, 480, y + 45, hex24to565(0x222222));
    }
    row++;
  }

  // ==========================================
  // 4. UNIFIED NAVIGATION FOOTER
  // ==========================================
  tft.setFreeFont(&UbuntuMono_Regular9pt7b); 
  tft.drawLine(0, 294, 480, 294, TFT_WHITE); 

  if (probe_current_page > 0 && total_sniffed_probes > 0) {
    tft.setTextColor(TFT_WHITE);
    tft.drawString("<- PREV", 20, 300);
  }
  
  tft.setTextColor(TFT_RED);
  tft.drawString("BACK", 215, 300); 

  if (((probe_current_page + 1) * PROBES_PER_PAGE) < total_sniffed_probes) {
    tft.setTextColor(TFT_WHITE);
    tft.drawString("NEXT ->", 360, 300);
  }
}

void initProbeTracker() {
  // 1. Initialize all device slots
  for (int i = 0; i < MAX_PROBE_SLOTS; i++) {
    memset(probeList[i].mac, 0, 6);
    probeList[i].hits = 0;
    probeList[i].first_seen = 0;
    probeList[i].last_seen = 0;
    probeList[i].ssid_count = 0;
    probeList[i].first_ssid_idx = -1; 
    probeList[i].generation = 0;
    probeList[i].needs_lookup = false;
    probeList[i].rssi = -100;           
    probeList[i].smoothedDistance = 0.0; 
    
    // --- INITIALIZE FINGERPRINTING & GROUP DATA ---
    probeList[i].pnl_hash = 0;
    probeList[i].hardware_hash = 0;
    probeList[i].mac_rotations = 1;
    // ---------------------------------------------------

    strncpy(probeList[i].vendor, "Unknown", 25);
  }

  // 2. Initialize the global SSID memory pool
  for (int i = 0; i < TOTAL_SSID_POOL; i++) {
    ssidPool[i].text[0] = '\0';
    ssidPool[i].next_node_idx = -1;
  }
}

void drawFoxhuntScreen() {
    last_displayed_rssi = -999; // Force redraw on every full screen draw
    last_drawn_min = 0;         // NEW: Force bounds redraw 
    last_drawn_max = 0;         // NEW: Force bounds redraw
    tft.fillScreen(TFT_BLACK);
    
    // ==========================================
    // ZONE MAP (non-overlapping):
    // Y=0-30:    Header (static)
    // Y=35-55:   MAC address (static)
    // Y=58-75:   Vendor (static, truncated)
    // Y=80-100:  "SIGNAL:" label (static)
    // Y=100-130: RSSI value (DYNAMIC — owned by loop() updater)
    // Y=130-195: Spatial dashboard (DYNAMIC — owned by loop() updater)
    // Y=220-275: Alert banner (DYNAMIC — owned by loop() updater)
    // Y=285-320: Footer (static)
    // ==========================================
    
    // 1. HEADER (static)
    tft.fillRect(0, 0, 480, 30, 
                 (currentRadioMode == RADIO_BLE) ? TFT_PURPLE : TFT_RED);
    tft.setTextColor(TFT_WHITE);
    tft.setTextDatum(MC_DATUM);
    tft.setFreeFont(&UbuntuMono_Regular11pt7b);
    const char* huntLabel = "WIFI FOXHUNT";
    if (currentRadioMode == RADIO_BLE) huntLabel = "BLE FOXHUNT";
    else if (currentRadioMode == RADIO_AP) huntLabel = "AP FOXHUNT";
    tft.drawString(huntLabel, 240, 15);

    // 2. TARGET MAC (static)
    tft.setFreeFont(&UbuntuMono_Regular9pt7b);
    tft.setTextColor(TFT_CYAN);
    char targetStr[64];
    snprintf(targetStr, sizeof(targetStr), 
             "TARGET: %02X:%02X:%02X:%02X:%02X:%02X",
             foxhunt_target_mac[0], foxhunt_target_mac[1],
             foxhunt_target_mac[2], foxhunt_target_mac[3],
             foxhunt_target_mac[4], foxhunt_target_mac[5]);
    tft.drawString(targetStr, 240, 40);

    // 3. VENDOR (static, truncated to prevent width overflow)
    tft.setTextColor(TFT_LIGHTGREY);
    char safeVendor[21];
    strncpy(safeVendor, foxhunt_target_vendor, 20);
    safeVendor[20] = '\0';
    tft.drawString(safeVendor, 240, 58); // Nudged up slightly for perfect spacing

    // 4. TARGET CHANNEL (Replaces the phantom "SIGNAL" label)
    if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP) {
        tft.setTextColor(TFT_ORANGE); 
        char chStr[16];
        snprintf(chStr, sizeof(chStr), "CH: %02d", target_channel);
        tft.drawString(chStr, 240, 76);
    }

    // 6. FOOTER (static)
    tft.drawLine(0, 285, 480, 285, TFT_WHITE);
    tft.drawRoundRect(190, 292, 100, 24, 3, TFT_RED);
    tft.setTextColor(TFT_WHITE);
    tft.setFreeFont(&UbuntuMono_Regular9pt7b);
    tft.setTextDatum(MC_DATUM);
    tft.drawString("ABORT", 240, 304);
    tft.setTextDatum(TL_DATUM); // Reset datum
}

double getChannelMetric(ChannelRecord r, SortMode mode) {
  if (mode == SORT_TOTAL) return (double)(r.tx_bytes + r.rx_bytes);
  if (mode == SORT_TX) return (double)r.tx_bytes; // Downlink
  if (mode == SORT_RX) return (double)r.rx_bytes; // Uplink
  if (mode == SORT_AVG) return (r.packets > 0) ? (double)(r.sum_bytes / r.packets) : 0;
  if (mode == SORT_CV) {
    if (r.packets == 0) return 0;
    double mean = (double)r.sum_bytes / r.packets;
    double variance = ((double)r.sum_sq_bytes / r.packets) - (mean * mean);
    if (variance <= 0 || mean == 0) return 0;
    return (sqrt(variance) / mean) * 100.0;
  }
  // Repurposing SORT_DIST to sort by Power (Avg RSSI)
  if (mode == SORT_DIST) return (double)r.avg_rssi; 
  
  return (double)(r.tx_bytes + r.rx_bytes); // Failsafe fallback
}

void forceSessionSort() {
  if (currentRadioMode == RADIO_WIFI) {
    for (int i = 1; i < sessionMacCount; i++) {
      MacRecord key = sessionData[i];
      double key_val = getSortMetric(key, currentSortMode);
      int j = i - 1;
      if (sort_descending) {
        while (j >= 0 && getSortMetric(sessionData[j], currentSortMode) < key_val) {
          sessionData[j + 1] = sessionData[j];
          j = j - 1;
        }
      } else {
        while (j >= 0 && getSortMetric(sessionData[j], currentSortMode) > key_val && key_val > 0.0) {
          sessionData[j + 1] = sessionData[j];
          j = j - 1;
        }
      }
      sessionData[j + 1] = key;
    }
  } 
  else if (currentRadioMode == RADIO_BLE) {
    for (int i = 1; i < sessionBleCount; i++) {
      BLERecord key = sessionBleData[i];
      double key_val = getBleSortMetric(key, currentBleSortMode);
      int j = i - 1;
      if (sort_descending) {
        while (j >= 0 && getBleSortMetric(sessionBleData[j], currentBleSortMode) < key_val) {
          sessionBleData[j + 1] = sessionBleData[j];
          j = j - 1;
        }
      } else {
        while (j >= 0 && getBleSortMetric(sessionBleData[j], currentBleSortMode) > key_val && key.hits > 0) {
          sessionBleData[j + 1] = sessionBleData[j];
          j = j - 1;
        }
      }
      sessionBleData[j + 1] = key;
    }
  } 
  else if (currentRadioMode == RADIO_AP) {
    for (int i = 1; i < sessionApCount; i++) {
      ApRecord key = sessionApData[i];
      double key_val = getSortMetric(key, currentSortMode);
      int j = i - 1;
      if (sort_descending) {
        while (j >= 0 && getSortMetric(sessionApData[j], currentSortMode) < key_val) {
          sessionApData[j + 1] = sessionApData[j];
          j = j - 1;
        }
      } else {
        while (j >= 0 && getSortMetric(sessionApData[j], currentSortMode) > key_val && key_val > 0.0) {
          sessionApData[j + 1] = sessionApData[j];
          j = j - 1;
        }
      }
      sessionApData[j + 1] = key;
    }
  }
  else if (currentRadioMode == RADIO_CHANNELS) {
    for (int i = 1; i < sessionChannelCount; i++) {
      ChannelRecord key = sessionChannelData[i];
      double key_val = getChannelMetric(key, currentSortMode);
      int j = i - 1;
      if (sort_descending) {
        while (j >= 0 && getChannelMetric(sessionChannelData[j], currentSortMode) < key_val) {
          sessionChannelData[j + 1] = sessionChannelData[j];
          j = j - 1;
        }
      } else {
        // Prevent sorting zero-data to the top in ascending mode
        while (j >= 0 && getChannelMetric(sessionChannelData[j], currentSortMode) > key_val && key_val > 0.0) {
          sessionChannelData[j + 1] = sessionChannelData[j];
          j = j - 1;
        }
      }
      sessionChannelData[j + 1] = key;
    }
  }
}

void drawPersistentTopN() {
    tft.setFreeFont(&UbuntuMono_B9pt7b);
    tft.setTextDatum(TL_DATUM);

    int top_count = 0;
    if (currentRadioMode == RADIO_WIFI) top_count = sessionMacCount;
    else if (currentRadioMode == RADIO_BLE) top_count = sessionBleCount;
    else if (currentRadioMode == RADIO_AP) top_count = sessionApCount;
    else if (currentRadioMode == RADIO_CHANNELS) top_count = sessionChannelCount;

    if (top_count > 10) top_count = 10;

    // 1. Static state trackers for delta-drawing (REMOVED HEAP-FRAG STRINGS)
    static char lastLabels[10][32] = {0}; 
    static int lastTopCount = 0;
    static uint8_t lastRadioMode = 255; // 255 forces an initial redraw on boot

    // 2. Force a full block wipe ONLY when changing radio modes
    bool forceRedraw = (currentRadioMode != lastRadioMode) || force_ui_refresh;
    if (forceRedraw) {
        tft.fillRect(0, 18, 480, HEADER_HEIGHT - 27, TFT_BLACK);
        for(int i = 0; i < 10; i++) {
            lastLabels[i][0] = '\0'; // Clear the cache array
        }
        lastRadioMode = currentRadioMode;
        force_ui_refresh = false; // Consume the flag so it only runs once
    }

    for (int i = 0; i < top_count; i++) {
        // Grid Math
        int col = i % 2;           
        int row = i / 2;           
        
        int x_pos = 5 + (col * 240);       
        int y_pos = 18 + (row * 16);  

        char display_name[28] = "Unknown"; // Buffer for the raw text

        if (currentRadioMode == RADIO_WIFI) {
            strncpy(display_name, sessionData[i].vendor, 26);
            display_name[26] = '\0';
        } 
        else if (currentRadioMode == RADIO_BLE) {
            if (strlen((char*)sessionBleData[i].name) > 0) {
                strncpy(display_name, (char*)sessionBleData[i].name, 26);
                display_name[26] = '\0';
            } else {
                snprintf(display_name, sizeof(display_name), "%02X:%02X:%02X:%02X:%02X:%02X", 
                         sessionBleData[i].mac[0], sessionBleData[i].mac[1], sessionBleData[i].mac[2], 
                         sessionBleData[i].mac[3], sessionBleData[i].mac[4], sessionBleData[i].mac[5]);
            }
        }
        else if (currentRadioMode == RADIO_AP) {
            // Uses sessionApData, display_name, and wider truncation bounds
            if (strcmp(sessionApData[i].ssid, "<HIDDEN>") == 0 || strcmp(sessionApData[i].ssid, "<UNKNOWN>") == 0) {
                snprintf(display_name, sizeof(display_name), "%s", sessionApData[i].ssid);
            } else if (sessionApData[i].has_clone) {
                char temp_ssid[22]; 
                strncpy(temp_ssid, sessionApData[i].ssid, 21); // 21 chars max for list
                temp_ssid[21] = '\0';
                snprintf(display_name, sizeof(display_name), "%s~%02X%02X", 
                         temp_ssid, sessionApData[i].bssid[4], sessionApData[i].bssid[5]);
            } else {
                strncpy(display_name, sessionApData[i].ssid, 26); // 26 chars max for list
                display_name[26] = '\0';
            }
        }
        else if (currentRadioMode == RADIO_CHANNELS) {
            float rho = 0.0;
            if (sessionChannelData[i].ema_variance > 0.01) {
                rho = sessionChannelData[i].ema_cov / sessionChannelData[i].ema_variance;
            }
            const char* stateStr = "STATIC";
            if (sessionChannelData[i].packets < 5) stateStr = "CALC...";
            else if (rho > 0.6) stateStr = "DRIFT";
            else if (rho > 0.2) stateStr = "ACTIVE";

            snprintf(display_name, sizeof(display_name), "CH:%02d [%s]", sessionChannelData[i].channel, stateStr);
        }

        // Final assembly of index + display name
        char label[32];
        snprintf(label, sizeof(label), "%d.%s", i + 1, display_name);

        // 3. Delta Check: Only draw if the string changed or a mode swap forced it
        if (forceRedraw || strcmp(label, lastLabels[i]) != 0) {
            if (!forceRedraw) {
                // Wipe just this specific 235x16 cell to prevent trailing characters 
                // from a previous, longer string ghosting on the screen.
                tft.fillRect(x_pos, y_pos, 235, 16, TFT_BLACK);
            }
            
            tft.setTextColor(TFT_WHITE, TFT_BLACK);
            tft.drawString(label, x_pos, y_pos);
            
            // Store the new label for future delta checks
            strncpy(lastLabels[i], label, sizeof(lastLabels[i]) - 1);
            lastLabels[i][sizeof(lastLabels[i]) - 1] = '\0';
        }
    }

    // 4. Stale Data Cleanup: If the list shrank, wipe the abandoned grid cells
    for (int i = top_count; i < lastTopCount; i++) {
        int col = i % 2;
        int row = i / 2;
        int x_pos = 5 + (col * 240);
        int y_pos = 18 + (row * 16);
        
        tft.fillRect(x_pos, y_pos, 235, 16, TFT_BLACK);
        lastLabels[i][0] = '\0'; // Clear the tracker
    }

    lastTopCount = top_count;
}

void drawTemporalLegend() {
    int displayCount = 0;
    if (currentRadioMode == RADIO_WIFI) displayCount = sortMacCount;
    else if (currentRadioMode == RADIO_BLE) displayCount = sortBleCount;
    else if (currentRadioMode == RADIO_AP) displayCount = sortApCount;
    else if (currentRadioMode == RADIO_CHANNELS) displayCount = sortChannelCount;

    // Bail early if there's nothing to draw
    if (!(displayCount > 0 || ((currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP || currentRadioMode == RADIO_CHANNELS) && sortOtherBytes > 0))) {
        return; 
    }

    // 1. CALCULATE AND DRAW "OTHER" IN THE TOP MENU BANNER
    int otherCount = 0;
    // REDUCED: The threshold for "Other" is now > 6
    if (displayCount > 6) {
        otherCount = displayCount - 6;
    }

    tft.setFreeFont(&UbuntuMono_Regular9pt7b);
    tft.setTextDatum(TL_DATUM); 
    tft.setTextColor(COLOR_HOT_CHEST, TFT_BLACK);
    
    // FIX 1: Start the wipe at y=0 to catch the top ascenders of the font.
    // Height expanded to 20 to fully encapsulate the 9pt7b bounding box.
    tft.fillRect(315, 0, 95, 20, TFT_BLACK);
    
    char otherStr[16];
    // FIX 2: Force a 2-digit format so the string is always the exact same length
    snprintf(otherStr, sizeof(otherStr), "OTHER:%d", otherCount);
    
    // The text draws starting at y=1, safely inside the wiped area!
    tft.drawString(otherStr, 315, 1);

    // 2. DRAW THE MAIN 6-DEVICE LEGEND (Now in the bottom position)
    int start_y = HEADER_HEIGHT - 6;
    // Wipe exactly the space between the header line and the chart
    tft.fillRect(0, start_y, 480, chart_start_y - start_y, TFT_BLACK);
    
    tft.setFreeFont(&UbuntuMono_Regular11pt7b);

    int renderCount = 0;
    if (currentRadioMode == RADIO_WIFI) renderCount = sortMacCount;
    else if (currentRadioMode == RADIO_BLE) renderCount = sortBleCount;
    else if (currentRadioMode == RADIO_AP) renderCount = sortApCount;
    else if (currentRadioMode == RADIO_CHANNELS) renderCount = sortChannelCount;

    // REDUCED: Only loop up to 6 items max
    for(int i = 0; i < 6 && i < renderCount; i++) {
        char short_text[25]; // Safe size for 20-char strings + null terminator

        if (currentRadioMode == RADIO_WIFI) {
            strncpy(short_text, sortData[i].vendor, 19);
            short_text[19] = '\0';
        } 
        else if (currentRadioMode == RADIO_BLE) {
            if (strlen(sortBleData[i].name) > 0) {
                strncpy(short_text, sortBleData[i].name, 19);
                short_text[19] = '\0';
            } else {
                snprintf(short_text, sizeof(short_text), "%02X:%02X:%02X:%02X:%02X:%02X", 
                         sortBleData[i].mac[0], sortBleData[i].mac[1], sortBleData[i].mac[2], 
                         sortBleData[i].mac[3], sortBleData[i].mac[4], sortBleData[i].mac[5]);
            }
        } 
        else if (currentRadioMode == RADIO_AP) {
            // Uses sortApData, short_text, and tighter truncation bounds
            if (strcmp(sortApData[i].ssid, "<HIDDEN>") == 0 || strcmp(sortApData[i].ssid, "<UNKNOWN>") == 0) {
                snprintf(short_text, sizeof(short_text), "%s", sortApData[i].ssid);
            } else if (sortApData[i].has_clone) {
                char temp_ssid[16]; 
                strncpy(temp_ssid, sortApData[i].ssid, 14); // 14 chars max for legend
                temp_ssid[14] = '\0';
                snprintf(short_text, sizeof(short_text), "%s~%02X%02X", 
                         temp_ssid, sortApData[i].bssid[4], sortApData[i].bssid[5]);
            } else {
                strncpy(short_text, sortApData[i].ssid, 19); // 19 chars max for legend
                short_text[19] = '\0';
            }
        }
        else if (currentRadioMode == RADIO_CHANNELS) {
            snprintf(short_text, sizeof(short_text), "CH %02d", sortChannelData[i].channel);
        }

        tft.setTextColor(colors[i]);
        
        // Grid Math (3 rows x 2 columns)
        int x_pos = 5 + (i % 2) * 240; 
        int y_pos = start_y + (i / 2) * 20; 

        // UPDATED: Eliminated dynamic String object for pure char array
        char label[32];
        snprintf(label, sizeof(label), "%d.%s", i + 1, short_text);
        
        tft.drawString(label, x_pos, y_pos);
    }
    
    // Draw the white separator line between the new bottom legend and the waterfall chart
    tft.drawLine(0, chart_start_y, 480, chart_start_y, COLOR_HOT_CHEST);
}

// --- PCAP QSORT COMPARATORS ---
int compareLeakAge(const void* a, const void* b) {
    LeakHistoryEntry* lA = (LeakHistoryEntry*)a;
    LeakHistoryEntry* lB = (LeakHistoryEntry*)b;
    
    // Push empty slots to the bottom
    if (lA->leak.meta.timestamp == 0 && lB->leak.meta.timestamp == 0) return 0;
    if (lA->leak.meta.timestamp == 0) return 1;
    if (lB->leak.meta.timestamp == 0) return -1;
    
    if (sort_descending) return (lB->leak.meta.timestamp > lA->leak.meta.timestamp) ? 1 : (lB->leak.meta.timestamp < lA->leak.meta.timestamp) ? -1 : 0;
    return (lA->leak.meta.timestamp > lB->leak.meta.timestamp) ? 1 : (lA->leak.meta.timestamp < lB->leak.meta.timestamp) ? -1 : 0;
}

int compareLeakLength(const void* a, const void* b) {
    LeakHistoryEntry* lA = (LeakHistoryEntry*)a;
    LeakHistoryEntry* lB = (LeakHistoryEntry*)b;
    
    if (lA->leak.meta.timestamp == 0 && lB->leak.meta.timestamp == 0) return 0;
    if (lA->leak.meta.timestamp == 0) return 1;
    if (lB->leak.meta.timestamp == 0) return -1;
    
    if (sort_descending) return (lB->leak.meta.frame_length > lA->leak.meta.frame_length) ? 1 : (lB->leak.meta.frame_length < lA->leak.meta.frame_length) ? -1 : 0;
    return (lA->leak.meta.frame_length > lB->leak.meta.frame_length) ? 1 : (lA->leak.meta.frame_length < lB->leak.meta.frame_length) ? -1 : 0;
}

int compareLeakHits(const void* a, const void* b) {
    LeakHistoryEntry* lA = (LeakHistoryEntry*)a;
    LeakHistoryEntry* lB = (LeakHistoryEntry*)b;
    
    if (lA->leak.meta.timestamp == 0 && lB->leak.meta.timestamp == 0) return 0;
    if (lA->leak.meta.timestamp == 0) return 1;
    if (lB->leak.meta.timestamp == 0) return -1;
    
    if (sort_descending) return (lB->hitCount > lA->hitCount) ? 1 : (lB->hitCount < lA->hitCount) ? -1 : 0;
    return (lA->hitCount > lB->hitCount) ? 1 : (lA->hitCount < lB->hitCount) ? -1 : 0;
}

// --- BULLETPROOF SORTING ENGINE ---
void processPcapData() {
    if (currentLeakSort == SORT_LEAK_AGE) {
        qsort(leakHistory, MAX_LEAK_SLOTS, sizeof(LeakHistoryEntry), compareLeakAge);
    } else if (currentLeakSort == SORT_LEAK_LENGTH) {
        qsort(leakHistory, MAX_LEAK_SLOTS, sizeof(LeakHistoryEntry), compareLeakLength);
    } else if (currentLeakSort == SORT_LEAK_HITS) {
        qsort(leakHistory, MAX_LEAK_SLOTS, sizeof(LeakHistoryEntry), compareLeakHits);
    }
}

bool handleTouchInputs(uint16_t t_x, uint16_t t_y) {
  bool trigger_render = false; // 1. Create local tracking variable

    // ==========================================
    // 1. CHART SCREEN TOUCH LOGIC
    // ==========================================
    if (currentState == SCREEN_CHART) {
      // TOP RIGHT: Menu Button
      if (t_x > 400 && t_y < 40) {
        currentState = SCREEN_MENU;
        pause_sniffing = true;
        esp_wifi_set_promiscuous(false);
        drawMenu();
        delay(300);
      }
      
      // BOTTOM FOOTER: Live Data Controls
      else if (t_y > 260) {
        
        // ==========================================
        // ZONE 1 (Left 0-145): SORT METRIC
        // ==========================================
        if (t_x < 145) {
          // 1. Wipe the inside
          tft.fillRect(3, 299, 139, 17, TFT_BLACK);
          
          // 2. Toggle the variable
          if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP) {
            if (currentSortMode == SORT_TOTAL) currentSortMode = SORT_TX;
            else if (currentSortMode == SORT_TX) currentSortMode = SORT_RX;
            else if (currentSortMode == SORT_RX) currentSortMode = SORT_AVG;
            else if (currentSortMode == SORT_AVG) currentSortMode = SORT_CV;
            else if (currentSortMode == SORT_CV) currentSortMode = SORT_DIST;
            else if (currentSortMode == SORT_DIST) currentSortMode = SORT_AGE;
            else currentSortMode = SORT_TOTAL;
          } 
          else if (currentRadioMode == RADIO_CHANNELS) {
            if (currentSortMode == SORT_TOTAL) currentSortMode = SORT_TX;     
            else if (currentSortMode == SORT_TX) currentSortMode = SORT_RX;   
            else if (currentSortMode == SORT_RX) currentSortMode = SORT_AVG;  
            else if (currentSortMode == SORT_AVG) currentSortMode = SORT_CV;  
            else if (currentSortMode == SORT_CV) currentSortMode = SORT_DIST; 
            else if (currentSortMode == SORT_DIST) currentSortMode = SORT_AGE; 
            else currentSortMode = SORT_TOTAL;                                 
          }
          else if (currentRadioMode == RADIO_BLE) {
            if (currentBleSortMode == SORT_BLE_HITS) currentBleSortMode = SORT_BLE_DIST;
            else if (currentBleSortMode == SORT_BLE_DIST) currentBleSortMode = SORT_BLE_AGE;
            else currentBleSortMode = SORT_BLE_HITS;
          }
          // --- ADDED PCAP LIVE TOGGLE ---
          else if (currentRadioMode == RADIO_PCAP) {
            if (currentLeakSort == SORT_LEAK_AGE) currentLeakSort = SORT_LEAK_LENGTH;
            else if (currentLeakSort == SORT_LEAK_LENGTH) currentLeakSort = SORT_LEAK_HITS;
            else currentLeakSort = SORT_LEAK_AGE;
          }
          
          // 3. Redraw
          drawChartFooter();
          trigger_render = true; // Trigger the engine to re-sort and redraw the bars
          delay(200); 
        }
        
        // ==========================================
        // ZONE 2 (Center 145-290): SORT DIRECTION
        // ==========================================
        else if (t_x >= 145 && t_x <= 290) {
          tft.fillRect(148, 299, 139, 17, TFT_BLACK);
          sort_descending = !sort_descending;
          drawChartFooter(); 
          delay(200);
        }
        
        // ==========================================
        // ZONE 3 (Right 290-435): LOG/LINEAR SCALE
        // ==========================================
        else if (t_x > 290 && t_x <= 435) {
          tft.fillRect(293, 299, 139, 17, TFT_BLACK);
          useLogScale = !useLogScale;
          drawChartFooter(); 
          delay(200);
        }
      }
    }

    // ==========================================
    // 2. MENU SCREEN TOUCH LOGIC
    // ==========================================
    else if (currentState == SCREEN_MENU) {
      
      // FOXHUNT BUTTON TOUCH ZONE
      if (t_x > 50 && t_x < 250 && t_y > 90 && t_y < 130) {
          
          bool foxhunt_available = false;
          if (currentRadioMode == RADIO_WIFI) foxhunt_available = (target_locked && sessionMacCount > 0);
          else if (currentRadioMode == RADIO_BLE) foxhunt_available = (sessionBleCount > 0);
          else if (currentRadioMode == RADIO_AP) foxhunt_available = (sessionApCount > 0);

          if (!foxhunt_available) return false; 
          
          is_selecting_target = true;
          currentState = SCREEN_DEVICE_LIST;
          drawDeviceList();
          delay(400);
      }
      // Probe Request Tracker Button
      else if (t_x > 300 && t_x < 450 && t_y > 140 && t_y < 180) {
        currentState = SCREEN_PROBE_TRACKER;
        probe_current_page = 0;
        drawProbeTracker();
        delay(300); 
      }
      // AP Scanner / CH Select Button
      else if (t_x > 50 && t_x < 250 && t_y > 190 && t_y < 230) {
        if (currentRadioMode == RADIO_WIFI) {
          currentState = SCREEN_AP_SCAN;
          drawApScanner();
          delay(300);
        } else if (currentRadioMode == RADIO_AP || currentRadioMode == RADIO_PCAP) {
          if (!target_locked) {
              target_locked = true;
              target_channel = 1;
          } else {
              target_channel++;
              if (target_channel > 13) {
                  target_locked = false;
                  target_channel = 0;
              }
          }
          
          memset(traffic_history, 0, sizeof(traffic_history)); 
          absolute_max_traffic = 10;
          resetMonitorState(); 
          
          drawMenu(); 
          delay(150); 
        }
      }
      // ==========================================
      // UNIFIED SNIFFED DEVICES / LEAK LIST BUTTON
      // ==========================================
      else if (t_x > 50 && t_x < 250 && t_y > 240 && t_y < 280) {
        currentState = SCREEN_DEVICE_LIST;
        device_current_page = 0;
        
        // Force an immediate sort before drawing so the array is ready
        if (currentRadioMode == RADIO_PCAP) processPcapData();
        else forceSessionSort();
        
        drawDeviceList();
        delay(300);
      }
      // ==========================================
      // RADIO MODE TOGGLE TOUCH LOGIC (X:300-450, Y:190-230)
      // ==========================================
      else if (t_x > 300 && t_x < 450 && t_y > 190 && t_y < 230) {
        
        target_locked = false; 
        memset(traffic_history, 0, sizeof(traffic_history)); 
        absolute_max_traffic = 10;                           

        RadioMode nextMode;
        if (currentRadioMode == RADIO_WIFI) nextMode = RADIO_BLE;
        else if (currentRadioMode == RADIO_BLE) nextMode = RADIO_AP;
        else if (currentRadioMode == RADIO_AP) nextMode = RADIO_CHANNELS;
        else if (currentRadioMode == RADIO_CHANNELS) nextMode = RADIO_PCAP;
        else nextMode = RADIO_WIFI;

        tft.setFreeFont(&UbuntuMono_Regular9pt7b);
        tft.setTextDatum(MC_DATUM); 
        
        if (nextMode == RADIO_WIFI) {
          tft.fillRect(300, 190, 150, 40, TFT_BLUE);
          tft.drawRect(300, 190, 150, 40, TFT_WHITE);
          tft.setTextColor(TFT_WHITE);
          tft.drawString("MODE: WI-FI", 375, 210);
        } else if (nextMode == RADIO_BLE) {
          tft.fillRect(300, 190, 150, 40, TFT_PURPLE);
          tft.drawRect(300, 190, 150, 40, TFT_WHITE);
          tft.setTextColor(TFT_WHITE);
          tft.drawString("MODE: BLE", 375, 210);
        } else if (nextMode == RADIO_AP) {
          tft.fillRect(300, 190, 150, 40, TFT_DARKGREEN);
          tft.drawRect(300, 190, 150, 40, TFT_WHITE);
          tft.setTextColor(TFT_WHITE);
          tft.drawString("MODE: NETWORKS", 375, 210);
        } else if (nextMode == RADIO_CHANNELS) {
          tft.fillRect(300, 190, 150, 40, TFT_ORANGE);
          tft.drawRect(300, 190, 150, 40, TFT_WHITE);
          tft.setTextColor(TFT_WHITE);
          tft.drawString("MODE: CHANNELS", 375, 210);
        } else if (nextMode == RADIO_PCAP) {
          tft.fillRect(300, 190, 150, 40, TFT_MAROON);
          tft.drawRect(300, 190, 150, 40, TFT_WHITE);
          tft.setTextColor(TFT_WHITE);
          tft.drawString("MODE: PCAP", 375, 210);
        }

        bool foxhunt_available = false;
        
        if (nextMode == RADIO_BLE) {
            if (sessionBleCount > 0) foxhunt_available = true;
        } else if (nextMode == RADIO_AP) {
            if (sessionApCount > 0) foxhunt_available = true;
        } else if (nextMode == RADIO_WIFI) {
            if (target_locked == true && sessionMacCount > 0) foxhunt_available = true;
        }

        if (foxhunt_available) {
            tft.fillRoundRect(50, 90, 200, 40, 3, TFT_RED); 
            tft.drawRoundRect(50, 90, 200, 40, 3, TFT_WHITE);
            tft.setTextColor(TFT_WHITE);
            tft.drawString("FOXHUNT", 150, 110);
        } else {
            uint16_t deadGrey = hex24to565(0x222222);
            tft.fillRect(50, 90, 200, 50, deadGrey); 
            tft.drawRect(50, 90, 200, 40, TFT_DARKGREY);
            tft.setTextColor(TFT_DARKGREY);
            tft.drawString("FOXHUNT", 150, 110);
            
            tft.setTextColor(hex24to565(0x444444));
            tft.drawString("(no targets yet)", 150, 125);
        }
        
        tft.setTextDatum(TL_DATUM); 

        // ==========================================
        // THE UNION SCRUB FIX
        // Because leakHistory shares a union with Wi-Fi/BLE session data, 
        // we MUST scrub it clean when switching to PCAP. If we don't, the 
        // PCAP sorting engine will choke on Wi-Fi garbage bytes!
        // ==========================================
        if (nextMode == RADIO_PCAP) {
            memset(leakHistory, 0, sizeof(LeakHistoryEntry) * MAX_LEAK_SLOTS);
        }

        switchRadioMode(nextMode);
        delay(200);
      }
      // ==========================================
      // EXIT BUTTON TOUCH LOGIC
      // ==========================================
      else if (t_x > 300 && t_x < 450 && t_y > 240 && t_y < 280) {
        currentState = SCREEN_CHART;
        tft.fillScreen(TFT_BLACK);
        drawChartHeader();
        drawChartFooter();
        
        force_ui_refresh = true; 
        
        if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP || currentRadioMode == RADIO_CHANNELS || currentRadioMode == RADIO_PCAP) {
            esp_wifi_set_promiscuous(true); 
        }
        
        if ((currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP || currentRadioMode == RADIO_PCAP) && target_locked) {
          esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);
        } else if (currentRadioMode != RADIO_BLE) {
          esp_wifi_set_channel(CHANNELS[current_ch_idx], WIFI_SECOND_CHAN_NONE);
        }
        
        current_x = 0;
        delay(300);
      }
    }

    // ==========================================
    // 3. OSINT PROBE TRACKER TOUCH LOGIC
    // ==========================================
    else if (currentState == SCREEN_PROBE_TRACKER) {
      
      // HEADER TOUCH (SORT CONTROLS)
      if (t_y <= 30) {
        if (t_x >= 275 && t_x < 410) {
          if (currentProbeSortMode == PROBE_SORT_HITS) currentProbeSortMode = PROBE_SORT_DIST;
          else if (currentProbeSortMode == PROBE_SORT_DIST) currentProbeSortMode = PROBE_SORT_SSIDS;
          else if (currentProbeSortMode == PROBE_SORT_SSIDS) currentProbeSortMode = PROBE_SORT_AGE;
          else currentProbeSortMode = PROBE_SORT_HITS;
          
          probe_current_page = 0; 
          drawProbeTracker();
          delay(200);
        }
        else if (t_x >= 410) {
          probe_sort_descending = !probe_sort_descending;
          probe_current_page = 0;
          drawProbeTracker();
          delay(200);
        }
      }
      
      // FOOTER TOUCH (NAVIGATION)
      else if (t_y > 285) {
        if (t_x < 160 && probe_current_page > 0) {
          probe_current_page--;
          drawProbeTracker();
          delay(250);
        }
        else if (t_x > 320 && ((probe_current_page + 1) * PROBES_PER_PAGE) < total_sniffed_probes) {
          probe_current_page++;
          drawProbeTracker();
          delay(250);
        }
        else if (t_x >= 160 && t_x <= 320) {
          currentState = SCREEN_MENU;
          drawMenu(); 
          delay(300);
        }
      }
    }

    // ==========================================
    // 4. AP SCANNER TOUCH LOGIC
    // ==========================================
    else if (currentState == SCREEN_AP_SCAN) {
      
      // 1. SNIFF ALL BUTTON (Free Airspace)
      if (t_y > 40 && t_y < 65) {
        target_locked = false;
        WiFi.scanDelete();
        esp_wifi_set_promiscuous(true);
        resetMonitorState();
        currentState = SCREEN_CHART;
        tft.fillScreen(TFT_BLACK);
        drawChartHeader();
        drawChartFooter();
        delay(300);
      }
      
      // 2. AP SELECTION LIST ROWS (y: 80 to 290)
      else if (t_y >= 80 && t_y < 290) {
        
        int clicked_row = (t_y - 80) / 35; 
        
        int actual_index = (ap_current_page * APS_PER_PAGE) + clicked_row;
        int n = WiFi.scanComplete();

        if (actual_index < n) {
          memcpy(target_bssid, WiFi.BSSID(actual_index), 6);
          target_channel = WiFi.channel(actual_index);
          target_rssi = WiFi.RSSI(actual_index);

          uint8_t* bssid = WiFi.BSSID(actual_index);
          String raw_ssid = WiFi.SSID(actual_index);

          bool has_clone = false;
          if (raw_ssid.length() > 0) {
            for (int j = 0; j < n; ++j) {
              if (actual_index != j && WiFi.SSID(j) == raw_ssid) {
                has_clone = true;
                break;
              }
            }
          }

          if (raw_ssid.length() == 0) {
            snprintf(target_ssid, sizeof(target_ssid), "<HIDDEN>~%02X%02X", bssid[4], bssid[5]);
          } else if (has_clone) {
            char temp_ssid[13];
            strncpy(temp_ssid, raw_ssid.c_str(), 12);
            temp_ssid[12] = '\0';
            snprintf(target_ssid, sizeof(target_ssid), "%s~%02X%02X", temp_ssid, bssid[4], bssid[5]);
          } else {
            char temp_ssid[18]; 
            strncpy(temp_ssid, raw_ssid.c_str(), 17);
            temp_ssid[17] = '\0';
            snprintf(target_ssid, sizeof(target_ssid), "%s", temp_ssid);
          }

          target_locked = true;

          WiFi.scanDelete();
          esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);
          esp_wifi_set_promiscuous(true);

          resetMonitorState();
          currentState = SCREEN_CHART;
          tft.fillScreen(TFT_BLACK);
          drawChartHeader();
          drawChartFooter();
          delay(300);
        }
      }

      // 3. PAGINATION & BACK FOOTER
      else if (t_y >= 290) {
        int total_aps = WiFi.scanComplete();
        
        if (t_x < 160 && ap_current_page > 0) {
          ap_current_page--;
          drawApScanner();
          delay(250);
        }
        else if (t_x > 320 && ((ap_current_page + 1) * APS_PER_PAGE) < total_aps) {
          ap_current_page++;
          drawApScanner();
          delay(250);
        }
        else if (t_x >= 160 && t_x <= 320) {
          currentState = SCREEN_MENU;
          ap_current_page = 0; 
          drawMenu(); 
          delay(300);
        }
      }
    }

    // ==========================================
    // 5. FOXHUNT SCREEN TOUCH LOGIC
    // ==========================================
    else if (currentState == SCREEN_FOXHUNT) {
      if (t_x > 190 && t_x < 290 && t_y > 290) {
        is_foxhunting = false;
        is_selecting_target = false;
        foxhunt_bounds_seeded = false; 
        
        target_locked = false; 
        current_ch_idx = 0;    
        esp_wifi_set_channel(CHANNELS[current_ch_idx], WIFI_SECOND_CHAN_NONE);

        currentState = SCREEN_MENU; 
        drawMenu();
        delay(300);
      }
    }
    
    // ==========================================
    // 6. SEEN DEVICES / LEAK LIST TOUCH LOGIC
    // ==========================================
    else if (currentState == SCREEN_DEVICE_LIST) {
      
      // ==========================================
      // A. HEADER TOUCH LOGIC (SORT CONTROLS)
      // ==========================================
      if (t_y <= 30) {
        // ZONE 1: TOGGLE SORT METRIC (X: 275 to 405)
        if (t_x >= 275 && t_x < 405) {
          
          if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP) {
            if (currentSortMode == SORT_TOTAL) currentSortMode = SORT_TX;
            else if (currentSortMode == SORT_TX) currentSortMode = SORT_RX;
            else if (currentSortMode == SORT_RX) currentSortMode = SORT_AVG;
            else if (currentSortMode == SORT_AVG) currentSortMode = SORT_CV;
            else if (currentSortMode == SORT_CV) currentSortMode = SORT_DIST;
            else if (currentSortMode == SORT_DIST) currentSortMode = SORT_AGE;
            else currentSortMode = SORT_TOTAL;
          } 
          else if (currentRadioMode == RADIO_CHANNELS) {
            if (currentSortMode == SORT_TOTAL) currentSortMode = SORT_TX;      
            else if (currentSortMode == SORT_TX) currentSortMode = SORT_RX;    
            else if (currentSortMode == SORT_RX) currentSortMode = SORT_AVG;   
            else if (currentSortMode == SORT_AVG) currentSortMode = SORT_CV;   
            else if (currentSortMode == SORT_CV) currentSortMode = SORT_DIST;  
            else currentSortMode = SORT_TOTAL;                                 
          }
          else if (currentRadioMode == RADIO_BLE) {
            if (currentBleSortMode == SORT_BLE_HITS) currentBleSortMode = SORT_BLE_DIST;
            else if (currentBleSortMode == SORT_BLE_DIST) currentBleSortMode = SORT_BLE_AGE;
            else currentBleSortMode = SORT_BLE_HITS;
          }
          // --- ADDED PCAP SORT TOGGLE ---
          else if (currentRadioMode == RADIO_PCAP) {
            if (currentLeakSort == SORT_LEAK_AGE) currentLeakSort = SORT_LEAK_LENGTH;
            else if (currentLeakSort == SORT_LEAK_LENGTH) currentLeakSort = SORT_LEAK_HITS;
            else currentLeakSort = SORT_LEAK_AGE;
          }
          
          device_current_page = 0; 
          
          // Force sort array before rendering list
          if (currentRadioMode == RADIO_PCAP) processPcapData();
          else forceSessionSort(); 
          
          drawDeviceList();
          delay(200);
        }
        // ZONE 2: TOGGLE SORT DIRECTION (X: 410 to 480)
        else if (t_x >= 410) {
          sort_descending = !sort_descending;
          device_current_page = 0; 
          
          // Force sort array before rendering list
          if (currentRadioMode == RADIO_PCAP) processPcapData();
          else forceSessionSort();
          
          drawDeviceList();
          delay(200);
        }
      }

      // ==========================================
      // B. FOOTER NAVIGATION (Y >= 294)
      // ==========================================
      else if (t_y >= 294) { 
        // --- ADDED PCAP PAGINATION MATH ---
        int items_per_page = (currentRadioMode == RADIO_PCAP) ? 3 : 7;
        int total_devices = 0;
        
        if (currentRadioMode == RADIO_WIFI) total_devices = sessionMacCount;
        else if (currentRadioMode == RADIO_BLE) total_devices = sessionBleCount;
        else if (currentRadioMode == RADIO_AP) total_devices = sessionApCount;
        else if (currentRadioMode == RADIO_CHANNELS) total_devices = sessionChannelCount;
        else if (currentRadioMode == RADIO_PCAP) {
            for (int i = 0; i < MAX_LEAK_SLOTS; i++) {
                if (leakHistory[i].hitCount > 0) total_devices++;
            }
        }

        // 1. PREV PAGE
        if (t_x < 160 && device_current_page > 0) {
          device_current_page--;
          drawDeviceList();
          delay(250);
        }
        // 2. NEXT PAGE
        else if (t_x > 320 && ((device_current_page + 1) * items_per_page) < total_devices) {
          device_current_page++;
          drawDeviceList();
          delay(250);
        }
        // 3. BACK TO MENU
        else if (t_x >= 160 && t_x <= 320) {
          currentState = SCREEN_MENU;
          device_current_page = 0; 
          drawMenu(); 
          delay(300);
        }
      }
      
      // ==========================================
      // C. LIST ROW SELECTION (The "Hot" Devices)
      // ==========================================
      else if (t_y >= 62 && t_y < 294) { 
        
        // --- ADDED PCAP GUARD (No foxhunting for leaks yet) ---
        if (currentRadioMode == RADIO_PCAP) return false;

        int tapped_screen_row = (t_y - 62) / 33;
        int total_devices = 0;
        
        if (currentRadioMode == RADIO_WIFI) total_devices = sessionMacCount;
        else if (currentRadioMode == RADIO_BLE) total_devices = sessionBleCount;
        else if (currentRadioMode == RADIO_AP) total_devices = sessionApCount;

        int tapped_array_index = (device_current_page * 7) + tapped_screen_row;

        if (tapped_screen_row < 7 && tapped_array_index < total_devices) {
          if (is_selecting_target) {
            is_selecting_target = false;
            is_foxhunting = true;
            smoothed_rssi = -100.0f;
            last_displayed_rssi = -999;      

            if (currentRadioMode == RADIO_WIFI) {
               memcpy(foxhunt_target_mac, sessionData[tapped_array_index].mac, 6);
              strncpy(foxhunt_target_vendor, sessionData[tapped_array_index].vendor, sizeof(foxhunt_target_vendor) - 1);
              foxhunt_target_vendor[sizeof(foxhunt_target_vendor) - 1] = '\0'; 
    
              foxhunt_rssi_min = sessionData[tapped_array_index].rssi_min;
              foxhunt_rssi_max = sessionData[tapped_array_index].rssi_max;
              foxhunt_bounds_seeded = (sessionData[tapped_array_index].packets > 6);
    
            } else if (currentRadioMode == RADIO_AP) {
              memcpy(foxhunt_target_mac, sessionApData[tapped_array_index].bssid, 6);
              strncpy(foxhunt_target_vendor, sessionApData[tapped_array_index].ssid, sizeof(foxhunt_target_vendor) - 1);
              foxhunt_target_vendor[sizeof(foxhunt_target_vendor) - 1] = '\0'; 
              
              foxhunt_rssi_min = sessionApData[tapped_array_index].rssi_min;
              foxhunt_rssi_max = sessionApData[tapped_array_index].rssi_max;
              foxhunt_bounds_seeded = (sessionApData[tapped_array_index].packets > 6);

              target_locked = true; 
              target_channel = sessionApData[tapped_array_index].channel;
              esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);

            } else if (currentRadioMode == RADIO_BLE) {
              memcpy(foxhunt_target_mac, sessionBleData[tapped_array_index].mac, 6);
              strncpy(foxhunt_target_vendor, sessionBleData[tapped_array_index].name, 25);
              if (foxhunt_target_vendor[0] == '\0') {
                strncpy(foxhunt_target_vendor, "<Unnamed BLE>", 25);
              }
              foxhunt_target_vendor[25] = '\0'; 
              
              foxhunt_rssi_min = -100;
              foxhunt_rssi_max = -100;
              foxhunt_bounds_seeded = false;
              
              target_locked = false;
            }

            currentState = SCREEN_FOXHUNT;
            
            if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP) {
                esp_wifi_set_promiscuous(true);
            }
            pause_sniffing = false;

            drawFoxhuntScreen(); 
            delay(200);
          }
        }
      }

    }
    
    // (Notice SCREEN_LEAK_LIST block is completely deleted!)
    
    return trigger_render; 
}

void updateFoxhuntRadar() {
    // --- WAVE HOUND ANIMATION ENGINE ---
    static unsigned long last_anim_tick = 0;
    static int sequence_index = 0; // Tracks where we are in the script
    static unsigned long current_delay = 300; // Tracks how long the current frame should stay on screen

    // Define the custom animation script (0 = sniff, 1 = sniff/wag, 2 = look up)
    // This yields 8 standard loops, followed by 1 loop where the head raises
    const int ANIM_SEQUENCE[] = {0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2};
    const int SEQUENCE_LENGTH = 20;

    // Animate using the dynamic delay interval
    if (millis() - last_anim_tick > current_delay) {
        last_anim_tick = millis();
        
        int current_val = (int)smoothed_rssi;
        uint16_t houndColor = TFT_WHITE;
        int step_time = 300;

        // Tactical Color Feedback & Speed based on signal strength (Hot/Cold logic)
        if (current_val > -60) {
            houndColor = COLOR_HOT_CHEST;  // Hot / Close
            step_time = 100;               // Fast walk
        } else if (current_val > -75) {
            houndColor = COLOR_WARM;       // Warm / Medium
            step_time = 300;               // Normal walk
        } else {
            houndColor = COLOR_COLD;       // Cold / Far
            step_time = 600;               // Slow walk
        }

        int dog_x = HOUND_CENTER_X - (HOUND_WIDTH / 2); 
        int dog_y = HOUND_BASELINE_Y - HOUND_HEIGHT; 

        // Look up the actual frame (0, 1, or 2) from our sequence array
        int current_frame = ANIM_SEQUENCE[sequence_index];

        // Render the frame to the display
        tft.drawBitmap(dog_x, dog_y, houndAnimation[current_frame], HOUND_WIDTH, HOUND_HEIGHT, houndColor, TFT_BLACK);
        
        // NOW determine how long THIS newly drawn frame should stay on screen
        if (current_frame == 2) {
            current_delay = 1000;      // Always lock to 1-second pause when looking up
        } else {
            current_delay = step_time; // Apply the dynamically calculated walking speed
        }
        
        // Advance to the next step in the sequence, looping back to 0 at the end
        sequence_index = (sequence_index + 1) % SEQUENCE_LENGTH; 
    }
    // -----------------------------------

    static unsigned long last_radar_update = 0;

    if (millis() - last_radar_update > 300) {
        int current_display_val = (int)smoothed_rssi;

        // 1. RSSI VALUE — Massive Font (owns Y=88 to Y=132)
        if (current_display_val != last_displayed_rssi) {
            tft.fillRect(0, 88, 480, 44, TFT_BLACK); // Expanded clear box for giant text
            tft.setTextDatum(MC_DATUM);
            tft.setFreeFont(&UbuntuMono_B9pt7b);
            
            // THE MULTIPLIER: Scales 9pt to ~27pt
            tft.setTextSize(3); 

            // Color-code by signal strength
            if      (current_display_val > -60) tft.setTextColor(COLOR_HOT_CHEST);
            else if (current_display_val > -75) tft.setTextColor(COLOR_WARM);
            else                                tft.setTextColor(COLOR_COLD);

            char rssiStr[32];
            snprintf(rssiStr, sizeof(rssiStr), "%d dBm", current_display_val);
            tft.drawString(rssiStr, 240, 110);
            
            // THE RESET: Crucial to prevent UI corruption!
            tft.setTextSize(1); 
            tft.setTextDatum(TL_DATUM);
            last_displayed_rssi = current_display_val;
        }

        // ==========================================
        // 2. THE DYNAMIC BOUNDS UPDATER (Gutted)
        // ==========================================
        if (currentRadioMode == RADIO_WIFI || currentRadioMode == RADIO_AP || currentRadioMode == RADIO_BLE) {
            if (foxhunt_rssi_min != last_drawn_min || foxhunt_rssi_max != last_drawn_max) {
                
                tft.fillRect(0, 135, 480, 60, TFT_BLACK); // Clean wipe
                tft.setFreeFont(&UbuntuMono_Regular9pt7b);
                tft.setTextDatum(MC_DATUM);

                char boundStr[64];
                snprintf(boundStr, sizeof(boundStr), 
                         "FLOOR: %d dBm  |  CEILING: %d dBm", foxhunt_rssi_min, foxhunt_rssi_max);
                tft.setTextColor(TFT_GREEN);
                tft.drawString(boundStr, 240, 165); // Centered vertically in the 60px wipe box

                tft.setTextDatum(TL_DATUM);

                last_drawn_min = foxhunt_rssi_min;
                last_drawn_max = foxhunt_rssi_max;
            }
        }
        // ==========================================

        last_radar_update = millis();
    }
}

void runProbeCorrelationEngine() {
    static unsigned long last_correlation_run = 0;
    
    if (millis() - last_correlation_run > 5000) { 
        last_correlation_run = millis();
        
        for (int i = 0; i < MAX_PROBE_SLOTS; i++) {
            if (probeList[i].generation == 0) continue; 
            if ((probeList[i].mac[0] & 0x02) == 0) continue; // Only process randomized MACs

            for (int j = i + 1; j < MAX_PROBE_SLOTS; j++) {
                 if (probeList[j].generation == 0) continue;
                 if ((probeList[j].mac[0] & 0x02) == 0) continue; 

                 // --- THE MERGE TRIGGER ---
                 if (isSameDevice(i, j)) {
                     
                     // 1. Update Rotations & Hits
                     probeList[i].mac_rotations += probeList[j].mac_rotations;
                     probeList[i].hits += probeList[j].hits;
                     
                     // 2. Adopt the most recent MAC address and timestamps
                     if (probeList[j].last_seen > probeList[i].last_seen) {
                         probeList[i].last_seen = probeList[j].last_seen;
                         memcpy(probeList[i].mac, probeList[j].mac, 6); // Stay current with the target's rotation
                     }
                     
                     // 3. Merge the Behavioral PNL Fingerprint
                     probeList[i].pnl_hash |= probeList[j].pnl_hash;

                     // ==========================================
                     // 4. THE STACK-BUFFERED MERGE PROTOCOL
                     // ==========================================
                     // MAX_MERGE_SSIDS matches EMERGENCY_CUTOFF so no valid SSIDs
                     // should be truncated. If j_ssid_count hits the cap, remaining
                     // nodes are freed in 4b without migration — acceptable data loss
                     // from a corrupted chain that exceeded the per-device limit.
                     const int MAX_MERGE_SSIDS = EMERGENCY_CUTOFF;
                     char j_ssids[MAX_MERGE_SSIDS][33];
                     uint8_t j_ssid_count = 0;
                     int node = probeList[j].first_ssid_idx;
                     
                     // 4a. Pre-collect J's SSIDs onto the stack
                     while (node != -1 && j_ssid_count < MAX_MERGE_SSIDS) {
                         if (strlen(ssidPool[node].text) > 0) {
                             strncpy(j_ssids[j_ssid_count], ssidPool[node].text, 32);
                             j_ssids[j_ssid_count][32] = '\0';
                             j_ssid_count++;
                         }
                         node = ssidPool[node].next_node_idx;
                     }

                     // 4b. THE BURN PROTOCOL: Free J's pool nodes FIRST to reclaim SRAM
                     int node_to_wipe = probeList[j].first_ssid_idx;
                     int fail_safe = 0; 
                     while (node_to_wipe != -1 && fail_safe < TOTAL_SSID_POOL) {
                         int next = ssidPool[node_to_wipe].next_node_idx;
                         ssidPool[node_to_wipe].text[0] = '\0'; 
                         ssidPool[node_to_wipe].next_node_idx = -1; 
                         node_to_wipe = next;
                         fail_safe++;
                     }
                     
                     // 4c. Wipe J's array slot completely (The Sentinel Burn)
                     memset(&probeList[j], 0, sizeof(ProbeRecordShared));
                     
                     // Restore the critical sentinels that cannot be 0
                     probeList[j].first_ssid_idx = -1; 
                     probeList[j].rssi = -100;         
                     strncpy(probeList[j].vendor, "Unknown", 25);

                     // 4d. Re-allocate unique SSIDs from the stack into I
                     for (int s = 0; s < j_ssid_count; s++) {
                         bool already_exists = false;
                         bool added = false;
                         probeList[i].first_ssid_idx = addSsidToPool(j_ssids[s], 
                                                                     probeList[i].first_ssid_idx, 
                                                                     already_exists, added, 
                                                                     probeList[i].ssid_count);
                         if (added) probeList[i].ssid_count++;
                     }
                 }
            }
        }
    }
}

// ==========================================
// CORE 1: RAM-ONLY QUEUE CONSUMER
// ==========================================
void logLeakToSerial(const PacketCapture& leak, const char* src_vendor,
                      const char* dst_vendor, const char* ssid) {

    // Render correctly regardless of IP version, reusing meta.ip_version
    // as the single source of truth (same field the on-screen PCAP display
    // already keys off of).
    char srcIpStr[48], dstIpStr[48];

    if (leak.meta.ip_version == 6) {
        char srcIpRaw[48], dstIpRaw[48];
        getIpString(6, leak.meta.src_ip, srcIpRaw, sizeof(srcIpRaw));
        getIpString(6, leak.meta.dst_ip, dstIpRaw, sizeof(dstIpRaw));
        compress_ipv6(srcIpRaw, srcIpStr, sizeof(srcIpStr));
        compress_ipv6(dstIpRaw, dstIpStr, sizeof(dstIpStr));
    } else {
        getIpString(leak.meta.ip_version, leak.meta.src_ip, srcIpStr, sizeof(srcIpStr));
        getIpString(leak.meta.ip_version, leak.meta.dst_ip, dstIpStr, sizeof(dstIpStr));
    }

    Serial.printf(
        "🚨 LEAK [%s] | BSSID(SSID): %02X:%02X:%02X:%02X:%02X:%02X (%s) | "
        "Src MAC: %02X:%02X:%02X:%02X:%02X:%02X (%s) [%s:%u] -> "
        "Dst MAC: %02X:%02X:%02X:%02X:%02X:%02X (%s) [%s:%u] | "
        "Ch: %u | Text: %s\n",
        leak.meta.is_high_value ? "HIGH-VALUE" : "STANDARD",
        leak.meta.bssid[0], leak.meta.bssid[1], leak.meta.bssid[2],
        leak.meta.bssid[3], leak.meta.bssid[4], leak.meta.bssid[5],
        ssid,
        leak.meta.src_mac[0], leak.meta.src_mac[1], leak.meta.src_mac[2],
        leak.meta.src_mac[3], leak.meta.src_mac[4], leak.meta.src_mac[5],
        src_vendor,
        srcIpStr, leak.meta.src_port,
        leak.meta.dst_mac[0], leak.meta.dst_mac[1], leak.meta.dst_mac[2],
        leak.meta.dst_mac[3], leak.meta.dst_mac[4], leak.meta.dst_mac[5],
        dst_vendor,
        dstIpStr, leak.meta.dst_port,
        leak.meta.channel,
        leak.text
    );
}

void processLeakQueue() {
    if (leakQueue == NULL) return;

    PacketCapture incomingLeak;
    bool ui_needs_update = false;

    while (xQueueReceive(leakQueue, &incomingLeak, 0) == pdTRUE) {

        // ==========================================
        // 0. TOKEN EXPANSION
        //    Run outside the ISR
        // ==========================================
        if (strcmp(incomingLeak.text, "ICMPV6_NS") == 0) {

            char src_str[40] = {0};
            char tgt_str[40] = {0};

            getIpString(
                6,
                incomingLeak.meta.src_ip,
                src_str,
                sizeof(src_str)
            );

            getIpString(
                6,
                incomingLeak.meta.dst_ip,
                tgt_str,
                sizeof(tgt_str)
            );

            snprintf(
                incomingLeak.text,
                sizeof(incomingLeak.text),
                "ICMPv6 ND: Who has %s? Tell %s",
                tgt_str,
                src_str
            );
        }

        // ==========================================
        // 1. TERMINAL HISTORY DEDUPLICATION
        //
        //    This is intentionally independent from
        //    persistent leakHistory eviction.
        // ==========================================
        bool foundTerminalMatch = false;
        int matchIndex = -1;

        for (int i = 0; i < MAX_TERMINAL_LINES; i++) {

            if (terminal_history[i].meta.timestamp > 0 &&
                memcmp(
                    terminal_history[i].meta.src_mac,
                    incomingLeak.meta.src_mac,
                    6
                ) == 0 &&
                strcmp(
                    terminal_history[i].text,
                    incomingLeak.text
                ) == 0) {

                foundTerminalMatch = true;
                matchIndex = i;
                break;
            }
        }

        if (foundTerminalMatch) {

            // Existing terminal entry: increment hits
            terminal_hits[matchIndex]++;

            // Refresh last-seen timestamp
            terminal_history[matchIndex].meta.timestamp =
                incomingLeak.meta.timestamp;

            // Move the refreshed entry to the front
            if (matchIndex > 0) {

                PacketCapture tempCap =
                    terminal_history[matchIndex];

                uint16_t tempHits =
                    terminal_hits[matchIndex];

                uint32_t tempFirst =
                    terminal_first_seen[matchIndex];

                for (int t = matchIndex; t > 0; t--) {
                    terminal_history[t] =
                        terminal_history[t - 1];

                    terminal_hits[t] =
                        terminal_hits[t - 1];

                    terminal_first_seen[t] =
                        terminal_first_seen[t - 1];
                }

                terminal_history[0] = tempCap;
                terminal_hits[0] = tempHits;
                terminal_first_seen[0] = tempFirst;
            }

            ui_needs_update = true;

        } else {

            // New terminal entry.
            // Shift existing entries toward the back.
            for (int t = MAX_TERMINAL_LINES - 1; t > 0; t--) {

                terminal_history[t] =
                    terminal_history[t - 1];

                terminal_hits[t] =
                    terminal_hits[t - 1];

                terminal_first_seen[t] =
                    terminal_first_seen[t - 1];
            }

            terminal_history[0] = incomingLeak;
            terminal_hits[0] = 1;
            terminal_first_seen[0] =
                incomingLeak.meta.timestamp;

            ui_needs_update = true;
        }


        // ==========================================
        // 2. PERSISTENT LIST DEDUPLICATION
        // ==========================================
        bool isDuplicate = false;

        for (int i = 0; i < MAX_LEAK_SLOTS; i++) {

            if (leakHistory[i].leak.meta.timestamp > 0 &&
                memcmp(
                    leakHistory[i].leak.meta.src_mac,
                    incomingLeak.meta.src_mac,
                    6
                ) == 0 &&
                strcmp(
                    leakHistory[i].leak.text,
                    incomingLeak.text
                ) == 0) {

                // Existing persistent entry.
                // Do NOT run the eviction engine.
                leakHistory[i].hitCount++;

                // Refresh last-seen timestamp.
                leakHistory[i].leak.meta.timestamp =
                    incomingLeak.meta.timestamp;

                isDuplicate = true;
                ui_needs_update = true;

                break;
            }
        }


        if (!isDuplicate) {

            // ==========================================
            // 3. RESOLVE VENDORS + LOG — UNCONDITIONAL
            //    Runs for every genuinely new capture,
            //    regardless of eviction outcome.
            // ==========================================
            MacRecord tempRec;
            char resolved_src_vendor[16] = "Unknown";
            char resolved_dst_vendor[16] = "Unknown";

            memset(&tempRec, 0, sizeof(MacRecord));
            memcpy(tempRec.mac, incomingLeak.meta.src_mac, 6);
            resolveMacVendor(&tempRec);
            strncpy(resolved_src_vendor, tempRec.vendor, sizeof(resolved_src_vendor) - 1);
            resolved_src_vendor[sizeof(resolved_src_vendor) - 1] = '\0';

            memset(&tempRec, 0, sizeof(MacRecord));
            memcpy(tempRec.mac, incomingLeak.meta.dst_mac, 6);
            resolveMacVendor(&tempRec);
            strncpy(resolved_dst_vendor, tempRec.vendor, sizeof(resolved_dst_vendor) - 1);
            resolved_dst_vendor[sizeof(resolved_dst_vendor) - 1] = '\0';

            char safeSsid[33] = "Unknown";
            for (int ap = 0; ap < MAX_BSSID_CACHE; ap++) {
                if (bssidCache[ap].last_seen == 0) continue;
                if (memcmp(incomingLeak.meta.bssid, bssidCache[ap].bssid, 6) == 0) {
                    strncpy(safeSsid, bssidCache[ap].ssid, sizeof(safeSsid) - 1);
                    safeSsid[sizeof(safeSsid) - 1] = '\0';
                    break;
                }
            }

            logLeakToSerial(incomingLeak, resolved_src_vendor, resolved_dst_vendor, safeSsid);

            // ==========================================
            // 4. SMART EVICTION ENGINE
            //    Only decides whether it also gets a
            //    permanent slot in leakHistory.
            // ==========================================
            int targetIndex = -1;

            for (int i = 0; i < MAX_LEAK_SLOTS; i++) {
                if (leakHistory[i].leak.meta.timestamp == 0) {
                    targetIndex = i;
                    break;
                }
            }

            if (targetIndex == -1) {
                int victim_idx = 0;
                int min_score = INT_MAX;
                uint32_t oldest_time = UINT32_MAX;

                for (int i = 0; i < MAX_LEAK_SLOTS; i++) {
                    int score = leakHistory[i].leak.retained_len;
                    if (score == 0) score = strlen(leakHistory[i].leak.text);
                    if (leakHistory[i].leak.meta.is_high_value) score += 300;

                    if (score < min_score) {
                        min_score = score;
                        victim_idx = i;
                        oldest_time = leakHistory[i].first_seen;
                    } else if (score == min_score) {
                        if (leakHistory[i].first_seen < oldest_time) {
                            victim_idx = i;
                            oldest_time = leakHistory[i].first_seen;
                        }
                    }
                }

                int incoming_score = incomingLeak.retained_len;
                if (incoming_score == 0) incoming_score = strlen(incomingLeak.text);
                if (incomingLeak.meta.is_high_value) incoming_score += 10000;

                if (incoming_score > min_score) {
                    targetIndex = victim_idx;
                }
            }

            // ==========================================
            // 5. INSERT — GATED, using vendors already resolved above
            // ==========================================
            if (targetIndex != -1) {
                leakHistory[targetIndex].leak = incomingLeak;
                leakHistory[targetIndex].hitCount = 1;
                leakHistory[targetIndex].first_seen = incomingLeak.meta.timestamp;
                leakHistory[targetIndex].flow_hash = incomingLeak.meta.flow_hash;
                strcpy(leakHistory[targetIndex].src_vendor, resolved_src_vendor);
                strcpy(leakHistory[targetIndex].dst_vendor, resolved_dst_vendor);

                ui_needs_update = true;
            }
        }
    }


    // ==========================================
    // 8. BATCHED UI REFRESH
    // ==========================================
    if (ui_needs_update &&
        currentState == SCREEN_DEVICE_LIST &&
        currentRadioMode == RADIO_PCAP) {

        processPcapData();
        drawDeviceList();
    }
}



void processWifiData() {
    // Snapshot the live buffer for the real-time UI/sorting
    memcpy((void*)sortData, (void*)liveData, sizeof(liveData));
    sortMacCount = liveMacCount;
    sortOtherBytes = liveOtherBytes;

    // Drain the "Other Bytes" bucket into the historical session
    sessionOtherBytes += liveOtherBytes;
    
    // Sync the Live Buffer into the Historical Session
    for (int i = 0; i < liveMacCount; i++) {
        bool found = false;
        float rawDistance = calculateRfDistance(liveData[i].rssi, 0, RADIO_WIFI_24GHZ);
        
        // A. Inner j loop — session sync + bounds refresh
        for (int j = 0; j < sessionMacCount; j++) {
            if (memcmp(sessionData[j].mac, (void*)liveData[i].mac, 6) == 0) {
                sessionData[j].packets += liveData[i].packets;
                sessionData[j].tx_bytes += liveData[i].tx_bytes;
                sessionData[j].rx_bytes += liveData[i].rx_bytes;
                sessionData[j].sum_bytes += liveData[i].sum_bytes;
                sessionData[j].sum_sq_bytes += liveData[i].sum_sq_bytes;
                sessionData[j].rssi = liveData[i].rssi;
                
                if (liveData[i].rate > 0) sessionData[j].rate = liveData[i].rate;
                sessionData[j].last_seen = liveData[i].last_seen;
                
                // Only stretch the session bounds if the liveData window actually
                // captured a valid physical transmission (!= 0 and != -100).
                if (liveData[i].rssi_min != 0) {
                    if (liveData[i].rssi_min < sessionData[j].rssi_min || sessionData[j].rssi_min == 0) {
                        sessionData[j].rssi_min = liveData[i].rssi_min;
                    }
                }
                if (liveData[i].rssi_max != -100) {
                    if (liveData[i].rssi_max > sessionData[j].rssi_max || sessionData[j].rssi_max == 0) {
                        sessionData[j].rssi_max = liveData[i].rssi_max;
                    }
                }

                if (rawDistance > 0) {
                    sessionData[j].smoothedDistance = (0.2 * rawDistance) + (0.8 * sessionData[j].smoothedDistance);
                }

                found = true;
                break;
            }
        }

        // B. If it's a completely new MAC, claim a new slot OR Evict
        if (!found) {
            int targetIndex = 0;

            if (sessionMacCount < MAX_MACS) {
                targetIndex = sessionMacCount;
                sessionMacCount++;
            } else {
                // Execute LRU Eviction!
                uint32_t oldestTime = 0xFFFFFFFF; 
                for (int k = 0; k < MAX_MACS; k++) {
                    if (sessionData[k].last_seen < oldestTime) {
                        oldestTime = sessionData[k].last_seen;
                        targetIndex = k;
                    }
                }
                // Dump the evicted device's stats so global totals remain accurate!
                sessionOtherBytes += (sessionData[targetIndex].tx_bytes + sessionData[targetIndex].rx_bytes);
            }

            memcpy((void*)&sessionData[targetIndex], (void*)&liveData[i], sizeof(MacRecord));
            sessionData[targetIndex].smoothedDistance = (rawDistance > 0) ? rawDistance : 0.0;
        }
    } 

    // Wipe the live buffer clean so the interrupt can refill it
    memset((void*)liveData, 0, sizeof(liveData));
    liveMacCount = 0;
    liveOtherBytes = 0;

    // --- FAST INSERTION SORT: WI-FI SNAPSHOT ---
    for (int i = 1; i < sortMacCount; i++) {
        MacRecord key = sortData[i];
        double key_val = getSortMetric(key, currentSortMode); 
        int j = i - 1;

        if (sort_descending) {
            while (j >= 0 && getSortMetric(sortData[j], currentSortMode) < key_val) {
                sortData[j + 1] = sortData[j];
                j = j - 1;
            }
        } else {
            while (j >= 0 && getSortMetric(sortData[j], currentSortMode) > key_val && key_val > 0.0) {
                sortData[j + 1] = sortData[j];
                j = j - 1;
            }
        }
        sortData[j + 1] = key;
    }

    // --- FAST INSERTION SORT: WI-FI SESSION ---
    for (int i = 1; i < sessionMacCount; i++) {
        MacRecord key = sessionData[i];
        double key_val = getSortMetric(key, currentSortMode); 
        int j = i - 1;

        if (sort_descending) {
            while (j >= 0 && getSortMetric(sessionData[j], currentSortMode) < key_val) {
                sessionData[j + 1] = sessionData[j];
                j = j - 1;
            }
        } else {
            while (j >= 0 && getSortMetric(sessionData[j], currentSortMode) > key_val && key_val > 0.0) {
                sessionData[j + 1] = sessionData[j];
                j = j - 1;
            }
        }
        sessionData[j + 1] = key;
    }

    // Calculate "Other" for the live waterfall chart
    sortOtherBytes = liveOtherBytes; 
    for(int i = 6; i < sortMacCount; i++) {
        sortOtherBytes += (sortData[i].tx_bytes + sortData[i].rx_bytes);
    }

    // Attempt Vendor Resolution
    for(int i = 0; i < 10 && i < sortMacCount; i++) resolveMacVendor(&sortData[i]);
    for(int i = 0; i < 10 && i < sessionMacCount; i++) resolveMacVendor(&sessionData[i]);
}

void processBleData() {
    memcpy(sortBleData, (void*)liveBleData, sizeof(liveBleData));
    sortBleCount = liveBleCount;

    for (int i = 0; i < liveBleCount; i++) {
        bool found = false;
        float rawDistance = calculateRfDistance(liveBleData[i].rssi, liveBleData[i].txPower, RADIO_BLE_24GHZ);
        
        for (int j = 0; j < sessionBleCount; j++) {
            if (memcmp(sessionBleData[j].mac, (void*)(uint8_t*)liveBleData[i].mac, 6) == 0) {
                sessionBleData[j].hits += liveBleData[i].hits;
                sessionBleData[j].rssi = liveBleData[i].rssi;
                sessionBleData[j].txPower = liveBleData[i].txPower; 
                sessionBleData[j].lastSeen = liveBleData[i].lastSeen;

                if (rawDistance > 0) {
                    sessionBleData[j].smoothedDistance = (0.2 * rawDistance) + (0.8 * sessionBleData[j].smoothedDistance);
                }

                if (liveBleData[i].name[0] != '\0') {
                    strncpy((char*)sessionBleData[j].name, (char*)liveBleData[i].name, 24);
                    sessionBleData[j].name[24] = '\0'; 
                }
                
                if (liveBleData[i].trackerType != TRACKER_NONE) sessionBleData[j].trackerType = liveBleData[i].trackerType;
                if (liveBleData[i].appearanceId != 0) sessionBleData[j].appearanceId = liveBleData[i].appearanceId;
                if (liveBleData[i].serviceId != 0) sessionBleData[j].serviceId = liveBleData[i].serviceId;

                found = true;
                break;
            }
        }

        if (!found) {
            int targetIndex = 0;

            if (sessionBleCount < MAX_BLE_DEVICES) {
                targetIndex = sessionBleCount;
                sessionBleCount++;
            } else {
                uint32_t oldestTime = 0xFFFFFFFF; 
                for (int k = 0; k < MAX_BLE_DEVICES; k++) {
                    if (sessionBleData[k].lastSeen < oldestTime) {
                        oldestTime = sessionBleData[k].lastSeen;
                        targetIndex = k;
                    }
                }
            }

            memcpy((void*)&sessionBleData[targetIndex], (void*)&liveBleData[i], sizeof(BLERecord));
            sessionBleData[targetIndex].smoothedDistance = (rawDistance > 0) ? rawDistance : 0.0;
        }
    }

    memset((void*)liveBleData, 0, sizeof(liveBleData));
    liveBleCount = 0;

    // --- FAST INSERTION SORT: BLE SNAPSHOT ---
    for (int i = 1; i < sortBleCount; i++) {
        BLERecord key = sortBleData[i];
        double key_val = getBleSortMetric(key, currentBleSortMode);
        int j = i - 1;

        if (sort_descending) {
            while (j >= 0 && getBleSortMetric(sortBleData[j], currentBleSortMode) < key_val) {
                sortBleData[j + 1] = sortBleData[j];
                j = j - 1;
            }
        } else {
            while (j >= 0 && getBleSortMetric(sortBleData[j], currentBleSortMode) > key_val && key.hits > 0) {
                sortBleData[j + 1] = sortBleData[j];
                j = j - 1;
            }
        }
        sortBleData[j + 1] = key;
    }

    // --- FAST INSERTION SORT: BLE SESSION ---
    for (int i = 1; i < sessionBleCount; i++) {
        BLERecord key = sessionBleData[i];
        double key_val = getBleSortMetric(key, currentBleSortMode);
        int j = i - 1;

        if (sort_descending) {
            while (j >= 0 && getBleSortMetric(sessionBleData[j], currentBleSortMode) < key_val) {
                sessionBleData[j + 1] = sessionBleData[j];
                j = j - 1;
            }
        } else {
            while (j >= 0 && getBleSortMetric(sessionBleData[j], currentBleSortMode) > key_val && key.hits > 0) {
                sessionBleData[j + 1] = sessionBleData[j];
                j = j - 1;
            }
        }
        sessionBleData[j + 1] = key;
    }
}

void processApData() {
    //memcpy((void*)sortApData, (void*)liveApData, sizeof(liveApData));
    //sortApCount = liveApCount;
    sortApCount = 0;
    for (int i = 0; i < liveApCount; i++) {
        // Only push APs to the temporal legend/waterfall if they moved actual data in this cycle
        if (liveApData[i].tx_bytes + liveApData[i].rx_bytes > 0) {
            // Safely cast away volatile using memcpy for the single struct
            memcpy((void*)&sortApData[sortApCount], (void*)&liveApData[i], sizeof(ApRecord));
            sortApCount++;
        }
    }
    
    for (int i = 0; i < liveApCount; i++) {
        bool found = false;
        float rawDistance = calculateRfDistance(liveApData[i].rssi, 0, RADIO_WIFI_24GHZ);

        for (int j = 0; j < sessionApCount; j++) {
            if (memcmp(sessionApData[j].bssid, (void*)liveApData[i].bssid, 6) == 0) {
                sessionApData[j].packets += liveApData[i].packets;
                sessionApData[j].tx_bytes += liveApData[i].tx_bytes;
                sessionApData[j].rx_bytes += liveApData[i].rx_bytes;
                sessionApData[j].sum_bytes += liveApData[i].sum_bytes;
                sessionApData[j].sum_sq_bytes += liveApData[i].sum_sq_bytes;
                
                sessionApData[j].last_seen = liveApData[i].last_seen;
                sessionApData[j].rssi = liveApData[i].rssi;
                if (liveApData[i].rssi_min < sessionApData[j].rssi_min || sessionApData[j].rssi_min == 0) {
                    sessionApData[j].rssi_min = liveApData[i].rssi_min;
                }
                if (liveApData[i].rssi_max > sessionApData[j].rssi_max || sessionApData[j].rssi_max == 0) {
                    sessionApData[j].rssi_max = liveApData[i].rssi_max;
                }
                sessionApData[j].channel = liveApData[i].channel;
                if (sessionApData[j].country[0] == '\0' && liveApData[i].country[0] != '\0') {
                    sessionApData[j].country[0] = liveApData[i].country[0];
                    sessionApData[j].country[1] = liveApData[i].country[1];
                    sessionApData[j].country[2] = '\0';
                }
                
                if (liveApData[i].max_rate > sessionApData[j].max_rate) {
                    sessionApData[j].max_rate = liveApData[i].max_rate;
                }
                
                if (rawDistance > 0) {
                    sessionApData[j].smoothedDistance = (0.2 * rawDistance) + (0.8 * sessionApData[j].smoothedDistance);
                }
                
                if (strcmp(sessionApData[j].ssid, "<UNKNOWN>") == 0 && strcmp((char*)liveApData[i].ssid, "<UNKNOWN>") != 0) {
                    strlcpy((char*)sessionApData[j].ssid, (char*)liveApData[i].ssid, sizeof(sessionApData[j].ssid));
                }
                sessionApData[j].has_clone = liveApData[i].has_clone;
                found = true; break;
            }
        }
        
        if (!found) {
            int targetIndex = -1;

            if (sessionApCount < MAX_AP_RECORDS) {
                targetIndex = sessionApCount;
                sessionApCount++;
            } else {
                unsigned long now = millis();
                int stalest_idx = 0;
                int weakest_idx = 0;
                unsigned long oldest_time = 0xFFFFFFFF;
                int lowest_rssi = 127;

                for (int k = 0; k < MAX_AP_RECORDS; k++) {
                    if (sessionApData[k].last_seen < oldest_time) {
                        oldest_time = sessionApData[k].last_seen;
                        stalest_idx = k;
                    }
                    if (sessionApData[k].rssi < lowest_rssi) {
                        lowest_rssi = sessionApData[k].rssi;
                        weakest_idx = k;
                    }
                }

                if ((now - oldest_time) > 60000) targetIndex = stalest_idx;
                else if (liveApData[i].rssi > lowest_rssi) targetIndex = weakest_idx;
            }

            if (targetIndex != -1) {
                memcpy((void*)&sessionApData[targetIndex], (void*)&liveApData[i], sizeof(ApRecord));
                sessionApData[targetIndex].smoothedDistance = (rawDistance > 0) ? rawDistance : 0.0;
            }
        }
    }
    
    // Clear the traffic counters, but PRESERVE THE DICTIONARY!
    for (int i = 0; i < liveApCount; i++) {
        liveApData[i].packets = 0;
        liveApData[i].tx_bytes = 0;
        liveApData[i].rx_bytes = 0;
        liveApData[i].sum_bytes = 0;
        liveApData[i].sum_sq_bytes = 0;
    }
    
    // --- FAST INSERTION SORT: AP SNAPSHOT ---
    for (int i = 1; i < sortApCount; i++) {
        ApRecord key = sortApData[i];
        double key_val = getSortMetric(key, currentSortMode);
        int j = i - 1;
        
        if (sort_descending) {
            while (j >= 0 && getSortMetric(sortApData[j], currentSortMode) < key_val) {
                sortApData[j + 1] = sortApData[j];
                j = j - 1;
            }
        } else {
            while (j >= 0 && getSortMetric(sortApData[j], currentSortMode) > key_val && key_val > 0.0) {
                sortApData[j + 1] = sortApData[j];
                j = j - 1;
            }
        }
        sortApData[j + 1] = key;
    }

    // --- FAST INSERTION SORT: AP SESSION ---
    for (int i = 1; i < sessionApCount; i++) {
        ApRecord key = sessionApData[i];
        double key_val = getSortMetric(key, currentSortMode);
        int j = i - 1;

        if (sort_descending) {
            while (j >= 0 && getSortMetric(sessionApData[j], currentSortMode) < key_val) {
                sessionApData[j + 1] = sessionApData[j];
                j = j - 1;
            }
        } else {
            while (j >= 0 && getSortMetric(sessionApData[j], currentSortMode) > key_val && key_val > 0.0) {
                sessionApData[j + 1] = sessionApData[j];
                j = j - 1;
            }
        }
        sessionApData[j + 1] = key;
    }
    
    sortOtherBytes = 0; 
    for(int i = 8; i < sortApCount; i++) {
        sortOtherBytes += (sortApData[i].tx_bytes + sortApData[i].rx_bytes);
    }
}

void processChannelData() {
    memcpy((void*)sortChannelData, (void*)liveChannelData, sizeof(liveChannelData));
    sortChannelCount = liveChannelCount;
    
    for (int i = 0; i < liveChannelCount; i++) {
        bool found = false;
        for (int j = 0; j < sessionChannelCount; j++) {
            if (sessionChannelData[j].channel == liveChannelData[i].channel) {
                sessionChannelData[j].packets += liveChannelData[i].packets;
                sessionChannelData[j].tx_bytes += liveChannelData[i].tx_bytes;
                sessionChannelData[j].rx_bytes += liveChannelData[i].rx_bytes;
                sessionChannelData[j].sum_bytes += liveChannelData[i].sum_bytes;
                sessionChannelData[j].sum_sq_bytes += liveChannelData[i].sum_sq_bytes;
                sessionChannelData[j].last_seen = liveChannelData[i].last_seen;
                
                sessionChannelData[j].avg_rssi = liveChannelData[i].avg_rssi;
                sessionChannelData[j].ema_variance = liveChannelData[i].ema_variance;
                sessionChannelData[j].prev_rssi = liveChannelData[i].prev_rssi;
                sessionChannelData[j].ema_cov = liveChannelData[i].ema_cov;
                
                found = true; break;
            }
        }
        
        if (!found && sessionChannelCount < MAX_CHANNEL_RECORDS) {
            memcpy((void*)&sessionChannelData[sessionChannelCount], (void*)&liveChannelData[i], sizeof(ChannelRecord));
            sessionChannelCount++;
        }
    }
    
    for (int i = 0; i < liveChannelCount; i++) {
        liveChannelData[i].packets = 0;
        liveChannelData[i].tx_bytes = 0;
        liveChannelData[i].rx_bytes = 0;
        liveChannelData[i].sum_bytes = 0;
        liveChannelData[i].sum_sq_bytes = 0;
    }
    
    // --- DYNAMIC INSERTION SORT: CHANNEL SNAPSHOT ---
    for (int i = 1; i < sortChannelCount; i++) {
        ChannelRecord key = sortChannelData[i];
        double key_val = getChannelMetric(key, currentSortMode);
        int j = i - 1;
        
        if (sort_descending) {
            while (j >= 0 && getChannelMetric(sortChannelData[j], currentSortMode) < key_val) {
                sortChannelData[j + 1] = sortChannelData[j];
                j = j - 1;
            }
        } else {
            while (j >= 0 && getChannelMetric(sortChannelData[j], currentSortMode) > key_val && key_val != 0) {
                sortChannelData[j + 1] = sortChannelData[j];
                j = j - 1;
            }
        }
        sortChannelData[j + 1] = key;
    }

    // --- DYNAMIC INSERTION SORT: CHANNEL SESSION ---
    for (int i = 1; i < sessionChannelCount; i++) {
        ChannelRecord key = sessionChannelData[i];
        double key_val = getChannelMetric(key, currentSortMode);
        int j = i - 1;
        
        if (sort_descending) {
            while (j >= 0 && getChannelMetric(sessionChannelData[j], currentSortMode) < key_val) {
                sessionChannelData[j + 1] = sessionChannelData[j];
                j = j - 1;
            }
        } else {
            while (j >= 0 && getChannelMetric(sessionChannelData[j], currentSortMode) > key_val && key_val != 0) {
                sessionChannelData[j + 1] = sessionChannelData[j];
                j = j - 1;
            }
        }
        sessionChannelData[j + 1] = key;
    }
            
    sortOtherBytes = 0; 
    for(int i = 6; i < sortChannelCount; i++) {
        sortOtherBytes += (sortChannelData[i].tx_bytes + sortChannelData[i].rx_bytes);
    }
}

void drawWaterfallChart() {
    // 1. Gate the legends
    if (currentRadioMode != RADIO_PCAP) {
        drawTemporalLegend();
        drawPersistentTopN();
    }

    int chart_area_height = CHART_BOTTOM - chart_start_y;
    
    // FIX 3: Use the exact same 3/4 split for ALL modes to keep the bottom graph height identical
    int split_y = chart_start_y + (chart_area_height * 3) / 4; 
    
    int ERASER_WIDTH = 44;

    // 3. Adjust the eraser to ONLY clear the bottom pane in PCAP mode
    int clear_start_y = (currentRadioMode == RADIO_PCAP) ? (split_y + 1) : (chart_start_y + 1);
    int clear_height = CHART_BOTTOM - clear_start_y;
    
    // Pure wipe logic (using dynamic clear_start_y and clear_height)
    if (current_x + ERASER_WIDTH <= 480) {
        tft.fillRect(current_x, clear_start_y, ERASER_WIDTH, clear_height, TFT_BLACK);
    } else {
        int w1 = 480 - current_x;
        tft.fillRect(current_x, clear_start_y, w1, clear_height, TFT_BLACK);
        tft.fillRect(0, clear_start_y, ERASER_WIDTH - w1, clear_height, TFT_BLACK);
    }

    // X-Axis Time Ticks
    if (current_x % 60 == 0) {
        tft.drawLine(current_x, split_y - 3, current_x, split_y + 3, COLOR_HOT_CHEST);
        tft.drawLine(current_x + 1, split_y - 3, current_x + 1, split_y + 3, COLOR_HOT_CHEST);
    } else {
        tft.drawPixel(current_x, split_y, COLOR_HOT_CHEST);
        tft.drawPixel(current_x + 1, split_y, COLOR_HOT_CHEST);
    }

    int current_y = split_y - 1; 
    uint32_t current_total_metric = 0;

    // --- CHART PLOTTING ---
    if (currentRadioMode == RADIO_WIFI) {
        uint32_t total_bytes = sortOtherBytes;
        for(int i = 0; i < 6 && i < sortMacCount; i++) total_bytes += (sortData[i].tx_bytes + sortData[i].rx_bytes);
        current_total_metric = total_bytes; 

        if (total_bytes > 0) {
            double log_total = 0;
            if (useLogScale) {
                for(int j = 0; j < 6 && j < sortMacCount; j++) {
                    uint32_t device_total = sortData[j].tx_bytes + sortData[j].rx_bytes;
                    log_total += log10((double)device_total + 1.0);
                }
                log_total += log10((double)sortOtherBytes + 1.0);
            }

            for(int i = 0; i < 6 && i < sortMacCount; i++) {
                double fraction;
                uint32_t current_device_bytes = sortData[i].tx_bytes + sortData[i].rx_bytes;

                if (useLogScale) fraction = log10((double)current_device_bytes + 1.0) / log_total;
                else fraction = (double)current_device_bytes / (double)total_bytes;

                int bar_height = (int)(fraction * (split_y - chart_start_y - 1));
                if (bar_height > (split_y - chart_start_y - 1)) bar_height = split_y - chart_start_y - 1;

                tft.drawLine(current_x, current_y, current_x, current_y - bar_height, colors[i]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, current_y - bar_height, colors[i]);
                current_y -= bar_height;
            }

            if (sortOtherBytes > 0 && current_y > chart_start_y) {
                tft.drawLine(current_x, current_y, current_x, chart_start_y + 1, colors[8]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, chart_start_y + 1, colors[8]);
            } else if (sortOtherBytes == 0 && current_y > chart_start_y && sortMacCount > 0) {
                tft.drawLine(current_x, current_y, current_x, chart_start_y + 1, colors[sortMacCount - 1]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, chart_start_y + 1, colors[sortMacCount - 1]);
            }
        }
    }
    else if (currentRadioMode == RADIO_BLE) {
        uint32_t total_hits = 0;
        uint32_t other_hits = 0;
        int ble_count = (sortBleCount > 6) ? 6 : sortBleCount;

        for(int i = 0; i < ble_count; i++) total_hits += sortBleData[i].hits;
        if (sortBleCount > 6) {
            for (int i = 6; i < sortBleCount; i++) other_hits += sortBleData[i].hits;
            total_hits += other_hits; 
        }
        current_total_metric = total_hits; 

        if (total_hits > 0) {
            double log_total = 0;
            if (useLogScale) {
                for(int j = 0; j < ble_count; j++) log_total += log10((double)sortBleData[j].hits + 1.0);
                if (other_hits > 0) log_total += log10((double)other_hits + 1.0);
            }

            for(int i = 0; i < ble_count; i++) {
                double fraction;
                if (useLogScale) fraction = log10((double)sortBleData[i].hits + 1.0) / log_total;
                else fraction = (double)sortBleData[i].hits / (double)total_hits;
                
                int bar_height = (int)(fraction * (split_y - chart_start_y - 1));
                if (bar_height > (split_y - chart_start_y - 1)) bar_height = split_y - chart_start_y - 1;

                tft.drawLine(current_x, current_y, current_x, current_y - bar_height, colors[i]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, current_y - bar_height, colors[i]);
                current_y -= bar_height;
            }
            
            if (other_hits > 0 && current_y > chart_start_y) {
                tft.drawLine(current_x, current_y, current_x, chart_start_y + 1, colors[8]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, chart_start_y + 1, colors[8]);
            } else if (other_hits == 0 && current_y > chart_start_y && ble_count > 0) {
                tft.drawLine(current_x, current_y, current_x, chart_start_y + 1, colors[ble_count - 1]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, chart_start_y + 1, colors[ble_count - 1]);
            }
        }
    }
    else if (currentRadioMode == RADIO_AP) {
        uint32_t total_bytes = sortOtherBytes;
        for(int i = 0; i < 6 && i < sortApCount; i++) total_bytes += (sortApData[i].tx_bytes + sortApData[i].rx_bytes);
        current_total_metric = total_bytes; 

        if (total_bytes > 0) {
            double log_total = 0;
            if (useLogScale) {
                for(int j = 0; j < 6 && j < sortApCount; j++) {
                    uint32_t device_total = sortApData[j].tx_bytes + sortApData[j].rx_bytes;
                    log_total += log10((double)device_total + 1.0);
                }
                log_total += log10((double)sortOtherBytes + 1.0);
            }

            for(int i = 0; i < 6 && i < sortApCount; i++) {
                double fraction;
                uint32_t current_device_bytes = sortApData[i].tx_bytes + sortApData[i].rx_bytes;
                
                if (useLogScale) fraction = log10((double)current_device_bytes + 1.0) / log_total;
                else fraction = (double)current_device_bytes / (double)total_bytes;

                int bar_height = (int)(fraction * (split_y - chart_start_y - 1));
                if (bar_height > (split_y - chart_start_y - 1)) bar_height = split_y - chart_start_y - 1;

                tft.drawLine(current_x, current_y, current_x, current_y - bar_height, colors[i]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, current_y - bar_height, colors[i]);
                current_y -= bar_height;
            }

            if (sortOtherBytes > 0 && current_y > chart_start_y) {
                tft.drawLine(current_x, current_y, current_x, chart_start_y + 1, colors[8]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, chart_start_y + 1, colors[8]);
            } else if (sortOtherBytes == 0 && current_y > chart_start_y && sortApCount > 0) {
                tft.drawLine(current_x, current_y, current_x, chart_start_y + 1, colors[sortApCount - 1]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, chart_start_y + 1, colors[sortApCount - 1]);
            }
        }
    }
    else if (currentRadioMode == RADIO_CHANNELS) {
        uint32_t total_bytes = sortOtherBytes;
        for(int i = 0; i < 6 && i < sortChannelCount; i++) total_bytes += (sortChannelData[i].tx_bytes + sortChannelData[i].rx_bytes);
        current_total_metric = total_bytes; 

        if (total_bytes > 0) {
            double log_total = 0;
            if (useLogScale) {
                for(int j = 0; j < 6 && j < sortChannelCount; j++) {
                    uint32_t c_total = sortChannelData[j].tx_bytes + sortChannelData[j].rx_bytes;
                    log_total += log10((double)c_total + 1.0);
                }
                log_total += log10((double)sortOtherBytes + 1.0);
            }

            for(int i = 0; i < 6 && i < sortChannelCount; i++) {
                double fraction;
                uint32_t current_c_bytes = sortChannelData[i].tx_bytes + sortChannelData[i].rx_bytes;
                
                if (useLogScale) fraction = log10((double)current_c_bytes + 1.0) / log_total;
                else fraction = (double)current_c_bytes / (double)total_bytes;

                int bar_height = (int)(fraction * (split_y - chart_start_y - 1));
                if (bar_height > (split_y - chart_start_y - 1)) bar_height = split_y - chart_start_y - 1;

                tft.drawLine(current_x, current_y, current_x, current_y - bar_height, colors[i]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, current_y - bar_height, colors[i]);
                current_y -= bar_height;
            }

            if (sortOtherBytes > 0 && current_y > chart_start_y) {
                tft.drawLine(current_x, current_y, current_x, chart_start_y + 1, colors[8]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, chart_start_y + 1, colors[8]);
            } else if (sortOtherBytes == 0 && current_y > chart_start_y && sortChannelCount > 0) {
                tft.drawLine(current_x, current_y, current_x, chart_start_y + 1, colors[sortChannelCount - 1]);
                tft.drawLine(current_x + 1, current_y, current_x + 1, chart_start_y + 1, colors[sortChannelCount - 1]);
            }
        }
    }
    static uint32_t last_rendered_leak_timestamp = 0;
    if (currentRadioMode == RADIO_PCAP) {
        current_total_metric = capture_bytes_render;
        
        // Redraw only if the newest packet in the buffer has changed
        if (terminal_history[0].meta.timestamp != last_rendered_leak_timestamp && terminal_history[0].meta.timestamp > 0) {
            last_rendered_leak_timestamp = terminal_history[0].meta.timestamp;

            int terminal_start_y = 26;
            tft.fillRect(0, terminal_start_y, 480, split_y - terminal_start_y - 1, TFT_BLACK);
            
            tft.setFreeFont(&UbuntuMono_Regular8pt7b);
            tft.setTextDatum(TL_DATUM);
            
            int cursor_y = terminal_start_y + 4;

// --- PASS 1: figure out which packets actually fit, newest-first ---
int drawIdx[MAX_TERMINAL_LINES];
int drawCount = 0;
{
    int scan_y = cursor_y;
    for (int i = 0; i < MAX_TERMINAL_LINES; i++) {
        if (terminal_history[i].meta.timestamp == 0) continue;

        int pLen = strnlen(terminal_history[i].text, MAX_LEAK_STR_LEN);
        int payload_lines = (pLen > 0) ? ((pLen - 1) / 57) + 1 : 1;
        if (payload_lines > 9) payload_lines = 9;
        int needed = 42 + (payload_lines * 14) + 5; // 3 meta rows + payload + margin

        if (scan_y + needed > split_y) break;
        scan_y += needed;
        drawIdx[drawCount++] = i;
    }
}

// --- PASS 2: draw them oldest-of-the-kept-set first, for the scroll effect ---
for (int k = drawCount - 1; k >= 0; k--) {
    int i = drawIdx[k]; 

                // ==========================================
// LIVE VENDOR LOOKUP — RAM CACHE ONLY
//
// IMPORTANT:
// No leakHistory dependency.
// No SD access.
// No vendor resolution.
// This is strictly an ephemeral fast-path lookup.
// ==========================================

char srcVend[9] = "";
char dstVend[9] = "";

if (!lookupVendorCache(
        terminal_history[i].meta.src_mac,
        srcVend,
        sizeof(srcVend))) {

    strlcpy(srcVend, "Unknown", sizeof(srcVend));
}

if (!lookupVendorCache(
        terminal_history[i].meta.dst_mac,
        dstVend,
        sizeof(dstVend))) {

    strlcpy(dstVend, "Unknown", sizeof(dstVend));
}

                // --- INLINE FORMATTERS ---
// 1. Compact Length (Max 4 chars)
char lenStr[8];
uint16_t fLen = terminal_history[i].meta.frame_length;
if (fLen < 1000) snprintf(lenStr, sizeof(lenStr), "%dB", fLen);
else snprintf(lenStr, sizeof(lenStr), "%dK", fLen / 1000);

// 2. Safe IPv6 Buffers (40 bytes to prevent overflow)
char srcIpRaw[40] = {0}, dstIpRaw[40] = {0};
getIpString(terminal_history[i].meta.ip_version, terminal_history[i].meta.src_ip, srcIpRaw, sizeof(srcIpRaw));
getIpString(terminal_history[i].meta.ip_version, terminal_history[i].meta.dst_ip, dstIpRaw, sizeof(dstIpRaw));

// 3. IPv6 Compression (RFC 5952 longest-run collapse, replaces old sequential strstr/memmove approach)
char srcIpStr[40] = {0}, dstIpStr[40] = {0};
if (terminal_history[i].meta.ip_version == 6) {
    compress_ipv6(srcIpRaw, srcIpStr, sizeof(srcIpStr));
    compress_ipv6(dstIpRaw, dstIpStr, sizeof(dstIpStr));
} else {
    strncpy(srcIpStr, srcIpRaw, sizeof(srcIpStr) - 1);
    strncpy(dstIpStr, dstIpRaw, sizeof(dstIpStr) - 1);
}

                // 4. Fast Live Age Calculator (Seconds Resolution)
                char firstSeenStr[8], lastSeenStr[8], ageCombo[18];
                uint32_t now_ms = millis();
                uint32_t first_sec = (now_ms - terminal_first_seen[i]) / 1000;
                uint32_t last_sec = (now_ms - terminal_history[i].meta.timestamp) / 1000;
                
                if (first_sec < 60) snprintf(firstSeenStr, sizeof(firstSeenStr), "%ds", first_sec);
                else if (first_sec < 3600) snprintf(firstSeenStr, sizeof(firstSeenStr), "%dm", first_sec / 60);
                else snprintf(firstSeenStr, sizeof(firstSeenStr), "%dh", first_sec / 3600);
                
                if (last_sec < 60) snprintf(lastSeenStr, sizeof(lastSeenStr), "%ds", last_sec);
                else if (last_sec < 3600) snprintf(lastSeenStr, sizeof(lastSeenStr), "%dm", last_sec / 60);
                else snprintf(lastSeenStr, sizeof(lastSeenStr), "%dh", last_sec / 3600);
                
                snprintf(ageCombo, sizeof(ageCombo), "%s|%s", firstSeenStr, lastSeenStr);

                // 5. Fetch Live SSID (Using persistent cache to bypass the union)
                char safeSsid[13] = "Unknown";
                for (int ap = 0; ap < MAX_BSSID_CACHE; ap++) {
                    if (bssidCache[ap].last_seen == 0) continue; // Skip empty slots
                    
                    if (memcmp(terminal_history[i].meta.bssid, bssidCache[ap].bssid, 6) == 0) {
                        strncpy(safeSsid, bssidCache[ap].ssid, 12);
                        safeSsid[12] = '\0';
                        break;
                    }
                }

                // --- ROW 1: [xHit] MAC(Vend)>MAC(Vend)|Len|C ---
                tft.setTextColor(TFT_CYAN);
                char line1[80];
                snprintf(line1, sizeof(line1), "[x%d]%02X%02X%02X%02X%02X%02X(%s)>%02X%02X%02X%02X%02X%02X(%s)|%s|C%d", 
                         terminal_hits[i],
                         terminal_history[i].meta.src_mac[0], terminal_history[i].meta.src_mac[1], terminal_history[i].meta.src_mac[2],
                         terminal_history[i].meta.src_mac[3], terminal_history[i].meta.src_mac[4], terminal_history[i].meta.src_mac[5],
                         srcVend,
                         terminal_history[i].meta.dst_mac[0], terminal_history[i].meta.dst_mac[1], terminal_history[i].meta.dst_mac[2],
                         terminal_history[i].meta.dst_mac[3], terminal_history[i].meta.dst_mac[4], terminal_history[i].meta.dst_mac[5],
                         dstVend, lenStr, terminal_history[i].meta.channel);
                tft.drawString(line1, 4, cursor_y);
                cursor_y += 14; 

                // --- ROW 2: BSSID(SSID)|DIR|SUBTYPE|PROTO|PORTS ---
                tft.setTextColor(TFT_YELLOW);
                char portStr[24] = "";
                if (terminal_history[i].meta.protocol == 6 || terminal_history[i].meta.protocol == 17) {
                    snprintf(portStr, sizeof(portStr), "|%d>%d", terminal_history[i].meta.src_port, terminal_history[i].meta.dst_port);
                }
                char line2[80];
                snprintf(line2, sizeof(line2), "%02X%02X%02X%02X%02X%02X(%s)|%s|%s|%s%s",
                         terminal_history[i].meta.bssid[0], terminal_history[i].meta.bssid[1], terminal_history[i].meta.bssid[2],
                         terminal_history[i].meta.bssid[3], terminal_history[i].meta.bssid[4], terminal_history[i].meta.bssid[5],
                         safeSsid,
                         getDirectionStr(terminal_history[i].meta.direction), 
                         getSubtypeStr(terminal_history[i].meta.frame_subtype),
                         getProtocolStr(terminal_history[i].meta.protocol), portStr);
                tft.drawString(line2, 4, cursor_y);
                cursor_y += 14;

                // --- ROW 3: IP>IP|first/last ---
                tft.setTextColor(TFT_ORANGE);
                char line3[90];
                snprintf(line3, sizeof(line3), "%s>%s|%s",
                         srcIpStr, dstIpStr, ageCombo);
                tft.drawString(line3, 4, cursor_y);
                cursor_y += 14; 

                // --- ROW 4 & 5: PAYLOAD ---
tft.setTextColor(TFT_GREEN);

int pLen = strnlen(terminal_history[i].text, MAX_LEAK_STR_LEN);
const int maxChars = 57; // (460-4)/8
int n_lines = (pLen > 0) ? ((pLen - 1) / maxChars) + 1 : 1;
if (n_lines > 9) n_lines = 9;

char sanitized[MAX_LEAK_STR_LEN + 1] = {0};
memcpy(sanitized, terminal_history[i].text, pLen);
for (int c = 0; c < pLen; c++) {
    if (sanitized[c] < 32 || sanitized[c] > 126) sanitized[c] = '.';
}

for (int line = 0; line < n_lines; line++) {
    char lineBuf[60] = {0};
    int offset = line * maxChars;
    int remaining = pLen - offset;
    int chunk = (remaining < maxChars) ? remaining : maxChars;
    strncpy(lineBuf, sanitized + offset, chunk);
    tft.drawString(lineBuf, 4, cursor_y);
    cursor_y += 14;
}
tft.drawLine(0, cursor_y + 2, 480, cursor_y + 2, COLOR_HOT_CHEST);
cursor_y += 5;
            }
        }
    }

    // --- BOTTOM PANE: SCALING ENGINE ---
    static RadioMode last_seen_mode = currentRadioMode;
    static uint8_t last_seen_bssid[6] = {0}; 
    
    static uint32_t true_max = 10;
    static uint16_t peak_h_index = 0;
    
    bool did_rescale = false; 

    if (currentRadioMode != last_seen_mode || memcmp(target_bssid, last_seen_bssid, 6) != 0) {
        true_max = 10;
        peak_h_index = 0;
        absolute_max_traffic = 10; 
        
        last_seen_mode = currentRadioMode;
        memcpy(last_seen_bssid, target_bssid, 6); 

        memset(traffic_history, 0, sizeof(traffic_history));
        did_rescale = true; 
    }

    int h_index = current_x / 2;
    traffic_history[h_index] = current_total_metric; 

    if (current_total_metric > absolute_max_traffic) {
        true_max = current_total_metric;
        peak_h_index = h_index;
        absolute_max_traffic = current_total_metric + (current_total_metric / 5); 
        did_rescale = true; 
    } else {
        if (current_total_metric > true_max) {
            true_max = current_total_metric;
            peak_h_index = h_index;
        }
        
        if (h_index == peak_h_index && current_total_metric < true_max) {
            true_max = 0;
            for (int i = 0; i < 240; i++) {
                if (traffic_history[i] > true_max) {
                    true_max = traffic_history[i];
                    peak_h_index = i;
                }
            }
            
            uint32_t next_scale = true_max + (true_max / 5);
            if (next_scale < 10) next_scale = 10; 
            
            if (next_scale < absolute_max_traffic) {
                absolute_max_traffic = next_scale;
                did_rescale = true; 
            }
        }
    }

    if (did_rescale) {
        tft.fillRect(0, split_y + 1, 480, CHART_BOTTOM - split_y, TFT_BLACK);
        tft.drawLine(0, split_y, 480, split_y, COLOR_HOT_CHEST);

        for (int c = 0; c < 240; c++) {
            int px = c * 2;
            if (px % 60 == 0) {
                tft.drawLine(px, split_y + 1, px, split_y + 3, COLOR_HOT_CHEST);
                tft.drawLine(px + 1, split_y + 1, px + 1, split_y + 3, COLOR_HOT_CHEST);
            }

            if (traffic_history[c] > 0) {
                int h = (int)(((double)traffic_history[c] / (double)absolute_max_traffic) * (CHART_BOTTOM - split_y - 1));
                if (h > CHART_BOTTOM - split_y - 4) h = CHART_BOTTOM - split_y - 4; 
                
                tft.drawLine(px, CHART_BOTTOM, px, CHART_BOTTOM - h, COLOR_HOT_CHEST);
                tft.drawLine(px + 1, CHART_BOTTOM, px + 1, CHART_BOTTOM - h, COLOR_HOT_CHEST);
            }
        }
    } else {
        if (current_total_metric > 0) {
            int h = (int)(((double)current_total_metric / (double)absolute_max_traffic) * (CHART_BOTTOM - split_y - 1));
            if (h > CHART_BOTTOM - split_y - 4) h = CHART_BOTTOM - split_y - 4; 
            
            tft.drawLine(current_x, CHART_BOTTOM, current_x, CHART_BOTTOM - h, COLOR_HOT_CHEST);
            tft.drawLine(current_x + 1, CHART_BOTTOM, current_x + 1, CHART_BOTTOM - h, COLOR_HOT_CHEST);
        }
    }

    // --- OVERLAYS ---
    // Gate the sweeping vertical lines to ONLY draw in the area below clear_start_y
    tft.drawFastVLine(current_x + 2, clear_start_y, clear_height, COLOR_HOT_CHEST);
    
    if (current_x + ERASER_WIDTH <= 480) {
        tft.drawFastVLine(current_x + ERASER_WIDTH - 1, clear_start_y, clear_height, COLOR_HOT_CHEST);
        tft.drawFastHLine(current_x, split_y, ERASER_WIDTH, COLOR_HOT_CHEST);
    } else {
        int w1 = 480 - current_x;
        tft.drawFastVLine(ERASER_WIDTH - w1 - 1, clear_start_y, clear_height, COLOR_HOT_CHEST);
        tft.drawFastHLine(current_x, split_y, w1, COLOR_HOT_CHEST);
        tft.drawFastHLine(0, split_y, ERASER_WIDTH - w1, COLOR_HOT_CHEST);
    }

    if (current_x <= 480 - ERASER_WIDTH || did_rescale) {
        int text_x = current_x + 6; 
        if (text_x > 480 - 40) text_x = 480 - 40; 

        tft.setFreeFont(&UbuntuMono_Regular8pt7b);
        tft.setTextDatum(TL_DATUM);
        tft.setTextColor(COLOR_HOT_CHEST);

        // Gate the top pane percentages AND the time scale so they don't overwrite PCAP text
        if (currentRadioMode != RADIO_PCAP) {
            tft.drawString("100%", text_x, chart_start_y + 4);
            int mid_y = chart_start_y + ((split_y - chart_start_y) / 2);
            tft.drawString("50%", text_x, mid_y - 6);
            
            if (currentRadioMode == RADIO_BLE || target_locked) tft.drawString("|=1m", text_x, split_y - 15); 
            else tft.drawString("|=2m", text_x, split_y - 15);
        }

        char maxStr[16];
        if (currentRadioMode == RADIO_BLE) {
            snprintf(maxStr, sizeof(maxStr), "%lu", absolute_max_traffic);
        } else {
            if (absolute_max_traffic < 1024) snprintf(maxStr, sizeof(maxStr), "%lu", absolute_max_traffic);
            else if (absolute_max_traffic < 1048576) snprintf(maxStr, sizeof(maxStr), "%luK", absolute_max_traffic / 1024);
            else if (absolute_max_traffic < 1073741824) snprintf(maxStr, sizeof(maxStr), "%luM", absolute_max_traffic / 1048576);
            else snprintf(maxStr, sizeof(maxStr), "%.1fG", (float)absolute_max_traffic / 1073741824.0);
        }
        
        tft.drawString(maxStr, text_x, split_y + 4);
        tft.drawString("0", text_x, CHART_BOTTOM - 12);
    }

    current_x += 2;
    if (current_x >= 480) current_x = 0;
}

void setup() {
  Serial.begin(115200);
  pinMode(15, OUTPUT); digitalWrite(15, HIGH);
  pinMode(21, OUTPUT); digitalWrite(21, HIGH);
  pinMode(5, OUTPUT);  digitalWrite(5, HIGH);

  Serial.printf("[MEM] Static footprint:  %u bytes\n", static_non_union);
Serial.printf("[MEM] Free heap at boot: %u bytes\n", esp_get_free_heap_size());
Serial.printf("[MEM] Free SRAM minimum: %u bytes\n", esp_get_minimum_free_heap_size());
Serial.printf("[MEM] sizeof(LiveCaptureEvent) = %u bytes\n", sizeof(LiveCaptureEvent));   // <-- add here
Serial.printf("[MEM] sizeof(PacketCapture)    = %u bytes\n", sizeof(PacketCapture));     // <-- and this one too
Serial.printf(
    "PacketCapture=%u bytes | leakQueue storage ~%u bytes\n",
    (unsigned)sizeof(PacketCapture),
    (unsigned)(sizeof(PacketCapture) * LEAK_QUEUE_DEPTH)
);
initProbeTracker();

// ==========================================
// 1. CREATE THE PCAP QUEUES + TRANSIENT BUFFERS
// ==========================================

// Allocate the two reusable full-payload buffers on the heap.
// These are NOT part of the persistent session union.
ptr_isr_evt = (LiveCaptureEvent*)malloc(sizeof(LiveCaptureEvent));
ptr_core1_evt = (LiveCaptureEvent*)malloc(sizeof(LiveCaptureEvent));

if (ptr_isr_evt == nullptr || ptr_core1_evt == nullptr) {
    Serial.println("FATAL: Failed to allocate transient buffers on heap!");
    while (true) delay(100);
}

// Post-parser queue: ONLY PacketCapture objects.
leakQueue = xQueueCreate(LEAK_QUEUE_DEPTH, sizeof(PacketCapture));

if (leakQueue == NULL) {
    Serial.println("[!] FATAL: Failed to create leakQueue!");
}

// Pre-parser queue: ONLY full-payload LiveCaptureEvent objects.
liveDumpQueue = xQueueCreate(
    LIVE_DUMP_QUEUE_DEPTH,
    sizeof(LiveCaptureEvent)
);

if (liveDumpQueue == NULL) {
    Serial.println("[!] FATAL: Failed to create liveDumpQueue!");
}

  // -----------------------------------------------------------

  // ==========================================
  // 2. INITIALIZE DISPLAY
  // ==========================================
  delay(1000);
  tft.init();
  tft.setTouch(calData);
  tft.setRotation(1);
  tft.fillScreen(TFT_BLACK);
  drawChartHeader();
  drawChartFooter();

  // ==========================================
  // 3. INITIALIZE SD CARD (Crucial to do this BEFORE the sniffer starts!)
  // ==========================================
  Serial.println("\n--- Initializing SD Card ---");
  if (!sd.begin(SdSpiConfig(5, SHARED_SPI, SD_SCK_MHZ(4)))) {
    Serial.println("[!] SD Card Mount Failed!");
    sd.initErrorPrint(&Serial);
  } else {
    Serial.println("[*] SD Card mounted successfully.");
    FsFile file = sd.open("/oui_db.txt", O_READ);
    if (!file) {
      Serial.println("[!] Failed to open /oui_db.txt! Check filename.");
    } else {
      Serial.printf("[*] SUCCESS! oui_db.txt found. Size: %llu bytes\n", file.fileSize());
      file.close();
    }
  }
  Serial.println("----------------------------\n");

  // ==========================================
  // 4. SPAWN CORE 1 TASKS (UI & SD Logging)
  // ==========================================
  // We will uncomment this in the next step once we write the task function!
  /*
  xTaskCreatePinnedToCore(
      sdLoggerTask,    // Task function
      "SD_Logger",     // Task name
      8192,            // Stack size (Bytes)
      NULL,            // Parameters
      1,               // Priority (1 is standard for Core 1)
      NULL,            // Task handle
      1                // Pin to Core 1
  );
  */

  // ==========================================
  // 5. TURN ON THE WATER (Start Sniffer)
  // ==========================================
  // The plumbing is fully ready. Open the valve.
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
  esp_wifi_set_channel(CHANNELS[current_ch_idx], WIFI_SECOND_CHAN_NONE);
  Serial.println("[*] Sniffer ISR active.");
}

void loop() {
  // ==========================================
  // BACKGROUND DATA ENGINES (Run every tick)
  // ==========================================
  processPendingVendors();
  runProbeCorrelationEngine(); 
  processLiveDumpQueue();
  processLeakQueue();
  
  uint16_t t_x = 0, t_y = 0;
  bool should_render = false;

  // 1. Check Touch inputs (State Controller)
  if (tft.getTouch(&t_x, &t_y)) {
      should_render = handleTouchInputs(t_x, t_y);
  }
    
  // 2. Run the Channel Hopper
  should_render |= updateRadioHopper();

  // 3. CONTINUOUS DELTA-DRAW: Foxhunt Animation Engine
  // (Must run every loop so the dog keeps walking even if signal is lost)
  if (currentState == SCREEN_FOXHUNT) {
      updateFoxhuntRadar();
  }

  // 4. EVENT-DRIVEN GATE: Heavy Math & Full UI Redraws
  if (should_render) {
    pause_sniffing = true; // Lock the radio buffers

    // --- MATH ENGINES ---
    if (currentRadioMode == RADIO_WIFI) processWifiData();
    else if (currentRadioMode == RADIO_BLE) processBleData();
    else if (currentRadioMode == RADIO_AP) processApData();
    else if (currentRadioMode == RADIO_CHANNELS) processChannelData();
    // --- ADDED PCAP MATH GATE ---
    else if (currentRadioMode == RADIO_PCAP) {
        // Snapshot the bytes for the UI and reset the ISR counter
        capture_bytes_render = capture_bytes_tick;
        capture_bytes_tick = 0;
        // IF THIS PRINTS '0', THE ISR IS BROKEN. 
        // IF THIS PRINTS '4000', THE CHART GRAPHICS ARE BROKEN.
        Serial.printf("PCAP Tick Vol: %u\n", capture_bytes_render);
    }

    pause_sniffing = false; // Unlock immediately!

    // --- FULL REDRAW GRAPHICS ENGINES ---
    if (currentState == SCREEN_CHART) {
        drawWaterfallChart();
    } else if (currentState == SCREEN_DEVICE_LIST) {
        drawDeviceList();
    } else if (currentState == SCREEN_AP_SCAN) {
        drawApScanner();
    } else if (currentState == SCREEN_PROBE_TRACKER) {
        drawProbeTracker();
    } 
    // Do NOT add SCREEN_LEAK_LIST here. It updates itself asynchronously!
    
    Serial.printf("Free Heap: %d bytes\n", ESP.getFreeHeap());
  }
  // ==========================================
    // ASYNCHRONOUS DIAGNOSTICS (Runs every 3 seconds)
    // ==========================================
    static uint32_t last_debug_print = 0;
if (millis() - last_debug_print > 3000) {

    uint32_t isr_att       = leak_isr_attempts;
    uint32_t isr_drop     = leak_isr_dropped;

    uint32_t f_seen       = leak_funnel_seen;
    uint32_t f_suppressed = leak_funnel_suppressed;
    uint32_t f_shipped    = leak_funnel_shipped;
    uint32_t ld_drop      = live_dump_dropped;

    Serial.printf(
        "[DIAG] Funnel: Seen=%u | Suppressed=%u | Shipped=%u\n",
        f_seen,
        f_suppressed,
        f_shipped
    );

    Serial.printf(
        "[DIAG] Drops: liveDumpQueue=%u | "
        "leakQueue ISR=%u/%u | Core1=%u/%u\n",
        ld_drop,
        isr_drop,
        isr_att,
        leak_core1_dropped,
        leak_core1_attempts
    );

    Serial.printf(
        "[DIAG] Free Heap: %d bytes\n",
        ESP.getFreeHeap()
    );

    leak_funnel_seen       = 0;
    leak_funnel_suppressed = 0;
    leak_funnel_shipped    = 0;
    live_dump_dropped      = 0;

    leak_isr_attempts      = 0;
    leak_isr_dropped       = 0;
    leak_core1_attempts    = 0;
    leak_core1_dropped     = 0;

    if (currentState == SCREEN_CHART &&
        currentRadioMode == RADIO_PCAP) {

        drawTelemetryHeader();
    }

    last_debug_print = millis();
}
}
