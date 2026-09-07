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
#include "capture/capture.h"
#include "modes/wifi.h"
#include "modes/ble.h"
#include "modes/ap_scanner.h"
#include "modes/channel_scanner.h"
#include "osint/osint.h"
#include "ui/ui_utils.h"
#include "ui/ui_state.h"
#include "ui/views/chart.h"
#include "ui/views/lists.h"
#include "ui/views/foxhunt.h"
#include "ui/input.h"






// Define the protocols so the math knows how to handle the physics

/**
 * Universal Log-Distance Path Loss Calculator
 * * @param rssi        The received signal strength (e.g., -75)
 * @param txPower     The broadcasted TX power in dBm (0 if unknown)
 * @param protocol    The RadioProtocol enum (BLE, Wi-Fi 2.4, Wi-Fi 5)
 * @param customLoss  (Optional) Override the path loss exponent. Default 0.0 uses standard presets.
 * @return            Estimated distance in meters
 */









// ==========================================
// BLUETOOTH DATA STRUCTURE
// ==========================================

// 1. Define this enum above the struct so it exists in memory first


// 2. The perfectly aligned struct


// Perfectly aligned with your drawDeviceList() function!

// NimBLE Global Scanner Pointer



// Still exactly 80 bytes!





std::atomic<bool> pause_sniffing{false};

bool sort_descending = true; // Default to loudest devices first






//Should be 80 bytes






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






// FNV-1a 32-bit Hash


// ==========================================
// PHY RATE TO MBPS TRANSLATOR
// ==========================================












// Returns the number of SSIDs in a probe record's list
// that have a known beacon in the dictionary





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










// --- The Smart Endpoint Wi-Fi Sniffer Callback ---

















/**
 * Fast Binary Search for Corporate Trackers (0x16 Service Data)
 */


/**
 * Fast Binary Search for Standard Hardware Services (0x02/0x03)
 */


// --- UI Drawing Functions ---




// ==========================================
// WIFI SORTING STATE
// ==========================================
SortMode currentSortMode = SORT_TOTAL; // Default state





// ==========================================
// BLE SORTING STATE
// ==========================================
BleSortMode currentBleSortMode = SORT_BLE_HITS; // Default state



// ==========================================
// PROBE REQUEST SORTING
// ==========================================







float calculateRfDistance(int rssi, int txPower, RadioProtocol protocol, float customLoss) {
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




















// Helper to find or allocate an SSID string in the shared pool




// --- Background Vendor Resolver (Runs safely on Core 1) ---




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











// --- BULLETPROOF SORTING ENGINE ---








// ==========================================
// CORE 1: RAM-ONLY QUEUE CONSUMER
// ==========================================
















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
