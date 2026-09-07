#pragma once
#include <stdint.h>
#include <stddef.h>
#include "parsers/parser_common.h"

#define MAX_BSSID_CACHE 16
#define MAX_LIVE_CAPTURE 1536
#define LIVE_DUMP_QUEUE_DEPTH 20
#define LEAK_QUEUE_DEPTH 15   
#define MAX_ACTIVE_FLOWS 64
#define MAX_LEAK_SLOTS 20
#define LIVE_DUMP_COOLDOWN_MS 30000 
#define SEC_COOLDOWN_MS 5000 
#define ALERT_CACHE_SIZE 8
#define MAX_TERMINAL_LINES 5
#define MAX_BLE_DEVICES 150
#define MAX_AP_RECORDS 100 // Bumped from 30! Safely fits inside the Union.
#define MAX_CHANNEL_RECORDS 100
#define MAX_BEACON_DICT 80 // MAX POSSIBLE IS 255 given uint8_t beaconDictCount
#define OUI_CACHE_SIZE 150
const int MAX_PROBE_SLOTS = 45;     // Max unique devices tracked
const int TOTAL_SSID_POOL = 150;     // Total unique SSID strings shared among all devices
const int EMERGENCY_CUTOFF = 15;    // Max SSIDs a single device can claim
const int MAX_MACS = 185;

struct BssidCacheEntry {
    uint32_t last_seen; // 4 bytes (Largest first)
    uint8_t bssid[6];   // 6 bytes
    char ssid[33];      // 33 bytes
};

enum RadioProtocol {
    RADIO_BLE_24GHZ,
    RADIO_WIFI_24GHZ,
    RADIO_WIFI_5GHZ
};

enum ProbeSortMode { PROBE_SORT_HITS, PROBE_SORT_DIST, PROBE_SORT_SSIDS, PROBE_SORT_AGE };
enum SortMode { SORT_TOTAL, SORT_TX, SORT_RX, SORT_AVG, SORT_CV, SORT_DIST, SORT_AGE };
enum BleSortMode { SORT_BLE_HITS, SORT_BLE_DIST, SORT_BLE_AGE };

// shared sort state + physics helper (defined in main.cpp)
extern SortMode currentSortMode;
extern BleSortMode currentBleSortMode;
extern bool sort_descending;
float calculateRfDistance(int rssi, int txPower, RadioProtocol protocol, float customLoss = 0.0);

struct FlowRecord {
    uint32_t flow_hash;       
    uint32_t first_seen_ms;   
    uint32_t last_seen_ms;
    uint32_t last_printed_ms;
    uint16_t count;
};

struct CryptoAlertCache {
    uint32_t last_alert_ms;
    uint8_t  mac_src[6];
    uint8_t  mac_dst[6];
};

struct PacketMeta {
    uint32_t timestamp;
    uint32_t flow_hash;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t frame_length;
    uint16_t ether_type;
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint8_t  ip_version;
    uint8_t  protocol;
    uint8_t  channel;
    uint8_t  direction;
    uint8_t  frame_subtype;
    uint8_t  tcp_flags;
    bool     is_high_value;
    uint8_t bssid[6];
};

struct LiveCaptureEvent {
    PacketMeta meta;
    uint16_t   raw_len;                 // bytes in raw_payload, up to MAX_LIVE_CAPTURE
    uint8_t    raw_payload[MAX_LIVE_CAPTURE];
};

struct PacketCapture {
    PacketMeta meta;
    uint16_t   retained_len;
    char    text[MAX_LEAK_STR_LEN];
};

struct LeakHistoryEntry {
    PacketCapture leak;           // Uses the unified struct
    uint32_t first_seen;          // 4 bytes 
    uint32_t flow_hash;           // 4 bytes (Added for tracking Core 1 hits)
    char     src_vendor[16];      // 16 bytes
    char     dst_vendor[16];      // 16 bytes
    uint16_t hitCount;            // 2 bytes
};

enum LeakSortMode {
    SORT_LEAK_AGE,
    SORT_LEAK_LENGTH,
    SORT_LEAK_HITS
};

enum UIState { SCREEN_CHART, SCREEN_MENU, SCREEN_AP_SCAN,
   SCREEN_DEVICE_LIST, SCREEN_PROBE_TRACKER,
   SCREEN_FOXHUNT, SCREEN_LEAK_LIST };

struct SSIDNode {
  char text[33];
  int next_node_idx = -1;                // Index of the next SSID for this device (-1 if end)
};

struct ProbeRecordShared {
  // --- 8-byte variables ---
  uint64_t pnl_hash;        // <--- NEW: 64-bit SSID Bloom Filter
  
  // --- 4-byte variables ---
  uint32_t hardware_hash;   // <--- NEW: 32-bit IE Tag Fingerprint
  unsigned long first_seen; 
  unsigned long last_seen;
  int first_ssid_idx;               
  float smoothedDistance;   
  
  // --- 2-byte variables ---
  uint16_t hits;
  
  // --- 1-byte arrays and variables ---
  uint8_t mac[6];
  char vendor[25];
  uint8_t ssid_count;
  uint8_t generation = 0;
  bool needs_lookup = false;
  int8_t rssi;              
  uint8_t mac_rotations;  // Tracks how many times this device has spoofed a new MAC
};

enum RadioMode { RADIO_WIFI, RADIO_BLE, RADIO_AP, RADIO_CHANNELS, RADIO_PCAP };

enum OsintTrackerType : uint8_t {
    TRACKER_NONE = 0,
    TRACKER_APPLE_FINDMY,
    TRACKER_APPLE_IBEACON,
    TRACKER_GOOGLE_FASTPAIR,
    TRACKER_SAMSUNG_SMARTTAG,
    TRACKER_TILE,
    TRACKER_MS_SWIFTPAIR,
    TRACKER_EDDYSTONE
};

struct BLERecord {
  // --- 4-Byte Types (Grouped at the top) ---
  uint32_t firstSeen;       
  uint32_t lastSeen;
  uint32_t hits;          
  float smoothedDistance; 

  // --- 2-Byte Types (The string replacements) ---
  uint16_t appearanceId;    
  uint16_t serviceId;       

  // --- 1-Byte Types & Arrays (Grouped at the bottom) ---
  uint8_t mac[6];         
  uint8_t trackerType;      
  int8_t rssi;               
  int8_t txPower; 
  uint8_t namePriority;     // <--- ADDED BACK: Protects your Eddystone URLs
  char name[25];            
  char payload[30];
};

struct ApRecord {
  // 8-byte types
  uint64_t sum_bytes;
  uint64_t sum_sq_bytes;

  // 4-byte types
  uint32_t first_seen; 
  uint32_t last_seen;  
  uint32_t packets;
  uint32_t tx_bytes;
  uint32_t rx_bytes;
  float smoothedDistance;

  // 1-byte types & arrays
  uint8_t bssid[6];       
  uint8_t channel;
  uint8_t max_rate;
  int8_t rssi;
  int8_t rssi_min;    
  int8_t rssi_max;    
  bool has_clone;     // NEW: O(1) lookup during UI rendering
  char ssid[25];      // Trimmed from 26 to 25 to maintain exactly 80 bytes
  char country[3];
};

struct ChannelRecord {
  uint64_t sum_bytes;
  uint64_t sum_sq_bytes;
  uint32_t first_seen;
  uint32_t last_seen;
  uint32_t packets;
  uint32_t tx_bytes;
  uint32_t rx_bytes;
  uint8_t channel;
  
  // --- The EMA Time-Series Variables ---
  float avg_rssi;     // The moving noise floor
  float ema_variance; // The volatility tracker
  float prev_rssi;    // Memory of the last packet
  float ema_cov;      // The autocorrelation tracker
};

struct MacRecord {
    uint64_t sum_bytes;
    uint64_t sum_sq_bytes;
    uint32_t first_seen;
    uint32_t last_seen;
    uint32_t packets;
    uint32_t tx_bytes;
    uint32_t rx_bytes;
    float smoothedDistance;
    uint8_t mac[6];
    char vendor[28];
    int8_t rssi;
    int8_t rssi_min;    // <--- NEW: spatial floor
    int8_t rssi_max;    // <--- NEW: spatial ceiling
    uint8_t rate;
    bool vendorFound;
    bool needs_lookup;
};

struct OUICache {
  uint8_t oui[3];
  char vendor[28]; // <--- Updated to match the new MacRecord limit
};

struct BeaconEntry {
    uint32_t last_seen; //  4 bytes — 4-byte type first
    int8_t rssi;        //  1 byte
    uint8_t bssid[6];  //  6 bytes
    char ssid[33];      // 33 bytes
                        // = 44 bytes, no padding needed
};

// Calculate the memory footprint of each mode
constexpr size_t wifi_size = sizeof(MacRecord) * MAX_MACS;           
constexpr size_t ble_size = sizeof(BLERecord) * MAX_BLE_DEVICES;     
constexpr size_t ap_size = sizeof(ApRecord) * MAX_AP_RECORDS;        
constexpr size_t channel_size = sizeof(ChannelRecord) * MAX_CHANNEL_RECORDS; 
constexpr size_t leak_size = sizeof(LeakHistoryEntry) * MAX_LEAK_SLOTS;

// Dynamically determine the true union boundary
constexpr size_t max_size_1 = (ble_size > wifi_size) ? ble_size : wifi_size;
constexpr size_t max_size_2 = (ap_size > channel_size) ? ap_size : channel_size;
constexpr size_t max_size_3 = (leak_size > max_size_1) ? leak_size : max_size_1; 
constexpr size_t union_size = (max_size_3 > max_size_2) ? max_size_3 : max_size_2;

constexpr size_t static_non_union =
    (union_size * 3) +                                        // live + sort + session
    (sizeof(OUICache)          * OUI_CACHE_SIZE)      +
    (sizeof(ProbeRecordShared) * MAX_PROBE_SLOTS)     +
    (sizeof(SSIDNode)          * TOTAL_SSID_POOL)     +
    (sizeof(BeaconEntry)       * MAX_BEACON_DICT);

constexpr size_t osint_layer_size =
    (sizeof(ProbeRecordShared) * MAX_PROBE_SLOTS) +
    (sizeof(SSIDNode)          * TOTAL_SSID_POOL) +
    (sizeof(BeaconEntry)       * MAX_BEACON_DICT);

// Compile-time safety checks relative to the TRUE union boundary
static_assert(union_size >= wifi_size, "FATAL: Wi-Fi array exceeds union boundary.");
static_assert(union_size >= ble_size, "FATAL: BLE array exceeds union boundary.");
static_assert(union_size >= ap_size, "FATAL: AP array exceeds union boundary.");
static_assert(union_size >= channel_size, "FATAL: Channel array exceeds union boundary.");

// Persistent OSINT layer budget check
static_assert(osint_layer_size < 20480, 
    "FATAL: Persistent OSINT layer exceeds 20KB budget.");

// Total known static allocation
constexpr size_t SRAM_BUDGET = 327680;  // 320KB — conservative application budget
                                         // leaving ~200KB for WiFi/BLE/stack/heap

static_assert(static_non_union <= SRAM_BUDGET,
    "FATAL: Static allocations exceed conservative SRAM budget. "
    "Reduce array sizes.");

union LiveBuffer {
  volatile MacRecord liveData[MAX_MACS];
  volatile BLERecord liveBleData[MAX_BLE_DEVICES];
  volatile ApRecord liveApData[MAX_AP_RECORDS];
  volatile ChannelRecord liveChannelData[MAX_CHANNEL_RECORDS];
};
union SortBuffer {
  MacRecord sortData[MAX_MACS];
  BLERecord sortBleData[MAX_BLE_DEVICES];
  ApRecord sortApData[MAX_AP_RECORDS];
  ChannelRecord sortChannelData[MAX_CHANNEL_RECORDS];
};
union SessionBuffer {
  MacRecord sessionData[MAX_MACS];
  BLERecord sessionBleData[MAX_BLE_DEVICES];
  ApRecord sessionApData[MAX_AP_RECORDS];
  ChannelRecord sessionChannelData[MAX_CHANNEL_RECORDS];
  LeakHistoryEntry leakHistory[MAX_LEAK_SLOTS];
};
extern LiveBuffer liveBuf;
extern SortBuffer sortBuf;
extern SessionBuffer sessionBuf;

extern volatile MacRecord (&liveData)[MAX_MACS];
extern volatile BLERecord (&liveBleData)[MAX_BLE_DEVICES];
extern volatile ApRecord (&liveApData)[MAX_AP_RECORDS];
extern volatile ChannelRecord (&liveChannelData)[MAX_CHANNEL_RECORDS];
extern MacRecord (&sortData)[MAX_MACS];
extern BLERecord (&sortBleData)[MAX_BLE_DEVICES];
extern ApRecord (&sortApData)[MAX_AP_RECORDS];
extern ChannelRecord (&sortChannelData)[MAX_CHANNEL_RECORDS];
extern MacRecord (&sessionData)[MAX_MACS];
extern BLERecord (&sessionBleData)[MAX_BLE_DEVICES];
extern ApRecord (&sessionApData)[MAX_AP_RECORDS];
extern ChannelRecord (&sessionChannelData)[MAX_CHANNEL_RECORDS];
extern LeakHistoryEntry (&leakHistory)[MAX_LEAK_SLOTS];

extern volatile uint16_t liveMacCount;
extern volatile uint32_t liveOtherBytes;
extern volatile uint16_t liveBleCount;
extern volatile uint16_t liveApCount;
extern volatile uint16_t liveChannelCount;
extern uint16_t sortMacCount;
extern uint32_t sortOtherBytes;
extern uint16_t sortBleCount;
extern uint16_t sortApCount;
extern uint16_t sortChannelCount;
extern uint16_t sessionMacCount;
extern uint32_t sessionOtherBytes;
extern uint16_t sessionBleCount;
extern uint16_t sessionApCount;
extern uint16_t sessionChannelCount;

extern FlowRecord flow_cache[MAX_ACTIVE_FLOWS];
extern CryptoAlertCache crypto_cache[ALERT_CACHE_SIZE];
extern uint8_t crypto_cache_idx;

