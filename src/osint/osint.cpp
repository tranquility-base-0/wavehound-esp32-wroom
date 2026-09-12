#include "osint.h"
#include "core/radio.h"
#include "core/rf_utils.h"
#include "osint/vendor.h"
#include "modes/ap_scanner.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

ProbeSortMode currentProbeSortMode = PROBE_SORT_HITS;
bool probe_sort_descending = true;
ProbeRecordShared probeList[MAX_PROBE_SLOTS];
SSIDNode ssidPool[TOTAL_SSID_POOL];
int probe_current_page = 0; 
const int PROBES_PER_PAGE = 5;
int total_sniffed_probes = 0;
// File-local helper: exact SSID-history confirmation for isSameDevice().
// Walks the two records' first_ssid_idx -> ssidPool linked lists and returns
// true if at least one exact common SSID exists. Wildcard entries are skipped
// consistently with crossReferenceProbeToBeacons()'s matching convention.
// Worst case: EMERGENCY_CUTOFF x EMERGENCY_CUTOFF = 225 strcmp per pair.
static bool exact_ssid_lists_intersect(int idxA, int idxB) {
    int nodeA = probeList[idxA].first_ssid_idx;

    while (nodeA != -1) {
        // Skip wildcard/sentinel entries (same convention as
        // crossReferenceProbeToBeacons, osint.cpp)
        if (ssidPool[nodeA].text[0] != '\0' &&
            strcmp(ssidPool[nodeA].text, "<Wld>") != 0 &&
            strcmp(ssidPool[nodeA].text, "<Nul>") != 0) {

            int nodeB = probeList[idxB].first_ssid_idx;

            while (nodeB != -1) {
                if (ssidPool[nodeB].text[0] != '\0' &&
                    strcmp(ssidPool[nodeB].text, "<Wld>") != 0 &&
                    strcmp(ssidPool[nodeB].text, "<Nul>") != 0 &&
                    strcmp(ssidPool[nodeA].text, ssidPool[nodeB].text) == 0) {
                    return true; // At least one exact common SSID
                }
                nodeB = ssidPool[nodeB].next_node_idx;
            }
        }

        nodeA = ssidPool[nodeA].next_node_idx;
    }

    return false;
}

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
        // Step 6 tightening: +30 only with evidence. Both bitmaps must be
        // non-zero (an empty bitmap proves nothing), and the containment
        // claim must be confirmed by at least one exact common SSID in the
        // existing first_ssid_idx -> ssidPool histories.
        if (hashA != 0 && hashB != 0 && exact_ssid_lists_intersect(idxA, idxB)) {
            confidence_score += 30; // Perfect subset match (exact-confirmed)
        }
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
    pause_sniffing = true;
    delay(10);

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

    pause_sniffing = false;
}
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
void runProbeCorrelationEngine() {
    static unsigned long last_correlation_run = 0;
    
    if (millis() - last_correlation_run > 5000) { 
        last_correlation_run = millis();
        
        pause_sniffing = true;
        delay(10);

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

        pause_sniffing = false;
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
