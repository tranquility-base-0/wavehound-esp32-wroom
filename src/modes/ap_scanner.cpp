#include "ap_scanner.h"
#include "core/radio.h"
#include <string.h>
#include <stdio.h>
BssidCacheEntry bssidCache[MAX_BSSID_CACHE];

int ap_current_page = 0;
const int APS_PER_PAGE = 6; // Number of APs that fit safely between the header and footer

BeaconEntry beaconDict[MAX_BEACON_DICT];
uint8_t beaconDictCount = 0;


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
