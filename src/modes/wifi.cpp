#include "wifi.h"
#include "osint/vendor.h"
#include <string.h>
int device_current_page = 0;
const int DEVICES_PER_PAGE = 13; // 9pt font with 18px line spacing fits 13 devices perfectly
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
