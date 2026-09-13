#include "ble.h"
#include "osint/vendor.h"
#include "core/rf_utils.h"
#include <string.h>
#include <NimBLEDevice.h>
BLEScan* pBLEScan;
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
