#include "ui_utils.h"
#include <Arduino.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "core/wavehound_state.h"
#include "modes/ble.h"
#include "modes/channel_scanner.h"

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

// ============================================================
// Shared insertion sort (see ui_utils.h for the semantics contract)
// ============================================================
namespace {
constexpr size_t max_s(size_t a, size_t b) { return (a > b) ? a : b; }
// Compile-time guard: the key scratch buffer must hold any record
// type routed through insertionSort(). A struct growth beyond this
// fails the build instead of silently corrupting sorts.
constexpr size_t kSortKeyBuf =
    max_s(sizeof(MacRecord),
          max_s(sizeof(BLERecord),
                max_s(sizeof(ApRecord), sizeof(ChannelRecord))));
} // namespace

void insertionSort(void* data, int count, size_t elem, int mode,
                   bool descending, SortMetricFn metric,
                   SortKeyValidFn key_valid) {
    if (data == nullptr || metric == nullptr || elem == 0 ||
        elem > kSortKeyBuf) {
        return;
    }
    uint8_t* base = (uint8_t*)data;
    uint8_t keybuf[kSortKeyBuf];

    for (int i = 1; i < count; i++) {
        memcpy(keybuf, base + (size_t)i * elem, elem);
        double key_val = metric(keybuf, mode);
        // Ascending validity guard (loop-invariant in the originals):
        // wifi/ap used key_val > 0.0 (key_valid == nullptr default),
        // BLE used key.hits > 0, channel used key_val != 0. When the
        // guard fails the original loop never shifted, so the key
        // stays in place — reproduced by skipping the shift loop.
        bool key_ok = key_valid ? key_valid(keybuf, key_val)
                                : (key_val > 0.0);
        int j = i - 1;

        if (descending) {
            while (j >= 0 &&
                   metric(base + (size_t)j * elem, mode) < key_val) {
                memcpy(base + (size_t)(j + 1) * elem,
                       base + (size_t)j * elem, elem);
                j--;
            }
        } else if (key_ok) {
            while (j >= 0 &&
                   metric(base + (size_t)j * elem, mode) > key_val) {
                memcpy(base + (size_t)(j + 1) * elem,
                       base + (size_t)j * elem, elem);
                j--;
            }
        }
        memcpy(base + (size_t)(j + 1) * elem, keybuf, elem);
    }
}

double cvPercentFromSums(uint64_t sum_bytes, uint64_t sum_sq_bytes,
                         uint32_t packets) {
    if (packets == 0) return 0.0;
    double mean = (double)sum_bytes / (double)packets;
    if (mean == 0.0) return 0.0;
    double variance =
        ((double)sum_sq_bytes / (double)packets) - (mean * mean);
    if (variance < 0.0) variance = 0.0;
    return (sqrt(variance) / mean) * 100.0;
}

double sortMetricBytesCommon(uint64_t sum_bytes, uint64_t sum_sq_bytes,
                             uint32_t packets, uint32_t tx_bytes,
                             uint32_t rx_bytes, float smoothedDistance,
                             uint32_t last_seen, int mode) {
    switch ((SortMode)mode) {
        case SORT_TOTAL:
            return (double)(tx_bytes + rx_bytes);
        case SORT_TX:
            return (double)tx_bytes;
        case SORT_RX:
            return (double)rx_bytes;
        case SORT_AVG:
            return (packets > 0) ? ((double)sum_bytes / packets) : 0.0;
        case SORT_CV:
            return cvPercentFromSums(sum_bytes, sum_sq_bytes, packets);
        case SORT_DIST:
            return (double)smoothedDistance;
        case SORT_AGE:
            return (double)last_seen;
    }
    return 0.0;
}

// --- Typed adapters for insertionSort() call sites ---

double uiSortMetricWifi(const void* rec, int mode) {
    const MacRecord& r = *(const MacRecord*)rec;
    return sortMetricBytesCommon(r.sum_bytes, r.sum_sq_bytes, r.packets,
                                 r.tx_bytes, r.rx_bytes,
                                 r.smoothedDistance, r.last_seen, mode);
}

double uiSortMetricAp(const void* rec, int mode) {
    const ApRecord& r = *(const ApRecord*)rec;
    return sortMetricBytesCommon(r.sum_bytes, r.sum_sq_bytes, r.packets,
                                 r.tx_bytes, r.rx_bytes,
                                 r.smoothedDistance, r.last_seen, mode);
}

double uiSortMetricBle(const void* rec, int mode) {
    return getBleSortMetric(*(BLERecord*)rec, (BleSortMode)mode);
}

bool uiSortKeyValidBle(const void* key, double /*key_val*/) {
    return ((const BLERecord*)key)->hits > 0;
}

double uiSortMetricChannel(const void* rec, int mode) {
    return getChannelMetric(*(const ChannelRecord*)rec, (SortMode)mode);
}

bool uiSortKeyValidChannel(const void* /*key*/, double key_val) {
    return key_val != 0;  // channel_scanner.cpp's original guard
}
