#pragma once
#include <stdint.h>
#include <stddef.h>

constexpr uint16_t hex24to565(uint32_t hex24) {
  return ((((hex24 >> 16) & 0xFF) & 0xF8) << 8) |
  ((((hex24 >> 8) & 0xFF) & 0xFC) << 3) |
  (((hex24) & 0xFF) >> 3);
}

void getAgeString(uint32_t timestamp, char* buf, size_t len);
void cleanOsintString(char* s);
void formatShortUnit(uint32_t bytes, char* buf, size_t len);
void formatTotalUnit(uint32_t bytes, char* buf, size_t len);

// ============================================================
// Shared insertion sort (flash consolidation).
// Behavior-preserving extraction of the duplicated insertion-sort
// blocks (wifi/ble/ap/channel, snapshot+session, plus
// forceSessionSort). Ordering, tie behavior, and the ascending
// "skip zero-valued keys" guard are preserved exactly:
//   - descending: element metric < key_val  (no validity guard,
//     matching every original descending loop)
//   - ascending:  element metric > key_val, and the shift loop
//     only runs when key_valid(key, key_val) holds; key_valid
//     == nullptr means the original default guard (key_val > 0.0)
// Elements are moved with full-record memcpy, identical to the
// original struct-assignment shifts.
// ============================================================
typedef double (*SortMetricFn)(const void* rec, int mode);
typedef bool (*SortKeyValidFn)(const void* key, double key_val);
void insertionSort(void* data, int count, size_t elem, int mode,
                   bool descending, SortMetricFn metric,
                   SortKeyValidFn key_valid = nullptr);

// Mean/variance/CV of per-record byte statistics.
// Exactly reproduces the wifi/ap inline variant:
//   packets==0 -> 0; mean==0 -> 0; variance<0 clamped to 0;
//   (sqrt(variance)/mean)*100.
// The channel-scanner metric variant (variance<=0 || mean==0 -> 0)
// was verified to produce identical values for every input, so it
// shares this helper too.
double cvPercentFromSums(uint64_t sum_bytes, uint64_t sum_sq_bytes,
                         uint32_t packets);

// Shared metric core for records whose byte-statistics prefix is
// identical (MacRecord, ApRecord): TOTAL/TX/RX/AVG/CV/DIST/AGE.
// SORT_AVG keeps the original double division (not the channel
// scanner's integer division).
double sortMetricBytesCommon(uint64_t sum_bytes, uint64_t sum_sq_bytes,
                             uint32_t packets, uint32_t tx_bytes,
                             uint32_t rx_bytes, float smoothedDistance,
                             uint32_t last_seen, int mode);

// Typed adapters handed to insertionSort() at each call site.
double uiSortMetricWifi(const void* rec, int mode);
double uiSortMetricAp(const void* rec, int mode);
double uiSortMetricBle(const void* rec, int mode);
bool   uiSortKeyValidBle(const void* key, double key_val);
double uiSortMetricChannel(const void* rec, int mode);
bool   uiSortKeyValidChannel(const void* key, double key_val);
