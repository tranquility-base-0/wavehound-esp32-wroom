#include "channel_scanner.h"
#include "ui/ui_utils.h"
#include <string.h>
#include <cmath>
double getChannelMetric(ChannelRecord r, SortMode mode) {
  if (mode == SORT_TOTAL) return (double)(r.tx_bytes + r.rx_bytes);
  if (mode == SORT_TX) return (double)r.tx_bytes; // Downlink
  if (mode == SORT_RX) return (double)r.rx_bytes; // Uplink
  if (mode == SORT_AVG) return (r.packets > 0) ? (double)(r.sum_bytes / r.packets) : 0;
  if (mode == SORT_CV) {
    // Identical value semantics to cvPercentFromSums (verified):
    // packets==0 -> 0; mean==0 -> 0; variance<=0 -> 0 (sqrt(0)/mean
    // is also 0 in the generic form).
    return cvPercentFromSums(r.sum_bytes, r.sum_sq_bytes, r.packets);
  }
  // Repurposing SORT_DIST to sort by Power (Avg RSSI)
  if (mode == SORT_DIST) return (double)r.avg_rssi;

  return (double)(r.tx_bytes + r.rx_bytes); // Failsafe fallback
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
    insertionSort(sortChannelData, sortChannelCount, sizeof(ChannelRecord),
                  (int)currentSortMode, sort_descending,
                  uiSortMetricChannel, uiSortKeyValidChannel);

    // --- DYNAMIC INSERTION SORT: CHANNEL SESSION ---
    insertionSort(sessionChannelData, sessionChannelCount,
                  sizeof(ChannelRecord), (int)currentSortMode,
                  sort_descending, uiSortMetricChannel,
                  uiSortKeyValidChannel);

    sortOtherBytes = 0;
    for(int i = 6; i < sortChannelCount; i++) {
        sortOtherBytes += (sortChannelData[i].tx_bytes + sortChannelData[i].rx_bytes);
    }
}
