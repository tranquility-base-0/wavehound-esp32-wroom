#pragma once
#include "core/wavehound_state.h"

extern BssidCacheEntry bssidCache[MAX_BSSID_CACHE];
extern int ap_current_page;
extern const int APS_PER_PAGE;
extern BeaconEntry beaconDict[MAX_BEACON_DICT];
extern uint8_t beaconDictCount;

void ingestBeacon(uint8_t* bssid, const char* ssid, int8_t rssi);
double getSortMetric(ApRecord& record, SortMode mode);
void processApData();
