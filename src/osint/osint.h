#pragma once
#include <stdint.h>
#include <stddef.h>
#include "core/wavehound_state.h"

// probe tracker globals
extern ProbeSortMode currentProbeSortMode;
extern bool probe_sort_descending;
extern ProbeRecordShared probeList[MAX_PROBE_SLOTS];
extern SSIDNode ssidPool[TOTAL_SSID_POOL];
extern int probe_current_page;
extern const int PROBES_PER_PAGE;
extern int total_sniffed_probes;

bool isSameDevice(int idxA, int idxB);
uint8_t getSsidBitIndex(const char* ssid);
int crossReferenceProbeToBeacons(int probe_idx, uint8_t* matched_bssid_out, int8_t* ap_rssi_out);
double getProbeMetric(ProbeRecordShared record, ProbeSortMode mode);
void sortProbeList();
int addSsidToPool(const char* ssid, int head_idx, bool &already_exists, bool &added, uint8_t current_count);
void processProbeRequestShared(uint8_t* mac, const char* ssid, const char* known_vendor = "", int8_t rssi = -100, uint32_t hw_hash = 0);
void processPendingVendors();
void runProbeCorrelationEngine();
void initProbeTracker();
