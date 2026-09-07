#pragma once
#include "core/wavehound_state.h"

extern int device_current_page;
extern const int DEVICES_PER_PAGE;

double getSortMetric(MacRecord& record, SortMode mode);
void processWifiData();
