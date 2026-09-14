#pragma once

#include "core/wavehound_state.h"

struct PcapPagination {
  int page_starts[MAX_LEAK_SLOTS]; // start valid_indices index of each page
  int valid_count;                 // occupied entries
};

// Shared dynamic PCAP pagination (rendered-height "snug" packing). Used by
// drawDeviceList() and handleTouchInputs() so the drawn NEXT -> button and the
// NEXT touch gate always agree.
PcapPagination computePcapPagination(int *valid_indices, int &valid_count,
                                     int &total_pages);

void drawMenu();
void drawApScanner();
void drawDeviceList();
void drawProbeTracker();
