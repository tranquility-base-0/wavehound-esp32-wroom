#pragma once
#include <stdint.h>

void drawTelemetryHeader(uint32_t leaks, uint32_t enqueued, uint32_t attempted);
void drawChartHeader();
void drawChartFooter();
void drawPersistentTopN();
void drawTemporalLegend();
void drawWaterfallChart();
