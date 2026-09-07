#pragma once
#include <Arduino.h>
#include <stddef.h>
#include <string>
#include <NimBLEDevice.h>
#include "core/wavehound_state.h"

extern BLEScan* pBLEScan;

double getBleSortMetric(BLERecord& record, BleSortMode mode);
void decodeEddystoneURL(const std::string& sData, char* outBuffer, size_t maxLen);
void processBleData();
