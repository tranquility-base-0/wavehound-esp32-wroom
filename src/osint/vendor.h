#pragma once
#include <stdint.h>
#include <stddef.h>
#include "SdFat.h"

struct MacRecord;  // defined in core/wavehound_state.h

extern SdFs sd;

bool lookupVendorCache(const uint8_t* mac, char* vendor, size_t vendorSize);
void resolveMacVendor(MacRecord* record);
const char* resolveBleCompanyId(uint16_t companyId);
const char* resolveBleAppearance(uint16_t appearanceId);
const char* resolveBleMemberUuid(uint16_t targetId);
const char* resolveBleServiceUuid(uint16_t targetId);

