#include "vendor.h"
#include <Arduino.h>
#include "core/wavehound_state.h"
#include "ble_oui.h"
#include "ble_appearance.h"
#include "ble_uuids.h"

SdFs sd;
OUICache vendorCache[OUI_CACHE_SIZE];
int cacheCount = 0;
int cacheHead = 0;

bool lookupVendorCache(
    const uint8_t* mac,
    char* vendor,
    size_t vendorSize
) {
    // Defensive argument validation
    if (mac == nullptr || vendor == nullptr || vendorSize == 0) {
        return false;
    }

    vendor[0] = '\0';

    // ==========================================
    // 0. SPECIAL MAC CLASSES
    // ==========================================

    // Broadcast
    if (mac[0] == 0xFF &&
        mac[1] == 0xFF &&
        mac[2] == 0xFF &&
        mac[3] == 0xFF &&
        mac[4] == 0xFF &&
        mac[5] == 0xFF) {

        strlcpy(vendor, "Bcast", vendorSize);
        return true;
    }

    // IPv6 multicast
    if (mac[0] == 0x33 &&
        mac[1] == 0x33) {

        strlcpy(vendor, "Mcast6", vendorSize);
        return true;
    }

    // IPv4 multicast
    if (mac[0] == 0x01 &&
        mac[1] == 0x00 &&
        mac[2] == 0x5E) {

        strlcpy(vendor, "Mcast4", vendorSize);
        return true;
    }

    // Locally administered / randomized
    if ((mac[0] & 0x02) != 0) {

        strlcpy(vendor, "<Random>", vendorSize);
        return true;
    }

    // ==========================================
    // 1. FAST OUI RAM CACHE
    // ==========================================

    for (int i = 0; i < cacheCount; i++) {

        if (vendorCache[i].oui[0] == mac[0] &&
            vendorCache[i].oui[1] == mac[1] &&
            vendorCache[i].oui[2] == mac[2]) {

            strlcpy(
                vendor,
                vendorCache[i].vendor,
                vendorSize
            );

            return true;
        }
    }

    // ==========================================
    // 2. NOT FOUND IN FAST CACHE
    //    IMPORTANT: NO SD ACCESS HERE
    // ==========================================

    return false;
}

void resolveMacVendor(MacRecord* record) {
  // If already resolved (e.g., via Information Elements "(IE)"), skip.
  if (record->vendorFound) return;

// 2. FAST PATH: RAM OUI CACHE / SPECIAL MAC CLASSES
if (lookupVendorCache(
        record->mac,
        record->vendor,
        sizeof(record->vendor))) {

    record->vendorFound = true;
    return;
}

  char target[7];
  snprintf(target, sizeof(target), "%02X%02X%02X", record->mac[0], record->mac[1], record->mac[2]);

  // 3. Binary Search the SD Card
  //    Fixed 32-byte records: missing/empty/mis-sized databases must fail
  //    safely instead of underflowing the record count and seeking past EOF.
  bool foundInDB = false;
  FsFile file = sd.open("/oui_db.txt", O_READ);
  if (file) {
    uint64_t db_size = file.fileSize();
    if (db_size > 0 && (db_size % 32) == 0) {
    uint32_t low = 0;
    uint32_t high = (uint32_t)((db_size / 32) - 1);

    while (low <= high) {
      uint32_t mid = low + (high - low) / 2;
      file.seek(mid * 32);
      char line[32];
      file.read(line, 32);
      char prefix[7];
      strncpy(prefix, line, 6);
      prefix[6] = '\0';

      int cmp = strcmp(target, prefix);
      if (cmp == 0) {
        // MATCH FOUND
        int text_start = 7;
        while(text_start < 32 && (line[text_start] == ' ' || line[text_start] == '\t')) {
          text_start++;
        }
        
        int available_chars = 32 - text_start;
        int max_capacity = sizeof(record->vendor) - 1;
        int copy_len = (available_chars < max_capacity) ? available_chars : max_capacity;
        
        strncpy(record->vendor, &line[text_start], copy_len); 
        record->vendor[copy_len] = '\0';
        
        for(int i = copy_len - 1; i >= 0; i--) {         
          if(record->vendor[i] == ' ' || record->vendor[i] == '\r' || record->vendor[i] == '\n') {
              record->vendor[i] = '\0';
          } else {
              break;
          }
        }
        foundInDB = true;
        break; 
      }
      else if (cmp < 0) {
        if (mid == 0) break;
        high = mid - 1;
      }
      else {
        low = mid + 1;
      }
    }
    }
    file.close();
  }

  // 4. Handle SD Card Miss (Fallback)
  if (!foundInDB) {
      strncpy(record->vendor, "Unknown", sizeof(record->vendor) - 1);
      record->vendor[sizeof(record->vendor) - 1] = '\0';
  }

  record->vendorFound = true; // Mark as found so we don't search SD again for "Unknown"

  // 5. Save to RAM Cache
  vendorCache[cacheHead].oui[0] = record->mac[0];
  vendorCache[cacheHead].oui[1] = record->mac[1];
  vendorCache[cacheHead].oui[2] = record->mac[2];
  
  // Cleaned up the magic number 26!
  strncpy(vendorCache[cacheHead].vendor, record->vendor, sizeof(vendorCache[cacheHead].vendor) - 1);
  vendorCache[cacheHead].vendor[sizeof(vendorCache[cacheHead].vendor) - 1] = '\0';
  
  if (cacheCount < OUI_CACHE_SIZE) cacheCount++;
  cacheHead = (cacheHead + 1) % OUI_CACHE_SIZE;
}

const char* resolveBleCompanyId(uint16_t companyId) {
  int left = 0;
  int right = numBleVendors - 1;

  while (left <= right) {
    int mid = left + (right - left) / 2;

    if (bleVendors[mid].id == companyId) {
      return bleVendors[mid].name; 
    }
    
    if (bleVendors[mid].id < companyId) {
      left = mid + 1; 
    } else {
      right = mid - 1; 
    }
  }
  return nullptr; // Use nullptr so the caller knows it failed
}

const char* resolveBleAppearance(uint16_t appearanceId) {
  // PASS 1: Search for the exact 16-bit ID
  int left = 0;
  int right = numBleAppearances - 1;

  while (left <= right) {
    int mid = left + (right - left) / 2;

    if (bleAppearances[mid].id == appearanceId) {
      return bleAppearances[mid].name; 
    }
    
    if (bleAppearances[mid].id < appearanceId) {
      left = mid + 1; 
    } else {
      right = mid - 1; 
    }
  }

  // PASS 2: Mask off the bottom 6 bits to search for Base Category
  uint16_t baseCategory = appearanceId & 0xFFC0;
  
  left = 0;
  right = numBleAppearances - 1;
  
  while (left <= right) {
    int mid = left + (right - left) / 2;

    if (bleAppearances[mid].id == baseCategory) {
      return bleAppearances[mid].name; 
    }
    
    if (bleAppearances[mid].id < baseCategory) {
      left = mid + 1; 
    } else {
      right = mid - 1; 
    }
  }
  
  return nullptr; 
}

const char* resolveBleMemberUuid(uint16_t targetId) {
  int left = 0;
  int right = numMemberUuids - 1;

  while (left <= right) {
    int mid = left + (right - left) / 2;

    if (memberUuids[mid].id == targetId) return memberUuids[mid].name;
    
    if (memberUuids[mid].id < targetId) left = mid + 1;
    else right = mid - 1;
  }
  return nullptr; 
}

const char* resolveBleServiceUuid(uint16_t targetId) {
  int left = 0;
  int right = numServiceUuids - 1;

  while (left <= right) {
    int mid = left + (right - left) / 2;

    if (serviceUuids[mid].id == targetId) return serviceUuids[mid].name;
    
    if (serviceUuids[mid].id < targetId) left = mid + 1;
    else right = mid - 1;
  }
  return nullptr; 
}

