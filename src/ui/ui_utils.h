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
