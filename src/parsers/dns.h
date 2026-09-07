#pragma once
#include <stdint.h>
#include <stddef.h>

bool parse_dns_mdns(const uint8_t* payload, uint16_t length, bool is_mdns, char* out_text, size_t max_len);
bool parse_llmnr(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
