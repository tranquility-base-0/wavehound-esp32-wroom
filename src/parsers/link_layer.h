#pragma once
#include <stdint.h>
#include <stddef.h>

bool parse_arp(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_icmpv4(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
const char* icmpv6_type_name(uint8_t type);
const char* icmpv6_code_name(uint8_t type, uint8_t code);
bool parse_icmpv6(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len, bool& is_high_value);
bool parse_eapol(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
