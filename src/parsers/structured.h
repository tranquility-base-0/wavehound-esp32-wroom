#pragma once
#include <stdint.h>
#include <stddef.h>

bool parse_mqtt(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len, bool& is_high_value);
bool parse_coap(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_snmp(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_generic_json(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
