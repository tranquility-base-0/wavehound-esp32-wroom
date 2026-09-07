#pragma once
#include <stdint.h>
#include <stddef.h>

bool parse_http_host( const uint8_t* payload, uint16_t length, char* out_text, size_t max_len );
bool parse_tls_cert(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_tls_sni(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_ssh(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_rdp(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
