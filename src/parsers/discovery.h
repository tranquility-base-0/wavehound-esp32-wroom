#pragma once
#include <stdint.h>
#include <stddef.h>

const char* getNetbiosSuffixStr(uint8_t suffixCode);
uint8_t decodeNetbiosName(const char* encoded, char* decodedName, size_t maxLen);
bool parse_netbios(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_nbds(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_ws_discovery(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_ssdp( const uint8_t* payload, uint16_t length, char* out_text, size_t max_len );
bool parse_lldp(const uint8_t* payload, uint16_t length, char* out_buf, size_t max_out);
bool parse_cdp(const uint8_t* payload, uint16_t length, char* out_buf, size_t max_out);
bool parse_socks(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_dropbox(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_ephemeral_upnp(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
