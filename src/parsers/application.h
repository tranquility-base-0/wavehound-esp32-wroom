#pragma once
#include <stdint.h>
#include <stddef.h>

bool parse_dhcp_v4(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_dhcp_v6(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_ipp(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_syslog(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_rtsp(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_ftp(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_telnet(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_tftp(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_smtp(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
bool parse_smb(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len);
