#pragma once
#include <stdint.h>
#include <stddef.h>
#include "esp_wifi.h"

#define MAX_LEAK_STR_LEN 512

const char* getSubtypeStr(uint8_t subtype);
const char* getDirectionStr(uint8_t dir);
const char* getProtocolStr(uint8_t proto);
void getIpString(uint8_t version, const uint8_t* ip_bytes, char* out_str, size_t max_len);
uint32_t hash_flow(const uint8_t* data, size_t len, uint16_t sport, uint16_t dport);
uint8_t getBitrateMbps(wifi_promiscuous_pkt_t *pkt);
bool extract_printable_runs(const uint8_t* data, uint16_t len, char* out, size_t max_len, uint8_t min_run = 4, bool flatten_ws = false, const char* separator = "|");
void translateProtocolStrings(char* text);
int copy_printable_ascii(const uint8_t* src, int len, char* dst, int max_len);
void format_ipv6_addr(const uint8_t* ip, char* buf, size_t max_len);
int decode_dns_name(const uint8_t* payload, int end_offset, int offset, char* out_name, int max_name_len);
void format_reverse_lookups(char* text, size_t max_len);
void compress_ipv6(const char* full, char* out, size_t out_size);
void trim_ascii(char* s);
bool extract_xml_value(const char* p, uint16_t length, const char* tag_suffix, char* out_buf, size_t max_out);
bool extract_json_val(const char* payload, uint16_t len, const char* key, char* out, size_t out_max);
bool extract_nested_json_val(const char* json, uint16_t json_len, const char* outer_key, const char* inner_key, char* out, size_t out_max);
bool looks_like_json(const char* s, uint16_t len);
int decode_dns_search_list(const uint8_t* data, int data_len, char* out, int max_len);
