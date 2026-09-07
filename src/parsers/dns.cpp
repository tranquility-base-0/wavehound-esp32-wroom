#include <Arduino.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <algorithm>
#include "parser_common.h"
#include "dns.h"

bool parse_dns_mdns(const uint8_t* payload, uint16_t length, bool is_mdns, char* out_text, size_t max_len) {
    if (length < 12) return false; 

    bool is_response = (payload[2] & 0x80) != 0;
    
    uint16_t qdcount = (payload[4] << 8) | payload[5];
    uint16_t ancount = (payload[6] << 8) | payload[7];
    uint16_t nscount = (payload[8] << 8) | payload[9];
    uint16_t arcount = (payload[10] << 8) | payload[11];

    char domains[MAX_LEAK_STR_LEN] = {0};
    int d_idx = 0;
    int valid_labels = 0;

    // CHANGED: process_name() replaced with a thin wrapper around
    // decode_dns_name(). This lambda keeps the same "append to shared
    // domains[] buffer" responsibility process_name used to have, but the
    // actual wire-walking/pointer-following is now in decode_dns_name().
    auto append_dns_name = [&](int start_offset) -> int {
    char name_buf[192];
    int result_offset = decode_dns_name(payload, length, start_offset, name_buf, sizeof(name_buf));

    if (result_offset < 0) {
        return -1;
    }

    int name_len = strlen(name_buf);
    if (name_len > 0 && d_idx + name_len + 3 < (int)sizeof(domains)) {
        if (valid_labels > 0) {
            domains[d_idx++] = ',';
            domains[d_idx++] = ' ';
        }
        memcpy(&domains[d_idx], name_buf, name_len);
        d_idx += name_len;
        valid_labels++;
    }

    return result_offset;
};


    int offset = 12;

    // 1. Process Questions
    for (int i = 0; i < qdcount && offset < length; i++) {
    offset = append_dns_name(offset);
    if (offset < 0) break;

    if (offset + 4 > length) {
        offset = length;
        break;
    }

    offset += 4;
    }

    // 2. Process Answers, Authorities, and Additionals
    int total_answers = ancount + nscount + arcount;
    for (int i = 0; i < total_answers && offset < length; i++) {
        offset = append_dns_name(offset);  // CHANGED
        
        if (offset + 10 <= length) {
            uint16_t rr_type = (payload[offset] << 8) | payload[offset+1];
            uint16_t rdlength = (payload[offset+8] << 8) | payload[offset+9];
            
            offset += 10;
            
            if (offset + rdlength > length) break;
            
            if (rr_type == 16) { // TXT — unchanged
                int txt_off = offset;
                int txt_end = offset + rdlength;
                
                while (txt_off < txt_end) {
                    uint8_t txt_len = payload[txt_off];
                    if (txt_off + 1 + txt_len > txt_end) break;
                    
                    bool is_printable = true;
                    for (int j = 0; j < txt_len; j++) {
                        uint8_t c = payload[txt_off + 1 + j];
                        if (c < 32 || c == 127) {
                            is_printable = false;
                            break;
                        }
                    }
                    
                    if (is_printable && txt_len > 0) {
                        if (d_idx + txt_len + 3 < sizeof(domains)) {
                            if (valid_labels > 0) {
                                domains[d_idx++] = ','; 
                                domains[d_idx++] = ' ';
                            }
                            memcpy(&domains[d_idx], &payload[txt_off+1], txt_len);
                            d_idx += txt_len;
                            valid_labels++;
                        }
                    }
                    txt_off += 1 + txt_len; 
                }
            }
            else if (rr_type == 1 && rdlength == 4) { // A — unchanged
                char ip_str[32];
                snprintf(ip_str, sizeof(ip_str), "[IP: %d.%d.%d.%d]", 
                         payload[offset], payload[offset+1], payload[offset+2], payload[offset+3]);
                int ip_len = strlen(ip_str);
                
                if (d_idx + ip_len + 3 < sizeof(domains)) {
                    if (valid_labels > 0) {
                        domains[d_idx++] = ','; 
                        domains[d_idx++] = ' ';
                    }
                    memcpy(&domains[d_idx], ip_str, ip_len);
                    d_idx += ip_len;
                    valid_labels++;
                }
            }
            // NEW: AAAA / IPv6
            else if (rr_type == 28 && rdlength == 16) {
                char raw_ip6[48];
                getIpString(6, &payload[offset], raw_ip6, sizeof(raw_ip6));

                char compressed_ip6[48];
                compress_ipv6(raw_ip6, compressed_ip6, sizeof(compressed_ip6));

                char out_str[56];
                snprintf(out_str, sizeof(out_str), "[IPv6: %s]", compressed_ip6);
                int out_len = strlen(out_str);

                if (d_idx + out_len + 3 < (int)sizeof(domains)) {
                    if (valid_labels > 0) { domains[d_idx++] = ','; domains[d_idx++] = ' '; }
                    memcpy(&domains[d_idx], out_str, out_len);
                    d_idx += out_len;
                    valid_labels++;
                }
            }
            else if (rr_type == 12 || rr_type == 5) { // PTR / CNAME
                append_dns_name(offset);  // CHANGED — return value still discarded, same as original
            }
            else if (rr_type == 33 && rdlength >= 7) { // SRV
                uint16_t srv_port = (payload[offset+4] << 8) | payload[offset+5];
                char port_str[32];
                snprintf(port_str, sizeof(port_str), "[Port: %u]", srv_port);
                int p_len = strlen(port_str);
                
                if (d_idx + p_len + 3 < sizeof(domains)) {
                    if (valid_labels > 0) {
                        domains[d_idx++] = ','; 
                        domains[d_idx++] = ' ';
                    }
                    memcpy(&domains[d_idx], port_str, p_len);
                    d_idx += p_len;
                    valid_labels++;
                }
                append_dns_name(offset + 6);  // CHANGED
            }

            offset += rdlength; 
        } else {
            break;
        }
    }

    domains[d_idx] = '\0';

    if (valid_labels > 0) {
        snprintf(out_text, max_len, "%s %s: %s", is_mdns ? "mDNS" : "DNS", is_response ? "Ans" : "Qry", domains);
        return true;
    }

    // 3. Salvaged TXT Record Sweeper — unchanged
    if (is_mdns) {
        int best_score = 0, best_s = 0, best_l = 0;
        int cur_s = 0, cur_l = 0;
        bool has_equals = false;

        for (int i = 12; i < length; i++) {
            char c = payload[i];
            if (c >= 32 && c <= 126) { 
                if (cur_l == 0) cur_s = i;
                if (c == '=') has_equals = true;
                cur_l++;
            } else {
                if (cur_l > 0) {
                    int cur_score = cur_l + (has_equals ? 15 : 0);
                    if (cur_score > best_score) {
                        best_score = cur_score; best_l = cur_l; best_s = cur_s;
                    }
                }
                cur_l = 0;
                has_equals = false;
            }
        }
        
        if (cur_l > 0) { 
            int cur_score = cur_l + (has_equals ? 15 : 0);
            if (cur_score > best_score) {
                best_score = cur_score; best_l = cur_l; best_s = cur_s;
            }
        }

        if (best_l >= 6 && best_score >= 15) {
            int copy_len = std::min(best_l, (int)max_len - 15);
            snprintf(out_text, max_len, "mDNS TXT: %.*s", copy_len, &payload[best_s]);
            return true;
        }
    }

    return false;
}

bool parse_llmnr(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    // Defensive entry guard
    if (length < 12 || payload == nullptr || out_text == nullptr || max_len < 30) {
        return false; 
    }

    uint16_t flags = (payload[2] << 8) | payload[3];
    bool is_response = (flags & 0x8000) != 0; // Check the QR bit (Query vs Response)
    uint16_t qdcount = (payload[4] << 8) | payload[5];

    // We primarily care about the Question section (what name are they looking for?)
    if (qdcount > 0) {
        char domain[80] = {0};
        int d_idx = 0;
        int i = 12; // Start immediately after header
        
        // SAFE SLIDING WINDOW
        while (i < length && payload[i] != 0x00) {
            uint8_t label_len = payload[i];
            
            // Abort on compression pointer (0xC0) to prevent infinite loops
            if ((label_len & 0xC0) == 0xC0) {
                break; 
            }

            // 1. Verify label doesn't exceed the packet payload
            if (label_len > 0 && label_len <= 63 && (i + 1 + label_len) <= length) {
                
                // 2. Verify label won't overflow our local domain buffer!
                if (d_idx + label_len + 1 >= sizeof(domain)) {
                    break;
                }
                
                if (d_idx > 0) domain[d_idx++] = '.';
                memcpy(&domain[d_idx], &payload[i + 1], label_len);
                d_idx += label_len;
                i += label_len + 1;
            } else {
                break;
            }
        }
        domain[d_idx] = '\0';

        if (d_idx > 0) {
            const char* type_str = is_response ? "Reply" : "Query";
            snprintf(out_text, max_len, "LLMNR [%s] Tgt: %s", type_str, domain);
            
            // Retained your original formatting call
            format_reverse_lookups(out_text, max_len);
            
            return true;
        }
    }
    return false;
}

