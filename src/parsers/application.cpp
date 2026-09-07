#include <Arduino.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <algorithm>
#include "parser_common.h"
#include "application.h"

bool parse_dhcp_v4(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    if (!payload || !out_text || max_len == 0 || length < 240) return false;
    
    if (payload[236] == 0x63 && payload[237] == 0x82 && 
        payload[238] == 0x53 && payload[239] == 0x63) {
        
        int offset = 240;
        char msg_type_str[16] = "UNK";
        
        char best_text[128] = {0};
        char dns_str[96] = {0};
        int current_priority = 99; 

        while (offset < length && payload[offset] != 255) {
            uint8_t opt_type = payload[offset];
            if (opt_type == 0) { offset++; continue; } 
            
            if (offset + 1 >= length) break;
            uint8_t opt_len = payload[offset + 1];
            if (offset + 2 + opt_len > length) break; 
            
            int opt_data = offset + 2;
            int this_priority = 99;
            char temp_buf[128] = {0};

            if (opt_type == 53 && opt_len == 1) {
                switch (payload[opt_data]) {
                    case 1: strlcpy(msg_type_str, "DISCOVER", sizeof(msg_type_str)); break;
                    case 2: strlcpy(msg_type_str, "OFFER", sizeof(msg_type_str)); break;
                    case 3: strlcpy(msg_type_str, "REQUEST", sizeof(msg_type_str)); break;
                    case 4: strlcpy(msg_type_str, "DECLINE", sizeof(msg_type_str)); break;
                    case 5: strlcpy(msg_type_str, "ACK", sizeof(msg_type_str)); break;
                    case 6: strlcpy(msg_type_str, "NAK", sizeof(msg_type_str)); break;
                    case 7: strlcpy(msg_type_str, "RELEASE", sizeof(msg_type_str)); break;
                    case 8: strlcpy(msg_type_str, "INFORM", sizeof(msg_type_str)); break;
                    default: snprintf(msg_type_str, sizeof(msg_type_str), "?%d", payload[opt_data]); break;
                }
            }
            else if (opt_type == 6 && opt_len >= 4 && (opt_len % 4 == 0)) {
                int dns_idx = 0;
                dns_idx += snprintf(dns_str, sizeof(dns_str), "DNS: ");
                for (int i = 0; i < opt_len; i += 4) {
                    if (dns_idx > 5 && dns_idx < (int)sizeof(dns_str) - 2) dns_str[dns_idx++] = ',';
                    if (dns_idx > (int)sizeof(dns_str) - 16) break; // Capacity safety
                    dns_idx += snprintf(dns_str + dns_idx, sizeof(dns_str) - dns_idx, "%d.%d.%d.%d",
                                        payload[opt_data + i], payload[opt_data + i + 1],
                                        payload[opt_data + i + 2], payload[opt_data + i + 3]);
                }
            }
            else if (opt_type == 81 && opt_len > 3) { 
                char fqdn_buf[64] = {0};
                int res = decode_dns_name(payload, opt_data + opt_len, opt_data + 3, fqdn_buf, sizeof(fqdn_buf));
                if (res >= 0 && fqdn_buf[0] != '\0') {
                    this_priority = 1;
                    snprintf(temp_buf, sizeof(temp_buf), "FQDN: %s", fqdn_buf);
                }
            }
            else if (opt_type == 12 && opt_len > 0) { 
                this_priority = 2; 
                snprintf(temp_buf, sizeof(temp_buf), "Host: ");
                copy_printable_ascii(&payload[opt_data], opt_len, temp_buf + 6, sizeof(temp_buf) - 6);
            }
            else if (opt_type == 60 && opt_len > 0) { 
                this_priority = 3; 
                snprintf(temp_buf, sizeof(temp_buf), "Vendor: ");
                copy_printable_ascii(&payload[opt_data], opt_len, temp_buf + 8, sizeof(temp_buf) - 8);
            }
            else if (opt_type == 61 && opt_len > 1) { 
                this_priority = 4;
                snprintf(temp_buf, sizeof(temp_buf), "ClientID: ");
                int out_idx = 10;
                for (int i = 1; i < opt_len && out_idx < (int)sizeof(temp_buf) - 3; i++) {
                    out_idx += snprintf(temp_buf + out_idx, sizeof(temp_buf) - out_idx, "%02X", payload[opt_data + i]);
                }
            }
            else if (opt_type == 55 && opt_len > 0) { 
                this_priority = 5;
                snprintf(temp_buf, sizeof(temp_buf), "PRL: ");
                int out_idx = 5;
                for (int i = 0; i < opt_len && out_idx < (int)sizeof(temp_buf) - 4; i++) {
                    out_idx += snprintf(temp_buf + out_idx, sizeof(temp_buf) - out_idx, "%d,", payload[opt_data + i]);
                }
                if (out_idx > 5) temp_buf[out_idx - 1] = '\0'; 
            }
            
            if (this_priority < current_priority && temp_buf[0] != '\0') {
                current_priority = this_priority;
                strlcpy(best_text, temp_buf, sizeof(best_text));
            }
            offset += 2 + opt_len;
        }

        // Always return true for a valid DHCP packet, even if it lacks text
        int written = snprintf(out_text, max_len, "DHCP [%s]", msg_type_str);
        if (best_text[0] != '\0' && written < (int)max_len) {
            written += snprintf(out_text + written, max_len - written, " %s", best_text);
        }
        if (dns_str[0] != '\0' && written < (int)max_len) {
            written += snprintf(out_text + written, max_len - written, " %s", dns_str);
        }
        return true;
    }
    return false;
}

bool parse_dhcp_v6(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    if (!payload || !out_text || max_len == 0 || length < 4) return false; 
    
    uint8_t msg_type = payload[0];
    char msg_type_str[16] = "UNK";
    
    switch (msg_type) {
        case 1:  strlcpy(msg_type_str, "SOLICIT", sizeof(msg_type_str)); break;
        case 2:  strlcpy(msg_type_str, "ADVERT", sizeof(msg_type_str)); break;
        case 3:  strlcpy(msg_type_str, "REQUEST", sizeof(msg_type_str)); break;
        case 4:  strlcpy(msg_type_str, "CONFIRM", sizeof(msg_type_str)); break;
        case 5:  strlcpy(msg_type_str, "RENEW", sizeof(msg_type_str)); break;
        case 6:  strlcpy(msg_type_str, "REBIND", sizeof(msg_type_str)); break;
        case 7:  strlcpy(msg_type_str, "REPLY", sizeof(msg_type_str)); break;
        case 8:  strlcpy(msg_type_str, "RELEASE", sizeof(msg_type_str)); break;
        case 9:  strlcpy(msg_type_str, "DECLINE", sizeof(msg_type_str)); break;
        case 10: strlcpy(msg_type_str, "RECONFIG", sizeof(msg_type_str)); break;
        case 11: strlcpy(msg_type_str, "INFO-REQ", sizeof(msg_type_str)); break;
        case 12: strlcpy(msg_type_str, "RELAY-FWD", sizeof(msg_type_str)); break;
        case 13: strlcpy(msg_type_str, "RELAY-REP", sizeof(msg_type_str)); break;
        default: snprintf(msg_type_str, sizeof(msg_type_str), "?%d", msg_type); break;
    }

    // Short-circuit Relays: Do not parse outer options to avoid polluting fingerprint
    if (msg_type == 12 || msg_type == 13) {
        snprintf(out_text, max_len, "DHCPv6 [%s]", msg_type_str);
        return true;
    }

    int offset = 4;
    int current_priority = 99;
    char best_text[128] = {0};
    char dns_str[128] = {0};

    while (offset + 4 <= length) {
        uint16_t opt_code = (payload[offset] << 8) | payload[offset + 1];
        uint16_t opt_len = (payload[offset + 2] << 8) | payload[offset + 3];
        offset += 4;
        
        if (offset + opt_len > length) break; 
        
        int opt_data = offset;
        int this_priority = 99;
        char temp_buf[128] = {0};

        if (opt_code == 39 && opt_len > 1) { 
            char fqdn_buf[64] = {0};
            int res = decode_dns_name(payload, opt_data + opt_len, opt_data + 1, fqdn_buf, sizeof(fqdn_buf));
            if (res >= 0 && fqdn_buf[0] != '\0') {
                this_priority = 1;
                snprintf(temp_buf, sizeof(temp_buf), "FQDN: %s", fqdn_buf);
            }
        }
        else if (opt_code == 16 && opt_len > 4) { // Option 16: Structured Vendor Class
            this_priority = 2; 
            snprintf(temp_buf, sizeof(temp_buf), "Vendor: ");
            int out_idx = 8;
            int v_off = 4; // Skip 4-byte enterprise ID
            
            while (v_off + 2 <= opt_len) {
                uint16_t v_len = (payload[opt_data + v_off] << 8) | payload[opt_data + v_off + 1];
                v_off += 2;
                if (v_off + v_len > opt_len) break; // Truncated class data
                
                if (out_idx > 8 && out_idx < (int)sizeof(temp_buf) - 2) temp_buf[out_idx++] = ' ';
                out_idx += copy_printable_ascii(&payload[opt_data + v_off], v_len, temp_buf + out_idx, sizeof(temp_buf) - out_idx);
                v_off += v_len;
            }
        }
        else if (opt_code == 1 && opt_len > 0) { 
            this_priority = 3;
            snprintf(temp_buf, sizeof(temp_buf), "DUID: ");
            int out_idx = 6;
            for (int i = 0; i < opt_len && out_idx < (int)sizeof(temp_buf) - 3; i++) {
                out_idx += snprintf(temp_buf + out_idx, sizeof(temp_buf) - out_idx, "%02X", payload[opt_data + i]);
            }
        }
        else if (opt_code == 23 && opt_len >= 16 && (opt_len % 16 == 0)) { // Option 23: DNS Servers
            int dns_idx = 0;
            dns_idx += snprintf(dns_str, sizeof(dns_str), "DNS: ");
            for (int i = 0; i < opt_len; i += 16) {
                if (dns_idx > 5) dns_str[dns_idx++] = ',';
                if (dns_idx > (int)sizeof(dns_str) - 40) break; // Capacity safety
                
                char ip_buf[40];
                format_ipv6_addr(&payload[opt_data + i], ip_buf, sizeof(ip_buf));
                dns_idx += snprintf(dns_str + dns_idx, sizeof(dns_str) - dns_idx, "%s", ip_buf);
            }
        }

        if (this_priority < current_priority && temp_buf[0] != '\0') {
            current_priority = this_priority;
            strlcpy(best_text, temp_buf, sizeof(best_text));
        }
        offset += opt_len; 
    }

    int written = snprintf(out_text, max_len, "DHCPv6 [%s]", msg_type_str);
    if (best_text[0] != '\0' && written < (int)max_len) {
        written += snprintf(out_text + written, max_len - written, " %s", best_text);
    }
    if (dns_str[0] != '\0' && written < (int)max_len) {
        written += snprintf(out_text + written, max_len - written, " %s", dns_str);
    }
    return true;
}

bool parse_ipp(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    if (!payload || !out_text || max_len == 0 || length < 8) return false;

    out_text[0] = '\0';
    size_t pos = 0;

    auto append_fmt = [&](const char* fmt, ...) -> bool {
        if (pos >= max_len) return false;
        va_list args;
        va_start(args, fmt);
        int written = vsnprintf(out_text + pos, max_len - pos, fmt, args);
        va_end(args);
        
        if (written < 0 || (size_t)written >= max_len - pos) {
            out_text[max_len - 1] = '\0';
            return false;
        }
        pos += (size_t)written;
        return true;
    };

    // 1. Handle initial HTTP POST negotiation on Port 631
    if (length >= 5 && memcmp(payload, "POST ", 5) == 0) {
        return append_fmt("IPP/CUPS: Print Job Initiated (HTTP POST)");
    }

    // 2. IPP Header Validation (Version + Opcode Plausibility)
    uint8_t major_version = payload[0];
    uint8_t minor_version = payload[1];
    
    if ((major_version != 1 && major_version != 2) || minor_version > 2) {
        return false;
    }
    
    // Basic Opcode/Status check: valid codes are never 0x0000 or 0xFFFF
    uint16_t op_status = (payload[2] << 8) | payload[3];
    if (op_status == 0x0000 || op_status == 0xFFFF) return false;

    uint16_t offset = 8; // Skip Version (2), Operation/Status (2), Request ID (4)
    
    char user[32] = {0};
    char doc[64]  = {0};
    bool found_user = false;
    bool found_doc  = false;
    bool malformed  = false;

    // 3. Strict TLV Walk
    while (offset < length) {
        uint8_t tag = payload[offset++];
        
        // End-of-attributes
        if (tag == 0x03) break; 
        
        // Explicitly handle known group delimiter tags
        if (tag == 0x01 || tag == 0x02 || tag == 0x04 || tag == 0x05 || tag == 0x06) {
            continue; 
        }
        
        // Ensure space for Name Length (2 bytes)
        if (length - offset < 2) { malformed = true; break; }
        uint16_t name_len = (payload[offset] << 8) | payload[offset + 1];
        offset += 2;
        
        // Ensure space for Name string
        if (length - offset < name_len) { malformed = true; break; }
        const uint8_t* name_ptr = &payload[offset];
        offset += name_len;
        
        // Ensure space for Value Length (2 bytes)
        if (length - offset < 2) { malformed = true; break; }
        uint16_t val_len = (payload[offset] << 8) | payload[offset + 1];
        offset += 2;
        
        // Ensure space for Value payload
        if (length - offset < val_len) { malformed = true; break; }
        const uint8_t* val_ptr = &payload[offset];
        offset += val_len;

        // 4. Extract Target Attributes (with ASCII sanitization)
        if (name_len == 20 && memcmp(name_ptr, "requesting-user-name", 20) == 0) {
            size_t copy_len = std::min((size_t)val_len, sizeof(user) - 1);
            for (size_t j = 0; j < copy_len; j++) {
                uint8_t c = val_ptr[j];
                user[j] = (c >= 32 && c <= 126) ? (char)c : '.';
            }
            user[copy_len] = '\0';
            found_user = true;
        } 
        else if (name_len == 13 && memcmp(name_ptr, "document-name", 13) == 0) {
            size_t copy_len = std::min((size_t)val_len, sizeof(doc) - 1);
            for (size_t j = 0; j < copy_len; j++) {
                uint8_t c = val_ptr[j];
                doc[j] = (c >= 32 && c <= 126) ? (char)c : '.';
            }
            doc[copy_len] = '\0';
            found_doc = true;
        }
    }

    // 5. Build Final Output (Reject completely if structural bounds were violated)
    if (malformed) return false;

    if (found_user && found_doc) {
        return append_fmt("IPP Print: %s -> '%s'", user, doc);
    } else if (found_doc) {
        return append_fmt("IPP Print: doc '%s'", doc);
    } else if (found_user) {
        return append_fmt("IPP Print: user '%s'", user);
    }

    return false;
}

bool parse_syslog(const uint8_t* payload,
                         uint16_t length,
                         char* out_text,
                         size_t max_len)
{
    if (!payload || !out_text || max_len < 10 || length < 2)
        return false;

    out_text[0] = '\0';

    uint16_t start_idx = 0;
    bool valid_pri = false;

    // ---------------------------------------------------------
    // Optional RFC 3164 / RFC 5424 PRI: <0> ... <191>
    // ---------------------------------------------------------
    if (payload[0] == '<') {
        uint16_t pri = 0;
        uint8_t digits = 0;
        uint16_t i = 1;

        while (i < length && digits < 3 &&
               payload[i] >= '0' && payload[i] <= '9') {

            pri = (uint16_t)(pri * 10 + (payload[i] - '0'));
            digits++;
            i++;
        }

        if (digits > 0 && i < length && payload[i] == '>' && pri <= 191) {
            valid_pri = true;
            start_idx = i + 1;
        }
    }

    // ---------------------------------------------------------
    // If there's no valid PRI, don't immediately reject:
    // some implementations emit syslog-like plaintext without it.
    // But require enough printable content below.
    // ---------------------------------------------------------

    char clean_log[96] = {0};
    size_t write_idx = 0;

    for (uint16_t i = start_idx;
         i < length && write_idx < sizeof(clean_log) - 1;
         i++) {

        uint8_t c = payload[i];

        // End of syslog line
        if (c == '\r' || c == '\n')
            break;

        // Flatten tabs for single-line UI
        if (c == '\t') {
            clean_log[write_idx++] = ' ';
        }
        // Printable ASCII
        else if (c >= 32 && c <= 126) {
            clean_log[write_idx++] = (char)c;
        }
        // Ignore other binary/control bytes
    }

    if (write_idx == 0)
        return false;

    clean_log[write_idx] = '\0';

    // ---------------------------------------------------------
    // Atomic output construction
    // ---------------------------------------------------------

    const char* prefix = valid_pri ? "Syslog: " : "Syslog?: ";

    int written = snprintf(
        out_text,
        max_len,
        "%s%.*s",
        prefix,
        (int)(max_len > strlen(prefix) ? max_len - strlen(prefix) - 1 : 0),
        clean_log
    );

    if (written < 0 || (size_t)written >= max_len) {
        out_text[0] = '\0';
        return false;
    }

    return true;
}

bool parse_rtsp(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    // 9 bytes is the absolute minimum for an RTSP command (e.g., "PLAY \r\n\r\n")
    if (length < 9) return false;

    const char* p = (const char*)payload;
    const char* payload_end = p + length;

    // Fast gate: Ensure this is actually RTSP traffic
    bool is_rtsp = (memcmp(p, "RTSP/1.", 7) == 0 || memcmp(p, "OPTIONS ", 8) == 0 || 
                    memcmp(p, "DESCRIBE ", 9) == 0 || memcmp(p, "SETUP ", 6) == 0 || 
                    memcmp(p, "PLAY ", 5) == 0 || memcmp(p, "TEARDOWN ", 9) == 0);
    
    if (!is_rtsp) return false;

    char device_info[64] = {0};
    char uri[64] = {0};
    char auth_type[16] = {0};
    char auth_creds[64] = {0}; 
    bool found_intel = false;

    // The longest needles we check inside the loop are exactly 21 bytes long
    // ("Authorization: Basic " and "Authorization: Digest")
    int max_i = (int)length - 21;

    // Sliding window to sweep for all metadata in one pass
    for (int i = 0; i <= max_i; i++) {
        
        // 1. Extract Hardware / Software Identifier (First match wins)
        if (device_info[0] == '\0') {
            const char* id_start = nullptr;
            if (memcmp(&p[i], "Server: ", 8) == 0) id_start = &p[i+8];
            else if (memcmp(&p[i], "User-Agent: ", 12) == 0) id_start = &p[i+12];
            
            if (id_start) {
                const char* end = id_start;
                while (end < payload_end && *end != '\r' && *end != '\n') end++;
                int copy_len = std::min((int)(end - id_start), 63);
                memcpy(device_info, id_start, copy_len);
                device_info[copy_len] = '\0';
                found_intel = true;
            }
        }

        // 2. Extract Stream URI
        if (uri[0] == '\0' && memcmp(&p[i], "rtsp://", 7) == 0) {
            const char* uri_end = &p[i];
            while (uri_end < payload_end && *uri_end != ' ' && *uri_end != '\r' && *uri_end != '\n') uri_end++;
            int copy_len = std::min((int)(uri_end - &p[i]), 63);
            memcpy(uri, &p[i], copy_len);
            uri[copy_len] = '\0';
            found_intel = true;
        }

        // 3. Extract Authentication State & Credentials
        if (auth_type[0] == '\0') {
            if (memcmp(&p[i], "Authorization: Basic ", 21) == 0) {
                snprintf(auth_type, sizeof(auth_type), "Basic");
                
                const char* b64_start = &p[i + 21];
                const char* b64_end = b64_start;
                while (b64_end < payload_end && *b64_end != '\r' && *b64_end != '\n' && *b64_end != ' ') b64_end++;
                
                int copy_len = std::min((int)(b64_end - b64_start), 63);
                if (copy_len > 0) {
                    memcpy(auth_creds, b64_start, copy_len);
                    auth_creds[copy_len] = '\0';
                }
                found_intel = true;
            }
            else if (memcmp(&p[i], "Authorization: Digest", 21) == 0) {
                snprintf(auth_type, sizeof(auth_type), "Digest");
                found_intel = true;
            }
            else if (memcmp(&p[i], "WWW-Authenticate: ", 18) == 0) {
                snprintf(auth_type, sizeof(auth_type), "Req");
                found_intel = true;
            }
        }
    }

    // Fallback: If it's an RTSP packet but has no headers
    if (!found_intel) {
        const char* end = p;
        while (end < payload_end && *end != '\r' && *end != '\n') end++;
        int copy_len = std::min((int)(end - p), (int)(max_len - 15));
        snprintf(out_text, max_len, "RTSP Cmd: %.*s", copy_len, p);
        return true;
    }

    // Assemble the final tactical string
    int idx = snprintf(out_text, max_len, "RTSP Cam");
    
    if (device_info[0] != '\0') {
        idx += snprintf(out_text + idx, max_len - idx, ": %s", device_info);
    }
    if (uri[0] != '\0') {
        idx += snprintf(out_text + idx, max_len - idx, " | %s", uri);
    }
    if (auth_type[0] != '\0') {
        if (auth_creds[0] != '\0') {
            snprintf(out_text + idx, max_len - idx, " (Auth:%s [%s])", auth_type, auth_creds);
        } else {
            snprintf(out_text + idx, max_len - idx, " (Auth:%s)", auth_type);
        }
    }

    return true;
}

bool parse_ftp(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    // Defensive entry guard
    if (length < 6 || payload == nullptr || out_text == nullptr || max_len < 20) return false;

    const char* p = (const char*)payload;

    // 1. Hunt for authentication commands (Case-insensitive using strncasecmp)
    if (strncasecmp(p, "USER ", 5) == 0 || strncasecmp(p, "PASS ", 5) == 0) {
        const char* end = p;
        
        // Read until the end of the line
        while (end < p + length && *end != '\r' && *end != '\n') end++;
        
        int copy_len = std::min((int)(end - p), (int)(max_len - 6));
        if (copy_len > 0) {
            snprintf(out_text, max_len, "FTP: %.*s", copy_len, p);
            return true;
        }
    }

    // 2. Catch Authentication Responses (Status codes are always numeric)
    if (memcmp(p, "230 ", 4) == 0) {
        snprintf(out_text, max_len, "FTP: Login Successful");
        return true;
    }
    else if (memcmp(p, "530 ", 4) == 0) {
        snprintf(out_text, max_len, "FTP: Login Failed");
        return true;
    }
    
    // 3. Catch Data Connection Routing (PASV / PORT)
    if (strncasecmp(p, "PORT ", 5) == 0 || memcmp(p, "227 ", 4) == 0) {
        const char* tuple_start = nullptr;
        int search_len = std::min((int)length, 64); // Bound the search space
        
        if (memcmp(p, "227 ", 4) == 0) {
            // Find the opening parenthesis for PASV: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
            for (int i = 4; i < search_len; i++) {
                if (p[i] == '(') {
                    tuple_start = &p[i + 1];
                    break;
                }
            }
        } else {
            // PORT command: numbers start immediately after "PORT "
            tuple_start = p + 5;
        }

        if (tuple_start) {
            // Extract the tuple into a safe, null-terminated buffer
            char tuple_buf[64] = {0};
            int i = 0;
            while (tuple_start + i < p + length && tuple_start[i] != '\r' && 
                   tuple_start[i] != ')' && i < 63) {
                tuple_buf[i] = tuple_start[i];
                i++;
            }

            int h1, h2, h3, h4, p1, p2;
            if (sscanf(tuple_buf, "%d,%d,%d,%d,%d,%d", &h1, &h2, &h3, &h4, &p1, &p2) == 6) {
                // Ensure all octets and port bytes strictly conform to 8-bit limits (0-255)
                bool valid = (h1 >= 0 && h1 <= 255) && (h2 >= 0 && h2 <= 255) &&
                             (h3 >= 0 && h3 <= 255) && (h4 >= 0 && h4 <= 255) &&
                             (p1 >= 0 && p1 <= 255) && (p2 >= 0 && p2 <= 255);
                
                if (valid) {
                    uint16_t port = (p1 << 8) | p2; 
                    snprintf(out_text, max_len, "FTP Data: %d.%d.%d.%d:%u", h1, h2, h3, h4, port);
                    return true;
                }
            }
        }
    }

    return false;
}

bool parse_telnet(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    // Defensive entry guard
    if (length < 1 || payload == nullptr || out_text == nullptr || max_len < 16) return false;

    char clean_text[64] = {0};
    uint8_t write_idx = 0;

    // Use uint16_t to strictly match the 'length' variable type
    for (uint16_t i = 0; i < length && write_idx < sizeof(clean_text) - 1; i++) {
        
        // Handle Telnet IAC (Interpret As Command)
        if (payload[i] == 0xFF) {
            if (i + 1 >= length) break;

            // IAC IAC = literal 0xFF data byte.
            // Not printable ASCII, so discard it.
            if (payload[i + 1] == 0xFF) {
                i++;
                continue;
            }

            // Most standard Telnet negotiation commands are 3 bytes: IAC <command> <option>
            if (i + 2 < length) {
                i += 2;
            } else {
                break;
            }
            continue;
        }

        // Only grab printable ASCII characters
        if (payload[i] >= 32 && payload[i] <= 126) {
            clean_text[write_idx++] = payload[i];
        } 
        // Stop if we hit a newline (extracts only the first line of the packet)
        else if (payload[i] == '\r' || payload[i] == '\n') {
            if (write_idx > 0) break;
        }
    }

    if (write_idx > 2) {
        snprintf(out_text, max_len, "Telnet: %s", clean_text);
        return true;
    }

    return false;
}

bool parse_tftp(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    if (!payload || !out_text || length < 4 || max_len < 20) return false;

    uint16_t opcode = ((uint16_t)payload[0] << 8) | payload[1];
    if (opcode != 1 && opcode != 2) return false;

    const char* action = (opcode == 1) ? "Read" : "Write";

    // ------------------------------------------
    // 1. Locate filename
    // ------------------------------------------
    uint16_t pos = 2;
    while (pos < length && payload[pos] != '\0') pos++;
    
    if (pos >= length || pos == 2) return false;
    uint16_t filename_len = pos - 2;

    pos++; // Move past filename NUL

    // ------------------------------------------
    // 2. Locate mode
    // ------------------------------------------
    uint16_t mode_start = pos;
    while (pos < length && payload[pos] != '\0') pos++;
    
    if (pos >= length || pos == mode_start) return false;
    uint16_t mode_len = pos - mode_start;

    // ------------------------------------------
    // 3. Validate common TFTP modes (Case-Insensitive per RFC 1350)
    // ------------------------------------------
    bool valid_mode =
        (mode_len == 5 && strncasecmp((const char*)&payload[mode_start], "octet", 5) == 0) ||
        (mode_len == 8 && strncasecmp((const char*)&payload[mode_start], "netascii", 8) == 0) ||
        (mode_len == 4 && strncasecmp((const char*)&payload[mode_start], "mail", 4) == 0);

    if (!valid_mode) return false;

    // ------------------------------------------
    // 4. Extract filename
    // ------------------------------------------
    int copy_len = std::min((int)filename_len, (int)(max_len - 15));
    if (copy_len <= 0) return false;

    snprintf(out_text, max_len, "TFTP %s: %.*s", action, copy_len, (const char*)&payload[2]);
    return true;
}

bool parse_smtp(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    // Defensive entry guard
    if (length < 4 || payload == nullptr || out_text == nullptr || max_len < 30) return false;

    const char* p = (const char*)payload;
    const char* payload_end = p + length;

    int max_i = (int)length - 4;

    // Slide through the packet looking for line boundaries
    for (int i = 0; i <= max_i; i++) {

        // A command must start at the very beginning of the payload
        // OR immediately after a newline.
        if (i == 0 || p[i - 1] == '\n') {
            const char* line = p + i;
            int rem = length - i;

            // Skip leading CR/LF just in case of unusual formatting.
            while (rem > 0 && (*line == '\r' || *line == '\n')) {
                line++;
                rem--;
            }

            if (rem < 4) continue;

            const char* target_label = nullptr;
            int skip_bytes = 0;

            // EHLO / HELO
            if (rem >= 5 &&
                (strncasecmp(line, "EHLO ", 5) == 0 ||
                 strncasecmp(line, "HELO ", 5) == 0)) {

                target_label = "HELO";
                skip_bytes = 5;
            }

            // MAIL FROM
            else if (rem >= 10 &&
                     strncasecmp(line, "MAIL FROM:", 10) == 0) {

                target_label = "From";
                skip_bytes = 10;
            }

            // RCPT TO
            else if (rem >= 8 &&
                     strncasecmp(line, "RCPT TO:", 8) == 0) {

                target_label = "To";
                skip_bytes = 8;
            }

            // SMTP server banner: 220 text / 220-text
            else if (rem >= 4 &&
                     memcmp(line, "220", 3) == 0 &&
                     (line[3] == ' ' || line[3] == '-')) {

                target_label = "Server";
                skip_bytes = 4;
            }

            // AUTH LOGIN
            else if (rem >= 10 &&
                     strncasecmp(line, "AUTH LOGIN", 10) == 0) {

                if (rem == 10 ||
                    line[10] == ' ' ||
                    line[10] == '\r' ||
                    line[10] == '\n') {

                    snprintf(out_text, max_len, "SMTP AUTH LOGIN");
                    return true;
                }
            }

            // AUTH PLAIN
            else if (rem >= 10 &&
                     strncasecmp(line, "AUTH PLAIN", 10) == 0) {

                if (rem == 10 ||
                    line[10] == ' ' ||
                    line[10] == '\r' ||
                    line[10] == '\n') {

                    snprintf(out_text, max_len, "SMTP AUTH PLAIN");
                    return true;
                }
            }

            // Extract matched field
            if (target_label) {
                const char* target_data = line + skip_bytes;

                while (target_data < payload_end &&
                       (*target_data == ' ' || *target_data == '<')) {
                    target_data++;
                }

                const char* end = target_data;

                while (end < payload_end &&
                       *end != '\r' &&
                       *end != '\n' &&
                       *end != '>') {
                    end++;
                }

                int copy_len =
                    std::min((int)(end - target_data),
                             (int)(max_len - 15));

                if (copy_len > 0) {
                    snprintf(out_text, max_len,
                             "SMTP %s: %.*s",
                             target_label,
                             copy_len,
                             target_data);
                    return true;
                }
            }
        }
    }

    return false;
}

bool parse_smb(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    // 1. Lower global minimum length to 20
    if (length < 20 || payload == nullptr || out_text == nullptr || max_len < 40) return false;

    const char magic_sig[] = "NTLMSSP\0";
    int max_i = (int)length - 20; 

    for (int i = 0; i <= max_i; i++) {
        if (memcmp(&payload[i], magic_sig, 8) == 0) {
            
            uint8_t msg_type = payload[i + 8];
            uint32_t rem = length - i;

            // ---------------------------------------------------------
            // Type 1: Negotiate (Client -> Server)
            // ---------------------------------------------------------
            if (msg_type == 0x01) {
                if ((uint32_t)i + 32 > length) continue; // 2. Message-specific length check
                
                uint16_t dom_len = payload[i + 16] | (payload[i + 17] << 8);
                uint32_t dom_off = payload[i + 20] | (payload[i + 21] << 8) | (payload[i + 22] << 16) | (payload[i + 23] << 24);
                
                uint16_t ws_len = payload[i + 24] | (payload[i + 25] << 8);
                uint32_t ws_off = payload[i + 28] | (payload[i + 29] << 8) | (payload[i + 30] << 16) | (payload[i + 31] << 24);

                char dom_name[32] = {0};
                char ws_name[32] = {0};

                // 3. Hardened offset subtraction arithmetic
                if (dom_len > 0 && dom_off <= rem && dom_len <= rem - dom_off) {
                    int d_idx = 0;
                    for (int k = 0; k < dom_len && d_idx < 31; k++) {
                        char c = payload[i + dom_off + k];
                        if (c >= 32 && c <= 126) dom_name[d_idx++] = c;
                    }
                }

                if (ws_len > 0 && ws_off <= rem && ws_len <= rem - ws_off) {
                    int w_idx = 0;
                    for (int k = 0; k < ws_len && w_idx < 31; k++) {
                        char c = payload[i + ws_off + k];
                        if (c >= 32 && c <= 126) ws_name[w_idx++] = c;
                    }
                }

                if (ws_name[0] != '\0') {
                    // 4. Do not invent "WORKGROUP"
                    snprintf(out_text, max_len, "SMB Client: %s\\%s", dom_name[0] ? dom_name : "?", ws_name);
                    return true;
                }
            }
            
            // ---------------------------------------------------------
            // Type 2: Challenge (Server -> Client)
            // ---------------------------------------------------------
            else if (msg_type == 0x02) {
                if ((uint32_t)i + 20 > length) continue;

                uint16_t tgt_len = payload[i + 12] | (payload[i + 13] << 8);
                uint32_t tgt_off = payload[i + 16] | (payload[i + 17] << 8) | (payload[i + 18] << 16) | (payload[i + 19] << 24);

                if (tgt_len > 0 && tgt_off <= rem && tgt_len <= rem - tgt_off) {
                    char tgt_name[32] = {0};
                    int t_idx = 0;
                    for (int k = 0; k < tgt_len && t_idx < 31; k++) {
                        char c = payload[i + tgt_off + k];
                        if (c >= 32 && c <= 126) tgt_name[t_idx++] = c;
                    }
                    if (t_idx > 0) {
                        snprintf(out_text, max_len, "SMB Server: %s", tgt_name);
                        return true;
                    }
                }
            }

            // ---------------------------------------------------------
            // Type 3: Authenticate (Client -> Server)
            // ---------------------------------------------------------
            else if (msg_type == 0x03) {
                if ((uint32_t)i + 44 > length) continue;

                uint16_t usr_len = payload[i + 36] | (payload[i + 37] << 8);
                uint32_t usr_off = payload[i + 40] | (payload[i + 41] << 8) | (payload[i + 42] << 16) | (payload[i + 43] << 24);

                if (usr_len > 0 && usr_off <= rem && usr_len <= rem - usr_off) {
                    char usr_name[32] = {0};
                    int u_idx = 0;
                    for (int k = 0; k < usr_len && u_idx < 31; k++) {
                        char c = payload[i + usr_off + k];
                        if (c >= 32 && c <= 126) usr_name[u_idx++] = c;
                    }
                    if (u_idx > 0) {
                        snprintf(out_text, max_len, "SMB Auth [User: %s]", usr_name);
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

