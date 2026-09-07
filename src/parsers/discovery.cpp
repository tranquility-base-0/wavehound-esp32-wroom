#include <Arduino.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <algorithm>
#include "parser_common.h"
#include "discovery.h"

static void ssdp_copy_trimmed( const char* src, size_t len, char* dst, size_t dst_size );
static void ssdp_append( char* out, size_t max_len, size_t& used, const char* fmt, ... );
static bool cdp_checksum_valid(const uint8_t* p, uint16_t length);

const char* getNetbiosSuffixStr(uint8_t suffixCode) {
    switch (suffixCode) {
        case 0x00: return "Workstation/Domain";
        case 0x03: return "Messenger Service";
        case 0x06: return "RAS Server";
        case 0x20: return "File Server";
        case 0x21: return "RAS Client";
        case 0x1B: return "Domain Master";
        case 0x1C: return "Domain Controller";
        case 0x1D: return "Master Browser";
        case 0x1E: return "Browser Election";
        case 0x1F: return "NetDDE Service";
        case 0xBE: return "Network Monitor";
        case 0xFF: return "Parse Error";
        default:   return "Unknown Suffix";
    }
}

uint8_t decodeNetbiosName(const char* encoded, char* decodedName, size_t maxLen) {
    uint8_t suffix = 0xFF; // Default error/unknown
    int outIdx = 0;
    int len = strlen(encoded);

    // Skip leading dot if your DNS parser accidentally passed one in
    int startIdx = (encoded[0] == '.') ? 1 : 0;

    for (int i = startIdx; i < len - 1 && outIdx < 16; i += 2) {
        char c1 = encoded[i];
        char c2 = encoded[i + 1];

        // Valid NetBIOS encoding uses ASCII 'A' through 'P'
        if (c1 >= 'A' && c1 <= 'P' && c2 >= 'A' && c2 <= 'P') {
            uint8_t high = c1 - 'A';
            uint8_t low  = c2 - 'A';
            decodedName[outIdx++] = (high << 4) | low;
        } else {
            break; // Stop if we hit malformed or non-NetBIOS data
        }
    }

    // A valid NetBIOS name yields exactly 16 bytes
    if (outIdx == 16) {
        suffix = decodedName[15]; // Grab the 16th byte
        
        // NetBIOS pads the name with spaces (0x20). 
        // We trim them off backwards so it looks clean on the TFT screen.
        int trimIdx = 14;
        while (trimIdx >= 0 && decodedName[trimIdx] == ' ') {
            trimIdx--;
        }
        decodedName[trimIdx + 1] = '\0'; // Null-terminate right after the actual name
    } else {
        // If it wasn't 16 bytes, just null-terminate whatever we managed to parse
        decodedName[outIdx < maxLen ? outIdx : maxLen - 1] = '\0';
    }

    return suffix;
}

bool parse_netbios(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    // A standard NetBIOS Name Service (NBNS) query has a 12-byte header.
    // Byte 12 is the length of the name (always 0x20 or 32 bytes).
    // The A-P encoded string starts at Byte 13.
    if (length >= 45 && payload[12] == 0x20) {
        
        // 1. Safely extract the 32-byte A-P encoded string
        char rawEncodedString[33];
        memcpy(rawEncodedString, &payload[13], 32);
        rawEncodedString[32] = '\0'; // Ensure null-termination

        // 2. Decode it using your memory-safe functions
        char cleanName[17]; 
        uint8_t suffixByte = decodeNetbiosName(rawEncodedString, cleanName, sizeof(cleanName));
        const char* serviceType = getNetbiosSuffixStr(suffixByte);

        // 3. Format it (Updated to show both)
        snprintf(out_text, max_len, "NBNS: [%s] -> %s [%s]", 
                 rawEncodedString, cleanName, serviceType);
        return true; 
    }
    return false;
}

bool parse_nbds(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    int written = snprintf(out_text, max_len, "NBDS:");
    bool found_any = false;

    int cur_s = 0, cur_l = 0;

    for (int i = 0; i <= length; i++) {
        char c = (i < length) ? payload[i] : 0;

        if (c >= 32 && c <= 126) {
            if (cur_l == 0) cur_s = i;
            cur_l++;
        } else {
            if (cur_l >= 5) {
                // Trim a leading/trailing space — NBT name fields are prefixed with a
                // 0x20 length byte, which is itself printable and merges into the same
                // run as the encoded name that follows it.
                int seg_s = cur_s;
                int seg_l = cur_l;
                while (seg_l > 0 && payload[seg_s] == ' ') { seg_s++; seg_l--; }
                while (seg_l > 0 && payload[seg_s + seg_l - 1] == ' ') { seg_l--; }

                if (seg_l >= 5) {
                    char temp[64] = {0};
                    int copy_len = std::min(seg_l, 63);
                    memcpy(temp, &payload[seg_s], copy_len);

                    if (!strstr(temp, "MAILSLOT") && !strstr(temp, "BROWSE")) {
                        // A real NetBIOS-encoded name is always exactly 32 A-P chars
                        // (16 bytes x 2 nibbles). Requiring the exact length (not just
                        // >=16) avoids misidentifying partial/truncated runs as names.
                        bool is_ap_blob = (seg_l == 32);
                        for (int j = 0; j < copy_len && is_ap_blob; j++) {
                            if (temp[j] < 'A' || temp[j] > 'P') is_ap_blob = false;
                        }

                        if (is_ap_blob) {
                            // Decode it instead of dropping it — this is the actual
                            // "translation" step that was missing.
                            char decoded[17] = {0};
                            uint8_t suffix = decodeNetbiosName(temp, decoded, sizeof(decoded));
                            
                            // ==========================================
                            // NEW "DOUBLE-KEY" PRINTING LOGIC GOES HERE
                            // ==========================================
                            if (decoded[0] != '\0' && !strstr(out_text, decoded) && written < (int)max_len) {
                                written += snprintf(out_text + written, max_len - written,
                                                     " [%s] -> %s [%s]", 
                                                     temp, decoded, getNetbiosSuffixStr(suffix));
                                found_any = true;
                            }
                            // ==========================================
                            
                        } else if (!strstr(out_text, temp)) {
                            if (written < (int)max_len) {
                                written += snprintf(out_text + written, max_len - written, " [%s]", temp);
                                found_any = true;
                            }
                        }
                    }
                }
            }
            cur_l = 0;
        }
    }
    return found_any;
}

bool parse_ws_discovery(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    if (length < 20 || payload == nullptr || out_text == nullptr || max_len < 20) return false;

    const char* p = (const char*)payload;

    char action_val[128] = {0};   // unchanged — action URIs are a fixed enum-like set, rarely long
char types_val[64]   = {0};   // unchanged — same reasoning
char xaddrs_val[192] = {0};   // was 96 — the most likely actual truncation point
char scopes_val[192] = {0};   // was 128 — ONVIF scope lists can carry several space-separated scope URIs (name, hardware, location, profile), similar risk to xaddrs

    bool found_action = extract_xml_value(p, length, "Action>", action_val, sizeof(action_val));
    bool found_types  = extract_xml_value(p, length, "Types>", types_val, sizeof(types_val));
    bool found_xaddrs = extract_xml_value(p, length, "XAddrs>", xaddrs_val, sizeof(xaddrs_val));
    bool found_scopes = extract_xml_value(p, length, "Scopes>", scopes_val, sizeof(scopes_val));

    // Trim XML whitespace artifacts from all successful extractions
    if (found_action) trim_ascii(action_val);
    if (found_types)  trim_ascii(types_val);
    if (found_xaddrs) trim_ascii(xaddrs_val);
    if (found_scopes) trim_ascii(scopes_val);

    if (!found_types && !found_xaddrs && !found_scopes) {
        return false;
    }

    // --- STEP 1: Determine the Action Type ---
    const char* msg_type = "WS-Discovery";
    if (found_action) {
        if (strstr(action_val, "ProbeMatch")) msg_type = "WS-Discovery [ProbeMatch]";
        else if (strstr(action_val, "Probe")) msg_type = "WS-Discovery [Probe]";
        else if (strstr(action_val, "Hello")) msg_type = "WS-Discovery [Hello]";
        else if (strstr(action_val, "Bye")) msg_type = "WS-Discovery [Bye]";
    }

    // --- STEP 2: UI Formatting Assembly ---
    char temp_out[MAX_LEAK_STR_LEN] = {0}; // was 256
    snprintf(temp_out, sizeof(temp_out), "%s:", msg_type);
    
    char chunk[128];

    if (found_types) {
        char type_buf[64] = {0};
        const char* type_start = types_val;
        
        char* colon = strchr(types_val, ':');
        if (colon) type_start = colon + 1;
        
        // Bulletproof QName isolation handling all XML whitespace chars
        size_t type_len = strcspn(type_start, " \t\r\n");
        if (type_len >= sizeof(type_buf)) type_len = sizeof(type_buf) - 1;
        
        memcpy(type_buf, type_start, type_len);
        type_buf[type_len] = '\0';
        
        snprintf(chunk, sizeof(chunk), " [Type: %s]", type_buf);
        strncat(temp_out, chunk, sizeof(temp_out) - strlen(temp_out) - 1);
    }
    
    if (found_scopes) {
        const char* prefix = "onvif://www.onvif.org/name/";
        size_t prefix_len = strlen(prefix);
        char* name_ptr = strstr(scopes_val, prefix);
        
        if (name_ptr) {
            name_ptr += prefix_len; 
            
            char clean_name[32] = {0};
            int idx = 0;
            while (name_ptr[idx] != ' ' && name_ptr[idx] != '\0' && idx < 31) {
                clean_name[idx] = name_ptr[idx];
                idx++;
            }
            snprintf(chunk, sizeof(chunk), " [Name: %s]", clean_name);
            strncat(temp_out, chunk, sizeof(temp_out) - strlen(temp_out) - 1);
        }
    }

    if (found_xaddrs) {
        snprintf(chunk, sizeof(chunk), " [URL: %s]", xaddrs_val);
        strncat(temp_out, chunk, sizeof(temp_out) - strlen(temp_out) - 1);
    }

    snprintf(out_text, max_len, "%s", temp_out);
    return true;
}

static void ssdp_copy_trimmed(
    const char* src,
    size_t len,
    char* dst,
    size_t dst_size
) {
    if (!dst || dst_size == 0) return;

    while (len > 0 &&
           (*src == ' ' || *src == '\t')) {
        src++;
        len--;
    }

    while (len > 0 &&
           (src[len - 1] == ' ' ||
            src[len - 1] == '\t' ||
            src[len - 1] == '\r')) {
        len--;
    }

    size_t n = (len < dst_size - 1) ? len : dst_size - 1;

    if (n > 0) {
        memcpy(dst, src, n);
    }

    dst[n] = '\0';
}

static void ssdp_append(
    char* out,
    size_t max_len,
    size_t& used,
    const char* fmt,
    ...
) {
    if (!out || max_len == 0 || used >= max_len - 1) return;

    va_list args;
    va_start(args, fmt);

    int written = vsnprintf(
        out + used,
        max_len - used,
        fmt,
        args
    );

    va_end(args);

    if (written <= 0) return;

    size_t remaining = max_len - used - 1;

    if ((size_t)written > remaining) {
        used = max_len - 1;
    } else {
        used += (size_t)written;
    }
}

bool parse_ssdp(
    const uint8_t* payload,
    uint16_t length,
    char* out_text,
    size_t max_len
) {
    if (!payload || !out_text || max_len < 2 || length < 8) {
        return false;
    }

    out_text[0] = '\0';

    // -----------------------------------------------------
    // Local bounded fields
    // -----------------------------------------------------

    char first_line[64] = {0};      // was 40

char host[64]          = {0};   // was 40
char man[40]           = {0};   // unchanged — "ssdp:discover" etc., always short
char mx[8]             = {0};   // unchanged — single-digit seconds value

char target_key[4]     = {0};   // unchanged — "ST" / "NT"
char target_val[128]   = {0};   // was 80 — URNs like your Samsung example run 40-50 chars; other vendors' nested service URNs can run longer

char nts[32]           = {0};   // unchanged — "ssdp:alive" / "ssdp:byebye"
char server[128]       = {0};   // was 80 — SERVER strings often chain 3+ tokens (OS/version, UPnP/version, product/version)
char usn[128]          = {0};   // was 80 — this is your actual bug; 82 chars needed, giving headroom for longer UUIDs+URN combos
char location[160]     = {0};   // was 100 — full URLs with paths, occasionally query strings
char cache_control[48] = {0};   // unchanged — "max-age=1800" style, always short
char date[40]          = {0};   // unchanged — RFC1123 dates are ~29 chars, some margin already

    const char* p =
        reinterpret_cast<const char*>(payload);

    const char* end = p + length;

    // -----------------------------------------------------
    // 1. FIRST LINE
    // -----------------------------------------------------

    const char* line_end =
        static_cast<const char*>(
            memchr(p, '\n', end - p)
        );

    if (!line_end) {
        line_end = end;
    }

    size_t line_len =
        static_cast<size_t>(line_end - p);

    ssdp_copy_trimmed(
        p,
        line_len,
        first_line,
        sizeof(first_line)
    );

    // -----------------------------------------------------
    // 2. CLASSIFY THE START LINE
    //
    // We only accept actual SSDP request/notification/
    // response syntax here.
    // -----------------------------------------------------

    bool looks_ssdp = false;

    if (strncasecmp(
            first_line,
            "M-SEARCH ",
            9
        ) == 0) {

        looks_ssdp = true;

    } else if (strncasecmp(
                   first_line,
                   "NOTIFY ",
                   7
               ) == 0) {

        looks_ssdp = true;

    } else if (strncasecmp(
                   first_line,
                   "HTTP/1.1 200",
                   12
               ) == 0) {

        looks_ssdp = true;

    } else if (strncasecmp(
                   first_line,
                   "HTTP/1.0 200",
                   12
               ) == 0) {

        looks_ssdp = true;
    }

    // Don't parse arbitrary HTTP traffic as SSDP.
    if (!looks_ssdp) {
        return false;
    }

    // Advance beyond first line.
    p = (line_end < end) ? line_end + 1 : end;

    // -----------------------------------------------------
    // 3. HEADER WALKER
    // -----------------------------------------------------

    while (p < end) {

        line_end =
            static_cast<const char*>(
                memchr(p, '\n', end - p)
            );

        if (!line_end) {
            line_end = end;
        }

        size_t current_len =
            static_cast<size_t>(line_end - p);

        // Blank line => end of HTTP-like headers.
        size_t meaningful_len = current_len;

        while (meaningful_len > 0 &&
               (p[meaningful_len - 1] == '\r' ||
                p[meaningful_len - 1] == ' '  ||
                p[meaningful_len - 1] == '\t')) {
            meaningful_len--;
        }

        if (meaningful_len == 0) {
            break;
        }

        const char* colon =
            static_cast<const char*>(
                memchr(p, ':', meaningful_len)
            );

        if (colon) {

            size_t key_len =
                static_cast<size_t>(colon - p);

            const char* value = colon + 1;

            size_t value_len =
                meaningful_len - key_len - 1;

            // Trim whitespace.
            while (value_len > 0 &&
                   (*value == ' ' || *value == '\t')) {
                value++;
                value_len--;
            }

            while (value_len > 0 &&
                   (value[value_len - 1] == '\r' ||
                    value[value_len - 1] == ' '  ||
                    value[value_len - 1] == '\t')) {
                value_len--;
            }

            // -------------------------------------------------
            // HOST
            // -------------------------------------------------
            if (key_len == 4 &&
                strncasecmp(p, "HOST", 4) == 0) {

                ssdp_copy_trimmed(
                    value, value_len,
                    host, sizeof(host)
                );
            }

            // -------------------------------------------------
            // MAN
            // -------------------------------------------------
            else if (key_len == 3 &&
                     strncasecmp(p, "MAN", 3) == 0) {

                ssdp_copy_trimmed(
                    value, value_len,
                    man, sizeof(man)
                );
            }

            // -------------------------------------------------
            // MX
            // -------------------------------------------------
            else if (key_len == 2 &&
                     strncasecmp(p, "MX", 2) == 0) {

                ssdp_copy_trimmed(
                    value, value_len,
                    mx, sizeof(mx)
                );
            }

            // -------------------------------------------------
            // ST / NT
            // -------------------------------------------------
            else if (
                key_len == 2 &&
                (strncasecmp(p, "ST", 2) == 0 ||
                 strncasecmp(p, "NT", 2) == 0)
            ) {

                target_key[0] = p[0];
                target_key[1] = p[1];
                target_key[2] = '\0';

                ssdp_copy_trimmed(
                    value, value_len,
                    target_val, sizeof(target_val)
                );
            }

            // -------------------------------------------------
            // NTS
            // -------------------------------------------------
            else if (
                key_len == 3 &&
                strncasecmp(p, "NTS", 3) == 0
            ) {

                ssdp_copy_trimmed(
                    value, value_len,
                    nts, sizeof(nts)
                );
            }

            // -------------------------------------------------
            // SERVER / USER-AGENT
            // -------------------------------------------------
            else if (
                (key_len == 6 &&
                 strncasecmp(p, "SERVER", 6) == 0) ||

                (key_len == 10 &&
                 strncasecmp(p, "USER-AGENT", 10) == 0)
            ) {

                if (server[0] == '\0') {
                    ssdp_copy_trimmed(
                        value, value_len,
                        server, sizeof(server)
                    );
                }
            }

            // -------------------------------------------------
            // USN
            // -------------------------------------------------
            else if (
                key_len == 3 &&
                strncasecmp(p, "USN", 3) == 0
            ) {

                ssdp_copy_trimmed(
                    value, value_len,
                    usn, sizeof(usn)
                );
            }

            // -------------------------------------------------
            // LOCATION / SECURELOCATION
            // -------------------------------------------------
            else if (
                (key_len == 8 &&
                 strncasecmp(p, "LOCATION", 8) == 0) ||

                (key_len == 14 &&
                 strncasecmp(p, "SECURELOCATION", 14) == 0)
            ) {

                if (location[0] == '\0') {
                    ssdp_copy_trimmed(
                        value, value_len,
                        location, sizeof(location)
                    );
                }
            }

            // -------------------------------------------------
            // CACHE-CONTROL
            // -------------------------------------------------
            else if (
                key_len == 13 &&
                strncasecmp(p, "CACHE-CONTROL", 13) == 0
            ) {

                ssdp_copy_trimmed(
                    value, value_len,
                    cache_control, sizeof(cache_control)
                );
            }

            // -------------------------------------------------
            // DATE
            // -------------------------------------------------
            else if (
                key_len == 4 &&
                strncasecmp(p, "DATE", 4) == 0
            ) {

                ssdp_copy_trimmed(
                    value, value_len,
                    date, sizeof(date)
                );
            }
        }

        p = (line_end < end) ? line_end + 1 : end;
    }

    // -----------------------------------------------------
    // 4. Clean common UPnP URN prefixes
    // -----------------------------------------------------

    const char* clean_target = target_val;

    if (strncmp(
            target_val,
            "urn:schemas-upnp-org:device:",
            28
        ) == 0) {

        clean_target = target_val + 28;

    } else if (strncmp(
                   target_val,
                   "urn:schemas-upnp-org:service:",
                   29
               ) == 0) {

        clean_target = target_val + 29;
    }

    // -----------------------------------------------------
    // 5. Assemble compact UI string
    // -----------------------------------------------------

    size_t used = 0;

    ssdp_append(
        out_text,
        max_len,
        used,
        "SSDP %s",
        first_line
    );

    if (host[0]) {
        ssdp_append(
            out_text,
            max_len,
            used,
            " | HOST=%s",
            host
        );
    }

    if (target_val[0]) {
        ssdp_append(
            out_text,
            max_len,
            used,
            " | %s=%s",
            target_key,
            clean_target
        );
    }

    if (man[0]) {
        ssdp_append(
            out_text,
            max_len,
            used,
            "\n    MAN=%s",
            man
        );
    }

    if (mx[0]) {
        ssdp_append(
            out_text,
            max_len,
            used,
            " MX=%s",
            mx
        );
    }

    if (nts[0]) {
        ssdp_append(
            out_text,
            max_len,
            used,
            "\n    NTS=%s",
            nts
        );
    }

    if (server[0]) {
        ssdp_append(
            out_text,
            max_len,
            used,
            "\n    SERVER=%s",
            server
        );
    }

    if (usn[0]) {
        ssdp_append(
            out_text,
            max_len,
            used,
            "\n    USN=%s",
            usn
        );
    }

    if (location[0]) {
        ssdp_append(
            out_text,
            max_len,
            used,
            "\n    LOCATION=%s",
            location
        );
    }

    if (cache_control[0]) {
        ssdp_append(
            out_text,
            max_len,
            used,
            "\n    CACHE=%s",
            cache_control
        );
    }

    if (date[0]) {
        ssdp_append(
            out_text,
            max_len,
            used,
            "\n    DATE=%s",
            date
        );
    }

    return used > 0;
}

bool parse_lldp(const uint8_t* payload, uint16_t length, char* out_buf, size_t max_out) {
    if (!payload || !out_buf || length < 2 || max_out < 8) return false;
    
    out_buf[0] = '\0';
    uint16_t offset = 0;
    size_t pos = 0;
    
    uint8_t mandatory_stage = 0;
    bool have_end = false;

    // Bounded append helper with explicit NUL reservation
    auto append_str = [&](const char* str) -> bool {
        size_t len = strlen(str);
        if (pos >= max_out) return false;
        
        size_t available = max_out - pos - 1; // Reserve 1 byte for '\0'
        if (len > available) return false;

        memcpy(out_buf + pos, str, len);
        pos += len;
        out_buf[pos] = '\0';
        return true;
    };

    if (!append_str("LLDP: ")) return false;

    // Subtraction-based invariant: At least two bytes remain for a TLV header
    while (length - offset >= 2) {
        uint8_t tlv_type = payload[offset] >> 1;
        uint16_t tlv_len = ((payload[offset] & 0x01) << 8) | payload[offset + 1];
        
        offset += 2;
        
        // Subtraction-safe boundary check
        if (tlv_len > length - offset) return false; 

        // Enforce strict 1 -> 2 -> 3 ordering for false-positive elimination
        if (tlv_type == 1) {
            if (mandatory_stage != 0 || tlv_len < 2) return false;
            mandatory_stage = 1;
        } else if (tlv_type == 2) {
            if (mandatory_stage != 1 || tlv_len < 2) return false;
            mandatory_stage = 2;
        } else if (tlv_type == 3) {
            if (mandatory_stage != 2 || tlv_len != 2) return false;
            mandatory_stage = 3;
        } else if (tlv_type == 0) {
            if (mandatory_stage != 3 || tlv_len != 0) return false;
            have_end = true;
            break;
        }
        
        // Extract High-Information TLVs (Port Desc, Sys Name, Sys Desc)
        if (tlv_type == 4 || tlv_type == 5 || tlv_type == 6) {
            const char* label = (tlv_type == 4) ? "[Port: " : (tlv_type == 5) ? "[Name: " : "[Desc: ";
            size_t label_len = strlen(label);
            
            // Atomic check: Ensure space for label + at least 1 char + "] " + '\0'
            size_t min_required = label_len + 4; 
            
            if (pos < max_out && (max_out - pos) >= min_required) {
                append_str(label);
                
                size_t available = max_out - pos - 3; // Reserve space for "] \0"
                size_t copy_len = std::min((size_t)tlv_len, available);
                
                for (size_t i = 0; i < copy_len; i++) {
                    uint8_t c = payload[offset + i];
                    out_buf[pos++] = (c >= 32 && c <= 126) ? (char)c : '.';
                }
                out_buf[pos] = '\0';
                
                append_str("] ");
            }
        }
        
        offset += tlv_len;
    }

    // Fail if the frame didn't cleanly terminate with a Type 0 TLV
    if (!have_end) {
        return false;
    }

    return (pos > 6);
}

static bool cdp_checksum_valid(const uint8_t* p, uint16_t length) {
    if (!p || length < 4) return false;

    uint32_t sum = 0;

    for (uint16_t i = 0; i + 1 < length; i += 2) {
        sum += ((uint16_t)p[i] << 8) | p[i + 1];

        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    if (length & 1) {
        sum += (uint16_t)p[length - 1] << 8;
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    return (sum & 0xFFFF) == 0xFFFF;
}

bool parse_cdp(const uint8_t* payload, uint16_t length, char* out_buf, size_t max_out) {
    if (!payload || !out_buf || length < 8 || max_out < 8) return false;
    
    out_buf[0] = '\0';
    uint16_t offset = 0;
    size_t pos = 0;

    auto append_str = [&](const char* str) -> bool {
        size_t len = strlen(str);
        if (pos >= max_out) return false;
        
        size_t available = max_out - pos - 1; 
        if (len > available) return false;

        memcpy(out_buf + pos, str, len);
        pos += len;
        out_buf[pos] = '\0';
        return true;
    };

    // Skip LLC/SNAP if present (AA AA 03 00 00 0C 20 00)
    if (payload[0] == 0xAA && payload[1] == 0xAA && payload[2] == 0x03) {
        if (length >= 8 && payload[3] == 0x00 && payload[4] == 0x00 && payload[5] == 0x0C && 
            payload[6] == 0x20 && payload[7] == 0x00) {
            offset += 8;
        } else {
            return false;
        }
    }

    // CDP Header Validation (Version, TTL, Checksum)
    if (length - offset < 4) return false;
    
    uint8_t version = payload[offset];
    uint8_t ttl = payload[offset + 1];
    
    if (version != 1 && version != 2) return false;
    if (ttl == 0) return false;
    
    // Strict checksum validation over the CDP frame
    if (!cdp_checksum_valid(payload + offset, length - offset)) return false;
    
    offset += 4;

    if (!append_str("CDP: ")) return false;

    // TLV Walk
    while (length - offset >= 4) {
        uint16_t tlv_type = (payload[offset] << 8) | payload[offset + 1];
        uint16_t tlv_len  = (payload[offset + 2] << 8) | payload[offset + 3];
        
        if (tlv_len < 4 || tlv_len > length - offset) return false; 

        uint16_t val_len = tlv_len - 4;
        uint16_t val_offset = offset + 4;

        // Expanded OSINT Extraction
        if (tlv_type == 0x01 || tlv_type == 0x03 || tlv_type == 0x05 || 
            tlv_type == 0x06 || tlv_type == 0x09 || tlv_type == 0x0A || tlv_type == 0x0B) {
            
            const char* label = (tlv_type == 0x01) ? "[Dev: " : 
                                (tlv_type == 0x03) ? "[Port: " : 
                                (tlv_type == 0x05) ? "[SW: "  : 
                                (tlv_type == 0x06) ? "[Plat: " :
                                (tlv_type == 0x09) ? "[VTP: " :
                                (tlv_type == 0x0A) ? "[VLAN: " : "[Duplex: ";
            
            size_t label_len = strlen(label);
            size_t min_required = label_len + 4; 
            
            if (pos < max_out && (max_out - pos) >= min_required) {
                append_str(label);
                
                size_t available = max_out - pos - 3; 
                size_t copy_len = std::min((size_t)val_len, available);
                
                for (size_t i = 0; i < copy_len; i++) {
                    uint8_t c = payload[val_offset + i];
                    // Sanitize logic now includes tabs
                    if (c == '\r' || c == '\n' || c == '\t') {
                        out_buf[pos++] = ' ';
                    } else {
                        out_buf[pos++] = (c >= 32 && c <= 126) ? (char)c : '.';
                    }
                }
                out_buf[pos] = '\0';
                append_str("] ");
            }
        }
        offset += tlv_len;
    }

    // Every byte must belong to a complete TLV sequence
    if (offset != length) return false;

    return (pos > 5); 
}

bool parse_socks(const uint8_t* payload,
                        uint16_t length,
                        char* out_text,
                        size_t max_len) {
    if (!payload || !out_text || length < 2 || max_len < 20)
        return false;

    out_text[0] = '\0';

    size_t pos = 0;

    // ------------------------------------------------------------------------
    // Bounded output helper
    // ------------------------------------------------------------------------
    auto append_str = [&](const char* str) -> bool {
        if (!str || pos >= max_len)
            return false;

        size_t len = strlen(str);

        // Reserve one byte for terminating NUL.
        if (len > max_len - pos - 1)
            return false;

        memcpy(out_text + pos, str, len);
        pos += len;
        out_text[pos] = '\0';

        return true;
    };

    // ------------------------------------------------------------------------
    // Bounded formatted append
    // ------------------------------------------------------------------------
    auto append_fmt = [&](const char* fmt, ...) -> bool {
        if (!fmt || pos >= max_len)
            return false;

        va_list args;
        va_start(args, fmt);

        int written = vsnprintf(
            out_text + pos,
            max_len - pos,
            fmt,
            args
        );

        va_end(args);

        if (written < 0)
            return false;

        size_t available = max_len - pos;

        // vsnprintf returns the number of characters that WOULD have
        // been written, excluding the terminating NUL.
        if ((size_t)written >= available) {
            out_text[max_len - 1] = '\0';
            return false;
        }

        pos += (size_t)written;
        return true;
    };

    // ------------------------------------------------------------------------
    // Safe C-string reader inside packet
    // ------------------------------------------------------------------------
    auto find_nul = [&](uint16_t start, uint16_t& end) -> bool {
        if (start >= length)
            return false;

        for (uint16_t i = start; i < length; i++) {
            if (payload[i] == '\0') {
                end = i;
                return true;
            }
        }

        return false;
    };

    // ------------------------------------------------------------------------
    // Printable username / domain helper
    // ------------------------------------------------------------------------
    auto append_sanitized = [&](uint16_t start,
                                uint16_t field_len,
                                const char* prefix,
                                const char* suffix) -> bool {
        size_t prefix_len = strlen(prefix);
        size_t suffix_len = strlen(suffix);

        // Need prefix + at least one character + suffix + NUL.
        if (pos >= max_len ||
            prefix_len > max_len - pos ||
            suffix_len > max_len - pos - prefix_len - 1) {
            return false;
        }

        if (!append_str(prefix))
            return false;

        size_t available = max_len - pos - suffix_len - 1;

        size_t copy_len = std::min(
            (size_t)field_len,
            available
        );

        for (size_t i = 0; i < copy_len; i++) {
            uint8_t c = payload[start + i];

            if (c >= 32 && c <= 126)
                out_text[pos++] = (char)c;
            else
                out_text[pos++] = '.';
        }

        out_text[pos] = '\0';

        return append_str(suffix);
    };

    // =========================================================================
    // SOCKS4 / SOCKS4a
    // =========================================================================
    if (payload[0] == 0x04) {

        // Minimum:
        // VN + CD + DSTPORT(2) + DSTIP(4) + USERID NUL
        if (length < 9)
            return false;

        uint8_t command = payload[1];

        // ---------------------------------------------------------------------
        // SOCKS4 REQUEST
        // ---------------------------------------------------------------------
        if (command == 0x01 || command == 0x02) {

            uint16_t dst_port =
                ((uint16_t)payload[2] << 8) |
                payload[3];

            uint32_t dst_ip =
                ((uint32_t)payload[4] << 24) |
                ((uint32_t)payload[5] << 16) |
                ((uint32_t)payload[6] << 8)  |
                payload[7];

            uint16_t user_end = 0;

            if (!find_nul(8, user_end))
                return false;

            uint16_t user_len = user_end - 8;

            // SOCKS4a:
            // 0.0.0.x where x != 0 indicates a domain follows USERID.
            bool is_socks4a =
                payload[4] == 0x00 &&
                payload[5] == 0x00 &&
                payload[6] == 0x00 &&
                payload[7] != 0x00;

            const char* action =
                (command == 0x01) ? "CONNECT" : "BIND";

            if (!append_fmt("SOCKS4 %s ", action))
                return false;

            // -----------------------------------------------------------------
            // SOCKS4a domain
            // -----------------------------------------------------------------
            if (is_socks4a) {
                uint16_t domain_start = user_end + 1;

                if (domain_start >= length)
                    return false;

                uint16_t domain_end = 0;

                if (!find_nul(domain_start, domain_end))
                    return false;

                uint16_t domain_len =
                    domain_end - domain_start;

                if (domain_len == 0)
                    return false;

                if (!append_sanitized(
                        domain_start,
                        domain_len,
                        "Domain:",
                        "")) {
                    return false;
                }

            } else {
                // -----------------------------------------------------------------
                // SOCKS4 IPv4
                // -----------------------------------------------------------------
                if (!append_fmt(
                        "IPv4:%u.%u.%u.%u",
                        payload[4],
                        payload[5],
                        payload[6],
                        payload[7])) {
                    return false;
                }
            }

            if (!append_fmt(":%u", dst_port))
                return false;

            // Username is useful OSINT, but don't emit an empty field.
            if (user_len > 0) {
                // Keep this bounded and sanitized.
                if (!append_sanitized(
                        8,
                        user_len,
                        " [User:",
                        "]")) {
                    return false;
                }
            }

            return true;
        }

        // ---------------------------------------------------------------------
        // SOCKS4 RESPONSE
        //
        // VN is normally 0x00.
        // CD:
        //   90 = request granted
        //   91 = request rejected / failed
        //   92 = rejected because identd could not connect
        //   93 = rejected because user ID mismatch
        // ---------------------------------------------------------------------
        if (payload[1] >= 90 && payload[1] <= 93) {

            uint8_t status = payload[1];

            const char* status_text = nullptr;

            switch (status) {
                case 90:
                    status_text = "Granted";
                    break;
                case 91:
                    status_text = "Rejected";
                    break;
                case 92:
                    status_text = "Ident Failed";
                    break;
                case 93:
                    status_text = "User ID Mismatch";
                    break;
                default:
                    return false;
            }

            uint16_t dst_port =
                ((uint16_t)payload[2] << 8) |
                payload[3];

            if (!append_fmt(
                    "SOCKS4 Reply: %s IPv4:%u.%u.%u.%u:%u",
                    status_text,
                    payload[4],
                    payload[5],
                    payload[6],
                    payload[7],
                    dst_port)) {
                return false;
            }

            return true;
        }

        return false;
    }

    // =========================================================================
    // SOCKS5
    // =========================================================================
    if (payload[0] == 0x05) {

        // ---------------------------------------------------------------------
        // SOCKS5 METHOD NEGOTIATION
        //
        // VER | NMETHODS | METHODS...
        // ---------------------------------------------------------------------
        uint8_t nmethods = payload[1];

        if (nmethods == 0)
            return false;

        if (nmethods > length - 2)
            return false;

        bool no_auth = false;
        bool userpass = false;
        bool gssapi = false;

        for (uint16_t i = 0; i < nmethods; i++) {
            switch (payload[2 + i]) {
                case 0x00:
                    no_auth = true;
                    break;

                case 0x01:
                    gssapi = true;
                    break;

                case 0x02:
                    userpass = true;
                    break;

                default:
                    break;
            }
        }

        // Exact method-negotiation length is a useful discriminator.
        if (length == (uint16_t)(2 + nmethods)) {

            if (!append_str("SOCKS5 Methods: "))
                return false;

            bool first = true;

            if (no_auth) {
                if (!append_str("NoAuth"))
                    return false;
                first = false;
            }

            if (userpass) {
                if (!first && !append_str(", "))
                    return false;
                if (!append_str("UserPass"))
                    return false;
                first = false;
            }

            if (gssapi) {
                if (!first && !append_str(", "))
                    return false;
                if (!append_str("GSSAPI"))
                    return false;
                first = false;
            }

            // Don't reject completely unknown method lists. A valid SOCKS5
            // implementation may use private/vendor-defined methods.
            if (first) {
                if (!append_fmt(
                        "Other(%u)",
                        nmethods)) {
                    return false;
                }
            }

            return true;
        }

        // ---------------------------------------------------------------------
        // SOCKS5 METHOD SELECTION RESPONSE
        //
        // VER | METHOD
        // ---------------------------------------------------------------------
        if (length == 2) {

            uint8_t method = payload[1];

            const char* method_text = nullptr;

            switch (method) {
                case 0x00:
                    method_text = "NoAuth";
                    break;

                case 0x01:
                    method_text = "GSSAPI";
                    break;

                case 0x02:
                    method_text = "UserPass";
                    break;

                case 0xFF:
                    method_text = "NoAcceptableMethod";
                    break;

                default:
                    method_text = "Other";
                    break;
            }

            if (!append_fmt(
                    "SOCKS5 Method: %s",
                    method_text)) {
                return false;
            }

            return true;
        }

        // ---------------------------------------------------------------------
        // SOCKS5 USERNAME/PASSWORD SUBNEGOTIATION
        //
        // VER | ULEN | UNAME | PLEN | PASSWD
        //
        // IMPORTANT:
        // We deliberately do NOT extract or display the password.
        // ---------------------------------------------------------------------
        if (payload[0] == 0x01) {
            // This overlaps with the first byte of other protocols, so only
            // recognize this form when the internal length structure matches.

            if (length >= 3) {
                uint8_t ulen = payload[1];

                if (ulen > 0 &&
                    ulen <= length - 3) {

                    uint16_t pass_len_pos =
                        (uint16_t)(2 + ulen);

                    if (pass_len_pos < length) {

                        uint8_t plen =
                            payload[pass_len_pos];

                        uint16_t pass_start =
                            (uint16_t)(pass_len_pos + 1);

                        if (plen <= length - pass_start &&
                            pass_start + plen == length) {

                            if (!append_fmt(
                                    "SOCKS5 UserPass Auth [UserLen:%u] [Password:present]",
                                    ulen)) {
                                return false;
                            }

                            return true;
                        }
                    }
                }
            }
        }

        // ---------------------------------------------------------------------
        // SOCKS5 REQUEST / RESPONSE
        //
        // VER | CMD/REP | RSV | ATYP | ADDR | PORT
        // ---------------------------------------------------------------------
        if (length < 7)
            return false;

        uint8_t field = payload[1];
        uint8_t reserved = payload[2];
        uint8_t atyp = payload[3];

        if (reserved != 0x00)
            return false;

        uint16_t offset = 4;

        // ---------------------------------------------------------------------
        // Parse destination/bind address
        // ---------------------------------------------------------------------
        char address[128] = {0};
        size_t addr_pos = 0;

        auto append_addr_char = [&](char c) -> bool {
            if (addr_pos + 1 >= sizeof(address))
                return false;

            address[addr_pos++] = c;
            address[addr_pos] = '\0';
            return true;
        };

        // IPv4
        if (atyp == 0x01) {

            if (length - offset < 4 + 2)
                return false;

            if (!snprintf(
                    address,
                    sizeof(address),
                    "%u.%u.%u.%u",
                    payload[offset],
                    payload[offset + 1],
                    payload[offset + 2],
                    payload[offset + 3])) {
                return false;
            }

            offset += 4;
        }

        // Domain
        else if (atyp == 0x03) {

            if (length - offset < 1)
                return false;

            uint8_t domain_len = payload[offset++];

            if (domain_len == 0)
                return false;

            if (domain_len > length - offset - 2)
                return false;

            if (domain_len >= sizeof(address))
                return false;

            for (uint16_t i = 0; i < domain_len; i++) {
                uint8_t c = payload[offset + i];

                address[i] =
                    (c >= 32 && c <= 126) ?
                    (char)c :
                    '.';
            }

            address[domain_len] = '\0';
            addr_pos = domain_len;

            offset += domain_len;
        }

        // IPv6
        else if (atyp == 0x04) {

            if (length - offset < 16 + 2)
                return false;

            // Print uncompressed IPv6. It's longer, but deterministic and
            // avoids introducing a separate compression routine.
            int written = snprintf(
                address,
                sizeof(address),
                "%02X%02X:%02X%02X:%02X%02X:%02X%02X:"
                "%02X%02X:%02X%02X:%02X%02X:%02X%02X",
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
                payload[offset + 4],
                payload[offset + 5],
                payload[offset + 6],
                payload[offset + 7],
                payload[offset + 8],
                payload[offset + 9],
                payload[offset + 10],
                payload[offset + 11],
                payload[offset + 12],
                payload[offset + 13],
                payload[offset + 14],
                payload[offset + 15]
            );

            if (written < 0 ||
                (size_t)written >= sizeof(address)) {
                return false;
            }

            addr_pos = (size_t)written;
            offset += 16;
        }

        else {
            return false;
        }

        // Port must follow the address.
        if (length - offset != 2)
            return false;

        uint16_t port =
            ((uint16_t)payload[offset] << 8) |
            payload[offset + 1];

        // ---------------------------------------------------------------------
        // Determine whether this is a request or response.
        //
        // Requests use:
        //   1 CONNECT
        //   2 BIND
        //   3 UDP ASSOCIATE
        //
        // Replies use:
        //   0 success
        //   1 general failure
        //   2 connection not allowed
        //   3 network unreachable
        //   4 host unreachable
        //   5 connection refused
        //   6 TTL expired
        //   7 command not supported
        //   8 address type not supported
        //
        // Ambiguity exists because numeric values overlap, so use the
        // protocol context heuristically but conservatively.
        // ---------------------------------------------------------------------

        if (field == 0x01 ||
            field == 0x02 ||
            field == 0x03) {

            const char* command =
                (field == 0x01) ? "CONNECT" :
                (field == 0x02) ? "BIND" :
                                  "UDP ASSOCIATE";

            if (!append_fmt(
                    "SOCKS5 %s %s:%u",
                    command,
                    address,
                    port)) {
                return false;
            }

            return true;
        }

        // SOCKS5 reply
        const char* reply = nullptr;

        switch (field) {
            case 0x00:
                reply = "Success";
                break;
            case 0x01:
                reply = "GeneralFailure";
                break;
            case 0x02:
                reply = "NotAllowed";
                break;
            case 0x03:
                reply = "NetworkUnreachable";
                break;
            case 0x04:
                reply = "HostUnreachable";
                break;
            case 0x05:
                reply = "ConnectionRefused";
                break;
            case 0x06:
                reply = "TTLExpired";
                break;
            case 0x07:
                reply = "CommandUnsupported";
                break;
            case 0x08:
                reply = "AddressTypeUnsupported";
                break;
            default:
                return false;
        }

        if (!append_fmt(
                "SOCKS5 Reply: %s %s:%u",
                reply,
                address,
                port)) {
            return false;
        }

        return true;
    }

    return false;
}

bool parse_dropbox(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    if (length < 2 || payload[0] != '{') return false; // Must look like JSON
    
    char version[32] = {0};
    char namespaces[64] = {0};
    char displayname[64] = {0};
    char host_int[32] = {0};
    
    bool has_ver = extract_json_val((const char*)payload, length, "version", version, sizeof(version));
    bool has_ns = extract_json_val((const char*)payload, length, "namespaces", namespaces, sizeof(namespaces));
    bool has_name = extract_json_val((const char*)payload, length, "displayname", displayname, sizeof(displayname));
    bool has_host = extract_json_val((const char*)payload, length, "host_int", host_int, sizeof(host_int));
    
    if (!has_ver && !has_ns && !has_name && !has_host) return false;
    
    int written = snprintf(out_text, max_len, "DROPBOX:");
    bool first = true;
    
    if (has_ver) {
        written += snprintf(out_text + written, max_len - written, "%s ver=%s", first ? "" : " |", version);
        first = false;
    }
    if (has_ns) {
        written += snprintf(out_text + written, max_len - written, "%s ns=%s", first ? "" : " |", namespaces);
        first = false;
    }
    if (has_name && displayname[0]) {
        written += snprintf(out_text + written, max_len - written, "%s name=\"%s\"", first ? "" : " |", displayname);
        first = false;
    }
    if (has_host) {
        written += snprintf(out_text + written, max_len - written, "%s host=%s", first ? "" : " |", host_int);
    }
    
    return true;
}

bool parse_ephemeral_upnp(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    if (length < 16) return false;

    const char* p = (const char*)payload;
    
    // Payload Signature Gate: Only process if it starts like an SSDP response or event
    if (memcmp(p, "HTTP/1.", 7) != 0 && memcmp(p, "NOTIFY ", 7) != 0 && memcmp(p, "M-SEARCH ", 9) != 0) {
        return false;
    }

    char server[64] = {0};
    char location[64] = {0};
    bool found_something = false;

    // Sliding window for Server and Location headers
    for (int i = 0; i < length - 10; i++) {
        if (memcmp(&p[i], "Server: ", 8) == 0) {
            const char* end = &p[i+8];
            while (end < p + length && *end != '\r' && *end != '\n') end++;
            
            int copy_len = std::min((int)(end - (&p[i+8])), 63);
            memcpy(server, &p[i+8], copy_len);
            server[copy_len] = '\0';
            found_something = true;
        }
        else if (memcmp(&p[i], "Location: ", 10) == 0) {
            const char* end = &p[i+10];
            while (end < p + length && *end != '\r' && *end != '\n') end++;
            
            // Clean up the URL slightly by skipping "http://" if present to save screen space
            int offset = 10;
            if (memcmp(&p[i+10], "http://", 7) == 0) offset = 17;
            
            int copy_len = std::min((int)(end - (&p[i+offset])), 63);
            memcpy(location, &p[i+offset], copy_len);
            location[copy_len] = '\0';
            found_something = true;
        }
    }

    if (server[0] != '\0' && location[0] != '\0') {
        snprintf(out_text, max_len, "UPnP: %s @ %s", server, location);
        return true;
    } else if (server[0] != '\0') {
        snprintf(out_text, max_len, "UPnP Server: %s", server);
        return true;
    } else if (location[0] != '\0') {
        snprintf(out_text, max_len, "UPnP Loc: %s", location);
        return true;
    }
    
    return false; // Let it fall through to generic text extractors if we didn't find the juicy headers
}

