#include <Arduino.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <algorithm>
#include "parser_common.h"
#include "web.h"

static bool extract_header(const char* p, uint16_t length, const char* target, char* out_buf, size_t max_out);

static bool extract_header(const char* p, uint16_t length, const char* target, char* out_buf, size_t max_out) {
    size_t t_len = strlen(target);
    if (length <= t_len) return false;

    for (int i = 0; i <= length - t_len; i++) {
        // Enforce boundary: Header must start at the beginning of the payload OR immediately after a newline
        if (i == 0 || p[i-1] == '\n') {
            
            // Case-insensitive match (e.g., "Host:", "host:", "HOST:")
            bool match = true;
            for (size_t j = 0; j < t_len; j++) {
                char c1 = p[i+j];
                char c2 = target[j];
                if (c1 >= 'A' && c1 <= 'Z') c1 += 32; // tolower
                if (c2 >= 'A' && c2 <= 'Z') c2 += 32; // tolower
                if (c1 != c2) {
                    match = false;
                    break;
                }
            }
            
            if (match) {
                // Slide past the header name and any subsequent spaces/tabs
                const char* val_start = &p[i + t_len];
                while (val_start < p + length && (*val_start == ' ' || *val_start == '\t')) {
                    val_start++;
                }
                
                // Read until end of line or end of payload
                const char* val_end = val_start;
                while (val_end < p + length && *val_end != '\r' && *val_end != '\n') {
                    val_end++;
                }
                
                int copy_len = val_end - val_start;
                if (copy_len > 0) {
                    copy_len = std::min(copy_len, (int)max_out - 1);
                    memcpy(out_buf, val_start, copy_len);
                    out_buf[copy_len] = '\0';
                    return true;
                }
            }
        }
    }
    return false;
}

bool parse_http_host(
    const uint8_t* payload,
    uint16_t length,
    char* out_text,
    size_t max_len
) {
    if (length < 16 ||
        payload == nullptr ||
        out_text == nullptr ||
        max_len < 20) {
        return false;
    }

    const char* p =
        reinterpret_cast<const char*>(payload);

    char first_line[128] = {0};
    char host_domain[64] = {0};
    char user_agent[64]  = {0};
    char auth_basic[64]  = {0};

    // -----------------------------------------------------
    // 1. REQUEST START LINE
    //
    // Only parse actual HTTP requests.
    // HTTP responses deliberately return false so they can
    // continue to the generic printable-run extractor.
    // -----------------------------------------------------

    if (memcmp(p, "GET ", 4) == 0 ||
        memcmp(p, "POST ", 5) == 0 ||
        memcmp(p, "PUT ", 4) == 0 ||
        memcmp(p, "HEAD ", 5) == 0) {

        const char* line_end =
            static_cast<const char*>(
                memchr(p, '\n', length)
            );

        if (!line_end) {
            return false;
        }

        size_t flen =
            static_cast<size_t>(line_end - p);

        if (flen > 0 && p[flen - 1] == '\r') {
            flen--;
        }

        size_t copy_len =
            std::min(
                flen,
                sizeof(first_line) - 1
            );

        memcpy(
            first_line,
            p,
            copy_len
        );

        first_line[copy_len] = '\0';

    } else {
        // HTTP response or unknown payload.
        // Deliberately fall through to catch-all.
        return false;
    }

    // -----------------------------------------------------
    // 2. DEEP HEADER EXTRACTION
    // -----------------------------------------------------

    bool found_host =
        extract_header(
            p,
            length,
            "Host:",
            host_domain,
            sizeof(host_domain)
        );

    bool found_ua =
        extract_header(
            p,
            length,
            "User-Agent:",
            user_agent,
            sizeof(user_agent)
        );

    bool found_auth =
        extract_header(
            p,
            length,
            "Authorization: Basic",
            auth_basic,
            sizeof(auth_basic)
        );

    // -----------------------------------------------------
    // 3. COMPACT UI STRING
    // -----------------------------------------------------

    char temp_out[MAX_LEAK_STR_LEN] = {0};

    // IMPORTANT:
    // Preserve "HTTP/1.1" in the request line so the
    // existing High-Value Triage can recognize HTTP.
    snprintf(
        temp_out,
        sizeof(temp_out),
        "%s",
        first_line
    );

    char chunk[128];

    if (found_host) {
        snprintf(
            chunk,
            sizeof(chunk),
            " [Host: %s]",
            host_domain
        );

        strncat(
            temp_out,
            chunk,
            sizeof(temp_out) - strlen(temp_out) - 1
        );
    }

    if (found_ua) {
        snprintf(
            chunk,
            sizeof(chunk),
            " [UA: %s]",
            user_agent
        );

        strncat(
            temp_out,
            chunk,
            sizeof(temp_out) - strlen(temp_out) - 1
        );
    }

    if (found_auth) {
        snprintf(
            chunk,
            sizeof(chunk),
            " [Auth: Basic %s]",
            auth_basic
        );

        strncat(
            temp_out,
            chunk,
            sizeof(temp_out) - strlen(temp_out) - 1
        );
    }

    snprintf(
        out_text,
        max_len,
        "%s",
        temp_out
    );

    return true;
}

bool parse_tls_cert(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    if (length < 24 || payload == nullptr || out_text == nullptr || max_len == 0) {
        return false;
    }

    char subject_cn[64]   = {0};
    char subject_org[64]  = {0};
    char subject_loc[32]  = {0};
    char subject_state[32]= {0};
    char subject_c[8]     = {0};

    char issuer_cn[64]    = {0};
    char issuer_org[64]   = {0};

    char san_dns[64]      = {0};
    char cert_url[64]     = {0}; 
    char cert_email[64]   = {0};
    char cert_date[32]    = {0};

    bool has_subject_cn  = false;
    bool has_subject_org = false;
    bool has_issuer_cn   = false;
    bool has_issuer_org  = false;
    bool has_cert_url    = false;
    bool has_email       = false;
    bool has_date        = false;

    for (uint16_t i = 0; i + 7 < length; i++) {
        // --- 1. X.500 RDN Attributes (OID Prefix: 06 03 55 04 XX) ---
        if (payload[i] == 0x06 && payload[i+1] == 0x03 && 
            payload[i+2] == 0x55 && payload[i+3] == 0x04) {
            
            uint8_t attr_type = payload[i+4];
            uint8_t tag_type  = payload[i+5]; // 0x13 = PrintableString, 0x0C = UTF8String, etc.
            uint8_t str_len   = payload[i+6];

            if ((tag_type == 0x13 || tag_type == 0x0C || tag_type == 0x16 || tag_type == 0x14) &&
                (i + 7 + str_len <= length) && str_len > 0) {
                
                const uint8_t* str_data = &payload[i + 7];

                switch (attr_type) {
                    case 0x03: { // Common Name (CN)
                        if (!has_issuer_cn) {
                            int copy_len = std::min((int)str_len, 63);
                            memcpy(issuer_cn, str_data, copy_len);
                            issuer_cn[copy_len] = '\0';
                            has_issuer_cn = true;
                        } else {
                            int copy_len = std::min((int)str_len, 63);
                            memcpy(subject_cn, str_data, copy_len);
                            subject_cn[copy_len] = '\0';
                            has_subject_cn = true;
                        }
                        break;
                    }
                    case 0x0A: { // Organization (O)
                        if (!has_issuer_org) {
                            int copy_len = std::min((int)str_len, 63);
                            memcpy(issuer_org, str_data, copy_len);
                            issuer_org[copy_len] = '\0';
                            has_issuer_org = true;
                        } else {
                            int copy_len = std::min((int)str_len, 63);
                            memcpy(subject_org, str_data, copy_len);
                            subject_org[copy_len] = '\0';
                            has_subject_org = true;
                        }
                        break;
                    }
                    case 0x07: { // Locality / City (L)
                        int copy_len = std::min((int)str_len, 31);
                        memcpy(subject_loc, str_data, copy_len);
                        subject_loc[copy_len] = '\0';
                        break;
                    }
                    case 0x08: { // State / Province (ST)
                        int copy_len = std::min((int)str_len, 31);
                        memcpy(subject_state, str_data, copy_len);
                        subject_state[copy_len] = '\0';
                        break;
                    }
                    case 0x06: { // Country (C)
                        int copy_len = std::min((int)str_len, 7);
                        memcpy(subject_c, str_data, copy_len);
                        subject_c[copy_len] = '\0';
                        break;
                    }
                    default:
                        break;
                }
                i += (6 + str_len);
                continue;
            }
        }

        // --- 2. Subject Alternative Name (SAN) (OID: 06 03 55 1D 11) ---
        if (payload[i] == 0x06 && payload[i+1] == 0x03 && 
            payload[i+2] == 0x55 && payload[i+3] == 0x1D && payload[i+4] == 0x11) {
            
            for (uint16_t s = i + 5; s + 2 < length && s < i + 30; s++) {
                if (payload[s] == 0x82) { // 0x82 is context tag [2] for dNSName
                    uint8_t dlen = payload[s+1];
                    if (dlen > 0 && (s + 2 + dlen <= length)) {
                        int copy_len = std::min((int)dlen, 63);
                        memcpy(san_dns, &payload[s+2], copy_len);
                        san_dns[copy_len] = '\0';
                        break;
                    }
                }
            }
        }

        // --- 3. Extract CA URLs (OCSP/CRL) (Tag 0x86 UniformResourceIdentifier) ---
        if (!has_cert_url && payload[i] == 0x86 && 
            payload[i+2] == 'h' && payload[i+3] == 't' && 
            payload[i+4] == 't' && payload[i+5] == 'p') {
            
            uint8_t url_len = payload[i+1];
            if (i + 2 + url_len <= length) {
                uint8_t start = (payload[i+6] == 's') ? 10 : 9; // skip http(s)://
                uint8_t end = start;
                while (end < url_len + 2 && payload[i + end] != '/') {
                    end++;
                }

                int domain_len = end - start;
                if (domain_len > 0 && domain_len < 63) {
                    memcpy(cert_url, &payload[i + start], domain_len);
                    cert_url[domain_len] = '\0';
                    has_cert_url = true;
                }
            }
        }

        // --- 4. Extract Email Addresses (OID: 1.2.840.113549.1.9.1) ---
        if (!has_email && i + 12 < length &&
            payload[i] == 0x06 && payload[i+1] == 0x09 &&
            payload[i+2] == 0x2A && payload[i+3] == 0x86 && payload[i+4] == 0x48 &&
            payload[i+5] == 0x86 && payload[i+6] == 0xF7 && payload[i+7] == 0x0D &&
            payload[i+8] == 0x01 && payload[i+9] == 0x09 && payload[i+10] == 0x01) {

            uint8_t str_len = payload[i+12];
            
            if (i + 13 + str_len <= length && str_len > 0 && str_len < 63) {
                memcpy(cert_email, &payload[i+13], str_len);
                cert_email[str_len] = '\0';
                has_email = true;
            }
        }

        // --- 5. Extract UTCTime (Tag 0x17) ---
        if (!has_date && payload[i] == 0x17 && payload[i+1] == 13) {
            if (i + 14 <= length && payload[i+2] >= '0' && payload[i+2] <= '9') {
                
                // Peek exactly 15 bytes ahead to see if the "Not After" date is appended
                if (i + 15 + 14 <= length && payload[i+15] == 0x17 && payload[i+16] == 13 && payload[i+17] >= '0') {
                    // We successfully caught both dates!
                    snprintf(cert_date, sizeof(cert_date), "20%c%c/%c%c/%c%c-20%c%c/%c%c/%c%c", 
                        payload[i+2], payload[i+3], payload[i+4], payload[i+5], payload[i+6], payload[i+7],
                        payload[i+17], payload[i+18], payload[i+19], payload[i+20], payload[i+21], payload[i+22]);
                    i += 28; // Fast-forward past both date blocks to save CPU cycles
                } else {
                    // Fallback: We only found the first date
                    snprintf(cert_date, sizeof(cert_date), "20%c%c/%c%c/%c%c", 
                        payload[i+2], payload[i+3], payload[i+4], payload[i+5], payload[i+6], payload[i+7]);
                    i += 14; 
                }
                has_date = true;
            }
        }
    }

    // Determine target entity: Subject takes precedence, fall back to SAN or Issuer
    const char* target_host = has_subject_cn ? subject_cn : (san_dns[0] != '\0' ? san_dns : issuer_cn);
    const char* target_org  = has_subject_org ? subject_org : issuer_org;

    // Fail if we didn't find ANY recognizable string
    if (target_host[0] == '\0' && target_org[0] == '\0' && cert_url[0] == '\0' && cert_email[0] == '\0') {
        return false; 
    }

    // Build rich location token if present: " (Spring, Texas US)"
    char geo_tag[48] = {0};
    if (subject_loc[0] != '\0' || subject_state[0] != '\0' || subject_c[0] != '\0') {
        if (subject_loc[0] != '\0' && subject_state[0] != '\0') {
            snprintf(geo_tag, sizeof(geo_tag), " (%s, %s %s)", subject_loc, subject_state, subject_c);
        } else if (subject_state[0] != '\0') {
            snprintf(geo_tag, sizeof(geo_tag), " (%s %s)", subject_state, subject_c);
        } else if (subject_c[0] != '\0') {
            snprintf(geo_tag, sizeof(geo_tag), " (%s)", subject_c);
        }
    }

    // Build the CA tag
    char ca_tag[70] = {0};
    if (has_issuer_cn && strcmp(target_host, issuer_cn) != 0) {
        snprintf(ca_tag, sizeof(ca_tag), " [CA:%s]", issuer_cn);
    }
    
    // Chain together our extra intelligence to save space
    char ext_tag[128] = {0};
    int ext_idx = 0;
    if (has_email) ext_idx += snprintf(ext_tag + ext_idx, sizeof(ext_tag) - ext_idx, " [E: %s]", cert_email);
    if (has_cert_url) ext_idx += snprintf(ext_tag + ext_idx, sizeof(ext_tag) - ext_idx, " [URI: %s]", cert_url);
    if (has_date) ext_idx += snprintf(ext_tag + ext_idx, sizeof(ext_tag) - ext_idx, " [Valid:%s]", cert_date);

    // Format output
    if (target_host[0] != '\0' && target_org[0] != '\0') {
        snprintf(out_text, max_len, "TLS Cert: %s|%s%s%s%s", target_host, target_org, geo_tag, ca_tag, ext_tag);
    } else if (target_host[0] != '\0') {
        snprintf(out_text, max_len, "TLS Cert: %s%s%s%s", target_host, geo_tag, ca_tag, ext_tag);
    } else if (target_org[0] != '\0') {
        snprintf(out_text, max_len, "TLS Cert Org: %s%s%s%s", target_org, geo_tag, ca_tag, ext_tag);
    } else {
        snprintf(out_text, max_len, "TLS Cert Info:%s", ext_tag);
    }

    return true;
}

bool parse_tls_sni(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    const char prefix[] = "HTTPS SNI: ";
    const size_t prefix_len = sizeof(prefix) - 1;

    // Minimum captured length required for our fixed-offset ClientHello parsing.
    if (length < 44 || payload == nullptr || out_text == nullptr || max_len <= prefix_len) {
        return false; 
    }

    int32_t start_offset = -1;
    uint32_t record_end = 0;

    // --- 1. THE SLIDING WINDOW (A-MSDU Bypass & Validation) ---
    for (uint16_t i = 0; i <= length - 44; i++) {

        // Check for TLS Handshake (0x16), Major Version (0x03), Valid Minor Version (0x00-0x04), ClientHello (0x01)
        if (payload[i] == 0x16 && 
            payload[i+1] == 0x03 && 
            payload[i+2] <= 0x04 &&   // <-- TIGHTER FILTER: Covers SSL 3.0 through theoretical TLS 1.4
            payload[i+5] == 0x01) {       

            uint16_t record_len = ((uint16_t)payload[i+3] << 8) | payload[i+4];
            uint32_t hs_len = ((uint32_t)payload[i+6] << 16) |
                              ((uint32_t)payload[i+7] << 8)  |
                               payload[i+8];

            // Safety Check 1: TLS record must fit entirely inside our captured buffer
            if ((uint32_t)i + 5 + record_len > length) {
                continue;
            }

            // Safety Check 2: The ClientHello (4-byte header + body) must fit inside its own TLS record
            if (hs_len + 4 > record_len) {
                continue;
            }

            // Passed all physical bounds checks. Lock onto this offset!
            start_offset = i;
            
            // --- STRICT RECORD BOUNDARY ---
            record_end = start_offset + 5 + record_len;
            break;
        }
    }

    if (start_offset == -1) return false;

    // Anchor the 32-bit cursor to the start of the Session ID length byte
    uint32_t cursor = start_offset + 43; 

    // 2. Skip Session ID
    if (cursor >= record_end) return false;
    uint8_t sid_len = payload[cursor++];
    if (sid_len > record_end - cursor) return false;
    cursor += sid_len;

    // 3. Skip Cipher Suites
    if (cursor + 2 > record_end) return false;
    uint16_t cipher_len = ((uint16_t)payload[cursor] << 8) | payload[cursor + 1];
    cursor += 2;
    if (cipher_len > record_end - cursor) return false;
    cursor += cipher_len;

    // 4. Skip Compression Methods
    if (cursor >= record_end) return false;
    uint8_t comp_len = payload[cursor++];
    if (comp_len > record_end - cursor) return false;
    cursor += comp_len;

    // 5. Get Extensions Length
    if (cursor + 2 > record_end) return false; 
    uint16_t ext_total_len = ((uint16_t)payload[cursor] << 8) | payload[cursor + 1];
    cursor += 2;

    // Explicitly fail if extensions declare a length that bleeds outside the known TLS record
    if (ext_total_len > record_end - cursor) return false;
    
    uint32_t ext_end = cursor + ext_total_len;

    // 6. Walk the Extensions List
    while (cursor + 4 <= ext_end) {
        uint16_t ext_type = (payload[cursor] << 8) | payload[cursor + 1];
        uint16_t ext_len = (payload[cursor + 2] << 8) | payload[cursor + 3];
        cursor += 4;

        // Ensure this specific extension doesn't bleed past the total extensions block
        if (ext_len > ext_end - cursor) return false;

        if (ext_type == 0x0000) { // Server Name Indication (SNI)
            
            // Validate the SNI list length before reading
            if (ext_len < 2) return false;
            uint16_t list_len = ((uint16_t)payload[cursor] << 8) | payload[cursor + 1];
            if (list_len > ext_len - 2) return false;

            uint32_t list_end = cursor + 2 + list_len;
            uint32_t list_cursor = cursor + 2;

            // Walk to list_end instead of ext_end
            while (list_cursor + 3 <= list_end) {
                uint8_t name_type = payload[list_cursor];
                uint16_t name_len = ((uint16_t)payload[list_cursor + 1] << 8) | payload[list_cursor + 2];
                list_cursor += 3;

                // Ensure the individual domain name doesn't bleed past the SNI list boundary
                if (name_len > list_end - list_cursor) return false;

                if (name_type == 0x00) { // 0x00 designates a DNS Hostname
                    if (name_len > 0) {
                        int copy_len = std::min((int)name_len, (int)(max_len - prefix_len - 1)); 
                        snprintf(out_text, max_len, "%s%.*s", prefix, copy_len, &payload[list_cursor]);
                        return true;
                    }
                }
                list_cursor += name_len;
            }
            return false; // Found SNI but couldn't resolve string
        }
        
        cursor += ext_len; // Jump to the next extension
    }

    return false;
}

bool parse_ssh(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    // Defensive entry guard: valid pointers, minimum payload size, and sufficient output buffer
    if (length < 10 || payload == nullptr || out_text == nullptr || max_len < 16) {
        return false;
    }

    // SSH banners are strictly required to sit at the absolute beginning of the payload
    if (memcmp(payload, "SSH-", 4) == 0) {
        const char* p = (const char*)payload;
        const char* end = p;
        const char* payload_end = p + length;

        // Read until the end of the line (usually \r\n)
        while (end < payload_end && *end != '\r' && *end != '\n') end++;

        // Safely bound the copy to our UI limits
        int copy_len = std::min((int)(end - p), (int)(max_len - 15));
        if (copy_len > 0) {
            snprintf(out_text, max_len, "SSH Banner: %.*s", copy_len, p);
            return true;
        }
    }
    return false;
}

bool parse_rdp(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    // Defensive entry guard: valid pointers, minimum payload size, and sufficient output buffer
    if (length < 17 || payload == nullptr || out_text == nullptr || max_len < 40) {
        return false;
    }

    // Fast gate: RDP X.224 Connection Requests ride on top of TPKT.
    // TPKT headers always start with Version 3 (0x03) and Reserved (0x00).
    if (payload[0] != 0x03 || payload[1] != 0x00) return false;

    const char* p = (const char*)payload;
    const char* payload_end = p + length;
    
    // The needle is 17 bytes long. Signed int prevents underflow.
    int max_i = (int)length - 17; 

    // Sliding window to hunt for the routing cookie
    for (int i = 0; i <= max_i; i++) {
        if (memcmp(&p[i], "Cookie: mstshash=", 17) == 0) {
            const char* user_start = &p[i + 17];
            const char* user_end = user_start;
            
            // Read the username until we hit a newline or space
            while (user_end < payload_end && *user_end != '\r' && *user_end != '\n' && *user_end != ' ') {
                user_end++;
            }

            int copy_len = std::min((int)(user_end - user_start), (int)(max_len - 30));
            if (copy_len > 0) {
                snprintf(out_text, max_len, "RDP Connect [User: %.*s]", copy_len, user_start);
                return true;
            }
        }
    }
    
    // Fallback: It passed the TPKT gate but didn't have a username cookie.
    // Is it actually an initial Connection Request (X.224 CR)? 
    // Byte 5 must be 0xE0 for a Connection Request.
    if (length > 5 && payload[5] == 0xE0) {
        snprintf(out_text, max_len, "RDP Connection Request (No Cookie)");
        return true;
    }

    // It is just ordinary TPKT-framed encrypted RDP traffic (e.g., mouse movements).
    // Silently ignore it to prevent display spam.
    return false;
}

