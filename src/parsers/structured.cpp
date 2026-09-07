#include <Arduino.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <algorithm>
#include "parser_common.h"
#include "structured.h"

static constexpr uint32_t MQTT_MAX_REMAINING_LENGTH = 268435455UL;

static uint32_t decode_mqtt_length(const uint8_t* p, uint16_t max_len, uint16_t& bytes_read);
static const uint8_t* extract_mqtt_string(const uint8_t* p, uint32_t remaining_len, char* out_buf, size_t max_out, uint32_t& bytes_consumed);
static bool mqtt_topic_name_valid(const uint8_t* p, uint32_t remaining_len);
static bool parse_mqtt_connect(const uint8_t* remaining, uint32_t bytes_left, char* out_text, size_t max_len, bool& is_high_value);
static bool parse_mqtt_publish(uint8_t flags, const uint8_t* remaining, uint32_t bytes_left, char* out_text, size_t max_len);

static uint32_t decode_mqtt_length(const uint8_t* p, uint16_t max_len, uint16_t& bytes_read) {
    uint32_t multiplier = 1;
    uint32_t value = 0;
    uint8_t encoded_byte;
    bytes_read = 0;
    
    do {
        if (bytes_read >= max_len || bytes_read >= 4) {
            bytes_read = 0; 
            return 0;
        }
        encoded_byte = p[bytes_read++];
        value += (encoded_byte & 127) * multiplier;
        multiplier *= 128;
    } while ((encoded_byte & 128) != 0);
    
    if (value > MQTT_MAX_REMAINING_LENGTH) {
        bytes_read = 0;
        return 0;
    }
    return value;
}

static const uint8_t* extract_mqtt_string(const uint8_t* p, uint32_t remaining_len, char* out_buf, size_t max_out, uint32_t& bytes_consumed) {
    bytes_consumed = 0;
    if (!p || remaining_len < 2) return nullptr;
    
    uint16_t str_len = (p[0] << 8) | p[1];
    uint32_t total = 2u + (uint32_t)str_len;
    
    if (remaining_len < total) return nullptr;
    bytes_consumed = total;
    
    if (out_buf && max_out > 0) {
        size_t copy_len = std::min((size_t)str_len, max_out - 1);
        memcpy(out_buf, p + 2, copy_len);
        out_buf[copy_len] = '\0';
    }
    
    return p + total;
}

static bool mqtt_topic_name_valid(const uint8_t* p, uint32_t remaining_len) {
    if (!p || remaining_len < 2) return false;
    
    uint16_t str_len = (p[0] << 8) | p[1];
    if (str_len == 0 || remaining_len < 2u + str_len) return false;

    // Scan the raw, untruncated string for illegal PUBLISH characters
    for (uint16_t i = 0; i < str_len; ++i) {
        if (p[2 + i] == '#' || p[2 + i] == '+') return false;
    }
    return true;
}

static bool parse_mqtt_connect(const uint8_t* remaining, uint32_t bytes_left, char* out_text, size_t max_len, bool& is_high_value) {
    char proto_name[10] = {0};
    uint32_t consumed = 0;
    
    const uint8_t* p = extract_mqtt_string(remaining, bytes_left, proto_name, sizeof(proto_name), consumed);
    if (!p || bytes_left < consumed + 4) return false;
    bytes_left -= consumed;

    if (strcmp(proto_name, "MQTT") != 0) return false;
    
    uint8_t protocol_level = p[0];
    if (protocol_level != 4) return false; 
    
    uint8_t connect_flags = p[1];
    if (connect_flags & 0x01) return false; 
    
    bool has_username = (connect_flags & 0x80) != 0;
    bool has_password = (connect_flags & 0x40) != 0;
    bool has_will     = (connect_flags & 0x04) != 0;
    uint8_t will_qos  = (connect_flags >> 3) & 0x03;
    bool will_retain  = (connect_flags & 0x20) != 0;
    
    if (has_password && !has_username) return false;
    
    if (!has_will) {
        if (will_qos != 0 || will_retain) return false;
    } else {
        if (will_qos == 3) return false;
    }

    p += 4; 
    bytes_left -= 4;

    char client_id[64]  = {0};      // was 32 — covers UUID-style IDs with margin
    p = extract_mqtt_string(p, bytes_left, client_id, sizeof(client_id), consumed);
    if (!p) return false;
    bytes_left -= consumed;

    char temp_out[MAX_LEAK_STR_LEN] = {0};  // was 256 — now genuinely needed given the above
    char chunk[256]      = {0};     // was 128 — must grow to avoid re-clipping username at the chunk-formatting stage
    snprintf(temp_out, sizeof(temp_out), "MQTT [CONNECT]: [Client: %s]", client_id);

    if (has_will) {
        for (int i = 0; i < 2; i++) {
            p = extract_mqtt_string(p, bytes_left, nullptr, 0, consumed);
            if (!p) return false; 
            bytes_left -= consumed;
        }
    }

    if (has_username) {
        char username[192]  = {0};      // was 32 — sized for realistic JWT/token lengths
        p = extract_mqtt_string(p, bytes_left, username, sizeof(username), consumed);
        if (!p) return false;
        bytes_left -= consumed;
        
        snprintf(chunk, sizeof(chunk), " [User: %s]", username);
        strncat(temp_out, chunk, sizeof(temp_out) - strlen(temp_out) - 1);
    }

    if (has_password) {
        p = extract_mqtt_string(p, bytes_left, nullptr, 0, consumed);
        if (!p) return false;
        bytes_left -= consumed;
        
        snprintf(chunk, sizeof(chunk), " [Password: present]");
        strncat(temp_out, chunk, sizeof(temp_out) - strlen(temp_out) - 1);
        is_high_value = true;
    }

    snprintf(out_text, max_len, "%s", temp_out);
    return true;
}

static bool parse_mqtt_publish(uint8_t flags, const uint8_t* remaining, uint32_t bytes_left, char* out_text, size_t max_len) {
    uint8_t qos = (flags >> 1) & 0x03;
    if (qos == 3) return false; 

    // Validate raw topic before extracting
    if (!mqtt_topic_name_valid(remaining, bytes_left)) return false;

    char topic[128] = {0};  // was 64
    uint32_t consumed = 0;
    
    const uint8_t* p = extract_mqtt_string(remaining, bytes_left, topic, sizeof(topic), consumed);
    if (!p) return false;
    bytes_left -= consumed;

    // Consume Packet Identifier if QoS > 0
    if (qos > 0) {
        if (bytes_left < 2) return false; 
        
        // MQTT Spec: Packet Identifier cannot be zero
        uint16_t packet_id = ((uint16_t)p[0] << 8) | (uint16_t)p[1];
        if (packet_id == 0) return false;
        
        p += 2;
        bytes_left -= 2;
    }
    
    // (p now correctly points to the start of the application payload)

    snprintf(out_text, max_len, "MQTT [PUBLISH]: [Topic: %s]", topic);
    return true;
}

bool parse_mqtt(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len, bool& is_high_value) {
    // FIXED: Explicitly reset the flag state to prevent false-positive leakage between packets
    is_high_value = false;

    if (!payload || length < 2 || !out_text || max_len < 20) return false;

    uint8_t msg_type = payload[0] >> 4;
    uint8_t flags = payload[0] & 0x0F;
    
    if (msg_type == 1 && flags != 0) return false; 

    if (msg_type != 1 && msg_type != 3) return false; 

    uint16_t len_bytes = 0;
    uint32_t remaining_length = decode_mqtt_length(&payload[1], length - 1, len_bytes);
    
    if (len_bytes == 0 || len_bytes + 1 + remaining_length > length) {
        return false; 
    }

    const uint8_t* remaining = payload + 1 + len_bytes;
    uint32_t bytes_left = remaining_length;

    if (msg_type == 1) {
        return parse_mqtt_connect(remaining, bytes_left, out_text, max_len, is_high_value);
    } else if (msg_type == 3) {
        return parse_mqtt_publish(flags, remaining, bytes_left, out_text, max_len);
    }

    return false;
}

bool parse_coap(const uint8_t* payload,
                       uint16_t length,
                       char* out_text,
                       size_t max_len) {
    if (!payload || !out_text || max_len == 0 || length < 4) {
        return false;
    }

    out_text[0] = '\0';
    size_t pos = 0;

    // ------------------------------------------------------------------------
    // Safe output helper
    // ------------------------------------------------------------------------
    auto append_fmt = [&](const char* fmt, ...) -> bool {
        if (pos >= max_len) return false;

        va_list args;
        va_start(args, fmt);

        int written = vsnprintf(
            out_text + pos,
            max_len - pos,
            fmt,
            args
        );

        va_end(args);

        if (written < 0 ||
            (size_t)written >= max_len - pos) {
            out_text[max_len - 1] = '\0';
            return false;
        }

        pos += (size_t)written;
        return true;
    };

    // ------------------------------------------------------------------------
    // 1. Fixed CoAP Header
    // ------------------------------------------------------------------------

    uint8_t ver  = (payload[0] >> 6) & 0x03;
    uint8_t type = (payload[0] >> 4) & 0x03;
    uint8_t tkl  = payload[0] & 0x0F;

    // CoAP currently uses Version 1.
    if (ver != 1) {
        return false;
    }

    // TKL values 0-8 are valid.
    // 9-15 are reserved.
    if (tkl > 8) {
        return false;
    }

    // Token must fit completely inside this packet.
    if ((uint32_t)4 + tkl > length) {
        return false;
    }

    uint8_t code = payload[1];

    uint16_t message_id =
        ((uint16_t)payload[2] << 8) |
        payload[3];

    // ------------------------------------------------------------------------
    // 2. Decode CoAP Code
    // ------------------------------------------------------------------------

    const char* code_str = "Unknown";

    switch (code) {
        // Request codes
        case 0x01: code_str = "GET";    break;
        case 0x02: code_str = "POST";   break;
        case 0x03: code_str = "PUT";    break;
        case 0x04: code_str = "DELETE"; break;

        // RFC 8132
        case 0x05: code_str = "FETCH";  break;
        case 0x06: code_str = "PATCH";  break;
        case 0x07: code_str = "iPATCH"; break;

        // 2.xx Success
        case 0x41: code_str = "2.01 Created";  break;
        case 0x42: code_str = "2.02 Deleted";  break;
        case 0x43: code_str = "2.03 Valid";    break;
        case 0x44: code_str = "2.04 Changed";  break;
        case 0x45: code_str = "2.05 Content";  break;

        // 4.xx Client Error
        case 0x80: code_str = "4.00 Bad Request";        break;
        case 0x81: code_str = "4.01 Unauthorized";       break;
        case 0x82: code_str = "4.02 Bad Option";         break;
        case 0x83: code_str = "4.03 Forbidden";          break;
        case 0x84: code_str = "4.04 Not Found";          break;
        case 0x85: code_str = "4.05 Method Not Allowed"; break;
        case 0x86: code_str = "4.06 Not Acceptable";     break;

        // 5.xx Server Error
        case 0xA0: code_str = "5.00 Internal Server Error"; break;
        case 0xA1: code_str = "5.01 Not Implemented";      break;
        case 0xA2: code_str = "5.02 Bad Gateway";           break;
        case 0xA3: code_str = "5.03 Service Unavailable";  break;
        case 0xA4: code_str = "5.04 Gateway Timeout";      break;
        case 0xA5: code_str = "5.05 Proxying Not Supported"; break;

        default:
            break;
    }

    // ------------------------------------------------------------------------
    // 3. Decode Message Type
    // ------------------------------------------------------------------------

    const char* type_str = "UNKNOWN";

    switch (type) {
        case 0: type_str = "CON"; break;
        case 1: type_str = "NON"; break;
        case 2: type_str = "ACK"; break;
        case 3: type_str = "RST"; break;
        default: return false;
    }

    // ------------------------------------------------------------------------
    // 4. Walk Token + Options
    // ------------------------------------------------------------------------

    uint16_t offset = (uint16_t)(4 + tkl);

    // CoAP option numbers are cumulative.
    uint16_t option_number = 0;

    char uri_path[64] = {0};
    char uri_query[96] = {0};
    char payload_text[64] = {0};

    bool has_uri_path = false;
    bool has_uri_query = false;
    bool has_payload_text = false;

    uint16_t content_format = 0;
    bool has_content_format = false;

    uint32_t observe_value = 0;
    bool has_observe = false;

    // ------------------------------------------------------------------------
    // 5. Option Walker
    // ------------------------------------------------------------------------

    while (offset < length) {

        // --------------------------------------------------------------------
        // Payload Marker
        // --------------------------------------------------------------------
        if (payload[offset] == 0xFF) {
            offset++;

            // A payload marker must be followed by at least one payload byte.
            if (offset >= length) {
                return false;
            }

            size_t copy_len =
                std::min(
                    (size_t)(length - offset),
                    sizeof(payload_text) - 1
                );

            size_t write_pos = 0;

            for (size_t i = 0; i < copy_len; i++) {
                uint8_t c = payload[offset + i];

                if (c >= 32 && c <= 126) {
                    payload_text[write_pos++] = (char)c;
                }
                else if (c == '\r' ||
                         c == '\n' ||
                         c == '\t') {
                    payload_text[write_pos++] = ' ';
                }
                else {
                    payload_text[write_pos++] = '.';
                }
            }

            payload_text[write_pos] = '\0';

            if (write_pos > 0) {
                has_payload_text = true;
            }

            break;
        }

        // --------------------------------------------------------------------
        // Option Header
        //
        // 4-bit delta + 4-bit length
        //
        // 0-12  = value directly
        // 13    = next byte + 13
        // 14    = next two bytes + 269
        // 15    = reserved
        // --------------------------------------------------------------------

        uint8_t option_byte = payload[offset++];

        uint16_t actual_delta =
            (uint16_t)((option_byte >> 4) & 0x0F);

        uint8_t opt_len =
            option_byte & 0x0F;

        // --------------------------------------------------------------------
        // Decode Option Delta
        // --------------------------------------------------------------------

        if (actual_delta == 13) {

            if (offset >= length) {
                return false;
            }

            actual_delta =
                (uint16_t)payload[offset++] + 13;
        }
        else if (actual_delta == 14) {

            if (length - offset < 2) {
                return false;
            }

            uint16_t ext =
                ((uint16_t)payload[offset] << 8) |
                payload[offset + 1];

            offset += 2;

            if (ext > (uint16_t)(0xFFFF - 269)) {
                return false;
            }

            actual_delta =
                (uint16_t)(269 + ext);
        }
        else if (actual_delta == 15) {

            // Reserved.
            return false;
        }

        // --------------------------------------------------------------------
        // Apply Delta to Running Option Number
        // --------------------------------------------------------------------

        if (actual_delta != 0) {

            if (option_number >
                (uint16_t)(0xFFFF - actual_delta)) {
                return false;
            }

            option_number =
                (uint16_t)(option_number + actual_delta);
        }

        // --------------------------------------------------------------------
        // Decode Option Length
        // --------------------------------------------------------------------

        uint16_t actual_len = opt_len;

        if (opt_len == 13) {

            if (offset >= length) {
                return false;
            }

            actual_len =
                (uint16_t)payload[offset++] + 13;
        }
        else if (opt_len == 14) {

            if (length - offset < 2) {
                return false;
            }

            uint16_t ext =
                ((uint16_t)payload[offset] << 8) |
                payload[offset + 1];

            offset += 2;

            if (ext > (uint16_t)(0xFFFF - 269)) {
                return false;
            }

            actual_len =
                (uint16_t)(269 + ext);
        }
        else if (opt_len == 15) {

            // Reserved.
            return false;
        }

        // --------------------------------------------------------------------
        // Option Value Must Fit Completely
        // --------------------------------------------------------------------

        if (actual_len > length - offset) {
            return false;
        }

        const uint8_t* value =
            &payload[offset];

        // --------------------------------------------------------------------
        // URI-Path Option = 11
        // --------------------------------------------------------------------

        if (option_number == 11 &&
            actual_len > 0) {

            size_t existing =
                strlen(uri_path);

            if (existing <
                sizeof(uri_path) - 1) {

                size_t available =
                    sizeof(uri_path) - 1 - existing;

                // Each URI-Path segment is separated by '/'.
                if (existing > 0 &&
                    available > 0) {

                    uri_path[existing++] = '/';
                    available--;
                }

                size_t copy_len =
                    std::min(
                        (size_t)actual_len,
                        available
                    );

                for (size_t i = 0;
                     i < copy_len;
                     i++) {

                    uint8_t c = value[i];

                    uri_path[existing++] =
                        (c >= 32 && c <= 126)
                            ? (char)c
                            : '.';
                }

                uri_path[existing] = '\0';
                has_uri_path = true;
            }
        }

        // --------------------------------------------------------------------
        // URI-Query Option = 15
        // --------------------------------------------------------------------

        else if (option_number == 15 &&
                 actual_len > 0) {

            size_t existing =
                strlen(uri_query);

            if (existing <
                sizeof(uri_query) - 1) {

                if (existing > 0) {
                    uri_query[existing++] = '&';
                }

                if (existing <
                    sizeof(uri_query) - 1) {

                    size_t available =
                        sizeof(uri_query) - 1 - existing;

                    size_t copy_len =
                        std::min(
                            (size_t)actual_len,
                            available
                        );

                    for (size_t i = 0;
                         i < copy_len;
                         i++) {

                        uint8_t c = value[i];

                        uri_query[existing++] =
                            (c >= 32 && c <= 126)
                                ? (char)c
                                : '.';
                    }

                    uri_query[existing] = '\0';
                    has_uri_query = true;
                }
            }
        }

        // --------------------------------------------------------------------
        // Content-Format Option = 12
        // --------------------------------------------------------------------

        else if (option_number == 12 &&
                 actual_len > 0 &&
                 actual_len <= 2) {

            uint16_t fmt = 0;

            for (uint16_t i = 0;
                 i < actual_len;
                 i++) {

                fmt =
                    (uint16_t)(
                        (fmt << 8) |
                        value[i]
                    );
            }

            content_format = fmt;
            has_content_format = true;
        }

        // --------------------------------------------------------------------
        // Observe Option = 6
        // --------------------------------------------------------------------

        else if (option_number == 6 &&
                 actual_len <= 3) {

            uint32_t obs = 0;

            for (uint16_t i = 0;
                 i < actual_len;
                 i++) {

                obs =
                    (obs << 8) |
                    value[i];
            }

            observe_value = obs;
            has_observe = true;
        }

        // Advance over option value.
        offset =
            (uint16_t)(offset + actual_len);
    }

    // ------------------------------------------------------------------------
    // 6. Require Something Meaningful
    // ------------------------------------------------------------------------

    if (code == 0 &&
        !has_uri_path &&
        !has_uri_query &&
        !has_payload_text &&
        !has_observe) {

        return false;
    }

    // ------------------------------------------------------------------------
    // 7. Build Output
    // ------------------------------------------------------------------------

    if (!append_fmt("CoAP: %s %s",
                    type_str,
                    code_str)) {
        return false;
    }

    if (has_uri_path) {

        if (!append_fmt(" [/%s]",
                        uri_path)) {
            return false;
        }
    }

    if (has_uri_query) {

        if (!append_fmt("?%s",
                        uri_query)) {
            return false;
        }
    }

    // ------------------------------------------------------------------------
    // Content-Format
    // ------------------------------------------------------------------------

    if (has_content_format) {

        const char* fmt_str = nullptr;

        switch (content_format) {
            case 0:
                fmt_str = "text/plain";
                break;

            case 40:
                fmt_str = "application/link-format";
                break;

            case 41:
                fmt_str = "application/xml";
                break;

            case 50:
                fmt_str = "application/json";
                break;

            case 60:
                fmt_str = "application/cbor";
                break;

            default:
                break;
        }

        if (fmt_str) {
            if (!append_fmt(" [Fmt:%s]",
                            fmt_str)) {
                return false;
            }
        }
    }

    // ------------------------------------------------------------------------
    // Observe
    // ------------------------------------------------------------------------

    if (has_observe) {

        if (!append_fmt(
                " [Observe:%lu]",
                (unsigned long)observe_value)) {
            return false;
        }
    }

    // ------------------------------------------------------------------------
    // Printable Payload
    // ------------------------------------------------------------------------

    if (has_payload_text) {

        if (!append_fmt(
                " [Data:%s]",
                payload_text)) {
            return false;
        }
    }

    return true;
}

bool parse_snmp(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    // SNMP packets are ASN.1 BER encoded. 
    // They must start with 0x30 (Sequence Tag)
    if (length < 10 || payload[0] != 0x30) return false;

    uint16_t idx = 1;
    
    // 1. Skip the Sequence Length field
    if (payload[idx] & 0x80) {
        uint8_t len_bytes = payload[idx] & 0x7F;
        idx += 1 + len_bytes;
    } else {
        idx += 1;
    }

    if (idx + 5 >= length) return false;

    // 2. Extract Version (Tag 0x02, Length 0x01)
    if (payload[idx] != 0x02 || payload[idx+1] != 0x01) return false;
    uint8_t ver = payload[idx+2];
    idx += 3;

    // SNMPv3 (ver == 3) encrypts/hashes community strings, so we only care about v1 (0) and v2c (1)
    if (ver != 0 && ver != 1) return false; 
    
    // 3. Extract Community String (Tag 0x04 for Octet String)
    if (payload[idx] != 0x04) return false;
    idx++;
    
    // String length (Assuming < 128 bytes, which is standard)
    if (payload[idx] & 0x80) return false; 
    uint8_t comm_len = payload[idx];
    idx++;

    // Bounds check
    if (idx + comm_len > length || comm_len >= 32) return false;

    char community[32] = {0};
    memcpy(community, &payload[idx], comm_len);
    
    int print_ver = (ver == 0) ? 1 : 2; // ver 0 is SNMPv1, ver 1 is SNMPv2c

    // 4. Check for default vulnerabilities
    bool is_vuln = (strcmp(community, "public") == 0 || strcmp(community, "private") == 0);

    snprintf(out_text, max_len, "SNMPv%d: '%s'%s", 
             print_ver, 
             community, 
             is_vuln ? " [! VULNERABLE !]" : "");
             
    return true;
}

bool parse_generic_json(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    const char* p = (const char*)payload;
    const char* end = p + length;
    const char* json_start = nullptr;
    const char* json_end = nullptr;

    for (int i = 0; i < length; i++) {
        if (!json_start && p[i] == '{') json_start = &p[i];
        if (p[i] == '}') json_end = &p[i];
    }
    if (json_start && !json_end) json_end = end - 1;
    if (!json_start || !json_end || json_end <= json_start) return false;
    
    // Reject binary garbage that merely happens to contain '{'/'}' bytes
    uint16_t json_len = (json_end - json_start) + 1;
    if (!looks_like_json(json_start, json_len)) return false;
    
    char model[64] = {0};
    char ip[32] = {0};
    char name[64] = {0};

    bool has_model = extract_json_val(json_start, json_len, "model", model, sizeof(model));
    if (!has_model) has_model = extract_nested_json_val(json_start, json_len, "deviceInfo", "model", model, sizeof(model));

    bool has_ip = extract_json_val(json_start, json_len, "ip", ip, sizeof(ip));
    if (!has_ip) has_ip = extract_nested_json_val(json_start, json_len, "deviceInfo", "ip", ip, sizeof(ip));

    bool has_name = extract_json_val(json_start, json_len, "name", name, sizeof(name));

    // Single header write — everything below appends onto this, nothing resets it again.
    int written = snprintf(out_text, max_len, "JSON:");
    written = std::min((int)max_len - 1, written);
    bool found_something = false;

    // --- Step 3: known high-value keys ---
    if (has_model) {
        written += snprintf(out_text + written, max_len - written, " mod=%s", model);
        written = std::min((int)max_len - 1, written);
        found_something = true;
    }
    if (has_ip) {
        written += snprintf(out_text + written, max_len - written, " ip=%s", ip);
        written = std::min((int)max_len - 1, written);
        found_something = true;
    }
    if (has_name) {
        written += snprintf(out_text + written, max_len - written, " name=%s", name);
        written = std::min((int)max_len - 1, written);
        found_something = true;
    }

    // --- Step 4: fall through unconditionally to grab keys up to depth 3 ---
    int keys_found = 0;
    int brace_depth = 0;
    bool any_root_key_written = false;
    const char* curr = json_start;

    // EXPANDED: Allow up to 15 keys to be found
    while (curr <= json_end && keys_found < 15 && written < (int)max_len - 1) {
        if (*curr == '{') {
            brace_depth++;
        } else if (*curr == '}') {
            brace_depth--;
        } 
        // EXPANDED: Dig up to 3 JSON layers deep to catch nested telemetry
        else if (*curr == '"' && brace_depth >= 1 && brace_depth <= 3) {
            const char* q_start = curr;
            const char* q_end = nullptr;
            for (const char* c = q_start + 1; c <= json_end; c++) {
                if (*c == '"' && *(c - 1) != '\\') { q_end = c; break; }
            }
            
            if (q_end) {
                const char* colon_check = q_end + 1;
                while (colon_check <= json_end && (*colon_check == ' ' || *colon_check == '\t')) colon_check++;
                
                if (colon_check <= json_end && *colon_check == ':') {
                    // EXPANDED: Allow slightly longer key names
                    int key_len = std::min((int)(q_end - (q_start + 1)), 16);

                    // Find where the value starts (skip colon + whitespace)
                    const char* val_start = colon_check + 1;
                    while (val_start <= json_end && (*val_start == ' ' || *val_start == '\t')) val_start++;

                    // EXPANDED: 64-byte buffer to accommodate full URLs
                    char value_buf[64] = {0};
                    bool has_scalar_value = false;

                    if (val_start <= json_end) {
                        if (*val_start == '"') {
                            // String value — find closing quote, respecting escaped quotes
                            const char* v_end = nullptr;
                            for (const char* c = val_start + 1; c <= json_end; c++) {
                                if (*c == '"' && *(c - 1) != '\\') { v_end = c; break; }
                            }
                            if (v_end) {
                                int vlen = std::min((int)(v_end - (val_start + 1)), (int)sizeof(value_buf) - 1);
                                memcpy(value_buf, val_start + 1, vlen);
                                value_buf[vlen] = '\0';
                                has_scalar_value = true;
                            }
                        } else if (*val_start != '{' && *val_start != '[') {
                            // Number / bool / null — scan until a JSON delimiter
                            const char* v_end = val_start;
                            while (v_end <= json_end && *v_end != ',' && *v_end != '}' &&
                                   *v_end != ']' && *v_end != ' ' && *v_end != '\t' && *v_end != '\n') {
                                v_end++;
                            }
                            int vlen = std::min((int)(v_end - val_start), (int)sizeof(value_buf) - 1);
                            memcpy(value_buf, val_start, vlen);
                            value_buf[vlen] = '\0';
                            has_scalar_value = true;
                        }
                    }

                    const char* sep = any_root_key_written ? "," : (found_something ? " keys:" : " ");
                    int n;
                    if (has_scalar_value) {
                        n = snprintf(out_text + written, max_len - written, "%s%.*s=%s",
                                     sep, key_len, q_start + 1, value_buf);
                    } else {
                        // If it's an object/array, just print the key as a breadcrumb
                        n = snprintf(out_text + written, max_len - written, "%s%.*s",
                                     sep, key_len, q_start + 1);
                    }
                    written = std::min((int)max_len - 1, written + n);
                    any_root_key_written = true;
                    keys_found++;
                }
                curr = q_end; // always skip past this quoted string
            }
        }
        curr++;
    }

    return found_something || keys_found > 0;
}

