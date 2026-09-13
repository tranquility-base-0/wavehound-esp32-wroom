#include <Arduino.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <algorithm>
#include "parser_common.h"

const char* getSubtypeStr(uint8_t subtype) {
    switch (subtype) {
        case 0:  return "Data";
        case 4:  return "Null";
        case 8:  return "QoS Data";
        case 9:  return "QoS+CF-Ack";
        case 10: return "QoS+CF-Poll";
        case 11: return "QoS+Ack+Poll";
        case 12: return "QoS Null";
        case 14: return "QoS CF-Poll";
        case 15: return "QoS Ack+Poll";
        default: return "Mgmt/Ctrl";
    }
}

const char* getDirectionStr(uint8_t dir) {
    switch(dir) {
        case 0: return "STA>STA";
        case 1: return "STA>AP";
        case 2: return "AP>STA";
        case 3: return "WDS";
        default: return "???";
    }
}

const char* getProtocolStr(uint8_t proto) {
    if (proto == 17) return "UDP";
    if (proto == 6) return "TCP";
    if (proto == 1) return "ICMP";
    if (proto == 58) return "ICMPv6";
    return "RAW";
}

void getIpString(uint8_t version, const uint8_t* ip_bytes, char* out_str, size_t max_len) {
    if (version == 4) {
        snprintf(out_str, max_len, "%d.%d.%d.%d",
                 ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
    } else if (version == 6) {
        // Now extracting the full 16-byte (128-bit) IPv6 address
        snprintf(out_str, max_len, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                 ip_bytes[4], ip_bytes[5], ip_bytes[6], ip_bytes[7],
                 ip_bytes[8], ip_bytes[9], ip_bytes[10], ip_bytes[11],
                 ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]);
    } else {
        snprintf(out_str, max_len, "None");
    }
}

uint32_t hash_flow(const uint8_t* data, size_t len, uint16_t sport, uint16_t dport) {
    uint32_t hash = 2166136261u;

    // Hash the ports first
    hash ^= (sport & 0xFF); hash *= 16777619;
    hash ^= (sport >> 8);   hash *= 16777619;
    hash ^= (dport & 0xFF); hash *= 16777619;
    hash ^= (dport >> 8);   hash *= 16777619;

    // Hash the payload
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619;
    }
    return hash;
}

uint8_t getBitrateMbps(wifi_promiscuous_pkt_t *pkt) {
  if (pkt->rx_ctrl.sig_mode == 0) {
    // Legacy 802.11b/g
    switch(pkt->rx_ctrl.rate) {
      case 0x00: return 1;
      case 0x01: return 2;
      case 0x02: return 5; // 5.5 Mbps rounded down
      case 0x03: return 11;
      case 0x0B: return 6;
      case 0x0F: return 9;
      case 0x0A: return 12;
      case 0x0E: return 18;
      case 0x09: return 24;
      case 0x0D: return 36;
      case 0x08: return 48;
      case 0x0C: return 54;
      default: return 0;
    }
  } else {
    // 802.11n (HT20 / HT40) MCS Index
    switch(pkt->rx_ctrl.mcs) {
      case 0: return 6;  // 6.5 Mbps
      case 1: return 13;
      case 2: return 19; // 19.5 Mbps
      case 3: return 26;
      case 4: return 39;
      case 5: return 52;
      case 6: return 58; // 58.5 Mbps
      case 7: return 65;
      default: return 0;
    }
  }
}

bool extract_printable_runs(const uint8_t* data, uint16_t len, char* out, size_t max_len,
                             uint8_t min_run, bool flatten_ws,
                             const char* separator) {

    if (!data || !out || max_len < 16 || len == 0) return false;

    uint16_t out_idx = 0;
    uint16_t consecutive = 0;
    uint16_t printable_count = 0;
    size_t sep_len = strlen(separator);

    // --- Phase 1: Raw Extraction ---
    for (uint16_t i = 0; i < len && out_idx < (max_len - 4); i++) {
        char c = (char)data[i];
        bool is_ws = (c == '\n' || c == '\r' || c == '\t');
        bool is_printable = (c >= 32 && c <= 126) || (flatten_ws && is_ws);

        if (is_printable) {
            consecutive++;
            if (consecutive == min_run) {
                for (int back = min_run; back >= 1 && out_idx < max_len - 1; back--) {
                    char rc = (char)data[i - back + 1];
                    if (flatten_ws && (rc == '\n' || rc == '\r' || rc == '\t')) rc = ' ';
                    out[out_idx++] = rc;
                }
                printable_count += min_run;
            } else if (consecutive > min_run && out_idx < max_len - 1) {
                out[out_idx++] = (flatten_ws && is_ws) ? ' ' : c;
                printable_count++;
            }
        } else {
            if (consecutive >= min_run && out_idx + sep_len < max_len - 1) {
                memcpy(out + out_idx, separator, sep_len);
                out_idx += sep_len;
            }
            consecutive = 0;
        }
    }

    out[out_idx] = '\0';

    // First line of defense: Must have at least 12 printable characters total
    if (printable_count < 12) return false;

    // --- Phase 2: Signature Classification ---
    const char* tag = nullptr;

    if (strstr(out, "HTTP/1.")) tag = "[HTTP]";
    else if (strstr(out, "<?xml") || (strchr(out, '<') && strchr(out, '>'))) tag = "[XML]";
    else if (strstr(out, "{\"") && strstr(out, "\":")) tag = "[JSON]";
    else if (strstr(out, "ocsp.") || strstr(out, "/ocsp")) tag = "[OCSP]";
    else if (strstr(out, ".crl")) tag = "[CRL]";
    else if (strstr(out, ".crt") || strstr(out, "cacerts.")) tag = "[CERT-URI]";
    else if (strstr(out, "://")) tag = "[URI]";
    else tag = "[TEXT]"; // Semantically precise fallback

    // --- Phase 3: Prepend Tag ---
    size_t tag_len = strlen(tag);
    if (out_idx + tag_len + 1 < max_len) {
        memmove(out + tag_len + 1, out, out_idx + 1);
        memcpy(out, tag, tag_len);
        out[tag_len] = ' ';
    }

    return true;
}

void translateProtocolStrings(char* text) {
    char temp_buffer[MAX_LEAK_STR_LEN];
    int len = strlen(text);
    // 0. Global Cleanup: Strip trailing "x V" or "xV" artifacts
    while (len > 0 && text[len-1] == ' ') { text[len-1] = '\0'; len--; } // Trim trailing spaces

    if (len >= 3 && text[len-3] == 'x' && text[len-2] == ' ' && text[len-1] == 'V') {
        text[len-3] = '\0';
        len -= 3;
    } else if (len >= 2 && text[len-2] == 'x' && text[len-1] == 'V') {
        text[len-2] = '\0';
        len -= 2;
    }

    while (len > 0 && text[len-1] == ' ') { text[len-1] = '\0'; len--; } // Trim again if exposed

    // ----------------------------------------------------
    // 2. mDNS IPv4 Reverse Lookup
    // ----------------------------------------------------
    char* in_addr = strstr(text, "in-addr arpa");
    if (in_addr != NULL) {
        int o1, o2, o3, o4;
        char* ptr = text;

        while (ptr < in_addr) {
            if (sscanf(ptr, "%d %d %d %d in-addr", &o4, &o3, &o2, &o1) == 4) {
                snprintf(temp_buffer, MAX_LEAK_STR_LEN, "mDNS Reverse Query: %d.%d.%d.%d", o1, o2, o3, o4);
                strncpy(text, temp_buffer, MAX_LEAK_STR_LEN);
                return;
            }
            ptr++;
        }
    }

    // ----------------------------------------------------
    // 3. mDNS IPv6 Reverse Lookup (Inline Replacement)
    // ----------------------------------------------------
    char* ip6 = strstr(text, "ip6");
    if (ip6 != NULL) {
        char nibbles[32];
        int n_idx = 0;
        char* ptr = ip6 - 1;

        while (ptr >= text && n_idx < 32) {
            char c = *ptr;
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
                nibbles[n_idx++] = c;
            }
            ptr--;
        }

        if (n_idx == 32) {
            char ipv6_str[40];
            int out_idx = 0;

            for (int i = 0; i < 32; i++) {
                ipv6_str[out_idx++] = nibbles[i];
                if (i % 4 == 3 && i != 31) {
                    ipv6_str[out_idx++] = ':';
                }
            }
            ipv6_str[out_idx] = '\0';

            // ptr is now resting just before the first parsed hex character.
            // We stitch: [Prefix] + [Clean IPv6] + [".ip6" Suffix]
            int prefix_len = (ptr + 1) - text;

            snprintf(temp_buffer, MAX_LEAK_STR_LEN, "%.*s%s.%s", prefix_len, text, ipv6_str, ip6);
            strncpy(text, temp_buffer, MAX_LEAK_STR_LEN);
            return;
        }
    }

    // ----------------------------------------------------
    // 4. Google Cast App ID Lookup (Inline Replacement)
    // ----------------------------------------------------
    if (strstr(text, "googlecast") != NULL) {
        struct CastApp {
            const char* id;
            const char* name;
        };

        static const CastApp castDictionary[] = {
    {"233637DE", "YouTube"},
    {"CA5E8412", "Netflix"},
    {"CC1AD845", "Default Media Receiver"},
    {"CFE7FEDA", "Default Media Receiver"},
    {"E8C28D3C", "Backdrop"},
    {"674A0243", "Android TV Media Shell"},
    {"8E6C866D", "Android TV Guest Mode"},
    {"CC32E753", "Spotify"},
    {"9AC194DC", "Plex"},
    {"3927FA74", "BubbleUPnP/Spotify"},
    {"84912283", "Dashcast"},
    {"0F5096E8", "Chrome Mirroring"},
    {"85CDB22F", "Cast Streaming Audio"},
    {"B3DCF968", "Twitch"}
};

        int numApps = sizeof(castDictionary) / sizeof(castDictionary[0]);

        for (int i = 0; i < numApps; i++) {
            // Use a pointer that updates so we can find multiple of the same ID
            char* match = strstr(text, castDictionary[i].id);

            while (match != NULL) {
                int prefix_len = match - text;
                char* suffix = match + strlen(castDictionary[i].id);

                snprintf(temp_buffer, MAX_LEAK_STR_LEN, "%.*s[%s]%s", prefix_len, text, castDictionary[i].name, suffix);
                strncpy(text, temp_buffer, MAX_LEAK_STR_LEN);

                // Re-evaluate on the newly modified string to check for duplicates
                match = strstr(text, castDictionary[i].id);
            }
        }
        // Notice: The return; statement is completely removed.

        // Optional fallback: If it's a Cast packet but the App ID isn't in our dictionary,
        // we can still clean it up slightly to just say it's an unknown Cast App
        // snprintf(temp_buffer, MAX_LEAK_STR_LEN, "Google Cast: Unknown App");
        // strncpy(text, temp_buffer, MAX_LEAK_STR_LEN);
        // return;
    }
}

int copy_printable_ascii(const uint8_t* src, int len, char* dst, int max_len) {
    if (!src || !dst || max_len <= 0) return 0;
    int out_idx = 0;
    for (int i = 0; i < len && out_idx < max_len - 1; i++) {
        char c = src[i];
        dst[out_idx++] = (c >= 32 && c <= 126) ? c : '.';
    }
    dst[out_idx] = '\0';
    return out_idx;
}

void format_ipv6_addr(const uint8_t* ip, char* buf, size_t max_len) {
    snprintf(buf, max_len, "%x:%x:%x:%x:%x:%x:%x:%x",
             (ip[0]<<8)|ip[1], (ip[2]<<8)|ip[3], (ip[4]<<8)|ip[5], (ip[6]<<8)|ip[7],
             (ip[8]<<8)|ip[9], (ip[10]<<8)|ip[11], (ip[12]<<8)|ip[13], (ip[14]<<8)|ip[15]);
}

int decode_dns_name(const uint8_t* payload, int end_offset, int offset, char* out_name, int max_name_len) {
    if (!payload || !out_name || max_name_len <= 0) return -1;

    out_name[0] = '\0';

    int original_offset = offset;
    int out_idx = 0;
    bool jumped = false;
    int jumps = 0;

    while (offset < end_offset) {
        uint8_t len = payload[offset];

        if (len == 0) {
            if (!jumped) original_offset = offset + 1;
            break;
        }

        if ((len & 0xC0) == 0xC0) {
            if (offset + 1 >= end_offset || jumps >= 16) {
                out_name[out_idx] = '\0';
                return -1;
            }
            if (!jumped) original_offset = offset + 2;

            int ptr = ((len & 0x3F) << 8) | payload[offset + 1];

            if (ptr >= offset) {           // backward-only
                out_name[out_idx] = '\0';
                return -1;
            }

            offset = ptr;
            jumped = true;
            jumps++;
            continue;
        }

        if (len > 63 || offset + 1 > end_offset || len > end_offset - offset - 1) {
            out_name[out_idx] = '\0';
            return -1;
        }

        offset++;
        if (out_idx > 0 && out_idx < max_name_len - 1) out_name[out_idx++] = '.';

        for (int i = 0; i < len; i++) {
            if (out_idx < max_name_len - 1) {
                uint8_t c = payload[offset + i];
                out_name[out_idx++] = (c < 32 || c == 127) ? '.' : (char)c;
            }
        }

        offset += len;
        if (!jumped) original_offset = offset;
    }

    out_name[out_idx] = '\0';
    return original_offset;
}

void format_reverse_lookups(char* text, size_t max_len) {
    // 1. Entry Guard: Match defensive conventions applied everywhere else
    if (text == nullptr || max_len == 0) return;

    // 2. VLA Removal: Use compile-time constant to enforce stack ceiling
    char temp_buffer[MAX_LEAK_STR_LEN];

    // Ensure we don't write past our fixed buffer if max_len is somehow larger
    size_t safe_len = (max_len < MAX_LEAK_STR_LEN) ? max_len : MAX_LEAK_STR_LEN;

    // ----------------------------------------------------
    // 1. IPv4 Reverse Lookup (.in-addr.arpa)
    // ----------------------------------------------------
    char* in_addr = strstr(text, "in-addr");
    if (in_addr != nullptr) {
        int o1, o2, o3, o4;
        char* ptr = text;

        while (ptr < in_addr) {
            if (sscanf(ptr, "%d.%d.%d.%d.in-addr", &o4, &o3, &o2, &o1) == 4) {
                // 3. Octet Range Validation: Protect against integer overflow/garbage
                if (o1 >= 0 && o1 <= 255 && o2 >= 0 && o2 <= 255 &&
                    o3 >= 0 && o3 <= 255 && o4 >= 0 && o4 <= 255) {

                    int prefix_len = ptr - text;
                    snprintf(temp_buffer, safe_len, "%.*sReverse Query: %d.%d.%d.%d",
                             prefix_len, text, o1, o2, o3, o4);
                    strncpy(text, temp_buffer, safe_len);
                    return;
                }
            }
            ptr++;
        }
    }

    // ----------------------------------------------------
    // 2. IPv6 Reverse Lookup (.ip6.arpa)
    // ----------------------------------------------------
    char* ip6 = strstr(text, "ip6");
    if (ip6 != nullptr) {
        char nibbles[32];
        int n_idx = 0;
        char* ptr = ip6 - 1;

        // Walk backwards to collect exactly 32 hex nibbles
        while (ptr >= text && n_idx < 32) {
            char c = *ptr;
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
                nibbles[n_idx++] = c;
            }
            ptr--;
        }

        if (n_idx == 32) {
            char ipv6_str[40];
            int out_idx = 0;

            // Reconstruct the IPv6 address with colons
            for (int i = 0; i < 32; i++) {
                ipv6_str[out_idx++] = nibbles[i];
                if (i % 4 == 3 && i != 31) {
                    ipv6_str[out_idx++] = ':';
                }
            }
            ipv6_str[out_idx] = '\0';

            int prefix_len = (ptr + 1) - text;
            snprintf(temp_buffer, safe_len, "%.*s%s", prefix_len, text, ipv6_str);
            strncpy(text, temp_buffer, safe_len);
            return;
        }
    }
}

void compress_ipv6(const char* full, char* out, size_t out_size) {
    if (out_size == 0) return;
    out[0] = '\0';

    const char* g_start[8];
    int g_len[8];
    int g_count = 0;

    const char* p = full;
    while (*p && g_count < 8) {
        g_start[g_count] = p;
        const char* colon = strchr(p, ':');
        g_len[g_count] = colon ? (int)(colon - p) : (int)strlen(p);
        g_count++;
        if (!colon) break;
        p = colon + 1;
    }

    bool is_zero[8] = {false};
    for (int i = 0; i < g_count; i++) {
        bool z = true;
        for (int j = 0; j < g_len[i]; j++) {
            if (g_start[i][j] != '0') { z = false; break; }
        }
        is_zero[i] = z;
    }

    int best_start = -1, best_len = 0, run_start = -1, run_len = 0;
    for (int i = 0; i < g_count; i++) {
        if (is_zero[i]) {
            if (run_start == -1) run_start = i;
            run_len++;
            if (run_len > best_len) { best_len = run_len; best_start = run_start; }
        } else {
            run_start = -1;
            run_len = 0;
        }
    }
    bool collapse = best_len >= 2;
    int collapse_end = best_start + best_len;

    size_t idx = 0;
    auto put = [&](char c) { if (idx + 1 < out_size) out[idx++] = c; };

    for (int i = 0; i < g_count; ) {
        if (collapse && i == best_start) {
            put(':');
            put(':');
            i = collapse_end;
            continue;
        }
        int j = 0;
        while (j < g_len[i] - 1 && g_start[i][j] == '0') j++;
        for (; j < g_len[i]; j++) put(g_start[i][j]);
        i++;
        if (i < g_count && !(collapse && i == best_start)) put(':');
    }

    out[idx < out_size ? idx : out_size - 1] = '\0';
}

void trim_ascii(char* s) {
    if (!s || !*s) return;

    char* start = s;
    while (*start && isspace((unsigned char)*start))
        start++;

    if (start != s)
        memmove(s, start, strlen(start) + 1);

    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1]))
        s[--n] = '\0';
}

bool extract_xml_value(const char* p, uint16_t length, const char* tag_suffix, char* out_buf, size_t max_out) {
    // Hardened entry guard
    if (!p || !tag_suffix || !out_buf || max_out < 2) return false;

    size_t t_len = strlen(tag_suffix);
    if (length < t_len) return false;

    const char* end = p + length;

    for (int i = 0; i <= length - t_len; i++) {
        bool match = true;
        for (size_t j = 0; j < t_len; j++) {
            if (p[i+j] != tag_suffix[j]) {
                match = false;
                break;
            }
        }

        // Fully tightened heuristic: strictly requires the start of a tag or namespace
        if (match && (i == 0 || p[i-1] == '<' || p[i-1] == ':')) {
            const char* val_start = &p[i + t_len];
            const char* val_end = val_start;

            while (val_end < end && *val_end != '<') {
                val_end++;
            }

            int copy_len = val_end - val_start;

            // Explicit defensive check
            if (copy_len <= 0) continue;

            copy_len = std::min(copy_len, (int)max_out - 1);
            memcpy(out_buf, val_start, copy_len);
            out_buf[copy_len] = '\0';
            return true;
        }
    }
    return false;
}

bool extract_json_val(const char* payload, uint16_t len, const char* key, char* out, size_t out_max) {
    char qkey[32];
    snprintf(qkey, sizeof(qkey), "\"%s\"", key);
    int qlen = strlen(qkey);

    const char* end = payload + len;
    const char* found = nullptr;

    // Bounded search for the key (e.g., "displayname")
    for (const char* curr = payload; curr <= end - qlen; curr++) {
        if (memcmp(curr, qkey, qlen) == 0) {
            found = curr;
            break;
        }
    }

    if (!found) return false;

    const char* p = found + qlen;
    while (p < end && *p != ':') p++;
    if (p >= end) return false;
    p++; // skip ':'

    while (p < end && (*p == ' ' || *p == '\t')) p++; // skip whitespace
    if (p >= end) return false;

    int i = 0;
    bool in_quotes = (*p == '"');
    int bracket_depth = 0; // Tracks [ ] arrays so we don't break on inner commas

    if (in_quotes) p++; // skip opening quote

    while (p < end && i < (int)out_max - 1) {
        if (in_quotes) {
            if (*p == '"') break; // end of string
        } else {
            if (*p == '[') bracket_depth++;
            else if (*p == ']') bracket_depth--;

            // Break on comma only if we aren't inside an array literal
            if (bracket_depth == 0 && (*p == ',' || *p == '}' || *p == '\r' || *p == '\n')) break;
        }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return i > 0;
}

bool extract_nested_json_val(const char* json, uint16_t json_len,
                              const char* outer_key, const char* inner_key,
                              char* out, size_t out_max) {
    char pattern[32];
    int plen = snprintf(pattern, sizeof(pattern), "\"%s\"", outer_key);

    const char* search_end = json + json_len - plen;
    const char* key_pos = nullptr;
    for (const char* c = json; c <= search_end; c++) {
        if (memcmp(c, pattern, plen) == 0) { key_pos = c; break; }
    }
    if (!key_pos) return false;

    // Find the '{' that opens this key's object value
    const char* json_end = json + json_len;
    const char* obj_start = key_pos + plen;
    while (obj_start < json_end && *obj_start != '{') obj_start++;
    if (obj_start >= json_end) return false;

    // Match the closing brace for THIS object only
    int depth = 1;
    const char* obj_end = obj_start + 1;
    while (obj_end < json_end && depth > 0) {
        if (*obj_end == '{') depth++;
        else if (*obj_end == '}') depth--;
        obj_end++;
    }
    if (depth != 0) return false; // truncated mid-object — don't guess

    return extract_json_val(obj_start, (uint16_t)(obj_end - obj_start), inner_key, out, out_max);
}

bool looks_like_json(const char* s, uint16_t len) {
    int depth = 0;
    bool in_string = false;
    for (uint16_t i = 0; i < len; i++) {
        char c = s[i];
        if (in_string) {
            if (c == '\\') { i++; continue; }
            if (c == '"') in_string = false;
            continue;
        }
        if (c == '"') { in_string = true; continue; }
        if (c == '{') { depth++; continue; }
        if (c == '}') { depth--; if (depth < 0) return false; continue; }
        if (!(isspace((unsigned char)c) || strchr(":,[]-+.eEtrufalsn0123456789", c))) {
            return false; // a byte json.loads() would choke on
        }
    }
    return true; // depth may be >0 here — that's fine, that's the truncation case
}

int decode_dns_search_list(const uint8_t* data,
                           int data_len,
                           char* out,
                           int max_len) {

    if (!data || !out || data_len <= 0 || max_len <= 0)
        return -1;

    out[0] = '\0';

    int pos = 0;
    int out_idx = 0;
    bool first_domain = true;

    while (pos < data_len) {

        // Padding / end of domain list.
        if (data[pos] == 0) {
            pos++;
            continue;
        }

        int domain_start = pos;
        int domain_len = 0;
        bool domain_valid = true;

        while (pos < data_len) {

            uint8_t label_len = data[pos];

            // End of this domain.
            if (label_len == 0) {
                pos++;
                break;
            }

            // Compression pointers are not expected here.
            // Reject them rather than trying to interpret them.
            if ((label_len & 0xC0) != 0) {
                domain_valid = false;
                break;
            }

            // DNS labels are limited to 63 bytes.
            if (label_len > 63) {
                domain_valid = false;
                break;
            }

            // Need label bytes.
            if (pos + 1 > data_len ||
                label_len > data_len - pos - 1) {
                domain_valid = false;
                break;
            }

            // Account for this label.
            pos += 1 + label_len;
            domain_len += 1 + label_len;
        }

        if (!domain_valid)
            return -1;

        // Empty / malformed domain.
        if (domain_len <= 1)
            continue;

        // Add comma separator.
        if (!first_domain) {
            if (out_idx >= max_len - 1)
                break;

            out[out_idx++] = ',';
        }

        first_domain = false;

        // Re-decode the domain from domain_start.
        int p = domain_start;
        bool first_label = true;

        while (p < pos && data[p] != 0) {

            uint8_t label_len = data[p++];

            if (label_len > 63 ||
                p + label_len > pos) {
                return -1;
            }

            if (!first_label) {
                if (out_idx >= max_len - 1)
                    break;

                out[out_idx++] = '.';
            }

            first_label = false;

            for (int i = 0; i < label_len; i++) {

                if (out_idx >= max_len - 1)
                    break;

                uint8_t c = data[p++];

                // Sanitize for TFT output.
                out[out_idx++] =
                    (c >= 32 && c <= 126) ? (char)c : '.';
            }
        }
    }

    out[out_idx] = '\0';
    return out_idx;
}

