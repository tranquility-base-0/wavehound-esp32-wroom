#include <Arduino.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <algorithm>
#include "parser_common.h"
#include "link_layer.h"

static bool icmp6_append(char* out, size_t max_len, int& written, const char* fmt, ...);

bool parse_arp(const uint8_t* payload, uint16_t length,
               char* out_text, size_t max_len) {

    if (!payload || !out_text || max_len == 0 || length < 28)
        return false;

    // Standard Ethernet / IPv4 ARP validation
    uint16_t htype = ((uint16_t)payload[0] << 8) | payload[1];
    uint16_t ptype = ((uint16_t)payload[2] << 8) | payload[3];
    uint8_t  hlen  = payload[4];
    uint8_t  plen  = payload[5];

    // Ethernet = 1
    // IPv4    = 0x0800
    // MAC     = 6 bytes
    // IPv4    = 4 bytes
    if (htype != 1 || ptype != 0x0800 ||
        hlen != 6 || plen != 4)
        return false;

    uint16_t opcode = ((uint16_t)payload[6] << 8) | payload[7];

    if (opcode != 1 && opcode != 2)
        return false;

    const uint8_t* sender_mac = &payload[8];
    const uint8_t* sender_ip  = &payload[14];
    const uint8_t* target_mac = &payload[18];
    const uint8_t* target_ip  = &payload[24];

    // -----------------------------------------------------
    // ARP REQUEST
    // "Who has target IP? Tell sender IP."
    // -----------------------------------------------------
    if (opcode == 1) {

        snprintf(out_text, max_len,
                 "ARP Req: Who has %d.%d.%d.%d? "
                 "Tell %d.%d.%d.%d",
                 target_ip[0], target_ip[1],
                 target_ip[2], target_ip[3],
                 sender_ip[0], sender_ip[1],
                 sender_ip[2], sender_ip[3]);

        return true;
    }

    // -----------------------------------------------------
    // ARP REPLY
    // "Target IP is at sender MAC."
    // -----------------------------------------------------
    snprintf(out_text, max_len,
             "ARP Reply: %d.%d.%d.%d is-at "
             "%02X:%02X:%02X:%02X:%02X:%02X",
             sender_ip[0], sender_ip[1],
             sender_ip[2], sender_ip[3],
             sender_mac[0], sender_mac[1],
             sender_mac[2], sender_mac[3],
             sender_mac[4], sender_mac[5]);

    return true;
}

bool parse_icmpv4(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    // ICMPv4 header is 8 bytes.
    if (length < 8 || payload == nullptr || out_text == nullptr || max_len == 0) {
        return false;
    }

    uint8_t type = payload[0];
    uint8_t code = payload[1];

    switch (type) {
        case 0:  
            snprintf(out_text, max_len, "ICMPv4: Echo Reply"); 
            return true;
        case 3: 
            // Destination Unreachable has highly specific codes
            switch(code) {
                case 0: snprintf(out_text, max_len, "ICMPv4: Dest Unreachable (Network)"); return true;
                case 1: snprintf(out_text, max_len, "ICMPv4: Dest Unreachable (Host)"); return true;
                case 3: snprintf(out_text, max_len, "ICMPv4: Dest Unreachable (Port Closed)"); return true;
                case 9: snprintf(out_text, max_len, "ICMPv4: Dest Unreachable (Admin Prohibited)"); return true;
                case 13: snprintf(out_text, max_len, "ICMPv4: Dest Unreachable (Firewall Block)"); return true;
                default: snprintf(out_text, max_len, "ICMPv4: Dest Unreachable (Code %u)", code); return true;
            }
        case 4:
            snprintf(out_text, max_len, "ICMPv4: Source Quench");
            return true;
        case 8:  
            snprintf(out_text, max_len, "ICMPv4: Echo Request (Ping)"); 
            return true;
        case 11: 
            snprintf(out_text, max_len, "ICMPv4: Time Exceeded (Traceroute)"); 
            return true;
        case 12:
            snprintf(out_text, max_len, "ICMPv4: Parameter Problem");
            return true;
        case 13:
            snprintf(out_text, max_len, "ICMPv4: Timestamp Request (Recon)");
            return true;
        case 14:
            snprintf(out_text, max_len, "ICMPv4: Timestamp Reply (Recon)");
            return true;
        default: 
            snprintf(out_text, max_len, "ICMPv4: Type %u, Code %u", type, code); 
            return true;
    }
}

const char* icmpv6_type_name(uint8_t type) {

    switch (type) {

        // Errors
        case 1:   return "Destination Unreachable";
        case 2:   return "Packet Too Big";
        case 3:   return "Time Exceeded";
        case 4:   return "Parameter Problem";

        // Echo / MLD / ND
        case 128: return "Echo Request";
        case 129: return "Echo Reply";
        case 130: return "MLD Query";
        case 131: return "MLD Report";
        case 132: return "MLD Done";
        case 133: return "Router Solicitation";
        case 134: return "Router Advertisement";
        case 135: return "Neighbor Solicitation";
        case 136: return "Neighbor Advertisement";
        case 137: return "Redirect";

        // Less-common but assigned ICMPv6
        case 138: return "Router Renumbering";
        case 139: return "Node Information Query";
        case 140: return "Node Information Response";
        case 141: return "Inverse ND Solicitation";
        case 142: return "Inverse ND Advertisement";
        case 143: return "MLDv2 Report";
        case 144: return "Home Agent Discovery Request";
        case 145: return "Home Agent Discovery Reply";
        case 146: return "Mobile Prefix Solicitation";
        case 147: return "Mobile Prefix Advertisement";
        case 148: return "Certification Path Solicitation";
        case 149: return "Certification Path Advertisement";
        case 150: return "Seamoby Mobility";
        case 151: return "Multicast Router Advertisement";
        case 152: return "Multicast Router Solicitation";
        case 153: return "Multicast Router Termination";
        case 154: return "FMIPv6";
        case 155: return "RPL Control";
        case 156: return "ILNPv6 Locator Update";
        case 157: return "Duplicate Address Request";
        case 158: return "Duplicate Address Confirmation";
        case 159: return "MPL Control";
        case 160: return "Extended Echo Request";
        case 161: return "Extended Echo Reply";

        default:
            return "Unknown";
    }
}

const char* icmpv6_code_name(uint8_t type, uint8_t code) {

    if (type == 1) {

        switch (code) {
            case 0: return "No route";
            case 1: return "Admin prohibited";
            case 2: return "Beyond source scope";
            case 3: return "Address unreachable";
            case 4: return "Port unreachable";
            case 5: return "Ingress/Egress policy";
            case 6: return "Reject route";
            case 7: return "SRH error";
            case 8: return "Headers too long";
            case 9: return "P-Route error";
            default: return "Unknown";
        }
    }

    if (type == 3) {
        switch (code) {
            case 0: return "Hop limit exceeded";
            case 1: return "Fragment reassembly timeout";
            default: return "Unknown";
        }
    }

    if (type == 4) {
        switch (code) {
            case 0: return "Erroneous header field";
            case 1: return "Unknown Next Header";
            case 2: return "Unknown IPv6 option";
            case 3: return "Incomplete first fragment";
            case 4: return "SR upper-layer error";
            case 5: return "Unknown Next Header (intermediate)";
            case 6: return "Extension header too big";
            case 7: return "Extension chain too long";
            case 8: return "Too many extension headers";
            case 9: return "Too many options";
            case 10: return "Option too big";
            default: return "Unknown";
        }
    }

    return "OK";
}

static bool icmp6_append(char* out,
                         size_t max_len,
                         int& written,
                         const char* fmt,
                         ...) {

    if (!out || written < 0 || written >= (int)max_len)
        return false;

    va_list args;
    va_start(args, fmt);

    int n = vsnprintf(out + written,
                      max_len - written,
                      fmt,
                      args);

    va_end(args);

    if (n < 0)
        return false;

    written += n;

    return written < (int)max_len;
}

bool parse_icmpv6(const uint8_t* payload,
                  uint16_t length,
                  char* out_text,
                  size_t max_len,
                  bool& is_high_value) {

    if (!payload ||
        !out_text ||
        max_len == 0 ||
        length < 4)
        return false;

    is_high_value = false;
    out_text[0] = '\0';

    uint8_t type = payload[0];
    uint8_t code = payload[1];

    const char* type_name = icmpv6_type_name(type);

    // -----------------------------------------------------
    // Mark particularly useful ICMPv6 traffic
    // -----------------------------------------------------

    switch (type) {

        case 133: // Router Solicitation
        case 134: // Router Advertisement
        case 135: // Neighbor Solicitation
        case 136: // Neighbor Advertisement
        case 137: // Redirect
        case 157: // DAR
        case 158: // DAC
            is_high_value = true;
            break;

        default:
            break;
    }


    // -----------------------------------------------------
    // BASIC HEADER-ONLY CASES
    // -----------------------------------------------------

    if (type >= 5 && type <= 127) {

        snprintf(out_text,
                 max_len,
                 "ICMPv6 [%u] %s Code:%u",
                 type,
                 type_name,
                 code);

        return true;
    }


    // -----------------------------------------------------
    // ERROR MESSAGES
    // -----------------------------------------------------

    if (type >= 1 && type <= 4) {

        snprintf(out_text,
                 max_len,
                 "ICMPv6 %s: %s",
                 type_name,
                 icmpv6_code_name(type, code));

        return true;
    }


    // -----------------------------------------------------
    // ECHO REQUEST / REPLY
    //
    // Bytes 4-5 = Identifier
    // Bytes 6-7 = Sequence
    // -----------------------------------------------------

    if (type == 128 || type == 129) {

        if (length < 8) {
            snprintf(out_text,
                     max_len,
                     "ICMPv6 %s (Malformed)",
                     type_name);
            return true;
        }

        uint16_t id =
            ((uint16_t)payload[4] << 8) | payload[5];

        uint16_t seq =
            ((uint16_t)payload[6] << 8) | payload[7];

        snprintf(out_text,
                 max_len,
                 "ICMPv6 %s ID:%u Seq:%u",
                 type_name,
                 id,
                 seq);

        return true;
    }


    // -----------------------------------------------------
    // ROUTER SOLICITATION
    //
    // Fixed body = 4 reserved bytes
    // Options begin at offset 8.
    // -----------------------------------------------------

    if (type == 133) {

        if (length < 8) {
            snprintf(out_text,
                     max_len,
                     "ICMPv6 RS (Malformed)");
            return true;
        }

        snprintf(out_text,
                 max_len,
                 "ICMPv6 Router Solicitation");

        return true;
    }


    // -----------------------------------------------------
    // ROUTER ADVERTISEMENT
    //
    // Fixed body:
    //
    // 4   Type/Code/Checksum
    // 1   Cur Hop Limit
    // 1   Flags
    // 2   Router Lifetime
    // 4   Reachable Time
    // 4   Retrans Timer
    //
    // Options begin at offset 16.
    // -----------------------------------------------------

    if (type == 134) {

        if (length < 16) {
            snprintf(out_text,
                     max_len,
                     "ICMPv6 RA (Malformed)");
            return true;
        }

        uint8_t hop_limit = payload[4];
        uint8_t flags = payload[5];

        uint16_t lifetime =
            ((uint16_t)payload[6] << 8) | payload[7];

        bool managed = (flags & 0x80) != 0;
        bool other   = (flags & 0x40) != 0;

        char prefix_buf[96] = {0};
        char dns_buf[128] = {0};
        char search_buf[128] = {0};
        char mtu_buf[32] = {0};

        int offset = 16;

        while (offset + 2 <= length) {

            uint8_t opt_type = payload[offset];
            uint8_t opt_units = payload[offset + 1];

            // ND option length is in units of 8 bytes.
            if (opt_units == 0)
                break;

            int opt_len = opt_units * 8;

            if (opt_len < 8 ||
                opt_len > length - offset)
                break;

            int opt_data = offset + 2;

            // -------------------------------------------------
            // Source Link-Layer Address
            // -------------------------------------------------

            if (opt_type == 1 && opt_len >= 8) {

                snprintf(out_text + strlen(out_text),
                         max_len - strlen(out_text),
                         "\nSLLA:%02X:%02X:%02X:%02X:%02X:%02X",
                         payload[opt_data],
                         payload[opt_data + 1],
                         payload[opt_data + 2],
                         payload[opt_data + 3],
                         payload[opt_data + 4],
                         payload[opt_data + 5]);
            }

            // -------------------------------------------------
            // Prefix Information
            //
            // Prefix length at +2.
            // Prefix itself at +14.
            // -------------------------------------------------

            else if (opt_type == 3 && opt_len >= 32) {

                uint8_t prefix_len = payload[opt_data];

                char ip[40] = {0};

                format_ipv6_addr(
                    &payload[opt_data + 14],
                    ip,
                    sizeof(ip));

                snprintf(prefix_buf,
                         sizeof(prefix_buf),
                         "%s/%u",
                         ip,
                         prefix_len);
            }

            // -------------------------------------------------
            // MTU
            // -------------------------------------------------

            else if (opt_type == 5 && opt_len >= 8) {

                uint32_t mtu =
                    ((uint32_t)payload[opt_data + 2] << 24) |
                    ((uint32_t)payload[opt_data + 3] << 16) |
                    ((uint32_t)payload[opt_data + 4] << 8) |
                    payload[opt_data + 5];

                snprintf(mtu_buf,
                         sizeof(mtu_buf),
                         "%lu",
                         (unsigned long)mtu);
            }

            // -------------------------------------------------
            // RDNSS
            //
            // Option:
            // +0  Reserved
            // +4  Lifetime
            // +8  IPv6 addresses
            // -------------------------------------------------

            else if (opt_type == 25 &&
                     opt_len >= 24 &&
                     ((opt_len - 8) % 16 == 0)) {

                int dns_idx = 0;

                dns_idx += snprintf(
                    dns_buf + dns_idx,
                    sizeof(dns_buf) - dns_idx,
                    "DNS:");

                for (int p = opt_data + 8;
                     p + 16 <= offset + opt_len;
                     p += 16) {

                    if (dns_idx >=
                        (int)sizeof(dns_buf) - 42)
                        break;

                    char ip[40] = {0};

                    format_ipv6_addr(
                        &payload[p],
                        ip,
                        sizeof(ip));

                    dns_idx += snprintf(
                        dns_buf + dns_idx,
                        sizeof(dns_buf) - dns_idx,
                        " %s",
                        ip);
                }
            }

            // -------------------------------------------------
            // DNSSL
            //
            // +0  Reserved
            // +4  Lifetime
            // +8  Domain Names
            // -------------------------------------------------

            else if (opt_type == 31 &&
                     opt_len >= 16) {

                int res = decode_dns_search_list(
                    &payload[opt_data + 6],
                    opt_len - 6,
                    search_buf,
                    sizeof(search_buf));

                if (res < 0)
                    search_buf[0] = '\0';
            }

            offset += opt_len;
        }

        // -----------------------------------------------------
        // Construct compact display.
        //
        // RA is one of the most information-rich packets,
        // so prioritize:
        //
        //   Router / flags
        //   Prefix
        //   DNS
        //   Search domain
        //   MTU
        // -----------------------------------------------------

        int written = snprintf(
            out_text,
            max_len,
            "ICMPv6 RA HL:%u LT:%u M:%u O:%u",
            hop_limit,
            lifetime,
            managed ? 1 : 0,
            other ? 1 : 0);

        if (prefix_buf[0] &&
            written < (int)max_len) {

            written += snprintf(
                out_text + written,
                max_len - written,
                "\nPrefix:%s",
                prefix_buf);
        }

        if (dns_buf[0] &&
            written < (int)max_len) {

            written += snprintf(
                out_text + written,
                max_len - written,
                "\n%s",
                dns_buf);
        }

        if (search_buf[0] &&
            written < (int)max_len) {

            written += snprintf(
                out_text + written,
                max_len - written,
                "\nSearch:%s",
                search_buf);
        }

        if (mtu_buf[0] &&
            written < (int)max_len) {

            snprintf(
                out_text + written,
                max_len - written,
                "\nMTU:%s",
                mtu_buf);
        }

        return true;
    }


    // -----------------------------------------------------
    // NEIGHBOR SOLICITATION
    //
    // Fixed body:
    // 4 reserved bytes
    // 16-byte Target Address
    //
    // Options begin at offset 24.
    // -----------------------------------------------------

    if (type == 135) {

        if (length < 24) {
            snprintf(out_text,
                     max_len,
                     "ICMPv6 NS (Malformed)");
            return true;
        }

        char target[40] = {0};

        format_ipv6_addr(
            &payload[8],
            target,
            sizeof(target));

        snprintf(out_text,
                 max_len,
                 "ICMPv6 NS Target:%s",
                 target);

        return true;
    }


    // -----------------------------------------------------
    // NEIGHBOR ADVERTISEMENT
    //
    // Fixed body:
    // 4 flags/reserved
    // 16 Target Address
    //
    // Options begin at offset 24.
    // -----------------------------------------------------

    if (type == 136) {

        if (length < 24) {
            snprintf(out_text,
                     max_len,
                     "ICMPv6 NA (Malformed)");
            return true;
        }

        uint32_t flags =
            ((uint32_t)payload[4] << 24) |
            ((uint32_t)payload[5] << 16) |
            ((uint32_t)payload[6] << 8) |
            payload[7];

        char target[40] = {0};

        format_ipv6_addr(
            &payload[8],
            target,
            sizeof(target));

        bool router =
            (flags & 0x80000000UL) != 0;

        bool solicited =
            (flags & 0x40000000UL) != 0;

        bool override =
            (flags & 0x20000000UL) != 0;

        snprintf(out_text,
                 max_len,
                 "ICMPv6 NA %s R:%u S:%u O:%u",
                 target,
                 router ? 1 : 0,
                 solicited ? 1 : 0,
                 override ? 1 : 0);

        return true;
    }


    // -----------------------------------------------------
    // MLD
    // -----------------------------------------------------

    if (type == 130 ||
        type == 131 ||
        type == 132 ||
        type == 143) {

        snprintf(out_text,
                 max_len,
                 "ICMPv6 %s",
                 type_name);

        return true;
    }


    // -----------------------------------------------------
    // FALLBACK
    // -----------------------------------------------------

    snprintf(out_text,
             max_len,
             "ICMPv6 [%u] %s Code:%u",
             type,
             type_name,
             code);

    return true;
}

bool parse_eapol(const uint8_t* payload, uint16_t length, char* out_text, size_t max_len) {
    if (!payload || !out_text || max_len == 0 || length < 2)
        return false;

    uint8_t eapol_type = payload[1];

    switch (eapol_type) {
        case 0:
            snprintf(out_text, max_len, "EAPOL: EAP Packet (802.1X Auth)");
            return true;
        case 1:
            snprintf(out_text, max_len, "EAPOL: Start");
            return true;
        case 2:
            snprintf(out_text, max_len, "EAPOL: Logoff");
            return true;
        case 3: {   // EAPOL-Key
            if (length < 7) {
                snprintf(out_text, max_len, "EAPOL-Key (Malformed)");
                return true;
            }

            uint8_t desc_type = payload[4];
            const char* desc_str = "UNK";
            if (desc_type == 2) desc_str = "RSN";
            else if (desc_type == 254) desc_str = "WPA";

            uint16_t key_info = ((uint16_t)payload[5] << 8) | payload[6];
            bool pairwise   = (key_info & 0x0008) != 0;
            bool install    = (key_info & 0x0040) != 0;
            bool ack        = (key_info & 0x0080) != 0;
            bool mic        = (key_info & 0x0100) != 0;
            bool secure     = (key_info & 0x0200) != 0;

            const char* msg_type = "Unknown";
            int msg_num = 0; 

            if (pairwise) {
                if (ack && !mic) { msg_type = "M1 (AP->STA)"; msg_num = 1; }
                else if (!ack && mic && !secure) { msg_type = "M2 (STA->AP)"; msg_num = 2; }
                else if (ack && mic && install && secure) { msg_type = "M3 (AP->STA)"; msg_num = 3; }
                else if (!ack && mic && !install && secure) { msg_type = "M4 (STA->AP)"; msg_num = 4; }
            } else {
                msg_type = "Group/Other Key";
            }

            // --- CRYPTO EXTRACTION BLOCK ---
            bool have_nonce = (length >= 49); // offset 17 + 32 bytes
            bool have_mic   = (length >= 97); // offset 81 + 16 bytes

            if (msg_num > 0 && have_nonce) { 
                char nonce_hex[65] = {0}; 
                char mic_hex[33] = {0};   

                const uint8_t* p_nonce = &payload[17];
                for (int i = 0; i < 32; i++) {
                    snprintf(&nonce_hex[i * 2], 3, "%02X", p_nonce[i]);
                }

                if (have_mic) {
                    const uint8_t* p_mic = &payload[81];
                    for (int i = 0; i < 16; i++) {
                        snprintf(&mic_hex[i * 2], 3, "%02X", p_mic[i]);
                    }
                }

                if (msg_num == 1) {
                    snprintf(out_text, max_len, "EAPOL-Key [%s]: %s | ANonce: %s", desc_str, msg_type, nonce_hex);
                } else if (msg_num == 2 && have_mic) {
                    snprintf(out_text, max_len, "EAPOL-Key [%s]: %s | SNonce: %s | MIC: %s", desc_str, msg_type, nonce_hex, mic_hex);
                } else if (msg_num == 3 && have_mic) {
                    snprintf(out_text, max_len, "EAPOL-Key [%s]: %s | ANonce: %s | MIC: %s", desc_str, msg_type, nonce_hex, mic_hex);
                } else if (msg_num == 4 && have_mic) {
                    snprintf(out_text, max_len, "EAPOL-Key [%s]: %s | MIC: %s", desc_str, msg_type, mic_hex);
                } else {
                    // Fallback if M2/M3/M4 is truncated before the MIC
                    snprintf(out_text, max_len, "EAPOL-Key [%s]: %s (Truncated)", desc_str, msg_type);
                }
            } else {
                snprintf(out_text, max_len, "EAPOL-Key [%s]: %s", desc_str, msg_type);
            }

            return true;
        }
        case 4:
            snprintf(out_text, max_len, "EAPOL: Encapsulated-ASF-Alert");
            return true;
        default:
            snprintf(out_text, max_len, "EAPOL: Unknown Type %d", eapol_type);
            return true;
    }
}

