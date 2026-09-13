#include "ui_utils.h"
#include <Arduino.h>
#include <stdio.h>
#include <string.h>

void getAgeString(uint32_t timestamp, char* buf, size_t len) {
    if (timestamp == 0) {
        snprintf(buf, len, "00h00m");
        return;
    }

    // Using subtraction handles the millis() 50-day rollover safely
    uint32_t elapsed = millis() - timestamp;
    uint32_t mins = elapsed / 60000;
    uint32_t hours = mins / 60;
    mins = mins % 60;

    // Cap at 99h to prevent layout breaking if left on for 4+ days
    if (hours > 99) {
        snprintf(buf, len, ">99h  ");
    } else {
        snprintf(buf, len, "%02luh%02lum", hours, mins);
    }
}
void cleanOsintString(char* s) {
    if (s == nullptr) return;

    // 1. Strip bulky corporate suffixes
    const char* suffixes[] = {", Inc.", " Inc.", " LLC", " Corp.", " Ltd."};
    for (int i = 0; i < 5; i++) {
        size_t suffix_len = strlen(suffixes[i]);
        char* pos;
        while ((pos = strstr(s, suffixes[i])) != nullptr) {
            // memmove safely handles overlapping memory regions.
            // We shift everything after the suffix leftward, including the '\0' terminator.
            memmove(pos, pos + suffix_len, strlen(pos + suffix_len) + 1);
        }
    }

    // 2. Crush double spaces after colons (e.g. "Apple:  Find My" -> "Apple:Find My")
    char* pos;
    while ((pos = strstr(s, ":  ")) != nullptr) {
        // Keep the ':', shift the rest of the string left by 2 bytes
        memmove(pos + 1, pos + 3, strlen(pos + 3) + 1);
    }

    // 3. Crush single spaces after colons
    while ((pos = strstr(s, ": ")) != nullptr) {
        // Keep the ':', shift the rest of the string left by 1 byte
        memmove(pos + 1, pos + 2, strlen(pos + 2) + 1);
    }
}
void formatShortUnit(uint32_t bytes, char* buf, size_t len) {
    if (bytes < 1000) snprintf(buf, len, "%3luB", bytes);
    else if (bytes < 1024000) snprintf(buf, len, "%3luK", bytes / 1024);
    else if (bytes < 1048576000) snprintf(buf, len, "%3luM", bytes / 1048576);
    else snprintf(buf, len, "%3.1fG", (float)bytes / 1073741824.0);
}
void formatTotalUnit(uint32_t bytes, char* buf, size_t len) {
    if (bytes < 1000) snprintf(buf, len, "%4luB", bytes);
    else if (bytes < 1024000) snprintf(buf, len, "%4luK", bytes / 1024);
    else if (bytes < 1048576000) snprintf(buf, len, "%4luM", bytes / 1048576);
    else snprintf(buf, len, "%4.1fG", (float)bytes / 1073741824.0);
}
