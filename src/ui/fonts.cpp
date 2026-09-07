// Single translation unit that defines all five fonts (external linkage).
// Every other UI TU includes the font headers without FONT_DATA and thus sees
// `extern const` declarations only, avoiding per-TU duplication of the bitmaps.
#include <Arduino.h>
#include <TFT_eSPI.h>
#define FONT_DATA
#include "UbuntuMono_Regular11pt7b.h"
#include "UbuntuMono_Regular9pt7b.h"
#include "UbuntuMono_Regular8pt7b.h"
#include "UbuntuMono_B9pt7b.h"
#include "UbuntuMono_RI9pt7b.h"
