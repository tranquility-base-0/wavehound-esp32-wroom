#pragma once
#include <stdint.h>

// fresh_press: true on the frame a physical press begins (down-edge).
// Only the SELECT CH keypad consumes it, for one-press-one-key debounce;
// all other touch controls ignore it.
bool handleTouchInputs(uint16_t t_x, uint16_t t_y, bool fresh_press);
