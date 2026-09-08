#pragma once
#include "core/wavehound_state.h"

// Universal log-distance path-loss estimator (protocol-agnostic physics).
// Returns estimated distance in meters, or -1.0 on invalid input.
float calculateRfDistance(int rssi, int txPower, RadioProtocol protocol, float customLoss = 0.0);
