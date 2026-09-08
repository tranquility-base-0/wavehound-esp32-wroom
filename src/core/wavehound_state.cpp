#include "wavehound_state.h"

LiveBuffer liveBuf;
SortBuffer sortBuf;
SessionBuffer sessionBuf;

volatile MacRecord (&liveData)[MAX_MACS] = liveBuf.liveData;
volatile BLERecord (&liveBleData)[MAX_BLE_DEVICES] = liveBuf.liveBleData;
volatile ApRecord (&liveApData)[MAX_AP_RECORDS] = liveBuf.liveApData;
volatile ChannelRecord (&liveChannelData)[MAX_CHANNEL_RECORDS] = liveBuf.liveChannelData;
MacRecord (&sortData)[MAX_MACS] = sortBuf.sortData;
BLERecord (&sortBleData)[MAX_BLE_DEVICES] = sortBuf.sortBleData;
ApRecord (&sortApData)[MAX_AP_RECORDS] = sortBuf.sortApData;
ChannelRecord (&sortChannelData)[MAX_CHANNEL_RECORDS] = sortBuf.sortChannelData;
MacRecord (&sessionData)[MAX_MACS] = sessionBuf.sessionData;
BLERecord (&sessionBleData)[MAX_BLE_DEVICES] = sessionBuf.sessionBleData;
ApRecord (&sessionApData)[MAX_AP_RECORDS] = sessionBuf.sessionApData;
ChannelRecord (&sessionChannelData)[MAX_CHANNEL_RECORDS] = sessionBuf.sessionChannelData;
LeakHistoryEntry (&leakHistory)[MAX_LEAK_SLOTS] = sessionBuf.leakHistory;

volatile uint16_t liveMacCount = 0;
volatile uint32_t liveOtherBytes = 0;
volatile uint16_t liveBleCount = 0;
volatile uint16_t liveApCount = 0;
volatile uint16_t liveChannelCount = 0;
uint16_t sortMacCount = 0;
uint32_t sortOtherBytes = 0;
uint16_t sortBleCount = 0;
uint16_t sortApCount = 0;
uint16_t sortChannelCount = 0;
uint16_t sessionMacCount = 0;
uint32_t sessionOtherBytes = 0;
uint16_t sessionBleCount = 0;
uint16_t sessionApCount = 0;
uint16_t sessionChannelCount = 0;

FlowRecord flow_cache[MAX_ACTIVE_FLOWS];
CryptoAlertCache crypto_cache[ALERT_CACHE_SIZE];
uint8_t crypto_cache_idx = 0;

SortMode currentSortMode = SORT_TOTAL;
BleSortMode currentBleSortMode = SORT_BLE_HITS;
bool sort_descending = true;
std::atomic<bool> pause_sniffing{false};

