#pragma once
#include "pch.h"
#include "mac.h"

// Frame Control Field (le uint16_t)
// low byte  : protocol + type + subtype
// high byte : flags
static const uint16_t FC_BEACON     = 0x0080;

// Tagged Parameter Number
static const uint8_t TP_DS_PARAM    = 0x03; // DS Parameter Set -> Current Channel
static const uint8_t TP_CSA         = 0x25; // CSA (37)
static const uint8_t TP_EXT_CSA     = 0x3C; // Extended CSA (60)

# pragma pack(push, 1)
struct Dot11MgmtHdr {
    uint16_t fc;    // Frame Control
    uint16_t du;    // Duration
    Mac addr1;
    Mac addr2;
    Mac addr3;
    uint16_t seq;
};

struct Dot11BeaconFixed {
    uint64_t ts;    // Timestamp
    uint16_t in;    // Interval
    uint16_t ca;    // Capability
};

// CSA (0x25)
struct Dot11Csa {
    uint8_t id;     // 0x25 (37)
    uint8_t len;    // 0x03
    uint8_t mode;
    uint8_t ch;     // New Channel Number
    uint8_t count;
};

// Extended CSA (0x3C)
struct Dot11ExtCsa {
    uint8_t id;     // 0x3C (60)
    uint8_t len;    // 0x04
    uint8_t mode;   
    uint8_t op_cl;  // New Operating Class
    uint8_t ch;     // New Channel Number
    uint8_t count;
};

#pragma pack(pop)
