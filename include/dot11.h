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
    uint16_t fc_;    // Frame Control
    uint16_t du_;    // Duration
    Mac addr1_;      // Receiver
    Mac addr2_;      // Transmitter
    Mac addr3_;      // BSSID
    uint16_t seq_;
};

struct Dot11BeaconHdr : public Dot11MgmtHdr {
    struct Fix {
        uint64_t ts_;    // Timestamp
        uint16_t in_;    // Interval
        uint16_t ca_;    // Capability
    } fix_;

    struct Tag {
        uint8_t num_;
        uint8_t len_;

        bool isValid(const u_char* end) const {
            const u_char* p = (const u_char*)this;
            return (p + sizeof(Tag) <= end) && (p + sizeof(Tag) + len_ <= end);
        }
        uint8_t* value() { return (uint8_t*)(this + 1); }
        Tag*    next()  { return (Tag*)((u_char*)this + sizeof(Tag) + len_); }
    };

    // CSA (0x25)
    struct Dot11Csa : Tag {
        uint8_t mode_;
        uint8_t ch_;     // New Channel Number
        uint8_t cnt_;

        void fill(uint8_t ch, uint8_t cnt = 1) {
            num_ = TP_CSA;
            len_ = 3;
            mode_ = 1;
            ch_ = ch;
            cnt_ = cnt;
        }
    };

    // Extended CSA (0x3C)
    struct Dot11ExtCsa : Tag {
        uint8_t mode_;   
        uint8_t opClass_;    // New Operating Class
        uint8_t ch_;         // New Channel Number
        uint8_t cnt_;

        void fill(uint8_t ch, uint8_t opCl, uint8_t cnt = 1) {
            num_ = TP_EXT_CSA;
            len_ = 4;
            mode_ = 1;
            opClass_ = opCl;
            ch_ = ch;
            cnt_ = cnt;
        }
    };

    bool isBeacon() const   { return fc_ == FC_BEACON; }
    Tag* firstTag()         { return (Tag*)(this + 1); }
};
typedef Dot11BeaconHdr*              PDot11BeaconHdr;
typedef Dot11BeaconHdr::Tag*         PDot11Tag;
typedef Dot11BeaconHdr::Dot11Csa*    PDot11Csa;
typedef Dot11BeaconHdr::Dot11ExtCsa* PDot11ExtCsa;

#pragma pack(pop)
