#pragma once
#include "pch.h"

#pragma pack(push, 1)
struct Mac {
    uint8_t m_[6];

    Mac();

    explicit Mac(const Mac& r);
    explicit Mac(const std::string& s);
    explicit Mac(uint8_t* m);

    std::string toString() const;

    Mac& operator =  (const Mac& r);            // assign
    bool operator == (const Mac& r) const;      // comparison
    bool operator != (const Mac& r) const;      // .
    bool operator <  (const Mac& r) const;      // .
    bool operator >  (const Mac& r) const;      // .
    bool operator <= (const Mac& r) const;      // .
    bool operator >= (const Mac& r) const;      // .

    static Mac& broadcastMac();
    static Mac& nullMac();

    bool isBroadcast() {
        for (int i = 0; i < 6; i++)
            if (m_[i] != 0xFF) return false;
        return true;
    }
    bool isNull() {
        for (int i = 0; i < 6; i++)
            if (m_[i] != 0x00) return false;
        return true;
    }
};
#pragma pack(pop)