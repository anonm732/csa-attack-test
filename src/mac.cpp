#include "pch.h"
#include "mac.h"

Mac::Mac() {
    memset(m_, 0, sizeof(m_));
}

Mac::Mac(const std::string& s) {
    unsigned int mac[6];    // %X in sscanf func need to unsigned int* (4 Bytes) ...
    int parsed = sscanf(s.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X",
                                    &mac[0], &mac[1], &mac[2], 
                                    &mac[3], &mac[4], &mac[5]
    );
    
    if (parsed != 6) {
        memset(m_, 0, sizeof(m_));
        fprintf(stderr, "MAC format is invalid.\n");
        exit(1);
    }

    for (int i = 0; i < 6; i++) m_[i] = (uint8_t)mac[i];
}

Mac::Mac(const Mac& r) {
    memcpy(m_, r.m_, sizeof(m_));
}

Mac::Mac(uint8_t* m) {
    memcpy(m_, m, sizeof(m_));
}

std::string Mac::toString() const {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                            m_[0],m_[1],m_[2],m_[3],m_[4],m_[5]
    );
    
    return std::string(buf);
}

Mac& Mac::operator =  (const Mac& r) { if (this != &r) memcpy(m_, r.m_, sizeof(m_)); return *this; }
bool Mac::operator == (const Mac& r) const { return memcmp(m_, r.m_, sizeof(m_)) == 0; }
bool Mac::operator != (const Mac& r) const { return !(*this == r); }
bool Mac::operator <  (const Mac& r) const { return memcmp(m_, r.m_, sizeof(m_)) < 0; }
bool Mac::operator >  (const Mac& r) const { return r < *this; }
bool Mac::operator <= (const Mac& r) const { return !(r < *this); }
bool Mac::operator >= (const Mac& r) const { return !(*this < r); }

Mac& Mac::broadcastMac() {
    static uint8_t byte[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    static Mac m(byte);
    return m;
}

Mac& Mac::nullMac() {
    uint8_t byte[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    static Mac m(byte);

    return m;
}