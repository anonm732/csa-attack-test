#pragma once
#include "pch.h"
#include "mac.h"
#include "dot11.h"

struct CsaPkt {
    pcap_t* pcap_;
    Mac apMac_;
    Mac stMac_;
    uint8_t curCh_;

    CsaPkt(pcap_t* pcap, const Mac& apMac, const Mac& stMac);

    // Pick Target Channel
    static uint8_t pickTargetChannel(uint8_t curCh);

    // process : return modified Beacon, No inject (Testable)
    std::vector<uint8_t> processBeacon(const uint8_t* pkt, uint32_t capLen);

    // start attack, inject
    void attack();

private:
    // for logging
    uint8_t lastTargetch_ = 0;

    // 
    std::vector<uint8_t> buildTagsWithCsa(const uint8_t* tagsStart, const uint8_t* tagsEnd, uint8_t targetCh);

    //
    std::vector<uint8_t> buildModifiedBeacon(const uint8_t* pkt, uint32_t capLen, uint16_t rtLen, uint8_t targetCh);
};