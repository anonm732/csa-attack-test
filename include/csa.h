#pragma once
#include "pch.h"
#include "mac.h"
#include "dot11.h"

struct CsaPkt {
    pcap_t* pcap_;
    Mac apMac_;
    Mac stMac_;
    uint8_t chOffset_;
    uint8_t curCh_;

    CsaPkt(pcap_t* pcap, const Mac& apMac, const Mac& stMac, uint8_t chOffset);


};