#include "pch.h"
#include "csa.h"

CsaPkt::CsaPkt(pcap_t* pcap, const Mac& apMac, const Mac& stMac, uint8_t chOffset)
    : pcap_(pcap), apMac_(apMac), stMac_(stMac), chOffset_(chOffset), curCh_(0) {}

// std::vector<uint8_t> 