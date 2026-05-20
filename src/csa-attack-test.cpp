#include "dot11.h"
#include "pch.h"
#include "mac.h"
#include "csa.h"
#include "radiotap.h"
#include "util.h"
#include <cstdint>

struct Param {
    char*   dev_        = nullptr;
    Mac     apMac_      { Mac::nullMac() };
    Mac     stMac_      { Mac::nullMac() };

    static void usage() {
        printf("syntax : csa-attack-test <interface> <ap_mac> [<station_mac>]\n");
        printf("sample : csa-attack-test mon0 00:11:22:33:44:55\n");
        printf("         csa-attack-test mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
        printf("\n[test]\nTEST_PCAP=<pcap_file> csa-attack-test <ap_mac> [<station_mac>]\n");
        printf("sample : TEST_PCAP=capture.pcapng csa-attack-test 00:11:22:33:44:55\n");
    }
} param;

int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = nullptr;

    const char* testPcap = getenv("TEST_PCAP");

    if (testPcap) {
        if (argc < 2) { Param::usage(); return -1; }
        param.apMac_ = Mac(argv[1]);
        if (argc >= 3) param.stMac_ = Mac(argv[2]);

        pcap = pcap_open_offline(testPcap, errbuf);
        if (pcap == nullptr) {
            fprintf(stderr, "pcap_open_offline(%s) failed - %s\n", testPcap, errbuf);
            return -1;
        }
        printf("[TEST] pcap file : %s\n", testPcap);
    } else {
        if (argc < 3) { Param::usage(); return -1; }
        param.dev_ = argv[1];
        param.apMac_ = Mac(argv[2]);
        if (argc >= 4) param.stMac_ = Mac(argv[3]);

        pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
        if (pcap == nullptr) {
            fprintf(stderr, "pcap_open_live(%s) failed - %s\n", param.dev_, errbuf);
            return -1;
        }
    }

    Mac target = param.stMac_.isNull()
                ? Mac(Mac::broadcastMac())
                : Mac(param.stMac_);

    printf("AP MAC : %s\n", param.apMac_.toString().c_str());
    printf("Target : %s\n\n", target.toString().c_str());

    CsaPkt csaPkt(pcap, param.apMac_, target);

    if (testPcap) {     // TEST MODE
        int cnt = 0;
        struct pcap_pkthdr* hdr;
        const u_char* raw;
        while (pcap_next_ex(pcap, &hdr, &raw) > 0) {
            std::vector<uint8_t> newPkt = csaPkt.processBeacon(raw, hdr->caplen);
            if (newPkt.empty()) continue;

            uint16_t rtLen = ((PRadioTapHdr)newPkt.data())->get_len();
            PDot11BeaconHdr beacon = (PDot11BeaconHdr)(newPkt.data() + rtLen);
            const uint8_t* end = newPkt.data() + newPkt.size(); // ~.data() is pointer -> skip by size

            bool hasCsa = false;
            bool hasExtCsa = false;
            for (PDot11Tag tag = beacon->firstTag(); tag->isValid(end); tag = tag->next()) {
                if (tag->num_ == TP_CSA) hasCsa = true;
                if (tag->num_ == TP_EXT_CSA) hasExtCsa = true;
            }

            printf("\n[%d] beacon processed :\nCSA:%s\nExtCSA:%s\naddr1:%s\n",
                            ++cnt, 
                            hasCsa ? "OK" : "MISSING", 
                            hasExtCsa ? "OK" : "MISSING", 
                            beacon->addr1_.toString().c_str()
            );
        }
        printf("[TEST] done : %d beacon processed\n", cnt);
    }


    pcap_close(pcap);
    return 0;
}