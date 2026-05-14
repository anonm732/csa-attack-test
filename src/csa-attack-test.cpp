#include "pch.h"
#include "mac.h"
#include "util.h"

struct Param {
    char*   dev_        = nullptr;
    Mac     apMac_      { Mac::nullMac() };
    Mac     stMac_      { Mac::nullMac() };
    uint8_t chOffset_   = 1;

    static void usage() {
        printf("syntax : csa-attack-test <interface> <ap mac> <channel offset> [<station mac>]\n");
        printf("sample : csa-attack-test mon0 00:11:22:33:44:55 6\n");
        printf("         csa-attack-test mon0 00:11:22:33:44:55 6 66:77:88:99:AA:BB\n");
    }
} param;

int main(int argc, char* argv[]) {
    if (argc < 4) {
        Param::usage();
        return -1;
    }

    param.dev_          = argv[1];
    param.apMac_        = Mac(argv[2]);
    param.chOffset_     = (uint8_t)atoi(argv[3]);

    // if stMac exists :
    if (argc >= 5) param.stMac_ = Mac(argv[4]);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return NULL - %s\n", param.dev_, errbuf);
        return -1;
    }

    // live test


    // offline test


    pcap_close(pcap);
    return 0;
}