#include "pch.h"
#include "mac.h"
#include "util.h"

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

    pcap_close(pcap);
    return 0;
}