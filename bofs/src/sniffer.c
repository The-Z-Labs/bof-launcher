#include "pcap.h"
#include <stdio.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include "beacon.h"

static void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body) {
    printf("Packet capture length: %d\n", packet_header->caplen);
    printf("Packet total length %d\n", packet_header->len);
}

unsigned char go(unsigned char* arg_data, int arg_len) {
    pcap_t *handle;
    char errbuf[2048];
    struct pcap_pkthdr packet_header;
    const u_char *packet;

    datap parser;
    char* ifce = NULL;

    BeaconDataParse(&parser, arg_data, arg_len);
    ifce = BeaconDataExtract(&parser, NULL);

    handle = pcap_open_live(ifce, 65000, 1, 1000, errbuf);
    if (handle == NULL) {
	return 1;
    }

    pcap_loop(handle, 0, &my_packet_handler, NULL);
    pcap_close(handle);

    return 0;
}
