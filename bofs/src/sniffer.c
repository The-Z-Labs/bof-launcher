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
    static char errbuf[2048];
    struct pcap_pkthdr packet_header;
    const u_char *packet;
    static struct bpf_program bpf;
    static bpf_u_int32 netmask;
    static bpf_u_int32 srcip;

    datap parser;
    char* ifce = NULL;

    BeaconDataParse(&parser, arg_data, arg_len);
    ifce = BeaconDataExtract(&parser, NULL);

    // Get network device source IP address and netmask.
    if (pcap_lookupnet(ifce, &srcip, &netmask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
	return 1;
    }

    handle = pcap_open_live(ifce, 65000, 1, 1000, errbuf);
    if (handle == NULL) {
	return 1;
    }

    // Convert the packet filter epxression into a packet filter binary.
    if (pcap_compile(handle, &bpf, "", 0, netmask) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
	return 1;
    }

    // Bind the packet filter to the libpcap handle.
    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
	return 1;
    }

    //pcap_loop(handle, 0, &my_packet_handler, NULL);
    pcap_close(handle);

    return 0;
}
