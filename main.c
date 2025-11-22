#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ip.h>
#include "e46_checksum.h"

#define IP_LAYER_OFFSET 14

void usage();

int main(int argc, char **argv)
{
    int opt;
    char *iface = NULL;
    char errbuf[16384] = {};
    char pcap_filter[256] = "";

    while ((opt = getopt(argc, argv, "i:")) != -1)
    {
        switch (opt)
        {
            case 'i':
                iface = optarg;
                break;
        }
    }

    if (iface == NULL)
    {
        printf("iface is not specified.\n");

        return 1;
    }

    printf("=======args=============================\n");
    printf("iface: %s\n", iface);
    printf("========================================\n");

    pcap_t *iface_handle;

    iface_handle = pcap_open_live(iface, BUFSIZ, 1, sizeof(errbuf), errbuf);

    if (iface_handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s", iface, errbuf);

        return 1;
    }

    printf("iface: %s opened successfully\n", iface);

    struct bpf_program bpf;
    bpf_u_int32 srcip;
    bpf_u_int32 netmask;

    if (pcap_lookupnet(iface, &srcip, &netmask, errbuf) == PCAP_ERROR)
    {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);

        return 1;
    }

    if (pcap_compile(iface_handle, &bpf, pcap_filter, 0, netmask) == PCAP_ERROR)
    {
        fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(iface_handle));

        return 1;
    }

    if (pcap_setfilter(iface_handle, &bpf) == PCAP_ERROR)
    {
        fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(iface_handle));

        return 1;
    }

    struct pcap_pkthdr header;
    const uint8_t *pck;

    while (pck = pcap_next(iface_handle, &header))
    {
        char new_pack[2048];
        char sip[24], dip[24];

        memcpy(new_pack, pck, header.caplen);

        if (header.caplen > 1500)
            continue;

        struct ip *hdr = (struct ip*)(new_pack + IP_LAYER_OFFSET);

        int iphdr_size = sizeof(struct ip);

        struct in_addr saddr, daddr;

        saddr = hdr->ip_src;
        daddr = hdr->ip_dst;

        struct in_addr increment_ip;
        inet_pton(AF_INET, "192.168.1.2", &increment_ip);

        if (saddr.s_addr == increment_ip.s_addr)
        {
            // Increment ip once
            uint32_t ip4 = ntohl(hdr->ip_src.s_addr);
            ip4++;
            hdr->ip_src.s_addr = htonl(ip4);

            char *ip = inet_ntoa(saddr);
            strcpy(sip, ip);

            ip = inet_ntoa(daddr);
            strcpy(dip, ip);

            e46_checksum(new_pack + IP_LAYER_OFFSET, header.caplen - IP_LAYER_OFFSET);

            printf("Packet source ip manipulated. sip: %s, dip: %s\n", sip, dip);

            if (pcap_inject(iface_handle, new_pack, header.caplen) == PCAP_ERROR)
            {
                printf("Could not written packet. err: %s\n", pcap_geterr(iface_handle));
            }
        }
    }
}

void usage()
{
    printf("ipchecksum <iface>\n");
}