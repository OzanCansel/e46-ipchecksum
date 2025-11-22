#include "e46_checksum.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

static uint16_t ipv4_checksum(const uint16_t *pkt, uint16_t hlen)
{
    int i;
    uint32_t csum = 0;

    csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4];

    pkt += 6;
    hlen -= 12;

    for (i = 0; hlen > 2; i++)
    {
        csum += pkt[i];
        hlen -= 2;
    }

    csum += pkt[i];

    csum = (csum >> 16) + (csum & 0x0000FFFF);
    csum += (csum >> 16);

    return (uint16_t) ~csum;
}

static uint16_t tcp4_checksum(
    const uint16_t *shdr,
    const uint16_t *pkt,
    uint16_t tlen
)
{
    int i;
    uint16_t pad = 0;
    uint32_t csum = 0;

    csum += shdr[0] + shdr[1] + shdr[2] + shdr[3] + htons(6) + htons(tlen);

    csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
        pkt[7];

    tlen -= 18;
    pkt += 9;

    for (i = 0; tlen > 1; i++)
    {
        csum += pkt[i];
        tlen -= 2;
    }

    if (tlen == 1) {
        *(uint8_t *)(&pad) = (*(uint8_t *)(pkt + i));
        csum += pad;
    }

    csum = (csum >> 16) + (csum & 0x0000FFFF);
    csum += (csum >> 16);

    return (uint16_t)~csum;
}

static uint16_t udp4_checksum(
    const uint16_t *shdr,
    const uint16_t *pkt,
    uint16_t tlen
)
{
    int i;
    uint16_t pad = 0;
    uint32_t csum = 0;

    csum += shdr[0] + shdr[1] + shdr[2] + shdr[3] + htons(17) + htons(tlen);

    csum += pkt[0] + pkt[1] + pkt[2];

    tlen -= 8;
    pkt += 4;

    for (i = 0; tlen > 1; i++)
    {
        csum += pkt[i];
        tlen -= 2;
    }

    if (tlen == 1) {
        *(uint8_t *)(&pad) = (*(uint8_t *)(pkt + i));
        csum += pad;
    }

    csum = (csum >> 16) + (csum & 0x0000FFFF);
    csum += (csum >> 16);

    uint16_t csum_u16 = (uint16_t)~csum;
    if (csum_u16 == 0)
        return 0xFFFF;
    else
        return csum_u16;
}

void e46_checksum(const uint8_t* ip_packet, int len)
{
    int payload_len = 0;
    int ip_hdr_size = 0;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct ip *hdr = (struct ip*)ip_packet;

    ip_hdr_size = hdr->ip_hl * 4;

    hdr->ip_sum = 0;
    hdr->ip_sum = ipv4_checksum((const uint16_t*)hdr, ip_hdr_size);

    if (hdr->ip_p == IPPROTO_TCP)
    {
        payload_len = ntohs(hdr->ip_len) - ip_hdr_size;
        tcp_header = (struct tcphdr*)(((uint8_t*)hdr) + ip_hdr_size);
        tcp_header->th_sum = tcp4_checksum(
            (const uint16_t*)&hdr->ip_src,
            (const uint16_t*)(((uint8_t*)hdr) + ip_hdr_size),
            payload_len
        );
    }
    else if (hdr->ip_p == IPPROTO_UDP)
    {
        payload_len = ntohs(hdr->ip_len) - ip_hdr_size;
        udp_header = (struct udphdr*)(((uint8_t*)hdr) + ip_hdr_size);
        udp_header->uh_sum = udp4_checksum(
            (const uint16_t*)&hdr->ip_src,
            (const uint16_t*)(((uint8_t*)hdr) + ip_hdr_size),
            payload_len
        );
    }
}