#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct iphdr *ip_header;
    int packet_count = 0;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL)
    {
        ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
        /*
        root@99d96c950aea:/# cd /code
        gcc -o original original.c -lpcap
        original.c: In function 'main':
        original.c:32:87: warning: cast to pointer from integer of different size [-Wint-to-pointer-cast]
        32 |  IP destination address: %s\n", ++packet_count, inet_ntoa(*((struct in_addr *)ip_header->daddr)));
        |                                                             ^
        There was a warning about casting an integer to a pointer.
        ip_header->daddr is likely an integer representing IPv4 address but it is casted to a pointer
        */
        struct in_addr addr;            // store such addresses
        addr.s_addr = ip_header->daddr; // passing the IP address without incorrect casting
        printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(addr));
    }

    pcap_close(handle);
    return 0;
}