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
    int last_octet_count[256] = {0}; // array to count occurrences of last octet values (0-255)

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    // open the pcap file for reading
    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    // loop through each packet in the pcap file
    while ((packet = pcap_next(handle, &header)) != NULL)
    {
        ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

        // extract the destination IP address
        struct in_addr addr;
        addr.s_addr = ip_header->daddr;

        // extract the last octet of the destination IP address
        int last_octet = addr.s_addr & 0xFF;

        // increment the count for this last octet
        last_octet_count[last_octet]++;
        printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(addr));
    }

    // print occurrences of each last octet value
    for (int i = 0; i < 256; i++)
    {
        if (last_octet_count[i] > 0)
        {
            printf("Last octet %d: %d\n", i, last_octet_count[i]);
        }
    }

    // close the pcap file
    pcap_close(handle);
    return 0;
}