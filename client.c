#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>

// ICMP Checksum Hesaplama
unsigned short calculate_checksum(unsigned short *p, int n) {
    unsigned long sum = 0;
    while (n > 1) {
        sum += *p++;
        n -= 2;
    }
    if (n == 1) {
        sum += *(unsigned char *)p;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main() {
    char errbuffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    // char *dev = pcap_lookupdev(errbuffer);
    char* dev = "en0";

    if (dev == NULL) {
        printf("Error finding device: %s\n", errbuffer);
        exit(EXIT_FAILURE);
    }
    printf("Using device: %s\n", dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuffer);
    if (handle == NULL) {
        printf("Error opening device: %s\n", errbuffer);
        exit(EXIT_FAILURE);
    }

    u_char packet[50];
    memset(packet, 0, sizeof(packet));

    // Ethernet Header
    // Destination MAC Address (broadcast)
    memset(packet, 0xff, 6);  // Broadcast
    // Source MAC Address (dummy)
    memset(packet + 6, 0x01, 6);
    // Ethernet Type (IPv4)
    packet[12] = 0x08;
    packet[13] = 0x00;

    // IP Header
    packet[14] = 0x45;  // Version & Header Length
    packet[15] = 0x00;  // Type of Service
    packet[16] = 0x00;  // Total Length (high byte)
    packet[17] = 0x32;  // Total Length (low byte)
    packet[18] = 0x1c;  // Identification (high byte)
    packet[19] = 0x46;  // Identification (low byte)
    packet[20] = 0x00;  // Flags and Fragment Offset
    packet[21] = 0x00;
    packet[22] = 0x05;  // TTL
    packet[23] = 0x01;  // Protocol (ICMP)
    packet[24] = 0x00;  // Header Checksum (will calculate later)
    packet[25] = 0x00;

    // Source IP Address
    packet[26] = 192;  // 192.168.1.1
    packet[27] = 168;
    packet[28] = 1;
    packet[29] = 1;

    // Destination IP Address
    packet[30] = 172;  //  172.20.10.15
    packet[31] = 20;
    packet[32] = 10;
    packet[33] = 15;

    // Calculate IP Checksum
    unsigned short *ip_hdr = (unsigned short *)&packet[14];
    unsigned short ip_checksum = calculate_checksum(ip_hdr, 20);
    packet[24] = (ip_checksum >> 8) & 0xff;
    packet[25] = ip_checksum & 0xff;

    // ICMP Header
    packet[34] = 0x08;  // Type (Echo Request)
    packet[35] = 0x00;  // Code
    packet[36] = 0x00;  // Checksum (will calculate later)
    packet[37] = 0x00;
    packet[38] = 0x12;  // Identifier (arbitrary)
    packet[39] = 0x34;
    packet[40] = 0x00;  // Sequence Number
    packet[41] = 0x01;

    // Calculate ICMP Checksum
    unsigned short *icmp_hdr = (unsigned short *)&packet[34];
    unsigned short icmp_checksum = calculate_checksum(icmp_hdr, 16);
    packet[36] = (icmp_checksum >> 8) & 0xff;
    packet[37] = icmp_checksum & 0xff;

    // Gönderim
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        printf("Error sending packet: %s\n", pcap_geterr(handle));
        return 1;
    }
    printf("ICMP Echo Request gönderildi.\n");

    // Dinleme
    struct pcap_pkthdr *header;
    const u_char *recv_packet;
    while (pcap_next_ex(handle, &header, &recv_packet) >= 0) {
        // Gelen paket IP protokolüne ait mi kontrol et
        if (recv_packet[23] == 0x01) {// Protocol ICMP
            if(recv_packet[34] == 0x00) {  // Type Echo Reply
                printf("ICMP Echo Reply alındı.\n");
                break;
            } else if(recv_packet[34] == 0x03) {  // Type Destination Unreachable
                if(recv_packet[35] == 0x00) {  // Code Network Unreachable
                    printf("ICMP Destination Unreachable (Network Unreachable) alındı.\n");
                } else if(recv_packet[35] == 0x01) {  // Code Host Unreachable
                    printf("ICMP Destination Unreachable (Host Unreachable) alındı.\n");
                } else if(recv_packet[35] == 0x02) {  // Code Protocol Unreachable
                    printf("ICMP Destination Unreachable (Protocol Unreachable) alındı.\n");
                } else if(recv_packet[35] == 0x03) {  // Code Port Unreachable
                    printf("ICMP Destination Unreachable (Port Unreachable) alındı.\n");
                } else if(recv_packet[35] == 0x04) {  // Code Fragmentation Needed and Don't Fragment was Set
                    printf("ICMP Destination Unreachable (Fragmentation Needed and Don't Fragment was Set) alındı.\n");
                } else if(recv_packet[35] == 0x05) {  // Code Source Route Failed
                    printf("ICMP Destination Unreachable (Source Route Failed) alındı.\n");
                } else if(recv_packet[35] == 0x06) {  // Code Destination Network Unknown
                    printf("ICMP Destination Unreachable (Destination Network Unknown) alındı.\n");
                } else if(recv_packet[35] == 0x07) {  // Code Destination Host Unknown
                    printf("ICMP Destination Unreachable (Destination Host Unknown) alındı.\n");
                } else if(recv_packet[35] == 0x08) {  // Code Source Host Isolated
                    printf("ICMP Destination Unreachable (Source Host Isolated) alındı.\n");
                } else if(recv_packet[35] == 0x09) {  // Code Network Administratively Prohibited
                    printf("ICMP Destination Unreachable (Network Administratively Prohibited) alındı.\n");
                } else if(recv_packet[35] == 0x0a) {  // Code Host Administratively Prohibited
                    printf("ICMP Destination Unreachable (Host Administratively Prohibited) alındı.\n");
                } else if(recv_packet[35] == 0x0b) {  // Code Network Unreachable for TOS
                    printf("ICMP Destination Unreachable (Network Unreachable for TOS) alındı.\n");
                } else if(recv_packet[35] == 0x0c) { // Code Host Unreachable for TOS
                    printf("ICMP Destination Unreachable (Host Unreachable for TOS) alındı.\n");
                } else if(recv_packet[35] == 0x0d) {  // Code Communication Administratively Prohibited
                    printf("ICMP Destination Unreachable (Communication Administratively Prohibited) alındı.\n");
                } else {
                    printf("ICMP Destination Unreachable (Unknown Code) alındı.\n");
                }
            } else if(recv_packet[34] == 0x04) {  // Type Source Quench
                printf("ICMP Source Quench alındı.\n");
            } else if(recv_packet[34] == 0x05) {  // Type Redirect
                if(recv_packet[35] == 0x00) {  // Code Redirect Datagram for the Network
                    printf("ICMP Redirect (Redirect Datagram for the Network) alındı.\n");
                } else if(recv_packet[35] == 0x01) {  // Code Redirect Datagram for the Host
                    printf("ICMP Redirect (Redirect Datagram for the Host) alındı.\n");
                } else if(recv_packet[35] == 0x02) {  // Code Redirect Datagram for the TOS & Network
                    printf("ICMP Redirect (Redirect Datagram for the TOS & Network) alındı.\n");
                } else if(recv_packet[35] == 0x03) {  // Code Redirect Datagram for the TOS & Host
                    printf("ICMP Redirect (Redirect Datagram for the TOS & Host) alındı.\n");
                } else {
                    printf("ICMP Redirect (Unknown Code) alındı.\n");
                }
            } else if(recv_packet[34] == 0x09) { // Type Router Advertisement
                printf("ICMP Router Advertisement alındı.\n");
            } else if(recv_packet[34] == 0x0a) {  // Type Router Solicitation
                printf("ICMP Router Solicitation alındı.\n");
            } else if(recv_packet[34] == 0x0b) {  // Type Time Exceeded
                if(recv_packet[35] == 0x00) {  // Code Time to Live Exceeded in Transit
                    printf("ICMP Time Exceeded (Time to Live Exceeded in Transit) alındı.\n");
                } else if(recv_packet[35] == 0x01) {  // Code Fragment Reassembly Time Exceeded
                    printf("ICMP Time Exceeded (Fragment Reassembly Time Exceeded) alındı.\n");
                } else {
                    printf("ICMP Time Exceeded (Unknown Code) alındı.\n");
                }
            } else if(recv_packet[34] == 0x0d) {  // Type Timestamp
                printf("ICMP Timestamp alındı.\n");
            } else if(recv_packet[34] == 0x0f) { // Type Information Request
                printf("ICMP Information Request alındı.\n");
            } else if(recv_packet[34] == 0x11) {  // Type Address Mask Request
                printf("ICMP Address Mask Request alındı.\n");
            } else if(recv_packet[34] == 0x1e) {  // Type Traceroute
                printf("ICMP Traceroute alındı.\n");
            } else {
                printf("Bilinmeyen ICMP türü alındı.\n");
            }
            break;
        }
    }

    pcap_close(handle);
    return 0;
}
