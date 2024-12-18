#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>

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

void send_icmp_reply(pcap_t *handle, const unsigned char *request) {
    unsigned char reply[50];
    memcpy(reply, request, 50);

    // Source ve Destination MAC değişimi
    memcpy(reply, request + 6, 6);
    memcpy(reply + 6, request, 6);

    // Source ve Destination IP değişimi
    memcpy(reply + 26, request + 30, 4);
    memcpy(reply + 30, request + 26, 4);

    // ICMP Header
    reply[34] = 0x00;  // Type (Echo Reply)
    reply[36] = 0x00;  // Checksum (hesaplanacak)
    reply[37] = 0x00;

    // ICMP Checksum
    unsigned short *icmp_hdr = (unsigned short *)&reply[34];
    unsigned short icmp_checksum = calculate_checksum(icmp_hdr, 16);
    reply[36] = (icmp_checksum >> 8) & 0xff;
    reply[37] = icmp_checksum & 0xff;

    // Paket gönderimi
    if (pcap_sendpacket(handle, reply, 50) != 0) {
        fprintf(stderr, "Error sending ICMP reply: %s\n", pcap_geterr(handle));
    } else {
        printf("ICMP Echo Reply gönderildi.\n");
    }
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

    printf("Sunucu çalışıyor ve ICMP paketlerini dinliyor...\n");

    struct pcap_pkthdr *header;
    const u_char *packet;
    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        // ICMP Echo Request kontrolü
        if(packet[30] == 192 && packet[31] == 168 && packet[32] == 1 && packet[33] == 1) {
            printf("Kendi gönderdiğimiz ICMP Echo Request paketini alındı. Atlanıyor...\n");
            continue;
        }
        
        if (packet[23] == 0x01) {// Protocol ICMP
            if(packet[34] == 0x08) {  // Type Echo Request
                printf("ICMP Echo Request alındı. Reply gönderiliyor...\n");
                send_icmp_reply(handle, packet);
            } else if(packet[34] == 0x0e) {  // Type Timestamp Request
                printf("ICMP Timestamp Request alındı. Reply gönderiliyor...\n");
            } else if(packet[34] == 0x10) { // Type Information Request
                printf("ICMP Information Request alındı. Reply gönderiliyor...\n");
            } else if(packet[34] == 0x12) { // Type Address Mask Request
                printf("ICMP Address Mask Request alındı. Reply gönderiliyor...\n");
            } else {
                printf("Bilinmeyen ICMP paketi alındı.\n");
            }
        }
    }

    pcap_close(handle);
    return 0;
}
