#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef unsigned char u_char;

// Global değişkenler
pcap_t *handle = NULL;
volatile sig_atomic_t keep_running = 1;
unsigned long packets_sent = 0;
unsigned long packets_received = 0;

// Sinyal yakalayıcı
void signal_handler(int signum) {
    keep_running = 0;
}

// Cleanup fonksiyonu
void cleanup() {
    if (handle) {
        pcap_close(handle);
    }
    printf("\n--- İstatistikler ---\n");
    printf("Gönderilen paket: %lu\n", packets_sent);
    printf("Alınan paket: %lu\n", packets_received);
}

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

// Arayüzün IP adresini alma
char* get_interface_ip(const char *interface_name) {
    struct ifaddrs *ifaddr, *ifa;
    static char ip[INET_ADDRSTRLEN];
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        if (ifa->ifa_addr->sa_family == AF_INET && 
            strcmp(ifa->ifa_name, interface_name) == 0) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
            freeifaddrs(ifaddr);
            return ip;
        }
    }

    freeifaddrs(ifaddr);
    return NULL;
}

// Paket içeriğini yazdırma fonksiyonu
void print_packet_info(const u_char *packet, int is_sent) {
    printf("\n%s Paket Detayları:\n", is_sent ? "Gönderilen" : "Alınan");
    printf("MAC Adresleri:\n");
    printf("  Kaynak: %02x:%02x:%02x:%02x:%02x:%02x\n",
           packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    printf("  Hedef: %02x:%02x:%02x:%02x:%02x:%02x\n",
           packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    
    printf("IP Adresleri:\n");
    printf("  Kaynak: %d.%d.%d.%d\n",
           packet[26], packet[27], packet[28], packet[29]);
    printf("  Hedef: %d.%d.%d.%d\n",
           packet[30], packet[31], packet[32], packet[33]);
    
    printf("ICMP Bilgileri:\n");
    printf("  Tip: 0x%02x\n", packet[34]);
    printf("  Kod: 0x%02x\n", packet[35]);
    printf("  Checksum: 0x%02x%02x\n", packet[36], packet[37]);
    printf("  Identifier: 0x%02x%02x\n", packet[38], packet[39]);
    printf("  Sequence: 0x%02x%02x\n", packet[40], packet[41]);
}

int main(int argc, char *argv[]) {
    char errbuffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    struct in_addr src_ip, dest_ip;

    // Hedef IP kontrolü
    if (argc != 2) {
        fprintf(stderr, "Kullanım: %s <hedef_ip>\n", argv[0]);
        fprintf(stderr, "Örnek: %s 192.168.1.100\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Hedef IP'yi parse et
    if (inet_pton(AF_INET, argv[1], &dest_ip) != 1) {
        fprintf(stderr, "Geçersiz IP adresi\n");
        exit(EXIT_FAILURE);
    }

    // Root kontrolü
    if (getuid() != 0) {
        fprintf(stderr, "Bu program root yetkisi gerektirir!\n");
        exit(EXIT_FAILURE);
    }

    // Sinyal yakalayıcı kurulumu
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Network arayüzünü bul
    if (pcap_findalldevs(&alldevs, errbuffer) == -1) {
        fprintf(stderr, "Arayüz listesi alınamadı: %s\n", errbuffer);
        exit(EXIT_FAILURE);
    }

    char *dev = alldevs->name;
    printf("Kullanılan arayüz: %s\n", dev);

    // Arayüzün IP adresini al
    char *source_ip = get_interface_ip(dev);
    if (!source_ip) {
        fprintf(stderr, "Arayüz IP adresi alınamadı\n");
        pcap_freealldevs(alldevs);
        exit(EXIT_FAILURE);
    }
    printf("Kaynak IP: %s\n", source_ip);
    printf("Hedef IP: %s\n", argv[1]);

    inet_pton(AF_INET, source_ip, &src_ip);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuffer);
    pcap_freealldevs(alldevs);

    if (handle == NULL) {
        fprintf(stderr, "Arayüz açılamadı: %s\n", errbuffer);
        exit(EXIT_FAILURE);
    }

    u_char packet[50];
    memset(packet, 0, sizeof(packet));

    // Ethernet Header
    memset(packet, 0xff, 6);      // Destination MAC (broadcast)
    memset(packet + 6, 0x01, 6);  // Source MAC
    packet[12] = 0x08;  // IPv4
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
    packet[22] = 0x01;  // TTL
    packet[23] = 0x01;  // Protocol (ICMP)
    packet[24] = 0x00;  // Header Checksum
    packet[25] = 0x00;

    // Source IP Address
    memcpy(packet + 26, &src_ip.s_addr, 4);

    // Destination IP Address
    memcpy(packet + 30, &dest_ip.s_addr, 4);

    // Calculate IP Checksum
    unsigned short *ip_hdr = (unsigned short *)&packet[14];
    unsigned short ip_checksum = calculate_checksum(ip_hdr, 20);
    packet[24] = (ip_checksum >> 8) & 0xff;
    packet[25] = ip_checksum & 0xff;

    // ICMP Header
    packet[34] = 0x08;  // Type (Echo Request)
    packet[35] = 0x00;  // Code
    packet[36] = 0x00;  // Checksum
    packet[37] = 0x00;
    packet[38] = 0x12;  // Identifier
    packet[39] = 0x34;
    packet[40] = 0x00;  // Sequence Number
    packet[41] = 0x01;

    // Calculate ICMP Checksum
    unsigned short *icmp_hdr = (unsigned short *)&packet[34];
    unsigned short icmp_checksum = calculate_checksum(icmp_hdr, 16);
    packet[36] = (icmp_checksum >> 8) & 0xff;
    packet[37] = icmp_checksum & 0xff;

    // Gönderim öncesi paket bilgilerini yazdır
    print_packet_info(packet, 1);

    // Gönderim
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "Paket gönderilemedi: %s\n", pcap_geterr(handle));
        cleanup();
        return 1;
    }
    packets_sent++;
    printf("ICMP Echo Request gönderildi.\n");

    // ARP tablosunu göster
    printf("\nARP Tablosu:\n");
    system("arp -n");

    // Dinleme
    struct pcap_pkthdr *header;
    const u_char *recv_packet;
    while (keep_running && pcap_next_ex(handle, &header, &recv_packet) >= 0) {
        if (recv_packet[23] == 0x01) {  // Protocol ICMP
            // Gelen paket bilgilerini yazdır
            print_packet_info(recv_packet, 0);

            // Kaynak IP kontrolü (bizim hedef IP'miz olmalı)
            if (memcmp(recv_packet + 26, packet + 30, 4) == 0) {
                printf("Yanıt bizim hedef IP'den geldi\n");
                
                // Hedef IP kontrolü (bizim IP'miz olmalı)
                if (memcmp(recv_packet + 30, packet + 26, 4) == 0) {
                    switch(recv_packet[34]) {  // ICMP Type
                        case 0x00:  // Echo Reply
                            printf("ICMP Echo Reply alındı.\n");
                            packets_received++;
                            goto exit_loop;

                        case 0x03:  // Destination Unreachable
                            switch(recv_packet[35]) {
                                case 0x00:
                                    printf("ICMP Destination Unreachable (Network Unreachable) alındı.\n");
                                    break;
                                case 0x01:
                                    printf("ICMP Destination Unreachable (Host Unreachable) alındı.\n");
                                    break;
                                case 0x02:
                                    printf("ICMP Destination Unreachable (Protocol Unreachable) alındı.\n");
                                    break;
                                case 0x03:
                                    printf("ICMP Destination Unreachable (Port Unreachable) alındı.\n");
                                    break;
                                case 0x04:
                                    printf("ICMP Destination Unreachable (Fragmentation Needed and Don't Fragment was Set) alındı.\n");
                                    break;
                                case 0x05:
                                    printf("ICMP Destination Unreachable (Source Route Failed) alındı.\n");
                                    break;
                                case 0x06:
                                    printf("ICMP Destination Unreachable (Destination Network Unknown) alındı.\n");
                                    break;
                                case 0x07:
                                    printf("ICMP Destination Unreachable (Destination Host Unknown) alındı.\n");
                                    break;
                                case 0x08:
                                    printf("ICMP Destination Unreachable (Source Host Isolated) alındı.\n");
                                    break;
                                case 0x09:
                                    printf("ICMP Destination Unreachable (Network Administratively Prohibited) alındı.\n");
                                    break;
                                case 0x0a:
                                    printf("ICMP Destination Unreachable (Host Administratively Prohibited) alındı.\n");
                                    break;
                                case 0x0b:
                                    printf("ICMP Destination Unreachable (Network Unreachable for TOS) alındı.\n");
                                    break;
                                case 0x0c:
                                    printf("ICMP Destination Unreachable (Host Unreachable for TOS) alındı.\n");
                                    break;
                                case 0x0d:
                                    printf("ICMP Destination Unreachable (Communication Administratively Prohibited) alındı.\n");
                                    break;
                                default:
                                    printf("ICMP Destination Unreachable (Unknown Code: %d) alındı.\n", recv_packet[35]);
                                    break;
                            }
                            goto exit_loop;

                        case 0x04:  // Source Quench
                            printf("ICMP Source Quench alındı.\n");
                            goto exit_loop;

                        case 0x05:  // Redirect
                            switch(recv_packet[35]) {
                                case 0x00:
                                    printf("ICMP Redirect (Redirect Datagram for the Network) alındı.\n");
                                    break;
                                case 0x01:
                                    printf("ICMP Redirect (Redirect Datagram for the Host) alındı.\n");
                                    break;
                                case 0x02:
                                    printf("ICMP Redirect (Redirect Datagram for the TOS & Network) alındı.\n");
                                    break;
                                case 0x03:
                                    printf("ICMP Redirect (Redirect Datagram for the TOS & Host) alındı.\n");
                                    break;
                                default:
                                    printf("ICMP Redirect (Unknown Code: %d) alındı.\n", recv_packet[35]);
                                    break;
                            }
                            goto exit_loop;

                        case 0x09:  // Router Advertisement
                            printf("ICMP Router Advertisement alındı.\n");
                            goto exit_loop;

                        case 0x0a:  // Router Solicitation
                            printf("ICMP Router Solicitation alındı.\n");
                            goto exit_loop;

                        case 0x0b:  // Time Exceeded
                            switch(recv_packet[35]) {
                                case 0x00:
                                    printf("ICMP Time Exceeded (Time to Live Exceeded in Transit) alındı.\n");
                                    break;
                                case 0x01:
                                    printf("ICMP Time Exceeded (Fragment Reassembly Time Exceeded) alındı.\n");
                                    break;
                                default:
                                    printf("ICMP Time Exceeded (Unknown Code: %d) alındı.\n", recv_packet[35]);
                                    break;
                            }
                            goto exit_loop;

                        case 0x0d:  // Timestamp
                            printf("ICMP Timestamp alındı.\n");
                            goto exit_loop;

                        case 0x0e:  // Timestamp Reply
                            printf("ICMP Timestamp Reply alındı.\n");
                            goto exit_loop;

                        case 0x0f:  // Information Request
                            printf("ICMP Information Request alındı.\n");
                            goto exit_loop;

                        case 0x10:  // Information Reply
                            printf("ICMP Information Reply alındı.\n");
                            goto exit_loop;

                        case 0x11:  // Address Mask Request
                            printf("ICMP Address Mask Request alındı.\n");
                            goto exit_loop;

                        case 0x12:  // Address Mask Reply
                            printf("ICMP Address Mask Reply alındı.\n");
                            goto exit_loop;

                        case 0x1e:  // Traceroute
                            printf("ICMP Traceroute alındı.\n");
                            goto exit_loop;

                        default:
                            printf("Bilinmeyen ICMP türü (0x%02x) alındı.\n", recv_packet[34]);
                            goto exit_loop;
                    }
                } else {
                    printf("Yanıt farklı bir hedef IP'ye gönderilmiş!\n");
                }
            } else {
                printf("Yanıt farklı bir kaynaktan geldi!\n");
            }
        }
    }
    exit_loop:

    cleanup();
    return 0;
}