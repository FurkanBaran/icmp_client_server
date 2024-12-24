#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <pcap.h>
    #pragma comment(lib, "wpcap.lib")
    #pragma comment(lib, "ws2_32.lib")
    #define PCAP_BUF_SIZE 65536
#else
    #include <pcap.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
    #include <netinet/if_ether.h>
    #include <net/if.h>
    #ifdef __APPLE__
        #include <net/if_dl.h>
        #include <net/if_types.h>
        #include <ifaddrs.h>
    #else
        #include <sys/ioctl.h>
        #include <linux/if_ether.h>
        #include <ifaddrs.h>
    #endif
    #include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
typedef unsigned char u_char;
#define TTL_VALUE 64
#define ETHERNET_HEADER_LEN 14
#define IP_HEADER_LEN 20
#define ICMP_HEADER_LEN 8
#define PACKET_SIZE (ETHERNET_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN)

#pragma pack(1)
typedef struct {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
} EthernetHeader;

typedef struct {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t source_ip;
    uint32_t dest_ip;
} IPHeader;

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
} ICMPHeader;
#pragma pack()

pcap_t *handle = NULL;
volatile sig_atomic_t keep_running = 1;
unsigned long packets_received = 0;
unsigned long packets_sent = 0;

#ifdef _WIN32
BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        keep_running = 0;
        printf("\nSunucu kapatılıyor...\n");
        return TRUE;
    }
    return FALSE;
}
#else
void signal_handler(int signum) {
    keep_running = 0;
    printf("\nSunucu kapatılıyor...\n");
}
#endif

void print_packet_info(const u_char *packet, int is_sent) {
    EthernetHeader *eth = (EthernetHeader *)packet;
    IPHeader *ip = (IPHeader *)(packet + ETHERNET_HEADER_LEN);
    ICMPHeader *icmp = (ICMPHeader *)(packet + ETHERNET_HEADER_LEN + IP_HEADER_LEN);

    printf("\n%s Paket Detayları:\n", is_sent ? "Gönderilen" : "Alınan");
    printf("MAC Adresleri:\n");
    printf("  Kaynak: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
           eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);
    printf("  Hedef: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->dest_mac[0], eth->dest_mac[1], eth->dest_mac[2],
           eth->dest_mac[3], eth->dest_mac[4], eth->dest_mac[5]);

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->source_ip), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->dest_ip), dst_ip, INET_ADDRSTRLEN);

    printf("IP Adresleri:\n");
    printf("  Kaynak: %s\n", src_ip);
    printf("  Hedef: %s\n", dst_ip);
    printf("  TTL: %d\n", ip->ttl);

    printf("ICMP Bilgileri:\n");
    printf("  Tip: 0x%02x\n", icmp->type);
    printf("  Kod: 0x%02x\n", icmp->code);
    printf("  Checksum: 0x%04x\n", ntohs(icmp->checksum));
    printf("  Identifier: 0x%04x\n", ntohs(icmp->identifier));
    printf("  Sequence: 0x%04x\n", ntohs(icmp->sequence));
}

unsigned short calculate_checksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

int get_interface_mac(const char *interface, uint8_t *mac_addr) {
#ifdef _WIN32
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) return -1;
    
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        if (strcmp(d->name, interface) == 0) {
            // Windows için MAC adresi alma işlemi
            // Bu kısım Windows API'si kullanılarak implement edilmeli
            memset(mac_addr, 0x01, 6); // Geçici çözüm
            pcap_freealldevs(alldevs);
            return 0;
        }
    }
    pcap_freealldevs(alldevs);
    return -1;
#elif defined(__APPLE__)
    struct ifaddrs *ifap, *ifaptr;
    unsigned char *ptr;
    
    if (getifaddrs(&ifap) == 0) {
        for (ifaptr = ifap; ifaptr != NULL; ifaptr = ifaptr->ifa_next) {
            if (strcmp(ifaptr->ifa_name, interface) == 0 && 
                ifaptr->ifa_addr->sa_family == AF_LINK) {
                ptr = (unsigned char *)LLADDR((struct sockaddr_dl *)ifaptr->ifa_addr);
                memcpy(mac_addr, ptr, 6);
                freeifaddrs(ifap);
                return 0;
            }
        }
        freeifaddrs(ifap);
    }
    return -1;
#else // Linux
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return -1;
    }

    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return 0;
#endif
}

char* get_interface_ip(const char *interface) {
    static char ip[INET_ADDRSTRLEN];
#ifdef _WIN32
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) return NULL;
    
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        if (strcmp(d->name, interface) == 0) {
            for (pcap_addr_t *a = d->addresses; a != NULL; a = a->next) {
                if (a->addr->sa_family == AF_INET) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
                    inet_ntop(AF_INET, &(sin->sin_addr), ip, INET_ADDRSTRLEN);
                    pcap_freealldevs(alldevs);
                    return ip;
                }
            }
        }
    }
    pcap_freealldevs(alldevs);
    return NULL;
#else
    struct ifaddrs *ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) {
        return NULL;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        if (ifa->ifa_addr->sa_family == AF_INET && 
            strcmp(ifa->ifa_name, interface) == 0) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
            freeifaddrs(ifaddr);
            return ip;
        }
    }

    freeifaddrs(ifaddr);
    return NULL;
#endif
}

void send_icmp_reply(pcap_t *handle, const u_char *request_packet) {
    u_char reply_packet[PACKET_SIZE];
    memset(reply_packet, 0, PACKET_SIZE);

    // Ethernet header
    EthernetHeader *eth_reply = (EthernetHeader *)reply_packet;
    EthernetHeader *eth_request = (EthernetHeader *)request_packet;
    memcpy(eth_reply->dest_mac, eth_request->src_mac, 6);
    memcpy(eth_reply->src_mac, eth_request->dest_mac, 6);
    eth_reply->ether_type = eth_request->ether_type;

    // IP header
    IPHeader *ip_reply = (IPHeader *)(reply_packet + ETHERNET_HEADER_LEN);
    IPHeader *ip_request = (IPHeader *)(request_packet + ETHERNET_HEADER_LEN);
    memcpy(ip_reply, ip_request, sizeof(IPHeader));
    ip_reply->dest_ip = ip_request->source_ip;
    ip_reply->source_ip = ip_request->dest_ip;
    ip_reply->ttl = TTL_VALUE;
    ip_reply->header_checksum = 0;
    ip_reply->header_checksum = calculate_checksum((unsigned short *)ip_reply, sizeof(IPHeader));

    // ICMP header
    ICMPHeader *icmp_reply = (ICMPHeader *)(reply_packet + ETHERNET_HEADER_LEN + IP_HEADER_LEN);
    ICMPHeader *icmp_request = (ICMPHeader *)(request_packet + ETHERNET_HEADER_LEN + IP_HEADER_LEN);
    icmp_reply->type = 0;  // Echo Reply
    icmp_reply->code = 0;
    icmp_reply->identifier = icmp_request->identifier;
    icmp_reply->sequence = icmp_request->sequence;
    icmp_reply->checksum = 0;
    icmp_reply->checksum = calculate_checksum((unsigned short *)icmp_reply, sizeof(ICMPHeader));

    print_packet_info(reply_packet, 1);
    
    if (pcap_sendpacket(handle, reply_packet, PACKET_SIZE) != 0) {
        fprintf(stderr, "Yanıt gönderilemedi: %s\n", pcap_geterr(handle));
    } else {
        packets_sent++;
        printf("ICMP Echo Reply gönderildi.\n");
    }
}

void init_platform() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        exit(1);
    }
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGINT, signal_handler);
#endif
}

void cleanup() {
    if (handle) {
        pcap_close(handle);
    }
#ifdef _WIN32
    WSACleanup();
#endif
    printf("\n--- Sunucu İstatistikleri ---\n");
    printf("Alınan paket: %lu\n", packets_received);
    printf("Gönderilen yanıt: %lu\n", packets_sent);
}

int main() {
    init_platform();

#ifdef _WIN32
    if (!IsUserAnAdmin()) {
#else
    if (getuid() != 0) {
#endif
        fprintf(stderr, "Yönetici/root yetkisi gerekli!\n");
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Interface bulunamadı: %s\n", errbuf);
        return 1;
    }

    char *interface = alldevs->name;
    printf("Kullanılan arayüz: %s\n", interface);

    char *server_ip = get_interface_ip(interface);
    if (!server_ip) {
        fprintf(stderr, "Server IP alınamadı\n");
        pcap_freealldevs(alldevs);
        return 1;
    }
    printf("Server IP: %s\n", server_ip);

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live hatası: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[100];
    snprintf(filter_exp, sizeof(filter_exp), "icmp[icmptype] = 8");  // Sadece Echo Request
    
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Filter derlenemedi\n");
        cleanup();
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Filter uygulanamadı\n");
        cleanup();
        return 1;
    }

    printf("\nICMP Server başlatıldı. Echo Request paketleri bekleniyor...\n");
    printf("Kapatmak için Ctrl+C'ye basın\n\n");

    struct pcap_pkthdr *header;
    const u_char *packet;

    while (keep_running) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;  // Timeout
        if (res < 0) break;      // Hata

        packets_received++;
        printf("\nICMP Echo Request alındı (#%lu)\n", packets_received);
        print_packet_info(packet, 0);
        
        send_icmp_reply(handle, packet);
    }

    cleanup();
    pcap_freealldevs(alldevs);
    return 0;
}