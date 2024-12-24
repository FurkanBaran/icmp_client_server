#ifdef __APPLE__
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
    #include <net/if.h>
    #include <net/if_dl.h>
    #include <net/if_types.h>
#else // Linux
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
    #include <net/if.h>
    #include <sys/ioctl.h>
    #include <linux/if_ether.h>
    #include <linux/if_arp.h>
#endif

#include <errno.h>

#define TIMEOUT_SEC 3
#define MAX_TRIES 4
#define TTL_VALUE 64
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0
#define ICMP_DEST_UNREACHABLE 3
#define ETH_ALEN 6
#define ETH_P_IP 0x0800

#pragma pack(1)
struct eth_header {
    uint8_t h_dest[ETH_ALEN];
    uint8_t h_source[ETH_ALEN];
    uint16_t h_proto;
};

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
volatile sig_atomic_t received_sigint = 0;
struct timeval timeout_tv;
struct timeval send_time;
unsigned short sequence = 0;
char source_ip_str[INET_ADDRSTRLEN];

void signal_handler(int signum) {
    received_sigint = 1;
    keep_running = 0;
    printf("\nProgram sonlandırılıyor...\n");
}

void cleanup() {
    if (handle) {
        pcap_close(handle);
    }
}

void print_packet_info(const u_char *packet, int is_sent) {
    struct eth_header *eth = (struct eth_header *)packet;
    IPHeader *ip = (IPHeader *)(packet + sizeof(struct eth_header));
    ICMPHeader *icmp = (ICMPHeader *)(packet + sizeof(struct eth_header) + sizeof(IPHeader));

    printf("\n%s Paket Detayları:\n", is_sent ? "Gönderilen" : "Alınan");
    printf("MAC Adresleri:\n");
    printf("  Kaynak: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("  Hedef: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

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

char* get_interface_ip(const char *interface) {
    struct ifaddrs *ifaddr, *ifa;
    static char ip[INET_ADDRSTRLEN];
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
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
}

int get_interface_mac(const char *interface, uint8_t *mac_addr) {
#ifdef __APPLE__
    struct ifaddrs *ifap, *ifaptr;
    
    if (getifaddrs(&ifap) == 0) {
        for (ifaptr = ifap; ifaptr != NULL; ifaptr = ifaptr->ifa_next) {
            if (strcmp(ifaptr->ifa_name, interface) == 0 && 
                ifaptr->ifa_addr->sa_family == AF_LINK) {
                struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifaptr->ifa_addr;
                memcpy(mac_addr, LLADDR(sdl), 6);
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

int send_icmp_request(pcap_t *handle, const char *interface, 
                     struct in_addr src_ip, struct in_addr dest_ip) {
    uint8_t packet[sizeof(struct eth_header) + sizeof(IPHeader) + sizeof(ICMPHeader)];
    memset(packet, 0, sizeof(packet));

    struct eth_header *eth = (struct eth_header *)packet;
    uint8_t src_mac[6];
    if (get_interface_mac(interface, src_mac) < 0) {
        fprintf(stderr, "MAC adresi alınamadı\n");
        return -1;
    }
    memcpy(eth->h_source, src_mac, 6);
    memset(eth->h_dest, 0xff, 6);
    eth->h_proto = htons(ETH_P_IP);

    IPHeader *ip = (IPHeader *)(packet + sizeof(struct eth_header));
    ip->version_ihl = 0x45;
    ip->tos = 0;
    ip->total_length = htons(sizeof(IPHeader) + sizeof(ICMPHeader));
    ip->identification = htons(getpid() & 0xFFFF);
    ip->flags_fragment_offset = 0;
    ip->ttl = TTL_VALUE;
    ip->protocol = IPPROTO_ICMP;
    ip->source_ip = src_ip.s_addr;
    ip->dest_ip = dest_ip.s_addr;
    ip->header_checksum = 0;
    ip->header_checksum = calculate_checksum((unsigned short *)ip, sizeof(IPHeader));

    ICMPHeader *icmp = (ICMPHeader *)(packet + sizeof(struct eth_header) + sizeof(IPHeader));
    icmp->type = ICMP_ECHO_REQUEST;
    icmp->code = 0;
    icmp->identifier = htons(getpid() & 0xFFFF);
    icmp->sequence = htons(++sequence);
    icmp->checksum = 0;
    icmp->checksum = calculate_checksum((unsigned short *)icmp, sizeof(ICMPHeader));

    print_packet_info(packet, 1);
    printf("ICMP Echo Request gönderiliyor...\n");
    gettimeofday(&send_time, NULL);

    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "Paket gönderilemedi: %s\n", pcap_geterr(handle));
        return -1;
    }

    return 0;
}

int process_packet(const u_char *packet, int len) {
    struct eth_header *eth = (struct eth_header *)packet;
    if (ntohs(eth->h_proto) != ETH_P_IP) return 0;

    IPHeader *ip = (IPHeader *)(packet + sizeof(struct eth_header));
    if (ip->protocol != IPPROTO_ICMP) return 0;

    ICMPHeader *icmp = (ICMPHeader *)(packet + sizeof(struct eth_header) + sizeof(IPHeader));
    
    print_packet_info(packet, 0);
    struct timeval recv_time, diff_time;
    gettimeofday(&recv_time, NULL);
    timersub(&recv_time, &send_time, &diff_time);
    double ms = (diff_time.tv_sec * 1000.0) + (diff_time.tv_usec / 1000.0);

    switch(icmp->type) {
        case 0x00:  // Echo Reply
            printf("ICMP Echo Reply alındı. (%.3f ms)\n", ms);
            return 1;

        case 0x03:  // Destination Unreachable
            printf("ICMP Destination Unreachable: ");
            switch(icmp->code) {
                case 0x00:
                    printf("Network Unreachable\n");
                    break;
                case 0x01:
                    printf("Host Unreachable\n");
                    break;
                case 0x02:
                    printf("Protocol Unreachable\n");
                    break;
                case 0x03:
                    printf("Port Unreachable\n");
                    break;
                case 0x04:
                    printf("Fragmentation Needed and Don't Fragment was Set\n");
                    break;
                default:
                    printf("Code: 0x%02x\n", icmp->code);
                    break;
            }
            return 1;

        case 0x0b:  // Time Exceeded
            printf("ICMP Time Exceeded: ");
            switch(icmp->code) {
                case 0x00:
                    printf("TTL Exceeded in Transit\n");
                    break;
                case 0x01:
                    printf("Fragment Reassembly Time Exceeded\n");
                    break;
                default:
                    printf("Code: 0x%02x\n", icmp->code);
                    break;
            }
            return 1;

        default:
            printf("Beklenmeyen ICMP paketi alındı (Type: 0x%02x, Code: 0x%02x) (%.3f ms)\n", 
                   icmp->type, icmp->code, ms);
            return 0;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Kullanım: %s <hedef_ip>\n", argv[0]);
        return 1;
    }

    if (getuid() != 0) {
        fprintf(stderr, "Root yetkisi gerekli!\n");
        return 1;
    }

    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    char errbuf[PCAP_ERRBUF_SIZE];
    struct in_addr src_ip, dest_ip;

    if (inet_pton(AF_INET, argv[1], &dest_ip) != 1) {
        fprintf(stderr, "Geçersiz IP adresi\n");
        return 1;
    }

    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Interface bulunamadı: %s\n", errbuf);
        return 1;
    }

    char *interface = alldevs->name;
    printf("Kullanılan arayüz: %s\n", interface);

    char *source_ip = get_interface_ip(interface);
    if (!source_ip) {
        fprintf(stderr, "Kaynak IP alınamadı\n");
        pcap_freealldevs(alldevs);
        return 1;
    }
    printf("Kaynak IP: %s\n", source_ip);
    printf("Hedef IP: %s\n", argv[1]);

    inet_pton(AF_INET, source_ip, &src_ip);

    handle = pcap_open_live(interface, BUFSIZ, 1, 100, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live hatası: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

        printf("\nARP Tablosu:\n");
    #ifdef __APPLE__
        system("arp -a");
    #else
        system("arp -n");
    #endif

    struct bpf_program fp;
    char filter_exp[256];
    #ifdef __APPLE__
        // macOS için daha spesifik filtre
        snprintf(filter_exp, sizeof(filter_exp), 
                "icmp and not (src host %s and dst host %s)", 
                source_ip, argv[1]);
    #else
        // Linux için mevcut filtre
        snprintf(filter_exp, sizeof(filter_exp), "icmp");
    #endif

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

    int tries = 0;
    while (keep_running && tries < MAX_TRIES) {
        if (received_sigint) {
            break;
        }

        if (send_icmp_request(handle, interface, src_ip, dest_ip) < 0) {
            fprintf(stderr, "ICMP isteği gönderilemedi\n");
            break;
        }

        struct pcap_pkthdr *header;
        const u_char *packet;
        int res;

        timeout_tv.tv_sec = TIMEOUT_SEC;
        timeout_tv.tv_usec = 0;

        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(pcap_get_selectable_fd(handle), &read_set);

        res = select(pcap_get_selectable_fd(handle) + 1, &read_set, NULL, NULL, &timeout_tv);
        if (res == 0) {
            printf("Deneme %d: Timeout - Yanıt alınamadı\n", tries + 1);
            tries++;
            continue;
        }
        else if (res < 0) {
            if (errno != EINTR) {
                perror("select");
                break;
            }
            continue;
        }

        res = pcap_next_ex(handle, &header, &packet);
        if (res < 0) break;
        if (res == 0) continue;

        if (process_packet(packet, header->len)) {
            break;
        }
    }

    if (tries >= MAX_TRIES) {
        printf("\nMaksimum deneme sayısına ulaşıldı. Hedef yanıt vermiyor.\n");
    }

    cleanup();
    pcap_freealldevs(alldevs);
    return 0;
}