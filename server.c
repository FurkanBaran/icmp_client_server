#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <errno.h>

#define TTL_VALUE 64

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
} ICMPHeader;

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

pcap_t *handle = NULL;
volatile sig_atomic_t keep_running = 1;
unsigned long packets_received = 0;
unsigned long packets_sent = 0;

void signal_handler(int signum) {
    keep_running = 0;
    printf("\nSunucu kapatılıyor...\n");
}

void cleanup() {
    if (handle) {
        pcap_close(handle);
    }
    printf("\n--- Sunucu İstatistikleri ---\n");
    printf("Alınan paket: %lu\n", packets_received);
    printf("Gönderilen yanıt: %lu\n", packets_sent);
}

void print_packet_info(const u_char *packet, int is_sent) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    IPHeader *ip = (IPHeader *)(packet + sizeof(struct ethhdr));
    ICMPHeader *icmp = (ICMPHeader *)(packet + sizeof(struct ethhdr) + sizeof(IPHeader));

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
}

void send_icmp_reply(pcap_t *handle, const u_char *request_packet) {
    uint8_t reply_packet[sizeof(struct ethhdr) + sizeof(IPHeader) + sizeof(ICMPHeader)];
    memset(reply_packet, 0, sizeof(reply_packet));

    // Ethernet header
    struct ethhdr *eth_reply = (struct ethhdr *)reply_packet;
    struct ethhdr *eth_request = (struct ethhdr *)request_packet;
    memcpy(eth_reply->h_dest, eth_request->h_source, 6);
    memcpy(eth_reply->h_source, eth_request->h_dest, 6);
    eth_reply->h_proto = eth_request->h_proto;

    // IP header
    IPHeader *ip_reply = (IPHeader *)(reply_packet + sizeof(struct ethhdr));
    IPHeader *ip_request = (IPHeader *)(request_packet + sizeof(struct ethhdr));
    memcpy(ip_reply, ip_request, sizeof(IPHeader));
    ip_reply->dest_ip = ip_request->source_ip;
    ip_reply->source_ip = ip_request->dest_ip;
    ip_reply->ttl = TTL_VALUE;
    ip_reply->header_checksum = 0;
    ip_reply->header_checksum = calculate_checksum((unsigned short *)ip_reply, sizeof(IPHeader));

    // ICMP header
    ICMPHeader *icmp_reply = (ICMPHeader *)(reply_packet + sizeof(struct ethhdr) + sizeof(IPHeader));
    ICMPHeader *icmp_request = (ICMPHeader *)(request_packet + sizeof(struct ethhdr) + sizeof(IPHeader));
    icmp_reply->type = 0;  // Echo Reply
    icmp_reply->code = 0;
    icmp_reply->identifier = icmp_request->identifier;
    icmp_reply->sequence = icmp_request->sequence;
    icmp_reply->checksum = 0;
    icmp_reply->checksum = calculate_checksum((unsigned short *)icmp_reply, sizeof(ICMPHeader));

    print_packet_info(reply_packet, 1);
    
    if (pcap_sendpacket(handle, reply_packet, sizeof(reply_packet)) != 0) {
        fprintf(stderr, "Yanıt gönderilemedi: %s\n", pcap_geterr(handle));
    } else {
        packets_sent++;
        printf("ICMP Echo Reply gönderildi.\n");
    }
}

int main() {
    if (getuid() != 0) {
        fprintf(stderr, "Root yetkisi gerekli!\n");
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

    signal(SIGINT, signal_handler);
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