#include <stdlib.h>       // Standart kütüphaneler
#include <stdio.h>
#include <pcap.h>         // Paket yakalama kütüphanesi
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <ifaddrs.h>      // Ağ arayüzleri için
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>       // Ağ arayüzleri için
#include <sys/ioctl.h>
#include <linux/if_ether.h>   // Ethernet port tanımları
#include <linux/if_arp.h>
#include <errno.h>

typedef unsigned char u_char;    // u_char tip tanımlaması

#define TIMEOUT_SEC 3            // Zaman aşımı süresi (saniye)
#define MAX_TRIES 4              // Maksimum deneme sayısı
#define TTL_VALUE 64             // TTL (Time To Live) değeri
#define ICMP_ECHO_REQUEST 8      // ICMP Echo Request türü
#define ICMP_ECHO_REPLY 0        // ICMP Echo Reply türü
#define ICMP_DEST_UNREACHABLE 3  // ICMP Destination Unreachable türü

struct timeval send_time;        // Paketin gönderilme zamanını tutmak için

// ICMP Başlık Yapısı
typedef struct {
    uint8_t type;             // ICMP tipi
    uint8_t code;             // ICMP kodu
    uint16_t checksum;        // Kontrol toplamı
    uint16_t identifier;      // Tanımlayıcı
    uint16_t sequence;        // Sıra numarası
} ICMPHeader;

// IP Başlık Yapısı
typedef struct {
    uint8_t version_ihl;          // Versiyon ve IHL bilgisi
    uint8_t tos;                  // Hizmet türü
    uint16_t total_length;        // Toplam uzunluk
    uint16_t identification;      // Tanımlama
    uint16_t flags_fragment_offset; // Bayraklar ve fragment ofseti
    uint8_t ttl;                  // Zaman aşımı değeri
    uint8_t protocol;             // Protokol
    uint16_t header_checksum;     // Başlık kontrol toplamı
    uint32_t source_ip;           // Kaynak IP adresi
    uint32_t dest_ip;             // Hedef IP adresi
} IPHeader;

pcap_t *handle = NULL;                 // pcap arayüzü için tanımlama
volatile sig_atomic_t keep_running = 1; // Programın çalışmaya devam edip etmeyeceğini belirten bayrak
struct timeval timeout_tv;             // Zaman aşımı için timeval yapısı
unsigned short sequence = 0;           // ICMP paketleri için sıra numarası
char source_ip_str[INET_ADDRSTRLEN];   // Kaynak IP adresini tutmak için karakter dizisi

// Paket bilgilerini ekrana yazdıran fonksiyon
void print_packet_info(const u_char *packet, int is_sent) {
    // Ethernet başlığını al
    struct ethhdr *eth = (struct ethhdr *)packet;
    // IP başlığını al
    IPHeader *ip = (IPHeader *)(packet + sizeof(struct ethhdr));
    // ICMP başlığını al
    ICMPHeader *icmp = (ICMPHeader *)(packet + sizeof(struct ethhdr) + sizeof(IPHeader));

    printf("\n%s Paket Detayları:\n", is_sent ? "Gönderilen" : "Alınan");

    // MAC adreslerini yazdır
    printf("MAC Adresleri:\n");
    printf("  Kaynak: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("  Hedef: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    // IP adreslerini karakter dizisine çevir
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->source_ip), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->dest_ip), dst_ip, INET_ADDRSTRLEN);

    // IP adreslerini yazdır
    printf("IP Adresleri:\n");
    printf("  Kaynak: %s\n", src_ip);
    printf("  Hedef: %s\n", dst_ip);
    printf("  TTL: %d\n", ip->ttl);

    // ICMP bilgilerini yazdır
    printf("ICMP Bilgileri:\n");
    printf("  Tip: 0x%02x\n", icmp->type);
    printf("  Kod: 0x%02x\n", icmp->code);
    printf("  Checksum: 0x%04x\n", ntohs(icmp->checksum));
    printf("  Identifier: 0x%04x\n", ntohs(icmp->identifier));
    printf("  Sequence: 0x%04x\n", ntohs(icmp->sequence));
}

// Sinyal yakalama fonksiyonu (Ctrl+C ile programın düzgün sonlanması için)
void signal_handler(int signum) {
    keep_running = 0; // Programın sonlandırılması için bayrağı sıfırla
    printf("\nProgram sonlandırılıyor...\n");
}

// Kaynakları temizlemek için fonksiyon
void cleanup() {
    if (handle) {
        pcap_close(handle); // pcap arayüzünü kapat
    }
}

// Kontrol toplamı hesaplama fonksiyonu (ICMP ve IP başlıkları için)
unsigned short calculate_checksum(unsigned short *addr, int len) {
    int nleft = len;             // Kalan bayt sayısı
    int sum = 0;                 // Toplam
    unsigned short *w = addr;    // Veri üzerinde ilerlemek için işaretçi
    unsigned short answer = 0;   // Sonuç

    // 16 bitlik kelimeler halinde toplama işlemi
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    // Eğer tek bir bayt kaldıysa, onu da ekle
    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    // Toplamı sonuca dönüştür
    sum = (sum >> 16) + (sum & 0xFFFF); // Taşan bitleri ekle
    sum += (sum >> 16);                 // Eğer tekrar taşma varsa ekle
    answer = ~sum;                      // Tüm bitleri ters çevir

    return answer; // Kontrol toplamını döndür
}

// Verilen arayüzün IP adresini alan fonksiyon
char* get_interface_ip(const char *interface) {
    struct ifaddrs *ifaddr, *ifa;
    static char ip[INET_ADDRSTRLEN]; // IP adresini tutmak için karakter dizisi

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs"); // Hata varsa bildir
        return NULL;
    }

    // Tüm arayüzleri dolaş
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue; // Adres yoksa atla

        // IPv4 adresi ve istenen arayüz mü?
        if (ifa->ifa_addr->sa_family == AF_INET && 
            strcmp(ifa->ifa_name, interface) == 0) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN); // IP adresini al
            freeifaddrs(ifaddr); // Belleği serbest bırak
            return ip; // IP adresini döndür
        }
    }

    freeifaddrs(ifaddr); // Belleği serbest bırak
    return NULL; // Bulunamadıysa NULL döndür
}

// Verilen arayüzün MAC adresini alan fonksiyon
int get_interface_mac(const char *interface, uint8_t *mac_addr) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0); // Soket oluştur
    if (sock < 0) return -1;

    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1); // Arayüz adını yapılandırmaya koy
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {   // MAC adresini al
        close(sock);
        return -1;
    }

    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6); // MAC adresini kopyala
    close(sock); // Soketi kapat
    return 0; // Başarılı
}

// ICMP Echo Request paketi gönderen fonksiyon
int send_icmp_request(pcap_t *handle, const char *interface, 
                         struct in_addr src_ip, struct in_addr dest_ip) {
    // Paket için yeterli boyutta bir arabellek oluştur
    uint8_t packet[sizeof(struct ethhdr) + sizeof(IPHeader) + sizeof(ICMPHeader)];
    memset(packet, 0, sizeof(packet)); // Paket içeriğini sıfırla

    // Ethernet başlığını yapılandır
    struct ethhdr *eth = (struct ethhdr *)packet;
    uint8_t src_mac[6];
    if (get_interface_mac(interface, src_mac) < 0) { // Kaynak MAC adresini al
        fprintf(stderr, "MAC adresi alınamadı\n");
        return -1;
    }
    memcpy(eth->h_source, src_mac, 6); // Kaynak MAC adresini ata
    memset(eth->h_dest, 0xff, 6);      // Hedef MAC adresini yayın adresi (broadcast) yap
    eth->h_proto = htons(ETH_P_IP);    // Protokolü IP olarak ayarla

    // IP başlığını yapılandır
    IPHeader *ip = (IPHeader *)(packet + sizeof(struct ethhdr));
    ip->version_ihl = 0x45;                            // IPv4 ve IHL=5 (5*4=20 byte)
    ip->tos = 0;                                       // Hizmet türü
    ip->total_length = htons(sizeof(IPHeader) + sizeof(ICMPHeader)); // Toplam uzunluk
    ip->identification = htons(getpid() & 0xFFFF);     // Tanımlayıcı olarak işlem ID'si
    ip->flags_fragment_offset = 0;                     // Bayraklar ve fragment ofseti
    ip->ttl = TTL_VALUE;                               // TTL değeri
    ip->protocol = IPPROTO_ICMP;                       // Protokol ICMP
    ip->source_ip = src_ip.s_addr;                     // Kaynak IP adresi
    ip->dest_ip = dest_ip.s_addr;                      // Hedef IP adresi
    ip->header_checksum = 0;                           // Kontrol toplamını sıfırla
    ip->header_checksum = calculate_checksum((unsigned short *)ip, sizeof(IPHeader)); // Kontrol toplamını hesapla

    // ICMP başlığını yapılandır
    ICMPHeader *icmp = (ICMPHeader *)(packet + sizeof(struct ethhdr) + sizeof(IPHeader));
    icmp->type = ICMP_ECHO_REQUEST;                   // ICMP türü Echo Request
    icmp->code = 0;                                   // Kod değeri 0
    icmp->identifier = htons(getpid() & 0xFFFF);      // Tanımlayıcı olarak işlem ID'si
    icmp->sequence = htons(++sequence);               // Sıra numarasını artır ve ata
    icmp->checksum = 0;                               // Kontrol toplamını sıfırla
    icmp->checksum = calculate_checksum((unsigned short *)icmp, sizeof(ICMPHeader)); // Kontrol toplamını hesapla

    // Paket bilgilerini ekrana yazdır
    print_packet_info(packet, 1);
    printf("ICMP Echo Request gönderiliyor...\n");

    // Gönderim zamanını kaydet
    gettimeofday(&send_time, NULL);

    // Paketi gönder
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "Paket gönderilemedi: %s\n", pcap_geterr(handle));
        return -1;
    }

    return 0; // Başarılı
}

// Gelen paketi işleyen fonksiyon
int process_packet(const u_char *packet, int len) {
    // Ethernet başlığını al
    struct ethhdr *eth = (struct ethhdr *)packet;
    if (ntohs(eth->h_proto) != ETH_P_IP) return 0; // IP değilse çık

    // IP başlığını al
    IPHeader *ip = (IPHeader *)(packet + sizeof(struct ethhdr));
    if (ip->protocol != IPPROTO_ICMP) return 0; // ICMP değilse çık

    // ICMP başlığını al
    ICMPHeader *icmp = (ICMPHeader *)(packet + sizeof(struct ethhdr) + sizeof(IPHeader));

    // Paket bilgilerini ekrana yazdır
    print_packet_info(packet, 0);

    // Yanıt zamanını al ve süreyi hesapla
    struct timeval recv_time, diff_time;
    gettimeofday(&recv_time, NULL);
    timersub(&recv_time, &send_time, &diff_time);
    double ms = (diff_time.tv_sec * 1000.0) + (diff_time.tv_usec / 1000.0);

    // ICMP tipine göre işlem yap
    switch(icmp->type) {
        case 0x00:  // Echo Reply
            printf("ICMP Echo Reply alındı. (%.3f ms)\n", ms);
            return 1;

        case 0x03:  // Destination Unreachable
            printf("ICMP Destination Unreachable: ");
            switch(icmp->code) {
                case 0x00:
                    printf("Ağ Ulaşılamıyor\n");
                    break;
                case 0x01:
                    printf("Host Ulaşılamıyor\n");
                    break;
                case 0x02:
                    printf("Protokol Ulaşılamıyor\n");
                    break;
                case 0x03:
                    printf("Port Ulaşılamıyor\n");
                    break;
                case 0x04:
                    printf("Fragmentasyon Gerekli ama 'Don't Fragment' Biti Ayarlı\n");
                    break;
                default:
                    printf("Kod: 0x%02x\n", icmp->code);
                    break;
            }
            return 1;

        case 0x0b:  // Time Exceeded
            printf("ICMP Time Exceeded: ");
            switch(icmp->code) {
                case 0x00:
                    printf("TTL Aşıldı\n");
                    break;
                case 0x01:
                    printf("Fragment Yeniden Birleştirme Zaman Aşıldı\n");
                    break;
                default:
                    printf("Kod: 0x%02x\n", icmp->code);
                    break;
            }
            return 1;

        default:
            printf("Beklenmeyen ICMP paketi alındı (Type: 0x%02x, Code: 0x%02x) (%.3f ms)\n", 
                   icmp->type, icmp->code, ms);
            return 0;
    }
}

// Ana fonksiyon
int main(int argc, char *argv[]) {
    // Komut satırı argüman kontrolü
    if (argc != 2) {
        fprintf(stderr, "Kullanım: %s <hedef_ip>\n", argv[0]);
        return 1;
    }

    // Root yetkisi kontrolü
    if (getuid() != 0) {
        fprintf(stderr, "Root yetkisi gerekli!\n");
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    struct in_addr src_ip, dest_ip;

    // Hedef IP adresini al ve kontrol et
    if (inet_pton(AF_INET, argv[1], &dest_ip) != 1) {
        fprintf(stderr, "Geçersiz IP adresi\n");
        return 1;
    }

    pcap_if_t *alldevs;
    // Tüm ağ arayüzlerini al
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Interface bulunamadı: %s\n", errbuf);
        return 1;
    }

    // İlk bulduğu arayüzü kullan
    char *interface = alldevs->name;
    printf("Kullanılan arayüz: %s\n", interface);

    // Kaynak IP adresini al
    char *source_ip = get_interface_ip(interface);
    if (!source_ip) {
        fprintf(stderr, "Kaynak IP alınamadı\n");
        pcap_freealldevs(alldevs);
        return 1;
    }
    printf("Kaynak IP: %s\n", source_ip);
    printf("Hedef IP: %s\n", argv[1]);

    inet_pton(AF_INET, source_ip, &src_ip);

    // Ağ arayüzünü aç
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live hatası: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    // ARP tablosunu göster
    printf("\nARP Tablosu:\n");
    system("arp -n");

    struct bpf_program fp; // Filtre programı
    char filter_exp[100];
    snprintf(filter_exp, sizeof(filter_exp), "icmp"); // ICMP paketlerini filtrele
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

    signal(SIGINT, signal_handler); // Ctrl+C sinyalini yakala

    int tries = 0; // Deneme sayacı
    while (keep_running && tries < MAX_TRIES) {
        // ICMP isteği gönder
        if (send_icmp_request(handle, interface, src_ip, dest_ip) < 0) {
            fprintf(stderr, "ICMP isteği gönderilemedi\n");
            break;
        }

        struct pcap_pkthdr *header;
        const u_char *packet;
        int res;

        // Zaman aşımı ayarları
        timeout_tv.tv_sec = TIMEOUT_SEC;
        timeout_tv.tv_usec = 0;

        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(pcap_get_selectable_fd(handle), &read_set);

        // Paket bekleme
        res = select(pcap_get_selectable_fd(handle) + 1, &read_set, NULL, NULL, &timeout_tv);
        if (res == 0) {
            printf("Deneme %d: Zaman aşımı - Yanıt alınamadı\n", tries + 1);
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

        // Paket alındıysa işle
        res = pcap_next_ex(handle, &header, &packet);
        if (res < 0) break;   // Hata varsa çık
        if (res == 0) continue; // Zaman aşımıysa tekrar dene

        if (process_packet(packet, header->len)) {
            break; // Başarılıysa döngüden çık
        }
    }

    if (tries >= MAX_TRIES) {
        printf("\nMaksimum deneme sayısına ulaşıldı. Hedef yanıt vermiyor.\n");
    }

    // Temizleme işlemleri
    cleanup();
    pcap_freealldevs(alldevs);
    return 0;
}