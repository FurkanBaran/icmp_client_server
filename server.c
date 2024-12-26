#include <stdlib.h>     // Standart kütüphaneler
#include <stdio.h>      // Giriş/çıkış işlemleri için kütüphane
#include <pcap.h>       // Ağ paketlerini yakalamak ve göndermek için kütüphane
#include <string.h>     // String işlemleri için kütüphane
#include <unistd.h>     // UNIX standart fonksiyonlar için kütüphane
#include <signal.h>     // Sinyal işlemleri için kütüphane
#include <ifaddrs.h>    // Ağ arayüz adreslerini almak için kütüphane
#include <netinet/in.h> // Ağ adresleri (IP) ile ilgili yapılar için kütüphane
#include <arpa/inet.h>  // IP adreslerini dönüştürmek için kütüphane
#include <net/if.h>     // Ağ arayüzleri ile ilgili işlemler için kütüphane
#include <errno.h>      // Hata kodlarını almak için kütüphane

// u_char tipini tanımlama
typedef unsigned char u_char;

#ifdef __APPLE__
    #include <net/if_dl.h>     // Ağ arayüzleri ile ilgili kütüphane (macOS)
    #include <net/if_types.h>  // Ağ arayüz tipleri için kütüphane (macOS)
#else
    #include <sys/ioctl.h>     // Giriş/çıkış kontrol işlemleri için kütüphane (Linux)
    #include <linux/if_ether.h>// Ethernet ile ilgili tanımlar için kütüphane (Linux)
    #include <linux/if_arp.h>  // ARP ile ilgili tanımlar için kütüphane (Linux)
#endif

#define TTL_VALUE 64   // Zaman aşımı değeri (Time To Live)
#define ETH_ALEN 6     // Ethernet adres uzunluğu (6 bayt)
#define ETH_P_IP 0x0800 // Ethernet protokol tipi IP

#pragma pack(1) // Yapıların bellek üzerinde hizalanmasını 1 bayt olarak ayarlar

// Ethernet başlık yapısı
struct eth_header {
    uint8_t h_dest[ETH_ALEN];   // Hedef MAC adresi
    uint8_t h_source[ETH_ALEN]; // Kaynak MAC adresi
    uint16_t h_proto;           // Üst katman protokol tipi
};

// IP başlık yapısı
typedef struct {
    uint8_t version_ihl;            // Versiyon ve header uzunluğu
    uint8_t tos;                    // Hizmet türü
    uint16_t total_length;          // Toplam paket uzunluğu
    uint16_t identification;        // Tanımlayıcı
    uint16_t flags_fragment_offset; // Bayraklar ve fragment ofseti
    uint8_t ttl;                    // Zaman aşımı değeri
    uint8_t protocol;               // Üst katman protokol tipi
    uint16_t header_checksum;       // Başlık kontrol toplamı
    uint32_t source_ip;             // Kaynak IP adresi
    uint32_t dest_ip;               // Hedef IP adresi
} IPHeader;

// ICMP başlık yapısı
typedef struct {
    uint8_t type;        // ICMP tipi
    uint8_t code;        // ICMP kodu
    uint16_t checksum;   // Kontrol toplamı
    uint16_t identifier; // Tanımlayıcı
    uint16_t sequence;   // Sıra numarası
} ICMPHeader;

#pragma pack() // Yapıların hizalamasını varsayılana çevirir

pcap_t *handle = NULL;                    // pcap arayüzü için tanımlama
volatile sig_atomic_t keep_running = 1;   // Programın çalışmaya devam edip etmeyeceğini belirten bayrak
volatile sig_atomic_t received_sigint = 0;// SIGINT sinyalinin alınıp alınmadığını belirten bayrak
unsigned long packets_received = 0;       // Alınan paket sayacı
unsigned long packets_sent = 0;           // Gönderilen paket sayacı

// Sinyal yakalama fonksiyonu (Ctrl+C ile programın düzgün sonlanması için)
void signal_handler(int signum) {
    received_sigint = 1; // SIGINT sinyalinin alındığını belirt
    keep_running = 0;    // Programın sonlandırılması için bayrağı sıfırla
    printf("\nSunucu kapatılıyor...\n");
}

// Kaynakları temizlemek ve istatistikleri yazdırmak için fonksiyon
void cleanup() {
    if (handle) {
        pcap_close(handle); // pcap arayüzünü kapat
    }
    // İstatistikleri ekrana yazdır
    printf("\n--- Sunucu İstatistikleri ---\n");
    printf("Alınan paket: %lu\n", packets_received);
    printf("Gönderilen yanıt: %lu\n", packets_sent);
}

// Paket bilgilerini ekrana yazdıran fonksiyon
void print_packet_info(const u_char *packet, int is_sent) {
    // Ethernet başlığını al
    struct eth_header *eth = (struct eth_header *)packet;
    // IP başlığını al
    IPHeader *ip = (IPHeader *)(packet + sizeof(struct eth_header));
    // ICMP başlığını al
    ICMPHeader *icmp = (ICMPHeader *)(packet + sizeof(struct eth_header) + sizeof(IPHeader));

    printf("\n%s Paket Detayları:\n", is_sent ? "Gönderilen" : "Alınan");
    // MAC adreslerini yazdır
    printf("MAC Adresleri:\n");
    printf("  Kaynak: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("  Hedef: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    // IP adreslerini karakter dizisine çevir ve yazdır
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->source_ip), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->dest_ip), dst_ip, INET_ADDRSTRLEN);

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

// Checksum hesaplama fonksiyonu (IP ve ICMP başlıkları için)
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

    return answer; // Checksum döndür
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
#ifdef __APPLE__
    struct ifaddrs *ifap, *ifaptr;

    if (getifaddrs(&ifap) == 0) {
        for (ifaptr = ifap; ifaptr != NULL; ifaptr = ifaptr->ifa_next) {
            if (strcmp(ifaptr->ifa_name, interface) == 0 && 
                ifaptr->ifa_addr->sa_family == AF_LINK) {
                struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifaptr->ifa_addr;
                memcpy(mac_addr, LLADDR(sdl), 6); // MAC adresini kopyala
                freeifaddrs(ifap); // Belleği serbest bırak
                return 0; // Başarılı
            }
        }
        freeifaddrs(ifap); // Belleği serbest bırak
    }
    return -1; // Başarısız
#else
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
#endif
}

// ICMP Echo Reply (Yanıt) paketi gönderen fonksiyon
void send_icmp_reply(pcap_t *handle, const u_char *request_packet) {
    // Yanıt paketi için yeterli boyutta bir arabellek oluştur
    uint8_t reply_packet[sizeof(struct eth_header) + sizeof(IPHeader) + sizeof(ICMPHeader)];
    memset(reply_packet, 0, sizeof(reply_packet)); // Paketin içeriğini sıfırla

    // Ethernet başlığını yapılandır
    struct eth_header *eth_reply = (struct eth_header *)reply_packet;
    struct eth_header *eth_request = (struct eth_header *)request_packet;
    memcpy(eth_reply->h_dest, eth_request->h_source, ETH_ALEN);    // Hedef MAC adresini ayarla
    memcpy(eth_reply->h_source, eth_request->h_dest, ETH_ALEN);    // Kaynak MAC adresini ayarla
    eth_reply->h_proto = eth_request->h_proto;                     // Protokol tipini ayarla

    // IP başlığını yapılandır
    IPHeader *ip_reply = (IPHeader *)(reply_packet + sizeof(struct eth_header));
    IPHeader *ip_request = (IPHeader *)(request_packet + sizeof(struct eth_header));
    memcpy(ip_reply, ip_request, sizeof(IPHeader));                // IP başlığını kopyala
    ip_reply->dest_ip = ip_request->source_ip;                     // Hedef IP adresini ayarla
    ip_reply->source_ip = ip_request->dest_ip;                     // Kaynak IP adresini ayarla
    ip_reply->ttl = TTL_VALUE;                                     // TTL değerini ayarla
    ip_reply->header_checksum = 0;                                 // Kontrol toplamını sıfırla
    ip_reply->header_checksum = calculate_checksum((unsigned short *)ip_reply, sizeof(IPHeader)); // Kontrol toplamını hesapla

    // ICMP başlığını yapılandır
    ICMPHeader *icmp_reply = (ICMPHeader *)(reply_packet + sizeof(struct eth_header) + sizeof(IPHeader));
    ICMPHeader *icmp_request = (ICMPHeader *)(request_packet + sizeof(struct eth_header) + sizeof(IPHeader));
    icmp_reply->type = 0;                                          // Echo Reply tipi
    icmp_reply->code = 0;                                          // Kod değeri 0
    icmp_reply->identifier = icmp_request->identifier;             // Tanımlayıcıyı aynen kopyala
    icmp_reply->sequence = icmp_request->sequence;                 // Sıra numarasını aynen kopyala
    icmp_reply->checksum = 0;                                      // Kontrol toplamını sıfırla
    icmp_reply->checksum = calculate_checksum((unsigned short *)icmp_reply, sizeof(ICMPHeader)); // Kontrol toplamını hesapla

    // Paket bilgilerini ekrana yazdır
    print_packet_info(reply_packet, 1);

    // Yanıt paketini gönder
    if (pcap_sendpacket(handle, reply_packet, sizeof(reply_packet)) != 0) {
        fprintf(stderr, "Yanıt gönderilemedi: %s\n", pcap_geterr(handle));
    } else {
        packets_sent++; // Gönderilen paket sayısını artır
        printf("ICMP Echo Reply gönderildi.\n");
    }
}

// Ana fonksiyon
int main() {
    // Root yetkisi kontrolü
    if (getuid() != 0) {
        fprintf(stderr, "Root yetkisi gerekli!\n");
        return 1;
    }

    // Sinyal işleyicilerini ayarla
    struct sigaction sa;
    sa.sa_handler = signal_handler; // Sinyal işleyici fonksiyonunu belirt
    sigemptyset(&sa.sa_mask);       // Sinyal maskelemesini sıfırla
    sa.sa_flags = 0;                // Ek bayrak yok
    sigaction(SIGINT, &sa, NULL);   // Ctrl+C sinyalini yakala
    sigaction(SIGTERM, &sa, NULL);  // TERM sinyalini yakala

    char errbuf[PCAP_ERRBUF_SIZE];  // Hata mesajları için arabellek
    pcap_if_t *alldevs;             // Tüm ağ arayüzlerinin listesi

    // Tüm ağ arayüzlerini al
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Interface bulunamadı: %s\n", errbuf);
        return 1;
    }

    // İlk bulduğu arayüzü kullan
    char *interface = alldevs->name;
    printf("Kullanılan arayüz: %s\n", interface);

    // Sunucunun IP adresini al
    char *server_ip = get_interface_ip(interface);
    if (!server_ip) {
        fprintf(stderr, "Server IP alınamadı\n");
        pcap_freealldevs(alldevs);
        return 1;
    }
    printf("Server IP: %s\n", server_ip);

    // Ağ arayüzünü aç
    handle = pcap_open_live(interface, BUFSIZ, 1, 100, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live hatası: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }
    // pcap arayüzünü non-blocking moda ayarla
    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        fprintf(stderr, "Non-blocking moda geçilemedi: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    // Paket filtreleme için BPF programını hazırla
    struct bpf_program fp;
    char filter_exp[100];
    snprintf(filter_exp, sizeof(filter_exp), "icmp[icmptype] = 8");  // Sadece ICMP Echo Request paketlerini yakala

    // Filtreyi derle
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Filter derlenemedi\n");
        cleanup();
        return 1;
    }

    // Filtreyi uygulamaya koy
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Filter uygulanamadı\n");
        cleanup();
        return 1;
    }

    // Sunucu başlatma mesajları
    printf("\nICMP Server başlatıldı. Echo Request paketleri bekleniyor...\n");
    printf("Kapatmak için Ctrl+C'ye basın\n\n");

    // Paket yakalama değişkenleri
    struct pcap_pkthdr *header;
    const u_char *packet;

    // Ana döngü: paketleri yakala ve işle
    while (keep_running) {
        // Paket alımı
        int res = pcap_next_ex(handle, &header, &packet);
        if (res > 0) {
            // IP başlığını al
            IPHeader *ip_request = (IPHeader *)(packet + sizeof(struct eth_header));

            // Hedef IP'yi kontrol et
            char dest_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_request->dest_ip), dest_ip, INET_ADDRSTRLEN);

            // Eğer hedef IP sunucunun IP'si değilse paketi işleme
            if (strcmp(dest_ip, server_ip) != 0) {
                continue; // Bir sonraki pakete geç
            }

            // Paket alındı, işlem yap
            packets_received++; // Alınan paket sayısını artır
            printf("\nICMP Echo Request alındı (#%lu)\n", packets_received);
            print_packet_info(packet, 0); // Paket bilgilerini yazdır
            send_icmp_reply(handle, packet); // ICMP Echo Reply yanıtını gönder
        } 
        if (res == 0)  usleep(1000);     // 1 milisaniye bekle
        if (res < 0){                   // Hata oluştu
            fprintf(stderr, "pcap_next_ex hatası: %s\n", pcap_geterr(handle));
            break;
        }
    }

    // Program sonlandırma işlemleri
    cleanup();              // Kaynakları temizle ve istatistikleri yazdır
    pcap_freealldevs(alldevs); // Belleği serbest bırak
    return 0;
}
