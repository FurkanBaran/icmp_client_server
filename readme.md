
# ICMP Echo Sunucusu ve İstemcisi

Bu proje, libpcap kütüphanesini kullanarak C dilinde basit bir ICMP Echo Sunucusu ve İstemcisi uygular. Sunucu, ICMP Echo Request (ping) paketlerini dinler ve ICMP Echo Reply paketleriyle yanıt verir. İstemci ise belirtilen hedef IP adresine ICMP Echo Request paketleri gönderir ve yanıtları bekler.


## Özellikler

### ICMP Echo Sunucusu (`server.c`):
- ICMP Echo Request paketlerini dinler.
- ICMP Echo Reply paketleriyle yanıt verir.
- Paket detaylarını ve sunucu istatistiklerini gösterir.

### ICMP Echo İstemcisi (`client.c`):
- Belirtilen IP adresine ICMP Echo Request paketleri gönderir.
- ICMP Echo Reply paketlerini bekler.
- Paket detaylarını ve gidiş-dönüş süresini gösterir.
- Maksimum deneme sayısıyla yeniden deneme mekanizması uygular.

## Gereksinimler
- **İşletim Sistemi:** Linux (örn. Ubuntu)
- **Derleyici:** GCC
- **Kütüphaneler:**
  - `libpcap` geliştirme başlık dosyaları

### Yetkilendirme:
- `libpcap` kütüphanesi kullanılarak ham paketlerle çalışıldığı ve ağ arayüzlerine erişim gerektiği için hem sunucunun hem de istemcinin `root` yetkileriyle çalıştırılması gerekir.

## Projenin Derlenmesi

### Gerekli Kütüphanelerin Yüklenmesi:
`libpcap` kütüphanesinin sisteminizde yüklü olduğundan emin olun. Ubuntu veya Debian tabanlı sistemlerde aşağıdaki komutlarla yükleyebilirsiniz:

```bash
sudo apt-get update
sudo apt-get install libpcap-dev
```

### Kaynak Dosyalarının İndirilmesi:
`server.c` ve `client.c` dosyalarını sisteminizde bir dizine kaydedin.

### Sunucu ve İstemcinin Derlenmesi:
Kaynak dosyalarının bulunduğu dizinde terminali açın ve aşağıdaki komutları çalıştırın:

#### Sunucunun Derlenmesi:
```bash
gcc -o server server.c -lpcap
```

#### İstemcinin Derlenmesi:
```bash
gcc -o client client.c -lpcap
```

## Sunucu ve İstemcinin Çalıştırılması

### ICMP Echo Sunucusunun Çalıştırılması

#### Sunucuyu Başlatın:
Sunucu çalıştırılabilir dosyasını `root` yetkileriyle çalıştırın:
```bash
sudo ./server
```

#### Sunucu Çıktısı:
Sunucu aşağıdaki gibi mesajlar gösterecektir:
```
Kullanılan arayüz: eth0
Server IP: 192.168.1.10

ICMP Server başlatıldı. Echo Request paketleri bekleniyor...
Kapatmak için Ctrl+C'ye basın
```

#### Sunucunun Durdurulması:
Sunucuyu düzgün bir şekilde durdurmak için `Ctrl+C` tuş kombinasyonuna basın. İstatistikleri gösterecektir:
```
Sunucu kapatılıyor...

--- Sunucu İstatistikleri ---
Alınan paket: 5
Gönderilen yanıt: 5
```

### ICMP Echo İstemcisinin Çalıştırılması

#### Kullanım Şekli:
İstemci bir argüman gerektirir: hedef IP adresi.
```bash
sudo ./client <hedef_ip>
```

#### Örnek:
Sunucu `192.168.1.10` IP adresinde çalışıyorsa, aşağıdaki komutu çalıştırın:
```bash
sudo ./client 192.168.1.10
```

#### İstemci Çıktısı:
İstemci, gönderilen ve alınan paketlerle ilgili detaylı bilgileri ve gidiş-dönüş süresini gösterecektir:
```
Kullanılan arayüz: eth0
Kaynak IP: 192.168.1.20
Hedef IP: 192.168.1.10

ARP Tablosu:
Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.1.10             ether   00:1a:2b:3c:4d:5e   C                     eth0

Gönderilen Paket Detayları:
MAC Adresleri:
  Kaynak: aa:bb:cc:dd:ee:ff
  Hedef: ff:ff:ff:ff:ff:ff
IP Adresleri:
  Kaynak: 192.168.1.20
  Hedef: 192.168.1.10
  TTL: 64
ICMP Bilgileri:
  Tip: 0x08
  Kod: 0x00
  Checksum: 0xf7ff
  Identifier: 0x1234
  Sequence: 0x0001

ICMP Echo Request gönderiliyor...

Alınan Paket Detayları:
MAC Adresleri:
  Kaynak: 00:1a:2b:3c:4d:5e
  Hedef: aa:bb:cc:dd:ee:ff
IP Adresleri:
  Kaynak: 192.168.1.10
  Hedef: 192.168.1.20
  TTL: 64
ICMP Bilgileri:
  Tip: 0x00
  Kod: 0x00
  Checksum: 0xf8ff
  Identifier: 0x1234
  Sequence: 0x0001

ICMP Echo Reply alındı. (Süre: 0.456 ms)
```

#### İstemcinin Durdurulması:
İstemci, yanıt aldıktan veya maksimum deneme sayısına ulaştıktan sonra duracaktır. Ayrıca `Ctrl+C` tuş kombinasyonuyla programı sonlandırabilirsiniz.

## Notlar

### Ağ Arayüzü Seçimi:
- Kod, mevcut olan ilk ağ arayüzünü seçer.
- Birden fazla arayüzünüz varsa, uygun olanı seçmek için kodu değiştirebilirsiniz.

### Platform Uyumluluğu:
- Kod, Linux sistemleri için tasarlanmıştır.
- Diğer Unix benzeri sistemler (örn. macOS) için bazı bölümler ayarlama gerektirebilir.

### Güvenlik ve Emniyet:
- Root yetkileriyle program çalıştırırken dikkatli olun.
- Kendi ortamınızda güvenlik açılarının farkında olun ve gerekli önlemleri alın.

## Sorun Giderme

### Derleme Hataları:
- Gerekli tüm kütüphane ve başlık dosyalarının yüklü olduğundan emin olun.
- Kodu değiştirdiyseniz, yazım hataları veya eksik noktalı virgüller için kontrol edin.

### İzin Reddedildi Hatası:
- Çalıştırılabilir dosyaları `sudo` ile veya `root` kullanıcısı olarak çalıştırdığınızdan emin olun.

### ICMP Yanıt Alamama:
- İstemci ve sunucu makineleri arasında ağ bağlantısının olduğunu doğrulayın.
- Güvenlik duvarlarının veya güvenlik gruplarının ICMP trafiğini engellemediğinden emin olun.
- Sunucunun çalıştığını ve doğru arayüzde dinlediğini kontrol edin.

### "Interface bulunamadı" Hatası:
- Program ağ arayüzünüzü doğru bir şekilde algılayamayabilir.
- Kod üzerinde uygun arayüzü elle belirtmek için değişiklik yapabilirsiniz.

## Referanslar
- [libpcap Dokümantasyonu](https://www.tcpdump.org/manpages/libpcap.3pcap.html)
- [ICMP Protokol Detayları](https://datatracker.ietf.org/doc/html/rfc792)
- [C'de libpcap Kullanarak Paket Yakalama](https://www.tcpdump.org/pcap.html)
