# NTP Security Scanner

## 1. NTP Nedir?

**Network Time Protocol (NTP)**, bilgisayar sistemlerinin saatlerini doğru bir şekilde senkronize etmek için kullanılan bir protokoldür. NTP, istemci ve sunucu arasında zaman bilgisini değiş tokuş ederek sistem saatlerini koordine eder.  

### Temel Özellikler
- Sistem saatini diğer NTP sunucularıyla senkronize eder.
- Stratum (katman) tabanlı yapıya sahiptir: Stratum 1 en doğru kaynak (ör. GPS, atomik saat) sunucular, Stratum 2 ise Stratum 1’den zaman alır.
- UDP port 123 üzerinden çalışır.
- NTPv4 RFC 5905 standardını uygular.
- Bazı NTP sunucuları “monlist” veya kontrol sorguları gibi özelliklerle ek bilgiler sağlayabilir.

---

## 2. NTP Güvenlik Zafiyetleri ve Tehditleri

NTP, zamanlama hizmeti sağlamasının yanı sıra bazı eski veya yanlış yapılandırılmış sürümler üzerinden saldırılara da açıktır. Scanner’ımız özellikle aşağıdaki noktaları kontrol eder:

### 2.1. Port Durumu
- UDP 123 portu açıksa NTP servisi kullanılabilir demektir.
- Kapanmışsa herhangi bir sorgu yanıtlanmaz.

### 2.2. Version Leak (Sürüm Bilgisi Sızması)
- NTP sunucusu, bazı paketlerde sürüm bilgisini yanıt olarak döndürebilir.
- Saldırganlar bu bilgiyi kullanarak zafiyetli sürümleri hedef alabilir.

### 2.3. Stratum, RefID ve Timestamps
- Stratum değeri, sunucunun hangi katmandan zaman aldığı bilgisini gösterir.
- RefID ve Receive Timestamp ile sunucunun saat ve referans kaynak bilgisi elde edilebilir.

### 2.4. Monlist Vulnerability (CVE-2013-5211)
- “monlist” özelliği, eski NTP sürümlerinde tüm istemci geçmişini listeleyen bir komuttur.
- Saldırganlar tarafından **Reflection DDoS saldırısı** için kullanılabilir.
- Scanner, monlist isteğine yanıt alıp alamadığını kontrol eder.

### 2.5. Control Query (Mode 6) Vulnerability
- NTP kontrol sorguları (mode 6), sunucudan detaylı sistem bilgisi alabilir.
- Yanlış yapılandırılmış sunucular bu sorgulara yanıt vererek sistem ve işlemci bilgilerini sızdırabilir.

### 2.6. Amplification Factor
- NTP paketleri küçük bir sorguya karşılık çok daha büyük yanıt dönebilir.
- Bu, saldırganların küçük paketlerle büyük trafik üretmesini sağlayarak **DDoS riskini** artırır.
- Scanner, gelen yanıtın boyutu ile gönderilen sorgu boyutunu karşılaştırarak amplifikasyon faktörünü hesaplar.

### 2.7. Query Restrictions
- Sunucu, belirli istemcilerden gelen sorguları kısıtlayabilir.
- Scanner, sorguların izinli veya kısıtlı olduğunu tespit eder.

---

## 3. Scanner Özellikleri

Bu Go tabanlı scanner:

1. **Port Açık/Kapalı Kontrolü**
2. **Sürüm Bilgisi Sızması Tespiti**
3. **Stratum ve RefID Bilgisi Toplama**
4. **Monlist Zafiyeti Kontrolü (CVE-2013-5211)**
5. **Control Query Mode 6 Zafiyeti Kontrolü**
6. **Amplifikasyon Faktör Hesaplama**
7. **Query Restrictions Testi**
8. **Renkli ve Detaylı Terminal Çıktısı**

---
