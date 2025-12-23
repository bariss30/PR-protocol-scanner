# POP3 — Banner ve TLS/STARTTLS Taraması

## Amaç ve Kullanım
POP3 (Post Office Protocol v3), e-posta sunucularından posta almak için kullanılır.  
Modülün amaçları:
- POP3 portlarının açık olup olmadığını kontrol etmek (110 / 995)
- Banner bilgisini almak ve ürün/sürüm sızmasını tespit etmek
- APOP timestamp kontrolü yapmak
- CAPA, STLS ve SASL desteklerini sorgulamak
- Plaintext authentication politika kontrolü (TLS olmadan)
- STARTTLS üzerinden TLS güvenliğini test etmek
- POP3S (TLS 995) bağlantısını test etmek
- Zayıf TLS protokollerini ve sertifika sorunlarını tespit etmek

---

## Temel İşleyiş
1. **Port 110 — Plain POP3**
   - TCP bağlantısı açılır
   - Banner okunur
   - Banner’da ürün/sürüm bilgisi olup olmadığı (`InfoLeak`) kontrol edilir
   - Banner’da APOP timestamp var mı kontrol edilir
   - `CAPA` komutu ile STLS ve SASL mekanizmaları sorgulanır
   - Plaintext auth politikası kontrol edilir (`USER/PASS` ile, gerçek parola kullanılmaz)

2. **STARTTLS (Port 110)**
   - Sunucu STARTTLS destekliyorsa TLS handshake başlatılır
   - TLS versiyonu ve cipher bilgisi alınır
   - Zayıf protokoller (TLS1.0/1.1) kontrol edilir

3. **POP3S (Port 995)**
   - TLS bağlantısı başlatılır
   - TLS versiyonu ve cipher bilgisi kaydedilir
   - Sertifika kontrolleri yapılır:
     - Expired / Not yet valid
     - Hostname mismatch
     - Self-signed veya chain hatası
   - Zayıf TLS protokolleri ayrıca kontrol edilir

---

## Kontroller ve Güvenlik Denetimleri
- ✅ Port 110 ve 995 açık mı?
- ✅ Banner sızıntısı (ürün/sürüm) var mı?
- ✅ APOP timestamp var mı?
- ✅ CAPA, STLS ve SASL mekanizmaları
- ✅ Plaintext authentication politikası
- ✅ STARTTLS üzerinden TLS kurulumu
- ✅ POP3S TLS kurulumu
- ✅ Zayıf TLS protokollerinin kabul edilip edilmediği
- ✅ Sertifika sorunları (expired, hostname mismatch, self-signed)

---

## Sonuçların Görselleştirilmesi
`POP3Result` struct’ı ile tüm bilgiler saklanır:
- Banner ve InfoLeak bilgisi
- Port durumu (110/995)
- CAPA / STLS / SASL destekleri
- Plaintext auth politikası ve sebebi
- STARTTLS ve POP3S TLS versiyon/cipher bilgisi
- Weak TLS protokolleri
- Sertifika sorunları
- Hata mesajları

Pretty-print ile renkli ve formatlı şekilde konsola yazdırılır.

---
