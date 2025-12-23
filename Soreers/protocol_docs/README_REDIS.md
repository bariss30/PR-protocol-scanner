# Redis Tarayıcı ve Güvenlik Denetimi

## Amaç ve Kullanım
Redis, açık kaynaklı bir bellek içi veri deposudur ve genellikle TCP 6379 üzerinden çalışır.  
Bu modülün amaçları:
- Redis sunucusunun açık olup olmadığını tespit etmek
- PING ve INFO komutlarıyla temel kontrolleri yapmak
- Auth (parola) gerekip gerekmediğini kontrol etmek
- Redis sürüm, mode, role ve işletim sistemi bilgilerini almak
- Yetkisiz komut çalıştırılabilirliğini tespit etmek
- Potansiyel güvenlik risklerini (vulnerabilities) belirlemek
- Opsiyonel olarak kullanıcı/parola kombinasyonlarıyla brute-force testi yapmak

---

## Temel İşleyiş

1. **Port 6379 Taraması**
   - TCP üzerinden bağlantı açılır
   - PING komutu gönderilir, PONG cevabı alınırsa sunucu çalışıyor demektir
   - INFO komutu ile sunucu bilgileri alınır
     - Eğer "-ERR AUTH" cevabı gelirse parola gerekli (`AuthRequired = true`)
     - Aksi takdirde, INFO sonucu parse edilip:
       - `Version` → Redis sürümü
       - `Mode` → Standalone / Cluster
       - `Role` → Master / Slave
       - `OS` → İşletim sistemi bilgisi
     kaydedilir
   - Yetkisiz çalıştırılabilen komutlar (`UnauthCommands`) kaydedilir

2. **Vulnerability Değerlendirmesi**
   - Auth yoksa veya PING yetkisiz cevap veriyorsa, erişim açığı olarak işaretlenir
   - Master node, TLS ve erişim kontrolü olmadan kritik risk oluşturur
   - Çok eski Redis sürümleri (örn. 2.x) güncelleme gerektirir

3. **Brute-Force Denemeleri**
   - `BruteForceRedis` fonksiyonu, kullanıcı/parola veya sadece parola kombinasyonlarını deneyebilir
   - Sonuçlar `RedisAuthResult` yapısında kaydedilir:
     - Başarılı mı (`Success`)
     - Kullanıcı ve parola kombinasyonu
     - Hata mesajları
   - Paralel/konkürent şekilde çalışır (default concurrency=5)

4. **RESP Protokolü**
   - Redis ile iletişim RESP protokolü üzerinden yapılır
   - `writeRESP` ile komut gönderilir, `readLine` ve `readBulk` ile cevap okunur

---

## Kontroller ve Güvenlik Bulguları

- ✅ Redis portu açık mı?
- ✅ Sunucu PING cevabı veriyor mu?
- ✅ Auth gerekli mi?
- ✅ Yetkisiz komut çalıştırılabiliyor mu?
- ✅ Redis sürümü, mode ve role bilgisi
- ✅ OS bilgisi
- ✅ Potansiyel güvenlik riskleri:
  - Auth olmadan erişim mümkün
  - PING cevabı ile bilgi sızdırma
  - Master node, TLS ve ACL yoksa riskli
  - Eski Redis sürümü kullanımı
- ✅ Brute-force ile parola testi

---

## Sonuçların Görselleştirilmesi
- `RedisResult.String()` ile renkli ve formatlı çıktı
- `RedisAuthResult.String()` ile brute-force sonuçları raporlanır
- Findings ve vulnerabilities listesi kullanıcıya net şekilde sunulur

---