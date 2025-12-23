# FTP — Derinlemesine İnceleme

## Amaç ve Kullanım
FTP (File Transfer Protocol), istemci ile sunucu arasında dosya aktarımı yapmak için kullanılan eski ama yaygın bir protokoldür.  
Kullanım amaçları:
- Dosya yükleme/indirme (upload/download)
- Uzak yedekleme
- İçerik dağıtımı
- Konfigürasyon veya yönetim dosyalarının taşınması  

Birçok **legacy sistem** ve **gömülü cihaz** halen FTP desteği bulundurur.

---

## Temel İşleyiş — Kontrol Kanalı
- **Kontrol kanalı (TCP/21):** Komutlar ve yanıtlar bu kanal üzerinden iletilir.  
- **Temel komutlar:** `USER`, `PASS`, `AUTH TLS`  
- **Yaygın yanıt kodları:**  
  - `220` → Hizmet hazır (banner)  
  - `331` → Kullanıcı adı alındı, parola bekleniyor  
  - `230` → Giriş başarılı  
  - `530` → Giriş reddedildi  

---

## Bu Modülün İşleyişi (Scanner Özeti)

### 1. Banner Grabbing (GetVersion)
- TCP/21’e bağlanılır, ilk satır okunur.  
- Banner’dan **sunucu tipi** ve **versiyon** çıkarılır.  
- Bu bilgi zafiyet veritabanlarıyla eşleştirilebilir.

### 2. Anonim Login Testi (AnonymousLogin)
- `USER anonymous` + `PASS anonymous` gönderilir.  
- Eğer yanıt `230` ise anonim giriş **başarılıdır**.

### 3. Kullanıcı/Parola Testi (SingleLogin / FTPLogin)
- Verilen kullanıcı/parola ile `USER` ve `PASS` gönderilir.  
- Yanıt `230` ise giriş başarılıdır.  
- `331` ve ardından `530` gelirse giriş reddedilmiştir.  

### 4. Explicit TLS Tespiti (SupportsExplicitTLS)
- `AUTH TLS` komutu gönderilir.  
- Eğer sunucu `234` veya benzeri olumlu bir yanıt verirse **Explicit TLS desteklenir**.  

### 5. Yanıt Okuma ve Hata Yönetimi
- Sunucu yanıtları satır satır okunur, ilk üç haneden kod çıkarılır.  
- Yanlış formatlı yanıtlar veya zaman aşımı durumları loglanır.  

### 6. Timeout ve Bağlantı Yönetimi
- `net.DialTimeout` ile bağlantılar sınırlandırılır.  
- Bu sayede asenkron taramalarda kaynak tüketimi kontrol edilir.  

---

## Güvenlik Kontrolleri (Bu Modülün Yaptıkları)
- ✅ Banner’dan sürüm tespiti  
- ✅ Anonim login denemesi  
- ✅ Kullanıcı/parola ile giriş testi  
- ✅ AUTH TLS desteği kontrolü  
- ✅ Yanıt kodu analizi (`230`, `331`, `530`)  
- ✅ Timeout ve bağlantı hatalarının raporlanması  

---
