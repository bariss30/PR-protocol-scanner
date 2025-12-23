# MySQL — Derinlemesine İnceleme

## Amaç ve Kullanım
MySQL, yaygın kullanılan bir ilişkisel veritabanı yönetim sistemidir (RDBMS).  
Kullanım amaçları:
- Veritabanı ve tablo yönetimi
- Kullanıcı yetkilendirme ve erişim kontrolü
- Veritabanı sorgulama ve veri analizi
- Güvenlik testleri ve penetrasyon testleri

MySQL genellikle TCP/3306 portu üzerinden hizmet verir.

---

## Temel İşleyiş
- Sunucuya TCP/3306 üzerinden bağlantı kurulur.
- Kullanıcı adı ve parola ile bağlanılır (`sql.Open` ve `db.Ping()`).
- Bağlantı başarılı ise:
  - Versiyon bilgisi alınır (`SELECT VERSION()`).
  - Kullanıcı yetkileri (`SHOW GRANTS FOR CURRENT_USER()`) sorgulanır.
  - Mevcut veritabanları (`SHOW DATABASES`) listelenir.
- Bağlantı hataları veya yetkisiz erişim durumları `MySQLResult.Error` alanında kaydedilir.

---

## Modülün İşleyişi

### 1. Temel Tarama (ScanMySQL)
- Verilen `target`, `user` ve `pass` ile MySQL sunucusuna bağlanır.  
- Hedef sunucuya bağlantı sağlanamazsa veya ping başarısız olursa hata döner.  
- Bağlantı başarılı ise:
  - MySQL sürümü alınır.
  - Kullanıcının yetkileri toplanır.
  - Mevcut veritabanları listelenir.
- Tüm bilgiler `MySQLResult` struct'ında saklanır.

### 2. Brute Force Testi (BruteForceMySQL)
- Kullanıcı ve parola listesi ile sunucuya sırayla bağlanır.  
- Başarılı girişler `ScanMySQL` fonksiyonu ile detaylandırılır:
  - Kullanıcı ve parola
  - MySQL versiyonu
  - Veritabanları
  - Yetkiler
- Başarısız girişler loglanır ve göz ardı edilir.  
- İşlem tamamlandığında başarılı girişler liste halinde döndürülür.

### 3. Sonuçların Görselleştirilmesi
- Başarılı girişlerde ekranda renkli ve formatlı bilgiler gösterilir:
  - Kullanıcı:parola
  - MySQL versiyonu
  - Veritabanı sayısı ve isimleri
  - Yetkiler listesi
- Hatalar veya başarısız girişler `Error` alanında saklanır.

---

## Kontroller ve Güvenlik Denetimleri
- ✅ Bağlantı ve kimlik doğrulama testi  
- ✅ MySQL sürüm bilgisi toplama  
- ✅ Kullanıcı yetkilerinin kontrolü (`SHOW GRANTS`)  
- ✅ Mevcut veritabanlarının listelenmesi (`SHOW DATABASES`)  
- ✅ Brute force ile kullanıcı/parola kombinasyonlarının denenmesi  
- ✅ Hata ve timeout yönetimi