# Telnet — Banner Okuma ve Brute-Force Denemesi

## Amaç ve Kullanım
Telnet, TCP üzerinden uzak sistemlerde terminal erişimi sağlamak için kullanılan eski bir protokoldür.  
Modülün amaçları:
- Telnet portlarının (default 23) açık olup olmadığını kontrol etmek
- Banner bilgisini almak ve giriş promptlarını tespit etmek
- Telnet kontrol karakterlerini temizlemek
- Kullanıcı adı ve parola kombinasyonları ile brute-force testi yapmak
- Başarılı ve başarısız girişleri kaydetmek
- Hata mesajlarını ve istatistikleri raporlamak

---

## Temel İşleyiş

1. **Banner Okuma ve Temizleme**
   - TCP bağlantısı açılır
   - Sunucudan gelen veriler `cleanTelnetResponse` fonksiyonu ile Telnet kontrol karakterlerinden arındırılır
   - Banner bilgisi okunur ve login promptları (login, user, password) tespit edilir

2. **Login Denemesi**
   - Kullanıcı adı gönderilir
   - Sunucudan gelen parola promptu beklenir
   - Parola gönderilir
   - Yanıt kontrol edilerek girişin başarılı mı yoksa başarısız mı olduğu belirlenir
   - Kali Linux gibi belirli sistemlerde özel göstergeler (welcome, last login, $, #) ile başarılı giriş tespit edilir

3. **Brute-Force İşleyişi**
   - Kullanıcı ve parola listeleri üzerinden tüm kombinasyonlar denenir
   - Çalışan goroutine’ler ile paralel denemeler yapılır (`workers`)
   - Sonuçlar `BruteForceResult` struct’ında saklanır
   - Başarılı girişler ayrı listede tutulur

---

## Kontroller ve Güvenlik Denetimleri
- ✅ Telnet portu açık mı?
- ✅ Banner okunabiliyor mu?
- ✅ Login ve password promptları tespit ediliyor mu?
- ✅ Kullanıcı/şifre kombinasyonları ile brute-force denemesi
- ✅ Başarılı ve başarısız girişlerin raporlanması
- ✅ Hata ve timeout durumları
- ✅ Brute-force istatistikleri (toplam deneme, başarı, başarısızlık, hata, geçen süre)

---

## Sonuçların Görselleştirilmesi
`BruteForceResult` ve `TelnetStats` struct’ları ile tüm bilgiler saklanır:
- Hedef ve port bilgisi
- Denenen kullanıcı adı ve parola kombinasyonları
- Giriş durumu: Başarılı / Başarısız / Hata
- Banner ve login prompt bilgisi
- Brute-force istatistikleri:
  - Toplam deneme sayısı
  - Başarılı girişler
  - Başarısız girişler
  - Hatalar
  - Geçen süre
- Pretty-print ile renkli ve formatlı şekilde konsola yazdırılır