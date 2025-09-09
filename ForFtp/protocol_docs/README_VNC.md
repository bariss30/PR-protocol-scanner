# VNC — Server Bilgisi ve Brute-Force Denemesi

## Amaç ve Kullanım
VNC (Virtual Network Computing), uzak masaüstü erişimi sağlamak için kullanılan bir protokoldür.  
Modülün amaçları:
- VNC sunucusuna TCP bağlantısı açmak (default port 5900)
- RFB (Remote FrameBuffer) handshake ile sunucu versiyonunu öğrenmek
- Desteklenen güvenlik tiplerini (None, VNC Auth, Tight vb.) tespit etmek
- Masaüstü çözünürlüğü ve isim bilgilerini almak
- No-auth (şifresiz) erişim veya VNC şifreli erişim var mı kontrol etmek
- Brute-force ile parola denemeleri yapmak
- Zayıf veya varsayılan şifrelerin varlığını tespit etmek

---

## Temel İşleyiş

1. **Sunucuya Bağlanma ve Versiyon Okuma**
   - TCP bağlantısı açılır
   - Sunucudan 12 byte RFB versiyonu okunur
   - 3.3 veya 3.8 sürümü seçilir ve sunucuya gönderilir

2. **Güvenlik Tiplerini Tespit Etme**
   - RFB 3.3: 4 byte security type okunur
   - RFB 3.7/3.8: 1 byte ile security type sayısı, ardından liste okunur
   - `None` ve `VNC Authentication` tespit edilir
   - No-auth veya VNC auth durumuna göre ServerInit okunur

3. **ServerInit ve Masaüstü Bilgisi**
   - Ekran genişlik/yükseklik bilgisi alınır
   - Desktop name okunur
   - Pixel format ve diğer opsiyonlar atlanır

4. **Brute-Force İşleyişi**
   - Şifre listesi veya kullanıcı x şifre kombinasyonları denenir
   - Paralel çalışan goroutine’ler ile denemeler yapılır (`concurrency`)
   - Her deneme `VNCAuthResult` struct’ında saklanır
   - Başarılı girişler ve hata mesajları raporlanır

5. **VNC Challenge-Response**
   - VNC Authentication için 16 byte challenge alınır
   - Parola ile DES şifreleme yapılır
   - Şifrelenmiş response gönderilir ve giriş durumu okunur

---

## Kontroller ve Güvenlik Denetimleri
- ✅ VNC portu (5900) açık mı?
- ✅ Sunucu versiyonu okunabiliyor mu?
- ✅ Desteklenen security type’lar neler?
- ✅ No-auth veya şifreli VNC erişimi var mı?
- ✅ Masaüstü çözünürlüğü ve isim bilgisi alınabiliyor mu?
- ✅ Brute-force ile şifre denemesi yapılabiliyor mu?
- ✅ Zayıf veya varsayılan şifreler tespit ediliyor mu?
- ✅ Hata ve timeout durumları

---

## Sonuçların Görselleştirilmesi
`VNCResult` ve `VNCAuthResult` struct’ları ile tüm bilgiler saklanır:
- Hedef ve port bilgisi
- Sunucu versiyonu ve seçilen versiyon
- Desteklenen security type’lar
- No-auth veya VNC Auth durumu
- Masaüstü genişlik, yükseklik ve isim bilgisi
- Bulunan zafiyetler veya güvenlik bulguları
- Brute-force denemeleri:
  - Denenen parola
  - Başarılı / başarısız durumu
  - Hata mesajları
- Pretty-print ile renkli ve formatlı şekilde konsola yazdırılır