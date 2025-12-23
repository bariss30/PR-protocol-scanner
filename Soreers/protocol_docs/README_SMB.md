# SMB — Banner, Versiyon ve Paylaşım Taraması

## Amaç ve Kullanım
SMB (Server Message Block), dosya ve yazıcı paylaşımı için kullanılan bir ağ protokolüdür.  
Modülün amaçları:
- SMB portlarının açık olup olmadığını kontrol etmek (139 / 445)
- SMB versiyonunu tespit etmek (SMB1, SMB2, SMB3)
- SMB imzalama durumunu kontrol etmek (Signing Enabled / Required)
- Desteklenen SMB dialectlerini sorgulamak
- Guest erişimi ile paylaşımları ve dosyaları listelemek
- Kullanıcı/şifre kombinasyonları ile brute-force testi yapmak
- Hata ve güvenlik durumlarını raporlamak

---

## Temel İşleyiş
1. **Port Kontrolü ve Bağlantı**
   - TCP bağlantısı açılır
   - Bağlantı sağlanamazsa hata kaydedilir
   - Bağlantı süresi ve timeout ayarlanır

2. **SMB2 / SMB3 Taraması**
   - SMB2/3 NEGOTIATE paketi gönderilir
   - Sunucudan gelen yanıt parse edilir:
     - Versiyon tespiti
     - Security Mode ve Signing durumu
     - Desteklenen dialectler
   - Başarısız olursa SMB1 ile tekrar deneme yapılır

3. **SMB1 Taraması**
   - SMB1 NEGOTIATE paketi gönderilir
   - Dialect index ve security mode bilgisi parse edilir
   - Signing durumları kaydedilir

4. **Guest ile Paylaşım Listesi**
   - Guest kullanıcı ile bağlanılır
   - Paylaşımlar listelenir
   - Her paylaşım içindeki dosya/klasörler okunur
   - Hata varsa kaydedilir

5. **Brute-Force Testi**
   - Kullanıcı ve şifre listeleri okunur
   - Kombinasyonlar denenir
   - Başarılı girişler kaydedilir

---

## Kontroller ve Güvenlik Denetimleri
- ✅ SMB portları (139 / 445) açık mı?
- ✅ SMB versiyonu ve dialectler
- ✅ İmzalama durumu (Signing Enabled / Required)
- ✅ Guest erişimi ile paylaşım ve dosya listesi
- ✅ Kullanıcı/şifre kombinasyonlarıyla brute-force sonucu
- ✅ Hata mesajları ve bağlantı sorunları

---

## Sonuçların Görselleştirilmesi
`SMBResult` struct’ı ile tüm bilgiler saklanır:
- Hedef ve port bilgisi
- SMB versiyonu ve dialectler
- Security Mode ve Signing durumu
- Guest erişimi ile paylaşımlar ve dosyalar
- Brute-force başarılı kullanıcı/şifre kombinasyonları
- Hata mesajları

Pretty-print ile renkli ve formatlı şekilde konsola yazdırılır.