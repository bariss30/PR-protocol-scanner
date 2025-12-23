# LDAP — Derinlemesine İnceleme

## Amaç ve Kullanım
LDAP (Lightweight Directory Access Protocol), dizin servislerine erişim ve yönetim için kullanılan bir protokoldür.  
Kullanım amaçları:
- Kullanıcı ve grup bilgilerini sorgulama ve yönetme
- Kimlik doğrulama ve yetkilendirme
- Kurumsal dizin servisleri ile entegrasyon
- Güvenlik ve erişim politikalarının uygulanması

LDAP genellikle TCP/389 (plain) veya TCP/636 (TLS/SSL) portlarında çalışır.

---

## Temel İşleyiş
- Sunucuya TCP üzerinden bağlantı kurulur (`ldap://target:389`).  
- Sunucu ile LDAP oturumu açılır, gerekli ise TLS başlatılır.  
- İstemci bind (giriş) komutu ile kimlik doğrulama yapar:
  - Anonymous bind: kimlik doğrulama yapılmadan bağlanma
  - Simple bind: kullanıcı/parola ile bağlanma
- RootDSE sorgusu ile sunucu hakkında bilgi alınabilir:
  - `namingContexts` → Dizindeki temel konteksler
  - `supportedSASLMechanisms` → Desteklenen SASL mekanizmaları
  - `vendorName`, `vendorVersion` → Sunucu vendor ve sürümü
  - `supportedLDAPVersion` → Desteklenen LDAP versiyonu
  - `subschemaSubentry` → Şema bilgisi

---

## Modülün İşleyişi

### 1. Temel Tarama (ScanLDAP)
- TCP üzerinden LDAP sunucusuna bağlanır.  
- Anonymous bind testi yapılır (`UnauthenticatedBind("")`).  
- RootDSE sorgusu ile:
  - Naming context’ler
  - SASL mekanizmaları
  - Versiyon, vendor ve şema bilgileri alınır.  
- Hata oluşursa `LDAPResult.Error` alanına kaydedilir.

### 2. Brute Force Testi (BruteForceLDAP)
- Kullanıcı ve parola listesi ile sunucuya sırayla bağlanır.  
- Başarılı login durumunda:
  - Sonuç loglanır
  - `LDAPResult` listesine eklenir
- Başarısız denemeler de loglanır ve sonuç listesine eklenir  
- Tüm denemeler sonunda işlem tamamlandığına dair banner gösterilir.

### 3. Sonuçların Görselleştirilmesi (LDAPResult.String)
- Bağlantı ve tarama sonuçları renkli ve biçimlendirilmiş şekilde gösterilir.  
- Gösterilen bilgiler:
  - Hedef IP/hostname
  - Anonymous bind durumu
  - Naming context’ler
  - Desteklenen SASL mekanizmaları
  - LDAP versiyonu ve vendor bilgisi
  - Şema bilgisi
  - Oluşan hatalar

---

## Kontroller ve Güvenlik Denetimleri
- ✅ Anonymous bind testi  
- ✅ SASL mekanizmaları kontrolü  
- ✅ RootDSE üzerinden versiyon, vendor ve şema bilgisi toplama  
- ✅ Kullanıcı/parola brute force testi  
- ✅ Bağlantı hatalarının ve timeout durumlarının yönetimi
