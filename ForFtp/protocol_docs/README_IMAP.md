# IMAP — Derinlemesine İnceleme

## Amaç ve Kullanım
IMAP (Internet Message Access Protocol), e-posta sunucularına erişim sağlamak ve kullanıcı postalarını senkronize etmek için kullanılan bir protokoldür.  
Kullanım amaçları:
- E-posta mesajlarını sunucuda saklama ve yönetme
- Uzak cihazlardan veya istemcilerden posta erişimi
- Çeşitli istemciler arasında posta senkronizasyonu
- Güvenli iletişim (STARTTLS veya TLS ile)  

IMAP, POP3’e göre avantaj sağlar:
- Mesajlar sunucuda kalır
- Klasör yönetimi ve çoklu cihaz senkronizasyonu desteklenir
- Mesaj durumları (okundu, okunmadı, yanıtlandı) tutulur

---

## Temel İşleyiş — Bağlantı ve Komutlar
IMAP istemci-sunucu iletişimi TCP üzerinden gerçekleştirilir:
- **Standart port:** 143 (plain, STARTTLS ile şifrelenebilir)  
- **Güvenli port:** 993 (implicit TLS/SSL)  

### İşleyiş Mantığı
- Sunucuya TCP bağlantısı kurulur.
- Sunucu bir banner/greeting mesajı gönderir (`* OK ...` veya `* PREAUTH ...`).
- İstemci, CAPABILITY komutu ile sunucunun desteklediği özellikleri öğrenir.
- İstemci mesajları almak, göndermek veya yönetmek için LOGIN ve diğer IMAP komutlarını kullanır.

### Önemli Komutlar ve Yanıtlar
- `CAPABILITY` → Sunucunun desteklediği uzantılar ve güvenlik özellikleri  
- `LOGIN user pass` → Kullanıcı adı ve parola ile giriş  
- `STARTTLS` → Bağlantıyı şifrelemek için TLS başlatma  
- Yanıt örnekleri:  
  - `* OK` → Başarılı yanıt  
  - `* NO` → Hatalı komut/giriş  
  - `* BAD` → Geçersiz komut  

---

## Bu Modülün İşleyişi (Scanner Özeti)

### 1. Banner Grabbing
- TCP/143 veya TCP/993 portuna bağlanılır.  
- Sunucudan gelen ilk satır okunur ve **banner** elde edilir.  
- Banner’dan **sunucu tipi** ve **versiyon** tahmini yapılır.  

### 2. STARTTLS Desteği
- Sunucunun **STARTTLS** komutunu destekleyip desteklemediği kontrol edilir.  
- Eğer destekleniyorsa, plain-text bağlantı şifrelenebilir.  

### 3. Plaintext Login Testi
- Şifrelenmemiş bağlantı üzerinden LOGIN denemesi yapılır (`LOGIN test test`).  
- Sunucu yanıtı analizi ile plaintext girişin mümkün olup olmadığı belirlenir.  
- `LOGINDISABLED` veya TLS/STARTTLS uyarısı varsa, plaintext giriş **engellenmiş** demektir.  

### 4. Bilgi Sızıntısı Tespiti
- Banner veya CAPABILITY yanıtları, sunucu yazılımı ve versiyon bilgisi sızdırabilir.  
- Yaygın IMAP sunucuları: Dovecot, Cyrus, Courier, UW-IMAP, Exchange, Gmail, hMailServer vb.  
- Bu bilgi güvenlik risklerine işaret eder.  

### 5. Yanıt Okuma ve Hata Yönetimi
- `textproto.Reader` ile satır satır okuma yapılır.  
- Yanıtlar normalize edilir, ilk üç karakter kod olarak değerlendirilir.  
- Hatalı format veya zaman aşımı durumları loglanır.  

### 6. Timeout ve Bağlantı Yönetimi
- `net.Dialer` ve `conn.SetDeadline` ile bağlantı süreleri sınırlandırılır.  
- Bu sayede asenkron veya paralel taramalarda kaynak kullanımı kontrol altında tutulur.  

---

## Güvenlik Kontrolleri (Modülün Yaptıkları)
- ✅ Banner’dan sunucu bilgisi ve olası versiyon tespiti  
- ✅ STARTTLS desteği kontrolü (plain-text şifreleme önlemi)  
- ✅ Plaintext login testi (LOGIN komutu ile şifreli/şifresiz giriş analizi)  
- ✅ Bilgi sızıntısı tespiti (sunucu yazılımı ve sürüm bilgisi)  
- ✅ Yanıt kodu analizi ve hata yönetimi  
- ✅ Timeout ve bağlantı hatalarının raporlanması  

---