# Enhanced SMB Vulnerability Scanner

Bu proje, SMB protokolü için kapsamlı güvenlik açığı tarama özellikleri sunar. Mevcut kütüphaneleri kullanarak aşağıdaki özellikleri içerir:

## Özellikler

### 1. SMB Versiyon Enumeration
- SMB1, SMB2.0.2, SMB2.1, SMB3.0, SMB3.0.2, SMB3.1.1 versiyonlarını tespit eder
- Desteklenen dialektleri listeler
- Protokol uyumluluğunu kontrol eder

### 2. SMB İmzalama (Signing) Durumu Kontrolü
- SMB1 ve SMB2 için imzalama durumunu kontrol eder
- İmzalama etkin mi/geçerli mi bilgisini verir
- Güvenlik açıklarını tespit eder

### 3. Açık Paylaşımları (Shares) Listeleme
- Anonim erişim ile paylaşım listesi
- Null session ile paylaşım listesi
- Guest kullanıcı ile paylaşım listesi
- Her paylaşım için okuma/yazma izinlerini test eder

### 4. SMB Brute Force
- Kullanıcı adı ve şifre listeleri ile brute force saldırısı
- Başarılı girişlerde paylaşım erişimini test eder
- İlerleme göstergesi ve detaylı raporlama

### 5. NetBIOS Fonksiyonalitesi
- NetBIOS servis bilgilerini toplar
- Bilgisayar adı, domain, workgroup bilgilerini çıkarır
- NetBIOS over TCP desteğini kontrol eder

### 6. SMB Read/Write Testi
- Başarılı kimlik doğrulama sonrası dosya okuma/yazma testi
- Paylaşım bazında izin kontrolü
- Güvenlik açıklarını tespit eder

## Kullanım

### Komut Satırı Kullanımı

```bash
# Temel SMB taraması
go run main.go -protocol smb -t 192.168.1.1

# Anonim login ile tarama
go run main.go -protocol smb -t 192.168.1.1 -A

# Tek kullanıcı/şifre ile tarama
go run main.go -protocol smb -t 192.168.1.1 -u admin -p password

# Kullanıcı ve şifre listeleri ile brute force
go run main.go -protocol smb -t 192.168.1.1 -U users.txt -P passwords.txt

# IP listesi ile toplu tarama
go run main.go -protocol smb -T iplist.txt -U users.txt -P passwords.txt

# Eşzamanlılık ve timeout ayarları
go run main.go -protocol smb -t 192.168.1.1 -c 20 -timeout 10
```

### Parametreler

- `-protocol smb`: SMB protokolü kullan (zorunlu)
- `-t <IP>`: Tek hedef IP adresi
- `-T <file>`: IP adreslerinin bulunduğu dosya
- `-u <username>`: Tek kullanıcı adı
- `-p <password>`: Tek şifre
- `-U <file>`: Kullanıcı adı listesi dosyası
- `-P <file>`: Şifre listesi dosyası
- `-A`: Anonim login denemesi
- `-c <number>`: Eşzamanlı çalışma sayısı (varsayılan: 10)
- `-timeout <seconds>`: Zaman aşımı süresi (varsayılan: 5)
- `-h`: Yardım

## Çıktı Örneği

```
[*] SMB taraması başlatıldı.

[*] Scanning target: 192.168.1.1
==================================================

[1] SMB Version Enumeration and Signing Check
----------------------------------------
[+] SMB Version: SMB 3.1.1
[+] Signing Enabled: true
[+] Signing Required: true
[+] Supported Dialects: [SMB 3.1.1]
[+] NetBIOS Active: Yes
[+] Computer Name: WIN-SERVER

[2] Detailed Version Enumeration
------------------------------
[+] Detected SMB Versions: [SMB1, SMB 3.1.1]

[3] Detailed Signing Analysis
-------------------------
[+] SMB1 Signing - Enabled: false, Required: false
[+] SMB2 Signing - Enabled: true, Required: true

[4] Share Enumeration
--------------------
[+] Found 3 accessible shares:
    - IPC$ (Unknown) - Permissions: Read Only
    - C$ (Unknown) - Permissions: Read/Write
    - ADMIN$ (Unknown) - Permissions: Read/Write

[5] Anonymous Login Test
-------------------------
[-] Anonymous login failed

[6] Single Credential Test
-------------------------
[+] Single login successful: 192.168.1.1 admin:password
[*] User permissions - Read: true, Write: true

[7] Brute Force Attack
--------------------
[*] Starting brute force with 4 users and 4 passwords
[+] SMB LOGIN SUCCESS: 192.168.1.1 admin:password
  [*] Share C$: Read=true, Write=true
[*] Progress: 100/16 attempts (100.0%)
[*] Brute force completed: 1 successful logins found

==================================================
```

## Güvenlik Açıkları

### Tespit Edilen Açıklar

1. **SMB1 Etkin**: SMB1 protokolü güvenlik açıklarına karşı savunmasızdır
2. **İmzalama Devre Dışı**: Man-in-the-middle saldırılarına açıktır
3. **Anonim Erişim**: Kimlik doğrulama olmadan erişim mümkün
4. **Zayıf Şifreler**: Brute force ile tespit edilen şifreler
5. **Açık Paylaşımlar**: Yetkisiz erişime açık paylaşımlar

### Öneriler

1. SMB1 protokolünü devre dışı bırakın
2. SMB imzalama zorunluluğunu etkinleştirin
3. Anonim erişimi kapatın
4. Güçlü şifreler kullanın
5. Paylaşım izinlerini gözden geçirin

## Teknik Detaylar

### Kullanılan Kütüphaneler

- `github.com/stacktitan/smb/smb`: SMB1 protokol desteği
- `github.com/hirochachacha/go-smb2`: SMB2/3 protokol desteği
- `golang.org/x/crypto`: Şifreleme işlemleri

### Protokol Desteği

- **SMB1**: Windows NT 4.0 ve üzeri
- **SMB2**: Windows Vista ve üzeri
- **SMB3**: Windows 8/Server 2012 ve üzeri

### Portlar

- **139**: NetBIOS over TCP
- **445**: SMB over TCP

## Geliştirme

### Yeni Özellik Ekleme

1. `scanner/smb/smb.go` dosyasına yeni fonksiyon ekleyin
2. `main.go` dosyasında `runSMB` fonksiyonunu güncelleyin
3. Test edin ve dokümantasyonu güncelleyin

### Hata Ayıklama

- Detaylı loglar için `fmt.Printf` kullanın
- Timeout değerlerini artırın
- Ağ bağlantısını kontrol edin

## Lisans

Bu proje eğitim amaçlı geliştirilmiştir. Sadece yetkili sistemlerde kullanın. 