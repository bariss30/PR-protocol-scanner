# SNMP Vulnerability Scanner

Bu proje, SNMP (Simple Network Management Protocol) protokolü için kapsamlı güvenlik açığı tarama özellikleri sunar. Mevcut kütüphaneleri kullanarak aşağıdaki özellikleri içerir:

## Özellikler

### 1. SNMP Versiyon Enumeration
- SNMPv1, SNMPv2c, SNMPv3 versiyonlarını tespit eder
- Desteklenen protokol versiyonlarını listeler
- Protokol uyumluluğunu kontrol eder

### 2. SNMP Community String Discovery
- Varsayılan community string'leri test eder
- Özel community string'leri tespit eder
- Her community string için erişim seviyesini kontrol eder

### 3. SNMP System Information Gathering
- Sistem açıklaması (sysDescr)
- Sistem adı (sysName)
- Sistem iletişim bilgisi (sysContact)
- Sistem konumu (sysLocation)
- Sistem Object ID (sysObjectID)
- Sistem çalışma süresi (sysUpTime)

### 4. SNMP Walk Operations
- SNMP walk işlemleri gerçekleştirir
- OID ağacını tarar
- Sistem bilgilerini toplar
- Ağ cihazı detaylarını çıkarır

### 5. SNMP Vulnerability Detection
- SNMPv1 kullanımını tespit eder (güvenlik açığı)
- Varsayılan community string'leri tespit eder
- Read-write erişim açıklarını tespit eder
- Bilgi sızıntısı açıklarını tespit eder

### 6. SNMP Brute Force
- Community string brute force saldırısı
- İlerleme göstergesi ve detaylı raporlama
- Başarılı community string'leri raporlar

## Kullanım

### Komut Satırı Kullanımı

```bash
# Temel SNMP taraması
go run main.go -protocol snmp -t 192.168.1.1

# SNMP taraması (timeout ile)
go run main.go -protocol snmp -t 192.168.1.1 -timeout 10

# Çoklu hedef SNMP taraması
go run main.go -protocol snmp -T iplist.txt

# Eşzamanlılık ayarları ile
go run main.go -protocol snmp -t 192.168.1.1 -c 20
```

### Parametreler

- `-protocol snmp`: SNMP protokolü kullan (zorunlu)
- `-t <IP>`: Tek hedef IP adresi
- `-T <file>`: IP adreslerinin bulunduğu dosya
- `-c <number>`: Eşzamanlı çalışma sayısı (varsayılan: 10)
- `-timeout <seconds>`: Zaman aşımı süresi (varsayılan: 5)
- `-h`: Yardım

## Çıktı Örneği

```
[*] SNMP taraması başlatıldı.

[*] Scanning target: 192.168.1.1
==================================================

[1] SNMP Version Enumeration and Community Discovery
--------------------------------------------------
[+] SNMP Version: SNMPv2c

[2] Community String Enumeration
------------------------------
[+] Found 2 community strings:
    1. public - Access: Read-Only (RO:true, RW:false)
    2. private - Access: Read-Write (RO:true, RW:true)

[3] System Information
--------------------
[+] System Description: Cisco IOS Software, C3560 Software (C3560-IPBASEK9-M), Version 12.2(53)EY, RELEASE SOFTWARE (fc1)
[+] System Name: Router-01
[+] System Contact: admin@company.com
[+] System Location: Server Room A
[+] System Object ID: 1.3.6.1.4.1.9.1.516
[+] System Up Time: 1234567890

[4] SNMP Walk Results
--------------------
[+] Found 45 OIDs:
    1. 1.3.6.1.2.1.1.1.0 = Cisco IOS Software, C3560 Software (System Description)
    2. 1.3.6.1.2.1.1.2.0 = 1.3.6.1.4.1.9.1.516 (System Object ID)
    3. 1.3.6.1.2.1.1.3.0 = 1234567890 (System Up Time)
    4. 1.3.6.1.2.1.1.4.0 = admin@company.com (System Contact)
    5. 1.3.6.1.2.1.1.5.0 = Router-01 (System Name)
    ... and 40 more OIDs

[5] Vulnerability Analysis
-------------------------
[+] Found 3 vulnerabilities:
    1. [Medium] Default Community String: Default community string 'public' is being used
        Details: Default community strings are well-known and easily guessable
    2. [High] Read-Write Access: Community string 'private' has read-write access
        Details: Read-write access allows unauthorized modification of device configuration
    3. [Low] Information Disclosure: System contact information is exposed
        Details: Contact information may reveal organizational details

[6] Brute Force Community Strings
--------------------------------
[*] No communities found, attempting brute force...
[-] Brute force failed to find any community strings

[7] Security Recommendations
--------------------------
Security recommendations:
  • Change default community string 'public'
  • Restrict write access for community 'private'
  • Review system contact information exposure
  • Review system location information exposure

==================================================
```

## Güvenlik Açıkları

### Tespit Edilen Açıklar

1. **SNMPv1 Kullanımı**: SNMPv1 protokolü güvenlik açıklarına karşı savunmasızdır
2. **Varsayılan Community String'ler**: Bilinen community string'lerin kullanımı
3. **Read-Write Erişim**: Yetkisiz yapılandırma değişikliği
4. **Bilgi Sızıntısı**: Sistem bilgilerinin açığa çıkması
5. **Zayıf Kimlik Doğrulama**: Community string tabanlı kimlik doğrulama

### Öneriler

1. SNMPv3 protokolüne geçin
2. Varsayılan community string'leri değiştirin
3. Read-write erişimi kısıtlayın
4. SNMP erişimini güvenlik duvarı ile kısıtlayın
5. Hassas bilgileri gizleyin
6. Güçlü community string'ler kullanın

## Teknik Detaylar

### Kullanılan Protokoller

- **SNMPv1**: Basit kimlik doğrulama (deprecated)
- **SNMPv2c**: Community string tabanlı kimlik doğrulama
- **SNMPv3**: Güvenli kimlik doğrulama ve şifreleme

### Portlar

- **161**: SNMP (Simple Network Management Protocol)
- **162**: SNMP Trap

### OID'ler

- **1.3.6.1.2.1.1.1.0**: System Description
- **1.3.6.1.2.1.1.2.0**: System Object ID
- **1.3.6.1.2.1.1.3.0**: System Up Time
- **1.3.6.1.2.1.1.4.0**: System Contact
- **1.3.6.1.2.1.1.5.0**: System Name
- **1.3.6.1.2.1.1.6.0**: System Location

### Community String'ler

Varsayılan community string'ler:
- `public` (read-only)
- `private` (read-write)
- `community`
- `admin`
- `cisco`
- `hp`
- `3com`

## Geliştirme

### Yeni Özellik Ekleme

1. `scanner/snmp/snmp.go` dosyasına yeni fonksiyon ekleyin
2. `main.go` dosyasında `runSNMP` fonksiyonunu güncelleyin
3. Test edin ve dokümantasyonu güncelleyin

### Hata Ayıklama

- Detaylı loglar için `fmt.Printf` kullanın
- Timeout değerlerini artırın
- Ağ bağlantısını kontrol edin

## Lisans

Bu proje eğitim amaçlı geliştirilmiştir. Sadece yetkili sistemlerde kullanın. 