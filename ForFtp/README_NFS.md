# NFS Vulnerability Scanner

Bu proje, NFS (Network File System) protokolü için kapsamlı güvenlik açığı tarama özellikleri sunar. Mevcut kütüphaneleri kullanarak aşağıdaki özellikleri içerir:

## Özellikler

### 1. NFS Versiyon Enumeration
- NFSv2, NFSv3, NFSv4 versiyonlarını tespit eder
- Desteklenen protokol versiyonlarını listeler
- Protokol uyumluluğunu kontrol eder

### 2. NFS Export Discovery
- Erişilebilir NFS export'larını tespit eder
- Export yollarını ve seçeneklerini listeler
- Her export için izin durumunu kontrol eder

### 3. NFS Authentication Analysis
- Kimlik doğrulama gereksinimlerini kontrol eder
- Anonim erişim durumunu tespit eder
- Desteklenen kimlik doğrulama yöntemlerini listeler

### 4. NFS Permission Testing
- Her export için okuma/yazma/çalıştırma izinlerini test eder
- Root squash durumunu kontrol eder
- Güvenlik açıklarını tespit eder

### 5. NFS Vulnerability Detection
- NFSv2 kullanımını tespit eder (güvenlik açığı)
- Anonim erişim açıklarını tespit eder
- Yazılabilir export'ları tespit eder
- Güvensiz seçenekleri tespit eder

### 6. Portmapper (rpcbind) Analysis
- Portmapper servisinin aktif olup olmadığını kontrol eder
- RPC servislerinin erişilebilirliğini test eder

## Kullanım

### Komut Satırı Kullanımı

```bash
# Temel NFS taraması
go run main.go -protocol nfs -t 192.168.1.1

# NFS taraması (timeout ile)
go run main.go -protocol nfs -t 192.168.1.1 -timeout 10

# Çoklu hedef NFS taraması
go run main.go -protocol nfs -T iplist.txt

# Eşzamanlılık ayarları ile
go run main.go -protocol nfs -t 192.168.1.1 -c 20
```

### Parametreler

- `-protocol nfs`: NFS protokolü kullan (zorunlu)
- `-t <IP>`: Tek hedef IP adresi
- `-T <file>`: IP adreslerinin bulunduğu dosya
- `-c <number>`: Eşzamanlı çalışma sayısı (varsayılan: 10)
- `-timeout <seconds>`: Zaman aşımı süresi (varsayılan: 5)
- `-h`: Yardım

## Çıktı Örneği

```
[*] NFS taraması başlatıldı.

[*] Scanning target: 192.168.1.1
==================================================

[1] NFS Version Enumeration and Export Discovery
---------------------------------------------
[+] NFS Version: NFSv3
[+] Supported Versions: [NFSv3, NFSv4]
[+] Portmapper Active: true

[2] Authentication Analysis
-------------------------
[+] Authentication Required: false
[+] Anonymous Access: true
[+] Auth Methods: AUTH_NULL

[3] Export Enumeration
--------------------
[+] Found 3 accessible exports:
    1. /home - Permissions: rw (r:true, w:true, x:true)
        Options: rw, no_root_squash
    2. /var - Permissions: r (r:true, w:false, x:true)
        Options: ro
    3. /tmp - Permissions: rwx (r:true, w:true, x:true)
        Options: rw, insecure

[4] Vulnerability Analysis
-------------------------
[+] Found 4 vulnerabilities:
    1. [Medium] Anonymous Access: NFS allows anonymous access without authentication
        Details: This allows unauthorized users to access exported filesystems
    2. [Medium] Writable Export: Export /home is writable
        Details: Writable exports can be used for data exfiltration or malware deployment
    3. [High] Root Squash Disabled: Export /home has root squash disabled
        Details: This allows root users to access files with root privileges
    4. [High] Insecure Export: Export /tmp uses insecure options
        Details: The 'insecure' option allows connections from unprivileged ports

[5] Read/Write Permission Testing
---------------------------------
[*] Export /home: Read=true, Write=true
[*] Export /var: Read=true, Write=false
[*] Export /tmp: Read=true, Write=true

[6] Security Recommendations
--------------------------
Security recommendations:
  • Disable anonymous access to NFS exports
  • Review write permissions for export /home
  • Enable root squash for export /home
  • Remove 'insecure' option from export /tmp
  • Restrict portmapper (rpcbind) access

==================================================
```

## Güvenlik Açıkları

### Tespit Edilen Açıklar

1. **NFSv2 Kullanımı**: NFSv2 protokolü güvenlik açıklarına karşı savunmasızdır
2. **Anonim Erişim**: Kimlik doğrulama olmadan erişim mümkün
3. **Yazılabilir Export'lar**: Yetkisiz yazma erişimi
4. **Root Squash Devre Dışı**: Root kullanıcılarının root yetkileriyle erişimi
5. **Güvensiz Seçenekler**: 'insecure' gibi güvenlik açığı oluşturan seçenekler

### Öneriler

1. NFSv2 protokolünü devre dışı bırakın
2. Anonim erişimi kapatın
3. Export izinlerini gözden geçirin
4. Root squash'ı etkinleştirin
5. Güvensiz seçenekleri kaldırın
6. Portmapper erişimini kısıtlayın

## Teknik Detaylar

### Kullanılan Protokoller

- **NFSv2**: Windows NT 4.0 ve üzeri (deprecated)
- **NFSv3**: Windows Vista ve üzeri
- **NFSv4**: Windows 8/Server 2012 ve üzeri

### Portlar

- **2049**: NFS (Network File System)
- **111**: Portmapper (rpcbind)

### RPC Programları

- **100003**: NFS Program
- **100005**: Mount Program
- **100000**: Portmapper Program

## Geliştirme

### Yeni Özellik Ekleme

1. `scanner/nfs/nfs.go` dosyasına yeni fonksiyon ekleyin
2. `main.go` dosyasında `runNFS` fonksiyonunu güncelleyin
3. Test edin ve dokümantasyonu güncelleyin

### Hata Ayıklama

- Detaylı loglar için `fmt.Printf` kullanın
- Timeout değerlerini artırın
- Ağ bağlantısını kontrol edin

## Lisans

Bu proje eğitim amaçlı geliştirilmiştir. Sadece yetkili sistemlerde kullanın. 









