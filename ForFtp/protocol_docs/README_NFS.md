# NFS — RPC ve Mountd Taraması

## Amaç ve Kullanım
NFS (Network File System), uzak sunucuların dosya sistemlerini paylaşmasını sağlar.  
Kullanım amaçları:
- RPC servislerini keşfetmek
- NFS versiyonlarını ve mountd portunu öğrenmek
- Paylaşılan dizinleri (exports) ve erişim izinlerini kontrol etmek
- Güvenlik testleri ve penetrasyon testleri

NFS genellikle TCP/111 (rpcbind/portmapper) ve mountd portları üzerinden çalışır.

---

## Temel İşleyiş
- Hedefe TCP/111 üzerinden rpcbind bağlantısı yapılır.
- rpcbind DUMP prosedürü ile sistemdeki RPC servisleri listelenir.
- NFS programları ve sürümleri belirlenir.
- Mountd portu bulunur ve EXPORTS sorgusu yapılır.
- Anonymous erişim (AUTH_NULL) kontrol edilir.
- Hedefteki paylaşılan dizinler, gruplar ve erişim durumu `NFSResult` yapısında saklanır.

---

## Modülün İşleyişi

### 1. Temel Tarama (ScanNFS)
- `isPortOpen` ile rpcbind servisi kontrol edilir.
- TCP bağlantısı kurulursa `rpcbindDump` çağrılır:
  - Tüm RPC program ve port eşlemeleri alınır
  - NFS programları filtrelenir
- NFS sürümleri özetlenir (`v2, v3, v4` gibi)
- Mountd portu belirlenir ve `fetchExports` ile paylaşılan dizinler toplanır.
- Sonuç `NFSResult` olarak döner.

### 2. RPC / XDR Fonksiyonları
- `rpcCall` struct: RPC çağrı parametreleri
- `buildRPCCall`: RPC çağrısı oluşturur ve TCP record marking uygular
- `readRPCReply`: RPC cevabını parçalı olarak okur
- `xdrReader`: XDR verilerini parse eder (`u32`, `bool`, `opaque`, `str`)

### 3. Paylaşılan Dizinler (EXPORTS)
- `fetchExports` ile mountd EXPORT prosedürü çağrılır
- Linked list formatında dizin ve grup bilgisi okunur
- Anonymous erişim kontrolü yapılır

### 4. Sonuçların Görselleştirilmesi
- Başarılı tarama sonucu formatlı olarak ekrana yazdırılır:
  - Hedef IP / Host
  - rpcbind durumu
  - NFS sürümleri
  - Mountd portu
  - Paylaşılan dizin sayısı ve isimleri
  - Hangi gruplar erişebilir
  - Anonymous erişim durumu
- Hatalar `ErrorMessage` alanında saklanır ve kırmızı renkle gösterilir.

---

## Kontroller ve Güvenlik Denetimleri
- ✅ rpcbind portu ve servisi kontrolü (111/tcp)
- ✅ NFS versiyonlarının tespiti
- ✅ Mountd portunun bulunması
- ✅ Exported dizinlerin listelenmesi
- ✅ Anonymous erişim kontrolü (AUTH_NULL)
- ✅ Hata ve timeout yönetimi