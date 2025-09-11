# SNMP (Simple Network Management Protocol) Rehberi

## 1️ SNMP Nedir?

SNMP (Simple Network Management Protocol), ağ cihazlarını (switch, router, server, yazıcı vb.) yönetmek ve izlemek için kullanılan bir protokoldür.  

**Temel amacı:** cihazlardan bilgi toplamak ve cihazları uzaktan yönetebilmektir.

- **Yönetici (Manager):** SNMP ile bilgi alan sistem veya uygulama.  
- **Ajan (Agent):** Cihazın üzerinde SNMP servisi çalışan, verileri sağlayan program.  
- **MIB (Management Information Base):** SNMP üzerinden erişilebilecek verilerin tanımlı olduğu veri tabanı.

---

## 2️ SNMP Sürümleri

### SNMPv1
- İlk sürüm, temel GET/SET işlemleri.  
- Güvenlik zayıf: sadece **community string** (parola benzeri) ile doğrulama yapar.  

### SNMPv2c
- v1’den geliştirilmiş; daha hızlı ve daha fazla veri tipini destekler.  
- Yine **community string** ile güvenlik sağlanır (kriptosuz).  

### SNMPv3
- Güvenlik odaklı sürüm.  
- **Authentication (kimlik doğrulama)** ve **Encryption (şifreleme)** destekler.  
- En güvenli sürüm olarak önerilir.

---

## 3️ OID (Object Identifier) Nedir?

- SNMP’de her veri **OID** ile tanımlanır.  
- OID, hiyerarşik bir sayı dizisidir (örn: `1.3.6.1.2.1.1.3.0`)  

**Örnek anlamlar:**

- `1.3.6.1.2.1.1.3.0` → **sysUpTime** (sistem açıldıktan sonra geçen süre)  
- `1.3.6.1.2.1.1.5.0` → **sysName** (cihazın ismi)  

**Hiyerarşi:**
iso(1)
└─ org(3)
└─ dod(6)
└─ internet(1)
└─ mgmt(2)
└─ mib-2(1)
└─ system(1)
├─ sysDescr(1)
├─ sysUpTime(3)
└─ sysName(5)
---

## 4️ MID (Management Information Base ID)

- Genellikle **OID ve MIB** birbirine bağlıdır.  
- MID terimi çok sık kullanılmaz, ama bazı araçlarda **MIB’deki belirli nesnenin ID’si** anlamına gelir.  
- Özetle: **OID = veriye erişim adresi, MID = MIB içindeki nesne tanımlayıcısı**.

---

## 5️ SNMP Çalışma Mantığı

- **GET:** Yönetici (manager) ajandan veri ister.  
  - Örn: sysUpTime’ı öğrenmek için GET isteği gönderir.  
- **SET:** Yönetici ajandaki bir değeri değiştirir.  
  - Örn: bir cihazın isim bilgisini değiştirmek.  
- **TRAP:** Ajan, yöneticiyi **olay olduğunda bilgilendirir**.  
  - Örn: port down, CPU aşırı yüklenmesi.  
- **Inform:** TRAP’a benzer ama yöneticiden onay alınır.

**Protokol Detayları:**
- SNMP **UDP üzerinden çalışır**.  
  - **Port 161:** SNMP agent için  
  - **Port 162:** TRAP mesajları için

---

## 6️ sysUpTime Nedir?

- **sysUpTime**, cihazın **en son açıldığı veya yeniden başlatıldığı zamandan itibaren geçen süreyi** gösterir.  
- Genellikle **saniye cinsinden** (veya SNMP “TimeTicks” formatında) olur.  
- Örn: Eğer `sysUpTime = 1234567` → cihaz açıldıktan sonra yaklaşık 1.2 milyon TimeTicks geçmiş.

---

## 7️ SNMP Öğrenmeye Başlamak İçin Öneriler

- **Pratik yap:** GNS3, Cisco Packet Tracer veya sanal lab ile SNMP GET/SET deneyin.  
- **Araçlar:**  
  - Linux: `snmpwalk`, `snmpget`, `snmpbulkwalk`  
  - Windows: Paessler SNMP Tester  
- **MIB’leri incele:** Hangi OID hangi veriyi döndürüyor öğrenin.  

###  Örnek SNMP GET Komutu (Linux):
```bash
snmpget -v2c -c public 192.168.1.1 1.3.6.1.2.1.1.3.0

-v2c → SNMP sürümü

-c public → community string

192.168.1.1 → cihaz IP

1.3.6.1.2.1.1.3.0 → sysUpTime OID


---

