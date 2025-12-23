package ldapscan

import (
	"SOREERS/utils"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type LDAPResult struct {
	Target          string
	Port            int
	IsLDAPS         bool // 636 Portu mu?
	SupportStartTLS bool // 389 üzerinde TLS desteği var mı?
	AnonymousBind   bool // Anonim giriş açık mı?
	NamingContexts  []string
	SupportedSASL   []string
	Version         string
	Vendor          string
	Error           string
}

type BruteResult struct {
	Username string
	Password string
	Success  bool
}

func (r LDAPResult) String() string {
	if r.Error != "" {
		return fmt.Sprintf("%s %s %s",
			utils.Colorize("✗", utils.ColorRed),
			utils.BoldText("LDAP Hata:"),
			utils.Colorize(r.Error, utils.ColorRed))
	}

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(utils.BoldText(utils.Colorize("╔════════════════ LDAP TARAMA SONUCU ════════════════╗\n", utils.ColorBlue)))
	b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "Target", fmt.Sprintf("%s:%d", r.Target, r.Port)))

	// Versiyon ve Vendor
	if r.Vendor != "" {
		b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "Vendor", utils.Colorize(r.Vendor, utils.ColorCyan)))
	}
	if r.Version != "" {
		b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "LDAP Version", utils.Colorize(r.Version, utils.ColorCyan)))
	}

	// Şifreleme Durumu
	tlsStatus := utils.Colorize("Yok (Düz Metin)", utils.ColorRed)
	if r.IsLDAPS {
		tlsStatus = utils.Colorize("LDAPS (SSL - Port 636)", utils.ColorGreen)
	} else if r.SupportStartTLS {
		tlsStatus = utils.Colorize("StartTLS Destekliyor", utils.ColorGreen)
	}
	b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "Encryption", tlsStatus))

	// Anonymous Bind (Zafiyet)
	anonStatus := utils.Colorize("Kapalı (Güvenli)", utils.ColorGreen)
	if r.AnonymousBind {
		anonStatus = utils.Colorize("AÇIK (Bilgi Sızıntısı!)", utils.ColorRed)
	}
	b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "Anonymous Bind", anonStatus))

	// Contexts (Domain Bilgisi)
	if len(r.NamingContexts) > 0 {
		b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "Naming Contexts", strings.Join(r.NamingContexts, ", ")))
	}

	// SASL Mekanizmaları
	if len(r.SupportedSASL) > 0 {
		b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "Supported SASL", strings.Join(r.SupportedSASL, ", ")))
	}

	b.WriteString(utils.BoldText(utils.Colorize("╚════════════════════════════════════════════════════╝\n", utils.ColorBlue)))
	return b.String()
}

// ScanLDAP: Hem 389 (StartTLS) hem de 636 (LDAPS) kontrolü yapar
func ScanLDAP(target string, timeout time.Duration) LDAPResult {
	// 1. Önce Port 389'u (Standart) Dene
	res389 := tryConnectAndScan(target, 389, false, timeout)
	if res389.Error == "" {
		return res389
	}

	// 2. Eğer 389 başarısızsa, Port 636'yı (LDAPS) Dene
	// Bu otomatik geçiş özelliğidir.
	res636 := tryConnectAndScan(target, 636, true, timeout)
	if res636.Error == "" {
		return res636
	}

	// İkisi de başarısızsa 389'un hatasını döndür
	return LDAPResult{Target: target, Port: 389, Error: "Bağlantı kurulamadı (389 ve 636 denendi)"}
}

func tryConnectAndScan(target string, port int, useLDAPS bool, timeout time.Duration) LDAPResult {
	res := LDAPResult{Target: target, Port: port, IsLDAPS: useLDAPS}

	// HATALI SATIR SİLİNDİ (addr := ...)

	var conn *ldap.Conn
	var err error

	dialer := &net.Dialer{Timeout: timeout}

	// Bağlantı Kurma
	if useLDAPS {
		// LDAPS (SSL) Bağlantısı - Port 636
		tlsConf := &tls.Config{InsecureSkipVerify: true}
		// URL burada oluşturuluyor, addr değişkenine gerek yok
		conn, err = ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", target, port), ldap.DialWithTLSConfig(tlsConf))
	} else {
		// Standart Bağlantı - Port 389
		conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s:%d", target, port), ldap.DialWithDialer(dialer))
	}

	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()
	conn.SetTimeout(timeout)

	// StartTLS Kontrolü (Sadece Port 389 ise ve LDAPS değilse)
	if !useLDAPS {
		err = conn.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err == nil {
			res.SupportStartTLS = true
		}
	}

	// Anonymous Bind Kontrolü
	if err := conn.UnauthenticatedBind(""); err == nil {
		res.AnonymousBind = true
	}

	// RootDSE Bilgilerini Çek (Metadata)
	searchReq := ldap.NewSearchRequest(
		"", // RootDSE
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, int(timeout/time.Second), false,
		"(objectClass=*)",
		[]string{
			"namingContexts",
			"supportedSASLMechanisms",
			"vendorName",
			"vendorVersion",
			"supportedLDAPVersion",
		},
		nil,
	)

	searchRes, err := conn.Search(searchReq)
	if err == nil && len(searchRes.Entries) > 0 {
		entry := searchRes.Entries[0]
		res.NamingContexts = entry.GetAttributeValues("namingContexts")
		res.SupportedSASL = entry.GetAttributeValues("supportedSASLMechanisms")
		res.Version = strings.Join(entry.GetAttributeValues("supportedLDAPVersion"), ",")
		res.Vendor = strings.Join(entry.GetAttributeValues("vendorName"), ",")
		if len(entry.GetAttributeValues("vendorVersion")) > 0 {
			res.Vendor += " " + strings.Join(entry.GetAttributeValues("vendorVersion"), ",")
		}
	} else {
		if !res.AnonymousBind {
			res.Error = "RootDSE okunamadı ve Anonymous Bind kapalı"
		}
	}

	return res
}

// BruteForceLDAP: Eşzamanlı (Concurrent) Saldırı
func BruteForceLDAP(target string, users, passwords []string, timeout time.Duration, concurrency int) []BruteResult {
	var results []BruteResult
	var mutex sync.Mutex

	// Varsayılan olarak 389 üzerinden deniyoruz.
	// AD ortamlarında genelde "DOMAIN\user" veya "user@domain.com" formatı gerekir.
	// OpenLDAP'ta ise tam DN gerekir: "cn=admin,dc=example,dc=com"
	// Bu tarayıcı basit kullanıcı adı denemesi yapar, gerekirse DN formatı kullanıcı listesine eklenmelidir.
	port := 389

	jobs := make(chan BruteResult, len(users)*len(passwords))
	resultsChan := make(chan BruteResult)
	var wg sync.WaitGroup

	// Worker Pool
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if tryLDAPLogin(target, port, job.Username, job.Password, timeout) {
					resultsChan <- BruteResult{Username: job.Username, Password: job.Password, Success: true}
				}
			}
		}()
	}

	// Sonuç Toplayıcı
	go func() {
		for res := range resultsChan {
			mutex.Lock()
			results = append(results, res)
			mutex.Unlock()
		}
	}()

	// İş Dağıtıcı
	for _, user := range users {
		for _, pass := range passwords {
			jobs <- BruteResult{Username: user, Password: pass}
		}
	}
	close(jobs)
	wg.Wait()
	close(resultsChan)

	time.Sleep(100 * time.Millisecond)
	return results
}

func tryLDAPLogin(target string, port int, user, pass string, timeout time.Duration) bool {
	url := fmt.Sprintf("ldap://%s:%d", target, port)
	dialer := &net.Dialer{Timeout: timeout}

	conn, err := ldap.DialURL(url, ldap.DialWithDialer(dialer))
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetTimeout(timeout)

	// Basit Bind Denemesi
	err = conn.Bind(user, pass)
	return err == nil
}
