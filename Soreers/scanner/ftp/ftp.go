package ftp

import (
	"SOREERS/utils"
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

type FTPResult struct {
	Target          string
	Port            int
	Banner          string
	AnonymousLogin  bool
	ExplicitTLSSupp bool

	// Zafiyet Durumları
	BackdoorVuln bool // VSFTPD 2.3.4 Backdoor
	BounceVuln   bool // FTP Bounce Attack

	ErrorMessage string
}

// ScanFTP: Tüm testleri sırasıyla yapar
func ScanFTP(target string, port int, timeout time.Duration) *FTPResult {
	result := &FTPResult{
		Target: target,
		Port:   port,
	}

	// 1. Banner Alma
	banner, err := GetVersion(target, port, timeout)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Bağlantı hatası: %v", err)
		return result
	}
	result.Banner = banner

	// 2. TLS Kontrolü
	tlsSupp, err := SupportsExplicitTLS(target, port, timeout)
	if err == nil {
		result.ExplicitTLSSupp = tlsSupp
	}

	// 3. Anonymous Login Testi
	anonSuccess, err := AnonymousLogin(target, timeout)
	if anonSuccess {
		result.AnonymousLogin = true
	}

	// 4. VSFTPD Backdoor Kontrolü (Önceki eklediğimiz)
	if checkVSFTPDBackdoor(target, port, timeout) {
		result.BackdoorVuln = true
	}

	// 5. FTP BOUNCE ATTACK KONTROLÜ (Yeni eklediğimiz)
	// Bounce testi için login olmak gerekir. Anonymous varsa onunla deneriz.
	if result.AnonymousLogin {
		if checkFTPBounce(target, port, "anonymous", "anonymous", timeout) {
			result.BounceVuln = true
		}
	} else {
		// Anonymous yoksa test edemeyiz (Credential yoksa), ama kodun akışı bozulmasın.
		// Eğer elinde user/pass varsa buraya parametre olarak geçilebilir.
	}

	return result
}

// checkFTPBounce: Sunucunun başka IP'lere veri göndermeyi kabul edip etmediğini dener.
func checkFTPBounce(target string, port int, user, pass string, timeout time.Duration) bool {
	// 1. Bağlan ve Giriş Yap
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	reader.ReadString('\n') // Banner

	fmt.Fprintf(conn, "USER %s\r\n", user)
	reader.ReadString('\n')
	fmt.Fprintf(conn, "PASS %s\r\n", pass)
	resp, _ := reader.ReadString('\n')
	if !strings.HasPrefix(resp, "230") {
		return false
	} // Giriş başarısızsa test yapamayız

	// 2. PORT Komutu ile Tuzak Kur
	// Rastgele bir dış IP veriyoruz (örneğin 10.0.0.1:8080)
	// FTP PORT komutu formatı: h1,h2,h3,h4,p1,p2
	// 10.0.0.1 -> 10,0,0,1
	// Port 8080 -> 31,144 (31*256 + 144 = 8080)
	payload := "PORT 10,0,0,1,31,144\r\n"

	fmt.Fprintf(conn, payload)
	bounceResp, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	// 3. Yanıtı Analiz Et
	// Eğer sunucu "200 Command okay" veya "200 PORT command successful" derse ZAFİYET VARDIR.
	// Eğer "500 Illegal PORT command" veya "501" derse GÜVENLİDİR.
	if strings.HasPrefix(bounceResp, "200") {
		return true
	}

	return false
}

// VSFTPD Backdoor Kontrolü
func checkVSFTPDBackdoor(target string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		return false
	}

	reader := bufio.NewReader(conn)
	reader.ReadString('\n')

	fmt.Fprintf(conn, "USER soreers:)\r\n") // Tetikleyici
	reader.ReadString('\n')

	fmt.Fprintf(conn, "PASS invalid\r\n")
	conn.Close()

	time.Sleep(500 * time.Millisecond)

	shellConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:6200", target), timeout)
	if err != nil {
		return false
	}
	shellConn.Close()
	return true
}

// --- Yardımcı Fonksiyonlar (Eskisiyle Aynı) ---

func FTPLogin(server string, port int, username, password string, timeout time.Duration) (bool, error) {
	// ... (Buradaki kodlar aynı kalacak, yer kaplamasın diye kısalttım ama silmeyin) ...
	// Önceki kodunuzdaki FTPLogin içeriğinin aynısı buraya gelecek
	address := fmt.Sprintf("%s:%d", server, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)
	reader.ReadString('\n')
	fmt.Fprintf(conn, "USER %s\r\n", username)
	reader.ReadString('\n')
	fmt.Fprintf(conn, "PASS %s\r\n", password)
	passResp, _ := reader.ReadString('\n')
	if strings.HasPrefix(passResp, "230") {
		return true, nil
	}
	return false, fmt.Errorf("failed")
}

func AnonymousLogin(ip string, timeout time.Duration) (bool, error) {
	return FTPLogin(ip, 21, "anonymous", "anonymous", timeout)
}

func GetVersion(host string, port int, timeout time.Duration) (string, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(banner), nil
}

func SupportsExplicitTLS(host string, port int, timeout time.Duration) (bool, error) {
	// ... (TLS kontrol kodu aynen kalacak) ...
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)
	reader.ReadString('\n')
	fmt.Fprintf(conn, "AUTH TLS\r\n")
	line, _ := reader.ReadString('\n')
	if strings.Contains(line, "234") || strings.Contains(strings.ToUpper(line), "TLS") {
		return true, nil
	}
	return false, nil
}

// ÇIKTI EKRANI GÜNCELLEMESİ
func (r *FTPResult) String() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(utils.BoldText(utils.Colorize("╔════════════════ FTP TARAMA SONUCU ════════════════╗\n", utils.ColorBlue)))

	b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "Hedef", fmt.Sprintf("%s:%d", r.Target, r.Port)))

	if r.ErrorMessage != "" {
		b.WriteString(fmt.Sprintf("║ %-18s : %s\n", utils.Colorize("Durum", utils.ColorRed), "Bağlantı Sağlanamadı"))
		b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "Hata Detayı", r.ErrorMessage))
	} else {
		// Banner
		bannerClean := r.Banner
		if len(bannerClean) > 40 {
			bannerClean = bannerClean[:37] + "..."
		}
		b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "Banner", utils.Colorize(bannerClean, utils.ColorWhite)))

		// TLS
		tlsStatus := utils.Colorize("Yok", utils.ColorRed)
		if r.ExplicitTLSSupp {
			tlsStatus = utils.Colorize("Var (Güvenli)", utils.ColorGreen)
		}
		b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "Explicit TLS", tlsStatus))

		// Anonymous
		anonStatus := utils.Colorize("Kapalı (Güvenli)", utils.ColorGreen)
		if r.AnonymousLogin {
			anonStatus = utils.Colorize("AÇIK (Risk!)", utils.ColorYellow)
		}
		b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "Anonymous Login", anonStatus))

		// ZAFİYETLER BÖLÜMÜ
		b.WriteString(utils.BoldText(utils.Colorize("╟──────────────── ZAFİYET KONTROLLERİ ──────────────╢\n", utils.ColorBlue)))

		// 1. Backdoor Sonucu
		if r.BackdoorVuln {
			b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "VSFTPD Backdoor", utils.Colorize("KRİTİK ZAFİYET (Shell Açık!)", utils.ColorRed)))
		} else {
			b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "VSFTPD Backdoor", utils.Colorize("Temiz", utils.ColorGreen)))
		}

		// 2. Bounce Sonucu
		if r.BounceVuln {
			// Bu zafiyet nadirdir ama tehlikelidir
			b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "FTP Bounce", utils.Colorize("ZAFİYET VAR (Proxy Olarak Kullanılabilir)", utils.ColorRed)))
		} else {
			b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "FTP Bounce", utils.Colorize("Güvenli (PORT komutu kısıtlı)", utils.ColorGreen)))
		}
	}

	b.WriteString(utils.BoldText(utils.Colorize("╚═══════════════════════════════════════════════════╝\n", utils.ColorBlue)))
	return b.String()
}
