package imap

import (
	"SOREERS/utils"
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

type IMAPResult struct {
	Target            string
	Port              int
	Banner            string
	InfoLeak          bool
	STARTTLS          bool
	PlaintextAuth     bool
	AnonymousLogin    bool // YENİ: Anonim giriş var mı?
	PlaintextAuthResp string
}

type BruteResult struct {
	Username string
	Password string
	Success  bool
}

func (r *IMAPResult) String() string {
	if r.Banner == "" && !r.STARTTLS && !r.PlaintextAuth {
		return fmt.Sprintf("%s %s %s",
			utils.Colorize("✗", utils.ColorRed),
			utils.BoldText("IMAP Hata:"),
			utils.Colorize(fmt.Sprintf("Bağlantı kurulamadı: %s:%d", r.Target, r.Port), utils.ColorRed))
	}

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(utils.BoldText(utils.Colorize("╔════════════════ IMAP TARAMA SONUCU ════════════════╗\n", utils.ColorBlue)))
	b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "Target", fmt.Sprintf("%s:%d", r.Target, r.Port)))

	if r.Banner != "" {
		bannerClean := r.Banner
		if len(bannerClean) > 40 {
			bannerClean = bannerClean[:37] + "..."
		}
		b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "Banner", utils.Colorize(bannerClean, utils.ColorWhite)))
	}

	infoLeakStatus := utils.Colorize("Yok", utils.ColorGreen)
	if r.InfoLeak {
		infoLeakStatus = utils.Colorize("VAR (Bilgi Sızıntısı)", utils.ColorYellow)
	}
	b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "Info Leak", infoLeakStatus))

	tlsStatus := utils.Colorize("Desteklenmiyor", utils.ColorYellow)
	if r.STARTTLS {
		tlsStatus = utils.Colorize("Destekleniyor", utils.ColorGreen)
	}
	b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "STARTTLS", tlsStatus))

	// Plaintext Auth
	plainStatus := utils.Colorize("Güvenli (İzin Verilmiyor)", utils.ColorGreen)
	if r.PlaintextAuth {
		plainStatus = utils.Colorize("RİSKLİ (Şifresiz Giriş Açık)", utils.ColorRed)
	}
	b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "Plaintext Login", plainStatus))

	// Anonymous Auth (YENİ)
	anonStatus := utils.Colorize("Kapalı (Güvenli)", utils.ColorGreen)
	if r.AnonymousLogin {
		anonStatus = utils.Colorize("AÇIK (Zafiyet!)", utils.ColorRed)
	}
	b.WriteString(fmt.Sprintf("║ %-18s : %s\n", "Anonymous Login", anonStatus))

	b.WriteString(utils.BoldText(utils.Colorize("╚════════════════════════════════════════════════════╝\n", utils.ColorBlue)))
	return b.String()
}

// RunIMAP: Tarama işlemini başlatır
func RunIMAP(target string, timeoutSec int) []*IMAPResult {
	timeout := time.Duration(timeoutSec) * time.Second
	imapPorts := []int{143, 993}
	var results []*IMAPResult

	for _, port := range imapPorts {
		res := &IMAPResult{Target: target, Port: port}

		// 1. Temel Taramalar
		banner, starttls, plaintext, plaintextResp, err := scanPort(target, port, timeout)
		if err != nil {
			results = append(results, res)
			continue
		}

		res.Banner = banner
		res.InfoLeak = hasInfoLeak(banner)
		res.STARTTLS = starttls
		res.PlaintextAuth = plaintext
		res.PlaintextAuthResp = plaintextResp

		// 2. Anonim Giriş Testi (YENİ)
		// Eğer port 143 ise ve plaintext kapalı değilse deneriz.
		// Port 993 ise zaten şifreli kanaldan deneriz.
		if checkIMAPAnonymous(target, port, timeout) {
			res.AnonymousLogin = true
		}

		results = append(results, res)
	}

	return results
}

// checkIMAPAnonymous: Standart anonymous/anonymous girişini dener
func checkIMAPAnonymous(target string, port int, timeout time.Duration) bool {
	return tryIMAPLogin(target, port, "anonymous", "anonymous", timeout)
}

// BruteForceIMAP: Kullanıcı adı ve şifre listesini dener
func BruteForceIMAP(target string, users, passwords []string, timeout time.Duration, concurrency int) []BruteResult {
	var results []BruteResult
	var mutex sync.Mutex

	// Varsayılan olarak 143 portunu dener
	port := 143

	jobs := make(chan BruteResult, len(users)*len(passwords))
	resultsChan := make(chan BruteResult)
	var wg sync.WaitGroup

	// Worker Pool Başlat
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				success := tryIMAPLogin(target, port, job.Username, job.Password, timeout)
				if success {
					resultsChan <- BruteResult{Username: job.Username, Password: job.Password, Success: true}
				}
			}
		}()
	}

	// Sonuçları Toplayıcı
	go func() {
		for res := range resultsChan {
			mutex.Lock()
			results = append(results, res)
			mutex.Unlock()
		}
	}()

	// İşleri Dağıt
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

// tryIMAPLogin: Tekil giriş denemesi (SSL/Plain ayrımı yaparak)
func tryIMAPLogin(target string, port int, user, pass string, timeout time.Duration) bool {
	// Port 993 ise SSL bağlantısı kurmalıyız
	if port == 993 {
		dialer := &net.Dialer{Timeout: timeout}
		tlsConf := &tls.Config{InsecureSkipVerify: true}
		conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", target, port), tlsConf)
		if err != nil {
			return false
		}
		defer conn.Close()
		return executeLoginCommand(conn, user, pass)
	}

	// Port 143 ise normal bağlantı
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return executeLoginCommand(conn, user, pass)
}

// executeLoginCommand: IMAP komutlarını gönderir ve yanıtı okur
func executeLoginCommand(conn net.Conn, user, pass string) bool {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := textproto.NewReader(bufio.NewReader(conn))
	writer := textproto.NewWriter(bufio.NewWriter(conn))

	// Banner'ı oku ve geç
	readGreeting(reader)

	// Giriş Komutu: A001 LOGIN "user" "pass"
	cmd := fmt.Sprintf("A001 LOGIN %q %q", user, pass)
	err := writer.PrintfLine(cmd)
	if err != nil {
		return false
	}

	// Yanıtı bekle
	for i := 0; i < 5; i++ {
		line, err := reader.ReadLine()
		if err != nil {
			return false
		}

		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "A001 OK") {
			return true // Başarılı
		}
		if strings.HasPrefix(upper, "A001 NO") || strings.HasPrefix(upper, "A001 BAD") {
			return false // Başarısız
		}
	}
	return false
}

// --- Yardımcı Fonksiyonlar (Öncekilerin Aynısı) ---

func scanPort(target string, port int, timeout time.Duration) (banner string, starttls bool, plaintextAllowed bool, plaintextResp string, err error) {
	if port == 993 {
		return scanIMAPTLS(target, port, timeout)
	}
	return scanIMAPPlain(target, port, timeout)
}

func scanIMAPPlain(target string, port int, timeout time.Duration) (banner string, starttls bool, plaintextAllowed bool, plaintextResp string, err error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", target, port))
	if err != nil {
		return "", false, false, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := textproto.NewReader(bufio.NewReader(conn))
	writer := textproto.NewWriter(bufio.NewWriter(conn))

	greetBanner, greetCaps := readGreeting(reader)
	banner = greetBanner

	caps2, starttlsSupported, logindisabled := fetchCapabilities(reader, writer, timeout)
	caps := mergeCaps(greetCaps, caps2)
	_ = caps
	starttls = starttlsSupported || hasToken(caps, "STARTTLS")

	if logindisabled || hasToken(caps, "LOGINDISABLED") {
		plaintextAllowed = false
		return
	}

	if hasLoginCapability(caps) {
		tag := "B001"
		_ = writer.PrintfLine("%s LOGIN test test", tag)
		_ = writer.W.Flush()
		var respLines []string
		for {
			line, rerr := reader.ReadLine()
			if rerr != nil {
				break
			}
			respLines = append(respLines, line)
			if strings.HasPrefix(line, tag+" OK") || strings.HasPrefix(line, tag+" NO") || strings.HasPrefix(line, tag+" BAD") {
				break
			}
		}
		plaintextResp = strings.TrimSpace(strings.Join(respLines, "\n"))

		upperResp := strings.ToUpper(plaintextResp)
		if strings.Contains(upperResp, "TLS") || strings.Contains(upperResp, "ENCRYPT") || strings.Contains(upperResp, "STARTTLS") || strings.Contains(upperResp, "LOGINDISABLED") {
			plaintextAllowed = false
		} else {
			plaintextAllowed = true
		}
	} else {
		plaintextAllowed = false
	}
	return
}

func scanIMAPTLS(target string, port int, timeout time.Duration) (banner string, starttls bool, plaintextAllowed bool, plaintextResp string, err error) {
	dialer := &net.Dialer{Timeout: timeout}
	tlsConf := &tls.Config{InsecureSkipVerify: true, ServerName: target}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", target, port), tlsConf)
	if err != nil {
		return "", false, false, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := textproto.NewReader(bufio.NewReader(conn))
	writer := textproto.NewWriter(bufio.NewWriter(conn))

	greetBanner, greetCaps := readGreeting(reader)
	banner = greetBanner

	caps2, starttlsSupported, _ := fetchCapabilities(reader, writer, timeout)
	caps := mergeCaps(greetCaps, caps2)
	starttls = starttlsSupported || hasToken(caps, "STARTTLS")
	plaintextAllowed = false
	plaintextResp = ""
	return
}

func readGreeting(reader *textproto.Reader) (banner string, caps []string) {
	var first string
	var found bool
	var foundCaps []string
	for i := 0; i < 20; i++ {
		line, err := reader.ReadLine()
		if err != nil {
			break
		}
		if !found {
			first = strings.TrimSpace(line)
			found = true
		}
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "* OK") || strings.HasPrefix(upper, "* PREAUTH") || strings.HasPrefix(upper, "* BYE") {
			lcap := parseBracketCapabilities(line)
			if len(lcap) > 0 {
				foundCaps = append(foundCaps, lcap...)
			}
			break
		}
	}
	return first, normalizeCaps(foundCaps)
}

func parseBracketCapabilities(line string) []string {
	upper := strings.ToUpper(line)
	start := strings.Index(upper, "[CAPABILITY ")
	if start < 0 {
		return nil
	}
	start += len("[CAPABILITY ")
	end := strings.Index(upper[start:], "]")
	if end < 0 {
		return nil
	}
	segment := line[start : start+end]
	tokens := strings.Fields(segment)
	return normalizeCaps(tokens)
}

func fetchCapabilities(reader *textproto.Reader, writer *textproto.Writer, timeout time.Duration) (capabilities []string, hasStartTLS bool, hasLoginDisabled bool) {
	tag := "A001"
	_ = writer.PrintfLine("%s CAPABILITY", tag)
	_ = writer.W.Flush()
	var caps []string
	for i := 0; i < 200; i++ {
		line, err := reader.ReadLine()
		if err != nil {
			break
		}
		upper := strings.ToUpper(line)
		if strings.HasPrefix(line, "*") && strings.Contains(upper, "CAPABILITY") {
			idx := strings.Index(upper, "CAPABILITY")
			if idx >= 0 {
				fields := strings.Fields(line[idx+len("CAPABILITY"):])
				for _, f := range fields {
					caps = append(caps, strings.TrimSpace(f))
				}
			}
			continue
		}
		if strings.HasPrefix(line, tag+" OK") || strings.HasPrefix(line, tag+" BAD") || strings.HasPrefix(line, tag+" NO") {
			break
		}
	}

	upperCaps := normalizeCaps(caps)
	capabilities = upperCaps
	for _, c := range upperCaps {
		if c == "STARTTLS" {
			hasStartTLS = true
		}
		if c == "LOGINDISABLED" {
			hasLoginDisabled = true
		}
	}
	return
}

func hasLoginCapability(capabilities []string) bool {
	for _, c := range capabilities {
		if c == "LOGIN" || strings.HasPrefix(c, "AUTH=") || strings.Contains(c, "LOGIN") || strings.Contains(c, "PLAIN") {
			return true
		}
	}
	return false
}

func hasInfoLeak(banner string) bool {
	b := strings.ToLower(banner)
	if b == "" {
		return false
	}
	leakers := []string{"dovecot", "cyrus", "courier", "uw-imap", "exchange", "gmail", "cisco", "citadel", "hmailserver", "imap"}
	for _, k := range leakers {
		if strings.Contains(b, k) {
			return true
		}
	}
	return false
}

func normalizeCaps(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, t := range in {
		u := strings.ToUpper(strings.TrimSpace(t))
		if u == "" {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	return out
}

func mergeCaps(a, b []string) []string {
	if len(a) == 0 {
		return normalizeCaps(b)
	}
	if len(b) == 0 {
		return normalizeCaps(a)
	}
	return normalizeCaps(append(append([]string{}, a...), b...))
}

func hasToken(caps []string, token string) bool {
	if len(caps) == 0 {
		return false
	}
	t := strings.ToUpper(token)
	for _, c := range caps {
		if c == t {
			return true
		}
	}
	return false
}
