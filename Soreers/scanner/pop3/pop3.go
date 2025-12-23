package pop3scan

import (
	"SOREERS/utils"
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

type POP3Result struct {
	Target             string
	Port110Open        bool
	Port995Open        bool
	Banner             string
	InfoLeak           bool // banner’da ürün/sürüm var
	HasTimestampBanner bool // APOP ihtimali: banner’da <...>
	SupportsCAPA       bool
	SupportsSTLS       bool
	SupportsSASL       []string
	AllowsPlainAuth    bool   // TLS yokken USER/PASS akışına izin veriyor (engellemiyorsa true)
	PlaintextReason    string // sunucu mesajından kısa özet
	STARTTLSSuccess    bool
	STARTTLSTLSVersion string
	STARTTLSCipher     string
	POP3SSuccess       bool // 995’te TLS kuruldu mu
	POP3STLSVersion    string
	POP3SCipher        string
	WeakTLSProtocols   []string // TLS1.0/1.1 kabul ediliyorsa not edilir
	CertIssues         []string // self-signed, expired, hostname mismatch gibi
	ErrorMessage       string
}

func ScanPOP3(target string, timeout time.Duration) *POP3Result {
	r := &POP3Result{Target: target}

	// --- Port 110: düz POP3
	conn110, err := net.DialTimeout("tcp", net.JoinHostPort(target, "110"), timeout)
	if err == nil {
		r.Port110Open = true
		defer conn110.Close()
		_ = conn110.SetDeadline(time.Now().Add(timeout))
		br := bufio.NewReader(conn110)

		// Banner
		banner, _ := br.ReadString('\n')
		r.Banner = strings.TrimSpace(banner)
		r.InfoLeak = leaksVersion(r.Banner)
		r.HasTimestampBanner = hasAPOPTimestamp(r.Banner)

		// CAPA
		writeLine(conn110, "CAPA")
		capaLines, capaOK := readMultiline(br)
		r.SupportsCAPA = capaOK
		if capaOK {
			for _, ln := range capaLines {
				if strings.EqualFold(strings.TrimSpace(ln), "STLS") {
					r.SupportsSTLS = true
				}
				if strings.HasPrefix(strings.ToUpper(ln), "SASL ") {
					mechs := strings.Fields(ln)[1:]
					r.SupportsSASL = append(r.SupportsSASL, mechs...)
				}
			}
		}

		// Plaintext auth davranışı (TLS yokken)
		// Amaç: Sunucu "TLS zorunlu" diye reddediyor mu? (İyi)
		// Yoksa normal akışa girip PASS'e kadar ilerliyor mu? (Kötü)
		// Burada gerçek kullanıcı parolası KULLANMIYORUZ; yalnızca politika kontrolü.
		r.AllowsPlainAuth, r.PlaintextReason = probePlainAuthPolicy(conn110, br, timeout)
	} else {
		// 110 kapalıysa devam (hata değil)
	}

	// --- Port 110 STARTTLS testi
	if r.Port110Open && r.SupportsSTLS {
		tok, vers, cipher := trySTARTTLS(target, timeout)
		r.STARTTLSSuccess = tok
		r.STARTTLSTLSVersion = vers
		r.STARTTLSCipher = cipher
		// Zayıf protokolleri ayrıca deneriz (110 üstünde STARTTLS el sıkışmasıyla)
		weak := probeWeakTLSOverConn(target, "110", timeout, true)
		r.WeakTLSProtocols = appendUnique(r.WeakTLSProtocols, weak...)
	}

	// --- Port 995: POP3S
	if ok, vers, cipher, certIssues := tryPOP3S(target, timeout); ok {
		r.Port995Open = true
		r.POP3SSuccess = true
		r.POP3STLSVersion = vers
		r.POP3SCipher = cipher
		r.CertIssues = appendUnique(r.CertIssues, certIssues...)
		weak := probeWeakTLSOverConn(target, "995", timeout, false)
		r.WeakTLSProtocols = appendUnique(r.WeakTLSProtocols, weak...)
	} else {
		// 995 kapalı olabilir; sorun değil.
	}

	return r
}

// ---- Helpers

func leaksVersion(banner string) bool {
	b := strings.ToLower(banner)
	// Sık görülen sunucu imzaları
	signs := []string{"dovecot", "cyrus", "qpopper", "courier", "uw-imap", "teapop", "mailenable", "qualcomm", "kerio"}
	for _, s := range signs {
		if strings.Contains(b, s) {
			return true
		}
	}
	// sürüm numarası gibi görünen bir parça
	return strings.ContainsAny(b, "0123456789") && strings.Contains(b, "/")
}

func hasAPOPTimestamp(banner string) bool {
	// RFC’ye göre APOP için genelde <1896.697170952@cs.berkeley.edu> gibi bir damga verilir
	b := strings.TrimSpace(banner)
	return strings.Contains(b, "<") && strings.Contains(b, ">")
}

func writeLine(c net.Conn, s string) error {
	_, err := c.Write([]byte(s + "\r\n"))
	return err
}

func readLine(br *bufio.Reader) (string, error) {
	ln, err := br.ReadString('\n')
	return strings.TrimRight(ln, "\r\n"), err
}

func readMultiline(br *bufio.Reader) ([]string, bool) {
	var lines []string
	ln, err := readLine(br)
	if err != nil {
		return nil, false
	}
	if !strings.HasPrefix(ln, "+OK") {
		return []string{ln}, false
	}
	for {
		l, err := readLine(br)
		if err != nil {
			return lines, false
		}
		if l == "." {
			break
		}
		lines = append(lines, l)
	}
	return lines, true
}

func probePlainAuthPolicy(conn net.Conn, br *bufio.Reader, timeout time.Duration) (bool, string) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// Bazı sunucular USER komutuna bile “cleartext disabled” döner.
	_ = writeLine(conn, "USER test")
	resp1, _ := readLine(br)
	_ = writeLine(conn, "PASS test")
	resp2, _ := readLine(br)

	// Örnek iyi mesajlar: "-ERR Plaintext authentication disabled", "-ERR TLS required"
	joined := (resp1 + " | " + resp2)
	low := strings.ToLower(joined)
	if strings.Contains(low, "tls required") ||
		strings.Contains(low, "plaintext") ||
		strings.Contains(low, "cleartext") ||
		strings.Contains(low, "must issue a starttls") {
		return false, strings.TrimSpace(joined)
	}
	// Eğer +OK ile oturum açarsa (çok nadir ve tehlikeli), yine plaintext izinlidir.
	if strings.HasPrefix(strings.ToUpper(resp2), "+OK") {
		return true, resp2
	}
	// Çoğu sunucu -ERR invalid user/pass döner → bu, politik olarak plaintext akışına izin verdiğini gösterir.
	if strings.HasPrefix(strings.ToUpper(resp1), "-ERR") || strings.HasPrefix(strings.ToUpper(resp2), "-ERR") {
		return true, strings.TrimSpace(joined)
	}
	return true, strings.TrimSpace(joined)
}

func trySTARTTLS(target string, timeout time.Duration) (bool, string, string) {
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(target, "110"), timeout)
	if err != nil {
		return false, "", ""
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))
	br := bufio.NewReader(raw)
	_, _ = br.ReadString('\n') // banner oku

	// STLS iste
	_ = writeLine(raw, "STLS")
	okLine, _ := readLine(br)
	if !strings.HasPrefix(strings.ToUpper(okLine), "+OK") {
		return false, "", ""
	}

	// TLS handshake başlat
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         target,
		InsecureSkipVerify: true,
	})
	if err := tlsConn.Handshake(); err != nil {
		return false, "", ""
	}

	// Handshake sonrası gerçekten şifreli kanaldan konuşabiliyor muyuz test et
	tlsBr := bufio.NewReader(tlsConn)
	if err := writeLine(tlsConn, "CAPA"); err != nil {
		return false, "", ""
	}
	line, _ := tlsBr.ReadString('\n')
	if !strings.HasPrefix(strings.ToUpper(line), "+OK") {
		// Cevap alamazsak problem olabilir
		return false, "", ""
	}

	state := tlsConn.ConnectionState()
	return true, tlsVersionStr(state.Version), cipherSuiteStr(state.CipherSuite)
}

func tryPOP3S(target string, timeout time.Duration) (bool, string, string, []string) {
	issues := []string{}
	conf := &tls.Config{
		ServerName:         target,
		InsecureSkipVerify: true, // sertifikayı ayrıca elle kontrol edeceğiz
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", net.JoinHostPort(target, "995"), conf)
	if err != nil {
		return false, "", "", issues
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	br := bufio.NewReader(conn)
	_, _ = br.ReadString('\n') // banner over TLS

	state := conn.ConnectionState()
	vers := tlsVersionStr(state.Version)
	ciph := cipherSuiteStr(state.CipherSuite)

	// Sertifika kontrolleri (expiry, chain, hostname)
	if len(state.PeerCertificates) > 0 {
		now := time.Now()
		leaf := state.PeerCertificates[0]
		if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			issues = append(issues, "certificate expired/not yet valid")
		}
		// Hostname match
		if err := leaf.VerifyHostname(target); err != nil {
			issues = append(issues, "hostname mismatch")
		}
		// Chain doğrulama
		opts := x509.VerifyOptions{DNSName: target, Roots: nil, Intermediates: x509.NewCertPool()}
		for i := 1; i < len(state.PeerCertificates); i++ {
			opts.Intermediates.AddCert(state.PeerCertificates[i])
		}
		if _, err := leaf.Verify(opts); err != nil {
			issues = append(issues, "untrusted/self-signed or chain error")
		}
	}
	return true, vers, ciph, issues
}

func probeWeakTLSOverConn(target, port string, timeout time.Duration, starttls bool) []string {
	var weak []string
	type probe struct {
		name    string
		version uint16
	}
	// TLS1.0 ve 1.1 kabul ediliyorsa zayıf say
	checks := []probe{
		{"TLS1.0", tls.VersionTLS10},
		{"TLS1.1", tls.VersionTLS11},
	}
	for _, c := range checks {
		ok := false
		if starttls {
			ok = tryStartTLSWithVersion(target, port, timeout, c.version)
		} else {
			ok = tryDirectTLSWithVersion(target, port, timeout, c.version)
		}
		if ok {
			weak = append(weak, c.name)
		}
	}
	return weak
}

func tryStartTLSWithVersion(target, port string, timeout time.Duration, ver uint16) bool {
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(target, port), timeout)
	if err != nil {
		return false
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))
	br := bufio.NewReader(raw)
	_, _ = br.ReadString('\n')
	_ = writeLine(raw, "STLS")
	ok, _ := readLine(br)
	if !strings.HasPrefix(strings.ToUpper(ok), "+OK") {
		return false
	}
	tlsConn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         ver,
		MaxVersion:         ver,
	})
	err = tlsConn.Handshake()
	return err == nil
}

func tryDirectTLSWithVersion(target, port string, timeout time.Duration, ver uint16) bool {
	conf := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         ver,
		MaxVersion:         ver,
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", net.JoinHostPort(target, port), conf)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func tlsVersionStr(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

func cipherSuiteStr(cs uint16) string {
	// Go isimlerini vermek zor; kimlik yeterli
	return fmt.Sprintf("0x%04x", cs)
}

func appendUnique[T comparable](in []T, vals ...T) []T {
	exists := map[T]struct{}{}
	for _, v := range in {
		exists[v] = struct{}{}
	}
	for _, v := range vals {
		if _, ok := exists[v]; !ok {
			in = append(in, v)
			exists[v] = struct{}{}
		}
	}
	return in
}

// ---- Pretty print

func (r *POP3Result) String() string {
	if r.ErrorMessage != "" {
		return fmt.Sprintf("%s %s %s",
			utils.Colorize("✗", utils.ColorRed),
			utils.BoldText("POP3 Hata:"),
			utils.Colorize(r.ErrorMessage, utils.ColorRed))
	}
	var b strings.Builder
	b.WriteString(utils.BoldText(utils.Colorize("╔══════════════════════════════════════════════╗\n", utils.ColorMagenta)))
	b.WriteString(fmt.Sprintf("%s %s\n", utils.Colorize("Target:", utils.ColorYellow), r.Target))
	b.WriteString(fmt.Sprintf("%s %v, %s %v\n", utils.Colorize("110 open:", utils.ColorYellow), r.Port110Open, utils.Colorize("995 open:", utils.ColorYellow), r.Port995Open))
	if r.Banner != "" {
		b.WriteString(fmt.Sprintf("%s %s\n", utils.Colorize("Banner:", utils.ColorYellow), utils.Colorize(r.Banner, utils.ColorWhite)))
	}
	if r.InfoLeak {
		b.WriteString(utils.Colorize("InfoLeak: banner exposes product/version\n", utils.ColorRed))
	}
	if r.HasTimestampBanner {
		b.WriteString(utils.Colorize("APOP hint: timestamp in banner\n", utils.ColorCyan))
	}
	b.WriteString(fmt.Sprintf("%s %v, %s %v, %s %v\n",
		utils.Colorize("CAPA:", utils.ColorYellow), r.SupportsCAPA,
		utils.Colorize("STLS:", utils.ColorYellow), r.SupportsSTLS,
		utils.Colorize("SASL:", utils.ColorYellow), strings.Join(r.SupportsSASL, ",")))
	b.WriteString(fmt.Sprintf("%s %v", utils.Colorize("Plaintext auth allowed:", utils.ColorYellow), r.AllowsPlainAuth))
	if r.PlaintextReason != "" {
		b.WriteString(fmt.Sprintf(" (%s)", utils.Colorize(r.PlaintextReason, utils.ColorWhite)))
	}
	b.WriteString("\n")
	if r.STARTTLSSuccess {
		b.WriteString(fmt.Sprintf("%s %s, %s %s\n",
			utils.Colorize("STARTTLS:", utils.ColorYellow), r.STARTTLSTLSVersion,
			utils.Colorize("cipher", utils.ColorYellow), r.STARTTLSCipher))
	}
	if r.POP3SSuccess {
		b.WriteString(fmt.Sprintf("%s %s, %s %s\n",
			utils.Colorize("POP3S:", utils.ColorYellow), r.POP3STLSVersion,
			utils.Colorize("cipher", utils.ColorYellow), r.POP3SCipher))
	}
	if len(r.WeakTLSProtocols) > 0 {
		b.WriteString(fmt.Sprintf("%s %s\n", utils.Colorize("Weak TLS accepted:", utils.ColorRed), strings.Join(r.WeakTLSProtocols, ", ")))
	}
	if len(r.CertIssues) > 0 {
		b.WriteString(fmt.Sprintf("%s %s\n", utils.Colorize("Cert issues:", utils.ColorRed), strings.Join(r.CertIssues, "; ")))
	}
	b.WriteString(utils.BoldText(utils.Colorize("╚══════════════════════════════════════════════╝\n", utils.ColorMagenta)))
	return b.String()
}

// ---- Convenience main-style runner (optional)
/*
func main() {
	res := ScanPOP3("127.0.0.1", 5*time.Second)
	fmt.Println(res.String())
}
*/
