package imap

import (
	"FORFTP/utils"
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"
)

type IMAPResult struct {
	Target            string
	Port              int
	Banner            string
	InfoLeak          bool
	STARTTLS          bool
	PlaintextAuth     bool
	PlaintextAuthResp string
}

func (r *IMAPResult) String() string {
	if r.Banner == "" && !r.STARTTLS && !r.PlaintextAuth {
		return fmt.Sprintf("%s %s %s",
			utils.Colorize("✗", utils.ColorRed),
			utils.BoldText("IMAP Hata:"),
			utils.Colorize(fmt.Sprintf("Bağlantı kurulamadı: %s:%d", r.Target, r.Port), utils.ColorRed))
	}

	var b strings.Builder
	b.WriteString(utils.BoldText(utils.Colorize("╔══════════════════════════════════════════════╗\n", utils.ColorBlue)))
	b.WriteString(fmt.Sprintf("%s %s:%d\n", utils.Colorize("Target:", utils.ColorYellow), r.Target, r.Port))
	if r.Banner != "" {
		b.WriteString(fmt.Sprintf("%s %s\n", utils.Colorize("Banner:", utils.ColorYellow), utils.Colorize(r.Banner, utils.ColorWhite)))
	}
	b.WriteString(fmt.Sprintf("%s %v\n", utils.Colorize("Bilgi sızıntısı:", utils.ColorRed), r.InfoLeak))
	b.WriteString(fmt.Sprintf("%s %v\n", utils.Colorize("STARTTLS desteği:", utils.ColorCyan), r.STARTTLS))
	b.WriteString(fmt.Sprintf("%s %v\n", utils.Colorize("Plaintext Login:", utils.ColorYellow), r.PlaintextAuth))
	if r.PlaintextAuthResp != "" {
		b.WriteString(fmt.Sprintf("%s %s\n", utils.Colorize("Plaintext Yanıt:", utils.ColorGreen), r.PlaintextAuthResp))
	}
	b.WriteString(utils.BoldText(utils.Colorize("╚══════════════════════════════════════════════╝\n", utils.ColorBlue)))
	return b.String()
}

func RunIMAP(target string, timeoutSec int) []*IMAPResult {
	timeout := time.Duration(timeoutSec) * time.Second
	imapPorts := []int{143, 993}
	var results []*IMAPResult

	for _, port := range imapPorts {
		res := &IMAPResult{Target: target, Port: port}
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
		results = append(results, res)
	}

	return results
}

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

	// Read greeting and any inline [CAPABILITY ...]
	greetBanner, greetCaps := readGreeting(reader)
	banner = greetBanner

	// Expand capabilities with CAPABILITY command
	caps2, starttlsSupported, logindisabled := fetchCapabilities(reader, writer, timeout)
	caps := mergeCaps(greetCaps, caps2)
	_ = caps
	starttls = starttlsSupported || hasToken(caps, "STARTTLS")

	// Determine if plaintext login is allowed on the current (unencrypted) connection
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

	// On implicit TLS, plaintext over the wire is already encrypted
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
		// Typical greeting starts with "* OK" or "* PREAUTH"
		if strings.HasPrefix(upper, "* OK") || strings.HasPrefix(upper, "* PREAUTH") || strings.HasPrefix(upper, "* BYE") {
			lcap := parseBracketCapabilities(line)
			if len(lcap) > 0 {
				foundCaps = append(foundCaps, lcap...)
			}
			// Some servers only send one line; we don't strictly require a terminator here
			// Break after capturing first significant greeting line
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
	for i := 0; i < 200; i++ { // reasonable upper bound to avoid infinite loop
		line, err := reader.ReadLine()
		if err != nil {
			break
		}
		upper := strings.ToUpper(line)
		if strings.HasPrefix(line, "*") && strings.Contains(upper, "CAPABILITY") {
			// Example: * CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN
			idx := strings.Index(upper, "CAPABILITY")
			if idx >= 0 {
				// slice original line maintains token cases
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
	// Common IMAP server products that often leak in greeting/banners
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
