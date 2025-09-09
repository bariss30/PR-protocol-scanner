package vnc

import (
	"FORFTP/utils"
	"crypto/des"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type VNCResult struct {
	Target          string
	Port            int
	Open            bool
	ServerVersion   string
	SelectedVersion string
	SecurityTypes   []string
	NoAuthAllowed   bool
	SupportsVNCAuth bool
	Width           int
	Height          int
	DesktopName     string
	Vulnerabilities []string
	ErrorMessage    string
}

func (r VNCResult) String() string {
	if r.ErrorMessage != "" {
		return fmt.Sprintf("%s %s %s",
			utils.Colorize("✗", utils.ColorRed),
			utils.BoldText("VNC Hata:"),
			utils.Colorize(r.ErrorMessage, utils.ColorRed))
	}

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(utils.BoldText(utils.Colorize("╔══════════════════════════════════════════════╗\n", utils.ColorBlue)))
	b.WriteString(fmt.Sprintf("%s %s:%d\n",
		utils.Colorize("Target:", utils.ColorYellow), r.Target, r.Port))
	if r.ServerVersion != "" {
		b.WriteString(fmt.Sprintf("%s %s\n",
			utils.Colorize("Server Version:", utils.ColorYellow),
			utils.Colorize(r.ServerVersion, utils.ColorWhite)))
	}
	if r.SelectedVersion != "" {
		b.WriteString(fmt.Sprintf("%s %s\n",
			utils.Colorize("Negotiated Version:", utils.ColorYellow),
			utils.Colorize(r.SelectedVersion, utils.ColorWhite)))
	}
	if len(r.SecurityTypes) > 0 {
		b.WriteString(fmt.Sprintf("%s %s\n",
			utils.Colorize("Security Types:", utils.ColorYellow),
			utils.Colorize(strings.Join(r.SecurityTypes, ", "), utils.ColorWhite)))
	}
	b.WriteString(fmt.Sprintf("%s %v\n", utils.Colorize("No Auth Allowed:", utils.ColorYellow), r.NoAuthAllowed))
	b.WriteString(fmt.Sprintf("%s %v\n", utils.Colorize("VNC Auth Supported:", utils.ColorYellow), r.SupportsVNCAuth))
	if r.Width > 0 && r.Height > 0 {
		b.WriteString(fmt.Sprintf("%s %dx%d\n",
			utils.Colorize("Desktop Resolution:", utils.ColorYellow),
			r.Width, r.Height))
		b.WriteString(fmt.Sprintf("%s %s\n",
			utils.Colorize("Desktop Name:", utils.ColorYellow),
			utils.Colorize(r.DesktopName, utils.ColorWhite)))
	}
	if len(r.Vulnerabilities) > 0 {
		b.WriteString(utils.BoldText(utils.Colorize("\nFindings:\n", utils.ColorBlue)))
		for i, v := range r.Vulnerabilities {
			b.WriteString(fmt.Sprintf("  %d. %s\n", i+1, utils.Colorize(v, utils.ColorRed)))
		}
	}
	b.WriteString(utils.BoldText(utils.Colorize("╚══════════════════════════════════════════════╝\n", utils.ColorBlue)))
	return b.String()
}

// ScanVNC performs a light-weight RFB handshake to enumerate version and security types.
func ScanVNC(target string, timeout time.Duration) VNCResult {
	res := VNCResult{
		Target: target,
		Port:   5900,
	}
	addr := fmt.Sprintf("%s:%d", target, res.Port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		res.Open = false
		res.ErrorMessage = err.Error()
		return res
	}
	defer conn.Close()
	res.Open = true
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Read server version (12 bytes)
	serverVersion, err := readExact(conn, 12)
	if err != nil {
		res.ErrorMessage = fmt.Sprintf("failed to read version: %v", err)
		return res
	}
	res.ServerVersion = strings.TrimRight(string(serverVersion), "\n\r\x00 ")

	// Negotiate version: prefer 3.8 when available, else 3.3
	selected := selectVersion(res.ServerVersion)
	res.SelectedVersion = selected
	if _, err = conn.Write([]byte(selected)); err != nil {
		res.ErrorMessage = fmt.Sprintf("failed to write version: %v", err)
		return res
	}

	// Security types differ by version
	if strings.Contains(selected, "003.003") {
		// RFB 3.3: server sends 4-byte security type
		sec32b, err := readExact(conn, 4)
		if err != nil {
			res.ErrorMessage = fmt.Sprintf("failed to read security type: %v", err)
			return res
		}
		secType := binary.BigEndian.Uint32(sec32b)
		if secType == 0 {
			// failure follows: reason length + reason
			reason, _ := readFailureReason(conn)
			res.ErrorMessage = fmt.Sprintf("server rejected connection: %s", reason)
			return res
		}
		secNames := []string{securityTypeName(byte(secType))}
		res.SecurityTypes = secNames
		for _, n := range secNames {
			if n == "None" {
				res.NoAuthAllowed = true
			}
			if n == "VNC Authentication" {
				res.SupportsVNCAuth = true
			}
		}
		if res.NoAuthAllowed {
			// In 3.3 with None, proceed with SecurityResult? Not present in 3.3.
			// Send ClientInit and read ServerInit
			_, _ = conn.Write([]byte{1})
			if err := readServerInit(conn, &res); err != nil {
				res.ErrorMessage = fmt.Sprintf("failed ServerInit: %v", err)
			}
		}
	} else {
		// RFB 3.7/3.8: server sends a list of security types
		countB, err := readExact(conn, 1)
		if err != nil {
			res.ErrorMessage = fmt.Sprintf("failed to read sec count: %v", err)
			return res
		}
		count := int(countB[0])
		if count == 0 {
			reason, _ := readFailureReason(conn)
			res.ErrorMessage = fmt.Sprintf("server rejected connection: %s", reason)
			return res
		}
		list, err := readExact(conn, count)
		if err != nil {
			res.ErrorMessage = fmt.Sprintf("failed to read sec list: %v", err)
			return res
		}
		for _, t := range list {
			name := securityTypeName(t)
			res.SecurityTypes = append(res.SecurityTypes, name)
			if name == "None" {
				res.NoAuthAllowed = true
			}
			if name == "VNC Authentication" {
				res.SupportsVNCAuth = true
			}
		}

		// Prefer selecting None if available to reach ServerInit; else select VNC auth to test challenge presence
		var selectType byte
		if res.NoAuthAllowed {
			selectType = 1
		} else if res.SupportsVNCAuth {
			selectType = 2
		}
		if selectType != 0 {
			_, _ = conn.Write([]byte{selectType})
			if selectType == 1 {
				// Expect SecurityResult (4 bytes), then ClientInit/ServerInit
				secRes, err := readExact(conn, 4)
				if err == nil && binary.BigEndian.Uint32(secRes) == 0 {
					_, _ = conn.Write([]byte{1})
					_ = readServerInit(conn, &res)
				} else if err == nil {
					// failure with reason
					_, _ = readFailureReason(conn)
				}
			} else if selectType == 2 {
				// Read challenge presence to confirm VNC auth reachable
				_, _ = readExact(conn, 16)
			}
		}
	}

	res.Vulnerabilities = evaluateFindings(res)
	return res
}

type VNCAuthResult struct {
	Target       string
	Port         int
	Username     string
	Password     string
	Success      bool
	ErrorMessage string
}

func (r VNCAuthResult) String() string {
	status := "[-]"
	if r.Success {
		status = "[+]"
	}
	userPart := ""
	if r.Username != "" {
		userPart = fmt.Sprintf("%s:", r.Username)
	}
	if r.ErrorMessage != "" {
		return fmt.Sprintf("%s VNC auth %s:%d %s%q -> error: %s", status, r.Target, r.Port, userPart, r.Password, r.ErrorMessage)
	}
	return fmt.Sprintf("%s VNC auth %s:%d %s%q", status, r.Target, r.Port, userPart, r.Password)
}

// BruteForceVNC attempts VNC authentication using provided passwords concurrently.
func BruteForceVNC(target string, passwords []string, timeout time.Duration, concurrency int) []VNCAuthResult {
	if concurrency <= 0 {
		concurrency = 5
	}
	results := make([]VNCAuthResult, 0, len(passwords))
	jobs := make(chan string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for pw := range jobs {
			ok, err := tryVNCPassword(target, pw, timeout)
			mu.Lock()
			results = append(results, VNCAuthResult{
				Target:       target,
				Port:         5900,
				Username:     "",
				Password:     pw,
				Success:      ok,
				ErrorMessage: errStr(err),
			})
			mu.Unlock()
		}
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker()
	}

	for _, pw := range passwords {
		jobs <- pw
	}
	close(jobs)
	wg.Wait()
	return results
}

// BruteForceVNCWithUsers attempts all username x password combinations.
// Username is not part of classic RFB auth; included for labeling/reporting only.
func BruteForceVNCWithUsers(target string, usernames []string, passwords []string, timeout time.Duration, concurrency int) []VNCAuthResult {
	if concurrency <= 0 {
		concurrency = 5
	}
	type combo struct{ user, pass string }
	jobs := make(chan combo)
	results := make([]VNCAuthResult, 0, len(usernames)*len(passwords))
	var wg sync.WaitGroup
	var mu sync.Mutex

	worker := func() {
		defer wg.Done()
		for job := range jobs {
			ok, err := tryVNCPassword(target, job.pass, timeout)
			mu.Lock()
			results = append(results, VNCAuthResult{
				Target:       target,
				Port:         5900,
				Username:     job.user,
				Password:     job.pass,
				Success:      ok,
				ErrorMessage: errStr(err),
			})
			mu.Unlock()
		}
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker()
	}
	go func() {
		for _, u := range usernames {
			for _, p := range passwords {
				jobs <- combo{u, p}
			}
		}
		close(jobs)
	}()
	wg.Wait()
	return results
}

// tryVNCPassword performs a fresh connection and RFB auth attempt using given password
func tryVNCPassword(target, password string, timeout time.Duration) (bool, error) {
	addr := fmt.Sprintf("%s:%d", target, 5900)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// version
	serverVersion, err := readExact(conn, 12)
	if err != nil {
		return false, err
	}
	selected := selectVersion(strings.TrimSpace(string(serverVersion)))
	if _, err = conn.Write([]byte(selected)); err != nil {
		return false, err
	}

	var vncSelected bool
	if strings.Contains(selected, "003.003") {
		// Single security type
		sec32b, err := readExact(conn, 4)
		if err != nil {
			return false, err
		}
		secType := binary.BigEndian.Uint32(sec32b)
		if secType == 0 {
			// server rejected
			return false, errors.New("server rejected connection")
		}
		if byte(secType) != 2 {
			return false, errors.New("VNC auth not offered")
		}
		vncSelected = true
	} else {
		cntb, err := readExact(conn, 1)
		if err != nil {
			return false, err
		}
		cnt := int(cntb[0])
		if cnt == 0 {
			_, _ = readFailureReason(conn)
			return false, errors.New("server rejected connection")
		}
		list, err := readExact(conn, cnt)
		if err != nil {
			return false, err
		}
		var hasVNC bool
		for _, t := range list {
			if t == 2 {
				hasVNC = true
				break
			}
		}
		if !hasVNC {
			return false, errors.New("VNC auth not offered")
		}
		// select VNC auth
		if _, err = conn.Write([]byte{2}); err != nil {
			return false, err
		}
		vncSelected = true
	}

	if !vncSelected {
		return false, errors.New("VNC auth not selected")
	}
	challenge, err := readExact(conn, 16)
	if err != nil {
		return false, err
	}
	resp, err := vncEncryptChallenge(challenge, password)
	if err != nil {
		return false, err
	}
	if _, err = conn.Write(resp); err != nil {
		return false, err
	}
	statusB, err := readExact(conn, 4)
	if err != nil {
		return false, err
	}
	status := binary.BigEndian.Uint32(statusB)
	if status == 0 {
		return true, nil
	}
	if status == 1 {
		// failure; read reason (optional)
		_, _ = readFailureReason(conn)
		return false, nil
	}
	return false, errors.New("too many tries or unknown status")
}

// Helpers
func readExact(conn net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	read := 0
	for read < n {
		r, err := conn.Read(buf[read:])
		if r > 0 {
			read += r
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && read > 0 {
				continue
			}
			return nil, err
		}
	}
	return buf, nil
}

func readFailureReason(conn net.Conn) (string, error) {
	lenB, err := readExact(conn, 4)
	if err != nil {
		return "", err
	}
	ln := int(binary.BigEndian.Uint32(lenB))
	if ln <= 0 || ln > 1<<20 {
		return "", nil
	}
	reasonB, err := readExact(conn, ln)
	if err != nil {
		return "", err
	}
	return string(reasonB), nil
}

func readServerInit(conn net.Conn, res *VNCResult) error {
	wh, err := readExact(conn, 4)
	if err != nil {
		return err
	}
	res.Width = int(binary.BigEndian.Uint16(wh[0:2]))
	res.Height = int(binary.BigEndian.Uint16(wh[2:4]))
	// Skip pixel format (16 bytes) and name length
	if _, err = readExact(conn, 16); err != nil {
		return err
	}
	nameLenB, err := readExact(conn, 4)
	if err != nil {
		return err
	}
	ln := int(binary.BigEndian.Uint32(nameLenB))
	if ln > 0 && ln < 1<<20 {
		nameB, err := readExact(conn, ln)
		if err == nil {
			res.DesktopName = string(nameB)
		}
	}
	return nil
}

func selectVersion(serverVersion string) string {
	ver := strings.TrimSpace(serverVersion)
	if strings.Contains(ver, "003.008") || strings.Contains(ver, "3.8") {
		return "RFB 003.008\n"
	}
	return "RFB 003.003\n"
}

func securityTypeName(t byte) string {
	switch t {
	case 1:
		return "None"
	case 2:
		return "VNC Authentication"
	case 5:
		return "RA2"
	case 6:
		return "RA2ne"
	case 16:
		return "Tight"
	case 19:
		return "VeNCrypt"
	case 30:
		return "TLS"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

func evaluateFindings(r VNCResult) []string {
	findings := []string{}
	if r.NoAuthAllowed {
		findings = append(findings, "No authentication required (critical: disable or enforce authentication)")
	}
	if r.SupportsVNCAuth {
		findings = append(findings, "VNC password-based auth available; weak/default passwords are common")
	}
	if r.Open && r.ServerVersion == "" {
		findings = append(findings, "Could not read server version; possible non-standard implementation")
	}
	return findings
}

func vncEncryptChallenge(challenge []byte, password string) ([]byte, error) {
	if len(challenge) != 16 {
		return nil, errors.New("invalid challenge length")
	}
	key := make([]byte, 8)
	for i := 0; i < 8; i++ {
		var b byte
		if i < len(password) {
			b = password[i]
		}
		key[i] = reverseBits(b)
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16)
	block.Encrypt(out[0:8], challenge[0:8])
	block.Encrypt(out[8:16], challenge[8:16])
	return out, nil
}

func reverseBits(b byte) byte {
	b = (b&0xF0)>>4 | (b&0x0F)<<4
	b = (b&0xCC)>>2 | (b&0x33)<<2
	b = (b&0xAA)>>1 | (b&0x55)<<1
	return b
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
