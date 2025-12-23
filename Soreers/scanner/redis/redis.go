package redis

import (
	"SOREERS/utils"
	"bufio"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type RedisResult struct {
	Target          string
	Port            int
	Open            bool
	PingOK          bool
	AuthRequired    bool
	Version         string
	Mode            string
	Role            string
	OS              string
	ConfigWritable  bool
	RDBDirWritable  bool
	UnauthCommands  []string
	Vulnerabilities []string
	ErrorMessage    string
}

func (r RedisResult) String() string {
	if r.ErrorMessage != "" {
		return fmt.Sprintf("%s[-] %s%s\n", utils.Red, "Redis Hata: "+r.ErrorMessage, utils.Reset)
	}

	var sb strings.Builder
	sb.WriteString(utils.Blue + "╔══════════════════════════════════════════════╗\n" + utils.Reset)
	sb.WriteString(fmt.Sprintf("%sTarget:%s %s:%d\n", utils.Yellow, utils.Reset, r.Target, r.Port))
	sb.WriteString(fmt.Sprintf("%sPing:%s %v\n", utils.Yellow, utils.Reset, r.PingOK))
	sb.WriteString(fmt.Sprintf("%sAuth required:%s %v\n", utils.Yellow, utils.Reset, r.AuthRequired))

	if r.Version != "" {
		sb.WriteString(fmt.Sprintf("%sVersion:%s %s\n", utils.Yellow, utils.Reset, utils.White+r.Version+utils.Reset))
		sb.WriteString(fmt.Sprintf("%sMode:%s %s\n", utils.Yellow, utils.Reset, utils.White+r.Mode+utils.Reset))
		sb.WriteString(fmt.Sprintf("%sRole:%s %s\n", utils.Yellow, utils.Reset, utils.White+r.Role+utils.Reset))
	}

	if r.OS != "" {
		sb.WriteString(fmt.Sprintf("%sOS:%s %s\n", utils.Yellow, utils.Reset, utils.White+r.OS+utils.Reset))
	}

	if len(r.UnauthCommands) > 0 {
		sb.WriteString(fmt.Sprintf("%sUnauth Commands:%s %s\n", utils.Yellow, utils.Reset, strings.Join(r.UnauthCommands, ", ")))
	}

	if len(r.Vulnerabilities) > 0 {
		sb.WriteString(utils.Red + "Findings:\n" + utils.Reset)
		for i, v := range r.Vulnerabilities {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, v))
		}
	}

	sb.WriteString(utils.Blue + "╚══════════════════════════════════════════════╝\n" + utils.Reset)
	return sb.String()
}

// ScanRedis TCP 6379 üzerinden Redis'e bağlanır, PING ve INFO deneyerek bulguları çıkarır.
func ScanRedis(target string, timeout time.Duration) RedisResult {
	res := RedisResult{Target: target, Port: 6379}
	addr := fmt.Sprintf("%s:%d", target, res.Port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		res.ErrorMessage = err.Error()
		return res
	}
	defer conn.Close()
	res.Open = true
	_ = conn.SetDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)

	// PING
	if err := writeRESP(conn, []string{"PING"}); err == nil {
		line, _ := readLine(reader)
		if strings.HasPrefix(line, "+PONG") {
			res.PingOK = true
		}
	}

	// INFO
	if err := writeRESP(conn, []string{"INFO"}); err == nil {
		line, _ := readLine(reader)
		if strings.HasPrefix(line, "-") && strings.Contains(strings.ToLower(line), "auth") {
			res.AuthRequired = true
		} else {
			info, _ := readBulk(reader, conn, line)
			parseInfo(info, &res)
			res.UnauthCommands = append(res.UnauthCommands, "INFO")
		}
	}

	res.Vulnerabilities = evaluateFindings(&res)
	return res
}

type RedisAuthResult struct {
	Target       string
	Port         int
	Username     string
	Password     string
	Success      bool
	ErrorMessage string
}

func (r RedisAuthResult) String() string {
	status := "[-]"
	if r.Success {
		status = "[+]"
	}
	if r.Username != "" {
		if r.ErrorMessage != "" {
			return fmt.Sprintf("%s Redis auth %s:%d %s:%q -> error: %s", status, r.Target, r.Port, r.Username, r.Password, r.ErrorMessage)
		}
		return fmt.Sprintf("%s Redis auth %s:%d %s:%q", status, r.Target, r.Port, r.Username, r.Password)
	}
	if r.ErrorMessage != "" {
		return fmt.Sprintf("%s Redis auth %s:%d %q -> error: %s", status, r.Target, r.Port, r.Password, r.ErrorMessage)
	}
	return fmt.Sprintf("%s Redis auth %s:%d %q", status, r.Target, r.Port, r.Password)
}

// BruteForceRedis denemesi
func BruteForceRedis(target string, usernames, passwords []string, timeout time.Duration, concurrency int) []RedisAuthResult {
	if concurrency <= 0 {
		concurrency = 5
	}
	type job struct {
		u, p string
		mode int
	} // mode 1: user+pass, 2: pass-only
	jobs := make(chan job)
	results := make([]RedisAuthResult, 0, (len(usernames)*len(passwords))+len(passwords))
	var mu sync.Mutex
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			ok, err := tryAuth(target, j.u, j.p, j.mode, timeout)
			mu.Lock()
			results = append(results, RedisAuthResult{
				Target:       target,
				Port:         6379,
				Username:     j.u,
				Password:     j.p,
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

	for _, u := range usernames {
		for _, p := range passwords {
			jobs <- job{u: u, p: p, mode: 1}
		}
	}
	for _, p := range passwords {
		jobs <- job{u: "", p: p, mode: 2}
	}

	close(jobs)
	wg.Wait()
	return results
}

// tryAuth
func tryAuth(target, username, password string, mode int, timeout time.Duration) (bool, error) {
	addr := fmt.Sprintf("%s:%d", target, 6379)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)

	var cmd []string
	if mode == 1 {
		cmd = []string{"AUTH", username, password}
	} else {
		cmd = []string{"AUTH", password}
	}

	if err := writeRESP(conn, cmd); err != nil {
		return false, err
	}
	line, err := readLine(reader)
	if err != nil {
		return false, err
	}
	if strings.HasPrefix(line, "+OK") {
		return true, nil
	}
	if strings.HasPrefix(line, "-") {
		return false, nil
	}
	return false, errors.New("unexpected reply")
}

// RESP helpers
func writeRESP(conn net.Conn, parts []string) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("*%d\r\n", len(parts)))
	for _, p := range parts {
		sb.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(p), p))
	}
	_, err := conn.Write([]byte(sb.String()))
	return err
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func readBulk(r *bufio.Reader, conn net.Conn, firstLine string) (string, error) {
	if len(firstLine) == 0 || firstLine[0] != '$' {
		return "", errors.New("not bulk")
	}
	raw := firstLine + "\r\n"
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	for {
		part, err := r.ReadString('\n')
		raw += part
		if err != nil {
			break
		}
		if strings.HasSuffix(raw, "\r\n") && strings.Contains(raw, "server") && strings.Contains(raw, "#") {
			break
		}
	}
	idx := strings.Index(raw, "\r\n")
	if idx >= 0 {
		return raw[idx+2:], nil
	}
	return raw, nil
}

// parseInfo
func parseInfo(info string, res *RedisResult) {
	lines := strings.Split(info, "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || ln[0] == '#' {
			continue
		}
		kv := strings.SplitN(ln, ":", 2)
		if len(kv) != 2 {
			continue
		}
		k := kv[0]
		v := kv[1]
		switch k {
		case "redis_version":
			res.Version = v
		case "redis_mode":
			res.Mode = v
		case "role":
			res.Role = v
		case "os":
			res.OS = v
		}
	}
}

// evaluateFindings
func evaluateFindings(r *RedisResult) []string {
	findings := []string{}
	if !r.AuthRequired {
		findings = append(findings, "Unauthenticated access possible; set requirepass or ACLs")
	}
	if r.PingOK && !r.AuthRequired {
		findings = append(findings, "PING responds without AUTH; exposure risk")
	}
	if r.Role == "master" {
		findings = append(findings, "Node is master; consider restricting access and enabling TLS")
	}
	if r.Version != "" && strings.HasPrefix(r.Version, "2.") {
		findings = append(findings, "Very old Redis version; upgrade urgently")
	}
	return findings
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
