	package ftp

	import (
		"FORFTP/utils"
		"bufio"
		"fmt"
		"net"
		"strconv"
		"strings"
		"time"
	)

	type FTPResult struct {
		Target          string
		Port            int
		Banner          string
		AnonymousLogin  bool
		LoginAttempted  bool
		LoginSuccess    bool
		Username        string
		Password        string
		ExplicitTLSSupp bool
		ErrorMessage    string
	}

	
	func FTPLogin(server string, port int, username, password string, timeout time.Duration) (bool, error) {
		address := fmt.Sprintf("%s:%d", server, port)
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err != nil {
			return false, fmt.Errorf("connection error: %w", err)
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)

		// Read welcome message
		_, err = reader.ReadString('\n')
		if err != nil {
			return false, fmt.Errorf("could not read welcome message: %w", err)
		}

		// Send USER command
		_, err = fmt.Fprintf(conn, "USER %s\r\n", username)
		if err != nil {
			return false, fmt.Errorf("could not send USER command: %w", err)
		}

		_, err = reader.ReadString('\n') // read USER response but ignore
		if err != nil {
			return false, fmt.Errorf("could not read USER response: %w", err)
		}

		// Send PASS command
		_, err = fmt.Fprintf(conn, "PASS %s\r\n", password)
		if err != nil {
			return false, fmt.Errorf("could not send PASS command: %w", err)
		}

		passResp, err := reader.ReadString('\n')
		if err != nil {
			return false, fmt.Errorf("could not read PASS response: %w", err)
		}

		// Check if login was successful (230 is FTP success code)
		if strings.HasPrefix(passResp, "230") {
			return true, nil
		}

		return false, fmt.Errorf("login failed: %s", strings.TrimSpace(passResp))
	}

	
	func AnonymousLogin(ip string, timeout time.Duration) (bool, error) {
		return FTPLogin(ip, 21, "anonymous", "anonymous", timeout)
	}

	
	func SingleLogin(ip, username, password string, timeout time.Duration) (bool, error) {
		return FTPLogin(ip, 21, username, password, timeout)
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

		// Banner genelde şöyle olur:
		// "220 vsFTPd 3.0.3 Service ready for new user.\r\n"
		// veya "220 ProFTPD 1.3.5 Server (Debian) [::ffff:127.0.0.1]\r\n"
		// Biz sadece sürüm bilgisini almak için satırı temizleyip dönebiliriz

		banner = strings.TrimSpace(banner)
		return banner, nil
	}

	func readResponse(reader *bufio.Reader) (int, string, error) {
		line, err := reader.ReadString('\n')
		if err != nil {
			return 0, "", err
		}
		line = strings.TrimSpace(line)
		if len(line) < 3 {
			return 0, "", fmt.Errorf("invalid response: %s", line)
		}
		code, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, "", err
		}
		return code, line, nil
	}

	func SupportsExplicitTLS(host string, port int, timeout time.Duration) (bool, error) {
		addr := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return false, err
		}
		defer conn.Close()

		conn.SetDeadline(time.Now().Add(timeout))
		reader := bufio.NewReader(conn)

		// Read server's initial response/banner
		_, _, err = readResponse(reader)
		if err != nil {
			return false, err
		}

		// Send AUTH TLS command
		fmt.Fprintf(conn, "AUTH TLS\r\n")
		code, resp, err := readResponse(reader)
		if err != nil {
			return false, err
		}

		// 234 is the standard FTP code for successful AUTH TLS negotiation
		if code == 234 || strings.Contains(strings.ToUpper(resp), "TLS") {
			return true, nil
		}
		return false, nil
	}
		


	func (r *FTPResult) String() string {
		if r.ErrorMessage != "" {
			return fmt.Sprintf("%s %s %s",
				utils.Colorize("✗", utils.ColorRed),
				utils.BoldText("FTP Hata:"),
				utils.Colorize(r.ErrorMessage, utils.ColorRed))
		}
		var b strings.Builder
		b.WriteString("\n")
		b.WriteString(utils.BoldText(utils.Colorize("╔══════════════════════════════════════════════╗\n", utils.ColorBlue)))
		b.WriteString(fmt.Sprintf("%s %s:%d\n", utils.Colorize("Target:", utils.ColorYellow), r.Target, r.Port))
		if r.Banner != "" {
			b.WriteString(fmt.Sprintf("%s %s\n", utils.Colorize("Banner:", utils.ColorYellow), utils.Colorize(r.Banner, utils.ColorWhite)))
		}
		b.WriteString(fmt.Sprintf("%s %v\n", utils.Colorize("Anonymous Login:", utils.ColorYellow), r.AnonymousLogin))
		if r.LoginAttempted {
			loginStatus := utils.Colorize("başarısız", utils.ColorRed)
			if r.LoginSuccess {
				loginStatus = utils.Colorize("başarılı", utils.ColorGreen)
			}
			b.WriteString(fmt.Sprintf("%s %s (%s/%s)\n",
				utils.Colorize("Kullanıcı Girişi:", utils.ColorYellow),
				loginStatus,
				utils.Colorize(r.Username, utils.ColorCyan),
				utils.Colorize(r.Password, utils.ColorCyan)))
		}
		b.WriteString(fmt.Sprintf("%s %v\n", utils.Colorize("Explicit TLS:", utils.ColorYellow), r.ExplicitTLSSupp))
		b.WriteString(utils.BoldText(utils.Colorize("╚══════════════════════════════════════════════╝\n", utils.ColorBlue)))
		return b.String()
	}