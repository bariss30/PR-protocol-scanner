package sip

import (
	"SOREERS/utils"
	"fmt"
	"net"
	"strings"
	"time"
)

type SIPResult struct {
	Target    string
	Server    string
	UserAgent string
	Reachable bool
	Error     string
}

func (r SIPResult) String() string {
	if r.Error != "" {
		return fmt.Sprintf("%s %s %s", utils.Colorize("✗", utils.ColorRed), utils.BoldText("SIP Hata:"), utils.Colorize(r.Error, utils.ColorRed))
	}
	parts := []string{}
	if r.Server != "" {
		parts = append(parts, "Server="+r.Server)
	}
	if r.UserAgent != "" {
		parts = append(parts, "User-Agent="+r.UserAgent)
	}
	reach := utils.Colorize(fmt.Sprintf("reachable=%v", r.Reachable), utils.ColorGreen)
	return fmt.Sprintf("%s %s %s %s", utils.BoldText(utils.Colorize("SIP", utils.ColorCyan)), utils.Colorize(r.Target, utils.ColorYellow), reach, strings.Join(parts, " "))
}

func ScanSIP(target string, timeout time.Duration) SIPResult {
	addr := fmt.Sprintf("%s:%d", target, 5060)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return SIPResult{Target: target, Error: err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	msg := "OPTIONS sip:" + target + " SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 0.0.0.0;branch=z9hG4bK-12345\r\n" +
		"Max-Forwards: 70\r\n" +
		"To: <sip:" + target + ">\r\n" +
		"From: <sip:scanner@local>;tag=1234\r\n" +
		"Call-ID: 1@local\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Contact: <sip:scanner@0.0.0.0>\r\n" +
		"Content-Length: 0\r\n\r\n"

	if _, err := conn.Write([]byte(msg)); err != nil {
		return SIPResult{Target: target, Error: err.Error()}
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return SIPResult{Target: target, Reachable: false}
	}
	resp := string(buf[:n])
	server := parseHeader(resp, "Server")
	ua := parseHeader(resp, "User-Agent")
	return SIPResult{Target: target, Reachable: true, Server: server, UserAgent: ua}
}

func parseHeader(resp, name string) string {
	name = name + ":"
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(name)) {
			return strings.TrimSpace(strings.TrimPrefix(line, name))
		}
	}
	return ""
}
