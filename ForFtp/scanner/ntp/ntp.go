package ntp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)


const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorBlue   = "\033[34m"
)


type NTPResult struct {
	Target              string
	PortOpen            bool
	VersionLeak         bool
	Version             int
	Stratum             int
	RefID               string
	System              string
	Processor           string
	ReceiveTimestamp    string
	MonlistVuln         bool
	MonlistDetails      string
	ControlQueryVuln    bool
	ControlQueryDetails string
	AmplificationFactor float64
	Restrictions        string
	ErrorMessage        string
}


func sendUDPMessage(target string, data []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("udp", target+":123", timeout)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write(data)
	if err != nil {
		return nil, fmt.Errorf("write failed: %v", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}
	return buf[:n], nil
}


func parseNTPResponse(resp []byte) (int, int, string, string) {
	if len(resp) < 48 {
		return 0, 0, "", ""
	}
	version := int((resp[0] >> 3) & 0x07)
	stratum := int(resp[1])
	refID := fmt.Sprintf("%d.%d.%d.%d", resp[12], resp[13], resp[14], resp[15])
	receiveTS := ntpTimeToString(binary.BigEndian.Uint64(resp[32:40]))
	return version, stratum, refID, receiveTS
}

func ntpTimeToString(ntpTS uint64) string {
	secs := ntpTS >> 32
	t := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(secs) * time.Second)
	return t.Format("2006-01-02 15:04:05")
}

func parseControlResponse(resp []byte) string {
	if len(resp) < 12 {
		return "Invalid response"
	}
	data := string(resp[12:])
	lines := strings.Split(data, "\n")
	var sb strings.Builder
	for _, line := range lines {
		if line != "" {
			sb.WriteString("    " + line + "\n")
		}
	}
	return sb.String()
}

func parseMonlistResponse(resp []byte) string {
	if len(resp) < 8 {
		return "Invalid response"
	}
	numItems := int(binary.BigEndian.Uint16(resp[4:6]))
	return fmt.Sprintf("    Peers returned: %d", numItems)
}

func checkRestrictions(target string) (string, string) {
	query := []byte{0x1b} // Basic client query
	resp, err := sendUDPMessage(target, query, 3*time.Second)
	if err != nil {
		return "Restricted", fmt.Sprintf("Query blocked: %v", err)
	}
	if len(resp) == 0 {
		return "Restricted", "No response to client query"
	}
	return "Unrestricted", "Queries allowed"
}

func checkMonlist(target string) (bool, string, string) {
	monlist := []byte{0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00}
	resp, err := sendUDPMessage(target, monlist, 3*time.Second)
	if err != nil {
		return false, "", fmt.Sprintf("Monlist check failed: %v", err)
	}
	if len(resp) == 0 {
		return false, "", "No response"
	}
	details := parseMonlistResponse(resp)
	return true, details, ""
}

func checkControlQuery(target string) (bool, string, string) {
	ctrl := []byte{0x16, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	resp, err := sendUDPMessage(target, ctrl, 3*time.Second)
	if err != nil {
		return false, "", fmt.Sprintf("Control query failed: %v", err)
	}
	if len(resp) == 0 {
		return false, "", "No response"
	}
	details := parseControlResponse(resp)
	return true, details, ""
}

func checkAmplification(target string, monlistVuln bool) (float64, string) {
	var query []byte
	var queryLen int
	if monlistVuln {
		query = []byte{0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00}
		queryLen = len(query)
	} else {
		query = make([]byte, 48)
		query[0] = 0x1b
		queryLen = 48
	}
	resp, err := sendUDPMessage(target, query, 3*time.Second)
	if err != nil {
		return 0, fmt.Sprintf("Amplification check failed: %v", err)
	}
	if len(resp) == 0 {
		return 0, "No response received"
	}
	return float64(len(resp)) / float64(queryLen), ""
}

func checkNTPInfo(target string) (bool, int, int, string, string, string, string, string) {
	query := make([]byte, 48)
	query[0] = 0x1b
	resp, err := sendUDPMessage(target, query, 3*time.Second)
	if err != nil {
		return false, 0, 0, "", "", "", "", fmt.Sprintf("NTP info check failed: %v", err)
	}
	if len(resp) < 48 {
		return false, 0, 0, "", "", "", "", "Insufficient response length"
	}
	version, stratum, refID, receiveTS := parseNTPResponse(resp)
	return version > 0, version, stratum, refID, receiveTS, "", "", ""
}

func Scan(target string) *NTPResult {
	res := &NTPResult{Target: target}

	conn, err := net.DialTimeout("udp", target+":123", 2*time.Second)
	if err != nil {
		res.PortOpen = false
		res.ErrorMessage = fmt.Sprintf("Port 123/UDP closed: %v", err)
		return res
	}
	conn.Close()
	res.PortOpen = true

	res.VersionLeak, res.Version, res.Stratum, res.RefID, res.ReceiveTimestamp, res.System, res.Processor, res.ErrorMessage = checkNTPInfo(target)
	res.MonlistVuln, res.MonlistDetails, _ = checkMonlist(target)
	res.ControlQueryVuln, res.ControlQueryDetails, _ = checkControlQuery(target)
	res.AmplificationFactor, _ = checkAmplification(target, res.MonlistVuln)
	res.Restrictions, _ = checkRestrictions(target)

	if res.ControlQueryVuln {
		lines := strings.Split(res.ControlQueryDetails, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "    system=") {
				res.System = strings.TrimPrefix(line, "    system=")
			} else if strings.HasPrefix(line, "    processor=") {
				res.Processor = strings.TrimPrefix(line, "    processor=")
			}
		}
	}

	return res
}

func (r *NTPResult) String() string {
	if !r.PortOpen {
		return fmt.Sprintf(
			"%s[✗] Target: %s - NTP Port Closed%s\nReason: %s\n",
			ColorRed, r.Target, ColorReset, r.ErrorMessage)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s═══════════════════════════════════════════════════════════\n", ColorCyan))
	sb.WriteString(fmt.Sprintf("%sNTP Scan Results for %s (UDP/123)%s\n", ColorBlue, r.Target, ColorReset))
	sb.WriteString(fmt.Sprintf("%s═══════════════════════════════════════════════════════════%s\n\n", ColorCyan, ColorReset))

	// Service Information
	sb.WriteString(fmt.Sprintf("%sService Information:%s\n", ColorBlue, ColorReset))
	sb.WriteString("───────────────────────────────\n")
	if r.VersionLeak {
		sb.WriteString(fmt.Sprintf("%s[+] Version: %s%d%s\n", ColorGreen, ColorReset, r.Version, ColorReset))
		sb.WriteString(fmt.Sprintf("    Stratum: %d\n", r.Stratum))
		sb.WriteString(fmt.Sprintf("    Reference ID: %s\n", r.RefID))
		sb.WriteString(fmt.Sprintf("    Receive Timestamp: %s\n", r.ReceiveTimestamp))
		if r.System != "" {
			sb.WriteString(fmt.Sprintf("    System: %s\n", r.System))
		}
		if r.Processor != "" {
			sb.WriteString(fmt.Sprintf("    Processor: %s\n", r.Processor))
		}
	} else {
		sb.WriteString(fmt.Sprintf("%s[-] No version or info leak detected%s\n", ColorYellow, ColorReset))
		if r.ErrorMessage != "" {
			sb.WriteString(fmt.Sprintf("    Reason: %s\n", r.ErrorMessage))
		}
	}
	sb.WriteString("───────────────────────────────\n\n")

	// Security Checks
	sb.WriteString(fmt.Sprintf("%sSecurity Checks:%s\n", ColorBlue, ColorReset))
	sb.WriteString("───────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("Query Restrictions: %s\n", r.Restrictions))
	if r.MonlistVuln {
		sb.WriteString(fmt.Sprintf("%s[!] Monlist Vulnerable (CVE-2013-5211)%s\n", ColorRed, ColorReset))
		sb.WriteString(fmt.Sprintf("%s\n", r.MonlistDetails))
	} else {
		sb.WriteString(fmt.Sprintf("%s[-] Monlist Not Vulnerable%s\n", ColorYellow, ColorReset))
	}
	if r.ControlQueryVuln {
		sb.WriteString(fmt.Sprintf("%s[!] Control Query (Mode 6) Allowed - Info Leak Risk%s\n", ColorRed, ColorReset))
		sb.WriteString(fmt.Sprintf("%s\n", r.ControlQueryDetails))
	} else {
		sb.WriteString(fmt.Sprintf("%s[-] Control Query Disabled%s\n", ColorYellow, ColorReset))
	}
	if r.AmplificationFactor > 1 {
		sb.WriteString(fmt.Sprintf("%s[!] Amplification Factor: %.1fx (Potential DDoS Risk)%s\n", ColorRed, r.AmplificationFactor, ColorReset))
	} else {
		sb.WriteString(fmt.Sprintf("%s[-] No Significant Amplification%s\n", ColorYellow, ColorReset))
	}
	sb.WriteString("───────────────────────────────\n")

	sb.WriteString(fmt.Sprintf("%s═══════════════════════════════════════════════════════════%s\n", ColorCyan, ColorReset))
	return sb.String()
}

