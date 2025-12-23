package ipmi

import (
	"SOREERS/utils"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

type IPMIResult struct {
	Target     string
	Reachable  bool
	ASFPresent bool
	Error      string
}

func (r IPMIResult) String() string {
	if r.Error != "" {
		return fmt.Sprintf("%s %s %s", utils.Colorize("✗", utils.ColorRed), utils.BoldText("IPMI Hata:"), utils.Colorize(r.Error, utils.ColorRed))
	}
	return fmt.Sprintf("%s reachable=%v asf=%v", utils.BoldText(utils.Colorize("IPMI", utils.ColorCyan)), r.Reachable, r.ASFPresent)
}

// ScanIPMI sends an RMCP ping to UDP 623 and checks for ASF presence
func ScanIPMI(target string, timeout time.Duration) IPMIResult {
	addr := fmt.Sprintf("%s:%d", target, 623)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return IPMIResult{Target: target, Error: err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// RMCP ASF Ping (per DMTF ASF v2.0):
	// RMCP Header (4 bytes): Version=0x06, Reserved=0x00, Seq=0xff, Class=0x06 (ASF)
	// ASF Message: IANA(0x000011be), Type=0x80 (Ping), Tag=0x00, Reserved=0x00, DataLength=0x00
	req := make([]byte, 4+8)
	req[0] = 0x06
	req[1] = 0x00
	req[2] = 0xff
	req[3] = 0x06
	// IANA Enterprise Number for DMTF: 0x000011be (big endian)
	binary.BigEndian.PutUint32(req[4:8], 0x000011be)
	req[8] = 0x80  // Ping
	req[9] = 0x00  // Tag
	req[10] = 0x00 // Reserved
	req[11] = 0x00 // DataLength

	if _, err := conn.Write(req); err != nil {
		return IPMIResult{Target: target, Error: err.Error()}
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return IPMIResult{Target: target, Reachable: false, ASFPresent: false}
	}

	asf := n >= 12 && buf[0] == 0x06 && buf[3] == 0x06
	return IPMIResult{Target: target, Reachable: true, ASFPresent: asf}
}
