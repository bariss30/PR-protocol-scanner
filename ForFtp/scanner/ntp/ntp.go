package ntp

import (
	"FORFTP/utils"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

type NTPResult struct {
	Target      string
	Reachable   bool
	Stratum     uint8
	ReferenceID uint32
	Error       string
}

func (r NTPResult) String() string {
	if r.Error != "" {
		return fmt.Sprintf("%s %s %s", utils.Colorize("✗", utils.ColorRed), utils.BoldText("NTP Hata:"), utils.Colorize(r.Error, utils.ColorRed))
	}
	status := "unreachable"
	if r.Reachable {
		status = "reachable"
	}
	return fmt.Sprintf("%s %s stratum=%d ref=0x%08x", utils.BoldText(utils.Colorize("NTP", utils.ColorCyan)), utils.Colorize(status, utils.ColorGreen), r.Stratum, r.ReferenceID)
}

func ScanNTP(target string, timeout time.Duration) NTPResult {
	addr := fmt.Sprintf("%s:%d", target, 123)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return NTPResult{Target: target, Error: err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	req := make([]byte, 48)
	// LI=0, VN=4, Mode=3 (client)
	req[0] = 0x23
	if _, err := conn.Write(req); err != nil {
		return NTPResult{Target: target, Error: err.Error()}
	}

	resp := make([]byte, 48)
	n, err := conn.Read(resp)
	if err != nil || n < 48 {
		return NTPResult{Target: target, Reachable: false, Error: "no response"}
	}

	stratum := resp[1]
	refID := binary.BigEndian.Uint32(resp[12:16])
	return NTPResult{Target: target, Reachable: true, Stratum: stratum, ReferenceID: refID}
}
