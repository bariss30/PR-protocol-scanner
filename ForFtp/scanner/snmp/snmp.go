package snmp

import (
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

type SNMPResult struct {
	Target      string
	Version     string
	Communities []string
	SystemInfo  map[string]string
	OIDs        []OIDInfo
	Error       error
}

type OIDInfo struct {
	OID         string
	Value       string
	Description string
}

func ScanSNMP(target string, port uint16, timeout time.Duration) *SNMPResult {
	result := &SNMPResult{
		Target:      target,
		Communities: []string{},
		SystemInfo:  map[string]string{},
		OIDs:        []OIDInfo{},
	}

	community := "public"
	params := &gosnmp.GoSNMP{
		Target:    target,
		Port:      port,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   1,
	}
	err := params.Connect()
	if err != nil {
		result.Error = fmt.Errorf("SNMP bağlantı hatası: %v", err)
		return result
	}
	defer params.Conn.Close()

	result.Version = "SNMPv2c"
	result.Communities = append(result.Communities, community)

	sysOIDs := map[string]string{
		"SysDescr":    ".1.3.6.1.2.1.1.1.0",
		"SysObjectID": ".1.3.6.1.2.1.1.2.0",
		"SysUpTime":   ".1.3.6.1.2.1.1.3.0",
		"SysContact":  ".1.3.6.1.2.1.1.4.0",
		"SysName":     ".1.3.6.1.2.1.1.5.0",
		"SysLocation": ".1.3.6.1.2.1.1.6.0",
	}

	for key, oid := range sysOIDs {
		pkt, err := params.Get([]string{oid})
		if err == nil && len(pkt.Variables) > 0 {
			val := pkt.Variables[0].Value
			if str, ok := val.(string); ok {
				result.SystemInfo[key] = str
			} else {
				result.SystemInfo[key] = fmt.Sprintf("%v", val)
			}
		}
	}

	walkOIDs := []string{".1.3.6.1.2.1.1"} // sadece system tablosu
	for _, walkOID := range walkOIDs {
		_ = params.Walk(walkOID, func(pdu gosnmp.SnmpPDU) error {
			val := fmt.Sprintf("%v", pdu.Value)
			result.OIDs = append(result.OIDs, OIDInfo{
				OID:         pdu.Name,
				Value:       val,
				Description: walkOID,
			})
			return nil
		})
	}

	return result
}

type SNMPCommunity struct {
	Name      string
	ReadWrite bool
	Access    string
}

func BruteForceSNMP(target string, port uint16, communities []string, timeout time.Duration) []SNMPCommunity {
	found := []SNMPCommunity{}
	for _, community := range communities {
		params := &gosnmp.GoSNMP{
			Target:    target,
			Port:      port,
			Community: community,
			Version:   gosnmp.Version2c,
			Timeout:   timeout,
			Retries:   1,
		}
		err := params.Connect()
		if err != nil {
			continue
		}
		defer params.Conn.Close()

		pkt, err := params.Get([]string{".1.3.6.1.2.1.1.1.0"})
		if err == nil && len(pkt.Variables) > 0 {
			found = append(found, SNMPCommunity{
				Name:      community,
				ReadWrite: false, // default
				Access:    "RO",  // default
			})
		}
	}
	return found
}

func ProvideSNMPSecurityRecommendations(result *SNMPResult) {
	fmt.Println("\n[Security Recommendations]")
	if result.Version == "SNMPv1" {
		fmt.Println(" • Upgrade to SNMPv3 - SNMPv1 is insecure")
	}
	for _, comm := range result.Communities {
		if comm == "public" || comm == "private" {
			fmt.Printf(" • Change default community string '%s'\n", comm)
		}
	}
}

// ANSI renkleri
const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Reset  = "\033[0m"
)

// byte array'i string'e çevirir
func bytesToString(val string) string {
	// val zaten fmt.Sprintf("%v", pdu.Value) ile string olmuşsa
	// format: [107 97 108 105] → temizle
	val = strings.Trim(val, "[]")
	parts := strings.Fields(val)
	var b []byte
	for _, p := range parts {
		var num int
		fmt.Sscanf(p, "%d", &num)
		b = append(b, byte(num))
	}
	return string(b)
}

func (r *SNMPResult) PrintReport() {
	fmt.Println(Cyan + "═══════════════════════════════════════" + Reset)
	fmt.Printf(Cyan+"Target: "+Reset+"%s\n", r.Target)
	fmt.Printf(Cyan+"Version: "+Reset+"%s\n", r.Version)

	fmt.Println(Cyan + "Communities Found:" + Reset)
	for _, comm := range r.Communities {
		fmt.Printf("  "+Green+"%s"+Reset+"\n", comm)
	}

	fmt.Println(Cyan + "System Info:" + Reset)
	for k, v := range r.SystemInfo {
		// ASCII çevirme
		fmt.Printf("  %s: %s\n", Yellow+k+Reset, bytesToString(v))
	}

	fmt.Println(Cyan + "OIDs:" + Reset)
	for _, oid := range r.OIDs {
		fmt.Printf("  %s -> %s\n", Green+oid.OID+Reset, bytesToString(oid.Value))
	}

	fmt.Println(Cyan + "═══════════════════════════════════════" + Reset)
}
