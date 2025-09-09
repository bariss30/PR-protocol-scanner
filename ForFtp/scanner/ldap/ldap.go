package ldapscan

import (
	"FORFTP/utils"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type LDAPResult struct {
	Target         string
	AnonymousBind  bool
	SupportedSASL  []string
	NamingContexts []string
	Version        string
	Vendor         string
	Schema         string
	Error          string
}

func (r LDAPResult) String() string {
	var b strings.Builder

	b.WriteString(utils.BoldText(utils.Colorize("LDAP", utils.ColorCyan)))
	b.WriteString(" ")
	b.WriteString(utils.Colorize(r.Target, utils.ColorYellow))
	b.WriteString(" | ")

	if r.AnonymousBind {
		b.WriteString(utils.Colorize("ANON: true", utils.ColorGreen))
	} else {
		b.WriteString(utils.Colorize("ANON: false", utils.ColorRed))
	}

	if len(r.NamingContexts) > 0 {
		b.WriteString(" | Contexts: ")
		b.WriteString(utils.Colorize(strings.Join(r.NamingContexts, ","), utils.ColorMagenta))
	}

	if len(r.SupportedSASL) > 0 {
		b.WriteString(" | SASL: ")
		b.WriteString(utils.Colorize(strings.Join(r.SupportedSASL, ","), utils.ColorBlue))
	}

	if r.Version != "" {
		b.WriteString(" | Version: ")
		b.WriteString(utils.Colorize(r.Version, utils.ColorCyan))
	}

	if r.Vendor != "" {
		b.WriteString(" | Vendor: ")
		b.WriteString(utils.Colorize(r.Vendor, utils.ColorCyan))
	}

	if r.Schema != "" {
		b.WriteString(" | Schema: ")
		b.WriteString(utils.Colorize(r.Schema, utils.ColorCyan))
	}

	if r.Error != "" {
		b.WriteString("\n")
		b.WriteString(utils.Colorize("✗ LDAP Error: "+r.Error, utils.ColorRed))
	}

	return b.String()
}

func ScanLDAP(target string, timeout time.Duration) LDAPResult {
	url := fmt.Sprintf("ldap://%s:389", target)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := ldap.DialURL(url, ldap.DialWithDialer(dialer))
	if err != nil {
		return LDAPResult{Target: target, Error: err.Error()}
	}
	defer conn.Close()

	conn.SetTimeout(timeout)

	anonOK := false
	if err := conn.UnauthenticatedBind(""); err == nil {
		anonOK = true
	}

	// RootDSE sorgusu ile daha fazla bilgi al
	searchReq := ldap.NewSearchRequest(
		"", // RootDSE
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, int(timeout/time.Second), false,
		"(objectClass=*)",
		[]string{
			"namingContexts",
			"supportedSASLMechanisms",
			"vendorName",
			"vendorVersion",
			"supportedLDAPVersion",
			"subschemaSubentry",
			"altServer",
		},
		nil,
	)

	res, err := conn.Search(searchReq)
	if err != nil {
		return LDAPResult{Target: target, AnonymousBind: anonOK, Error: err.Error()}
	}

	var contexts, sasl []string
	var version, vendor, schema string
	if len(res.Entries) > 0 {
		entry := res.Entries[0]
		contexts = entry.GetAttributeValues("namingContexts")
		sasl = entry.GetAttributeValues("supportedSASLMechanisms")
		version = strings.Join(entry.GetAttributeValues("supportedLDAPVersion"), ",")
		vendor = strings.Join(entry.GetAttributeValues("vendorName"), ",")
		schema = strings.Join(entry.GetAttributeValues("subschemaSubentry"), ",")
	}

	return LDAPResult{
		Target:         target,
		AnonymousBind:  anonOK,
		NamingContexts: contexts,
		SupportedSASL:  sasl,
		Version:        version,
		Vendor:         vendor,
		Schema:         schema,
	}
}

func BruteForceLDAP(target string, users, passwords []string, timeout time.Duration) []LDAPResult {
	var results []LDAPResult
	url := fmt.Sprintf("ldap://%s:389", target)

	utils.PrintBanner("[*] LDAP brute force başlatılıyor...")

	for _, user := range users {
		for _, pass := range passwords {
			dialer := &net.Dialer{Timeout: timeout}
			conn, err := ldap.DialURL(url, ldap.DialWithDialer(dialer))
			if err != nil {
				results = append(results, LDAPResult{Target: target, Error: err.Error()})
				continue
			}

			err = conn.Bind(user, pass)
			if err == nil {
				res := LDAPResult{
					Target:        target,
					AnonymousBind: false,
					Error:         "",
				}
				results = append(results, res)
				fmt.Println(utils.Colorize(fmt.Sprintf("[+] Başarılı LDAP login: %s:%s", user, pass), utils.ColorGreen))
			} else {
				results = append(results, LDAPResult{
					Target: target,
					Error:  fmt.Sprintf("Başarısız: %s:%s", user, pass),
				})
				fmt.Println(utils.Colorize(fmt.Sprintf("[-] Başarısız: %s:%s", user, pass), utils.ColorRed))
			}

			conn.Close()
		}
	}

	utils.PrintBanner("[*] LDAP brute force tamamlandı.")
	return results
}
