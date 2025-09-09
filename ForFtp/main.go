package main

import (
	"FORFTP/scanner/ftp"
	"FORFTP/scanner/imap"
	"FORFTP/scanner/ipmi"
	ldapscan "FORFTP/scanner/ldap"
	mysqlscan "FORFTP/scanner/mysql"
	"FORFTP/scanner/nfs"
	"FORFTP/scanner/ntp"
	pop3scan "FORFTP/scanner/pop3"
	"FORFTP/scanner/redis"
	"FORFTP/scanner/smb"
	"FORFTP/scanner/snmp"
	"FORFTP/scanner/telnet"
	"FORFTP/scanner/vnc"
	"FORFTP/utils"
	"flag"
	"fmt"

	//"net"
	"os"
	"strings"
	"time"
)

type FTPJob struct {
	Target   string
	Username string
	Password string
}

type FTPResult struct {
	Job     FTPJob
	Success bool
	Err     error
}

type ScanConfig struct {
	Protocol    string
	Targets     []string
	Timeout     time.Duration
	Concurrency int
	Credentials CredentialConfig
}

type CredentialConfig struct {
	Username  string
	Password  string
	UserList  string
	PassList  string
	Anonymous bool
}

func main() {
	printBanner()
	protocol := flag.String("protocol", "ftp", "Kullanılacak protokol (ftp, smb, nfs, snmp, pop3, imap)")
	ip := flag.String("t", "", "Hedef IP adresi")
	ipList := flag.String("T", "", "IP adreslerinin bulunduğu dosya")
	timeout := flag.Int("timeout", 5, "Zaman aşımı süresi (saniye)")

	user := flag.String("u", "", "Tek kullanıcı adı")
	pass := flag.String("p", "", "Tek şifre")
	userList := flag.String("U", "", "Kullanıcı adı listesi dosyası")
	passList := flag.String("P", "", "Şifre listesi dosyası")
	anon := flag.Bool("A", false, "Anonim FTP giriş denemesi")
	help := flag.Bool("h", false, "Yardım")
	concurrency := flag.Int("c", 10, "Eşzamanlı çalışma sayısı (goroutine sayısı)")

	flag.Parse()
	for _, arg := range os.Args[1:] {
		if arg == "--help" {
			printHelp()
			return
		}
	}
	if *help {
		printHelp()
		return
	}

	if *ip == "" && *ipList == "" {
		fmt.Println("[-] Hedef IP veya IP listesi dosyası belirtilmeli (-t veya -T)")
		return
	}

	var targets []string
	if *ip != "" {
		targets = append(targets, *ip)
	} else if *ipList != "" {
		lines, err := utils.ReadLines(*ipList)
		if err != nil {
			fmt.Println("[-] IP listesi okunamadı:", err)
			os.Exit(1)
		}
		targets = lines
	}

	config := ScanConfig{
		Protocol:    *protocol,
		Targets:     targets,
		Timeout:     time.Duration(*timeout) * time.Second,
		Concurrency: *concurrency,
		Credentials: CredentialConfig{
			Username:  *user,
			Password:  *pass,
			UserList:  *userList,
			PassList:  *passList,
			Anonymous: *anon,
		},
	}

	switch config.Protocol {
	case "ftp":
		if err := runFTP(&config); err != nil {
			fmt.Println("[-] FTP taraması sırasında hata oluştu:", err)
			os.Exit(1)
		}
	case "redis":
		fmt.Println("[*] Redis taraması başlatılıyor...")
		target := config.Targets[0]

		res := redis.ScanRedis(target, config.Timeout)
		fmt.Println(res.String())

		if config.Credentials.UserList != "" && config.Credentials.PassList != "" {
			users, _ := getUsers(config.Credentials)
			passwords, _ := getPasswords(config.Credentials)

			fmt.Println("[*] Redis brute force başlatılıyor...")
			bruteResults := redis.BruteForceRedis(target, users, passwords, config.Timeout, config.Concurrency)

			successCount := 0
			for _, r := range bruteResults {
				if r.Success {
					successCount++
					fmt.Printf("%s[+] Başarılı giriş: %s:%s%s\n", utils.Green, r.Username, r.Password, utils.Reset)
				} else {
					fmt.Printf("%s[-] Başarısız giriş: %s:%s%s\n", utils.Red, r.Username, r.Password, utils.Reset)
				}
			}
			fmt.Printf("[*] Brute force tamamlandı. Toplam başarılı giriş: %d\n", successCount)
		}
	case "ldap":
		target := config.Targets[0]
		fmt.Println("[*] LDAP taraması başlatılıyor:", target)

		result := ldapscan.ScanLDAP(target, config.Timeout)
		fmt.Println(result.String())

		if config.Credentials.UserList != "" && config.Credentials.PassList != "" {
			users, _ := getUsers(config.Credentials)
			passwords, _ := getPasswords(config.Credentials)
			fmt.Println("[*] LDAP brute force başlatılıyor...")
			ldapResults := ldapscan.BruteForceLDAP(target, users, passwords, config.Timeout)

			successCount := 0
			for _, r := range ldapResults {
				if r.Error == "" {
					successCount++
				}
			}
			fmt.Printf("[*] LDAP brute force tamamlandı. Toplam başarılı giriş: %d\n", successCount)
		}
	case "mysql":
		target := config.Targets[0]
		fmt.Println("[*] MySQL taraması başlatılıyor:", target)

		// Sürüm taraması
		result := mysqlscan.ScanMySQL(target, config.Credentials.Username, config.Credentials.Password, config.Timeout)
		if result.Error != "" {
			fmt.Println("[-] Hata:", result.Error)
		} else {
			fmt.Printf("[+] MySQL version: %s\n", result.Version)
		}

		// Brute force
		if config.Credentials.UserList != "" && config.Credentials.PassList != "" {
			users, _ := getUsers(config.Credentials)
			passwords, _ := getPasswords(config.Credentials)
			fmt.Println("[*] MySQL brute force başlatılıyor...")
			mysqlscan.BruteForceMySQL(target, users, passwords, config.Timeout)
		}

	case "smb":
		target := config.Targets[0]
		port := 445

		result := smb.ScanSMB(target, port, config.Timeout)
		fmt.Println(result.String())

		if config.Credentials.UserList != "" && config.Credentials.PassList != "" {
			fmt.Println("[*] Brute force başlatılıyor...")

			found, err := smb.SMBBruteForce(target, port, config.Credentials.UserList, config.Credentials.PassList, config.Timeout)
			if err != nil {
				fmt.Println("Hata:", err)
			} else if len(found) > 0 {
				fmt.Println("Bulunan hesaplar:")
				for _, combo := range found {
					fmt.Println("   ", combo)
				}
			} else {
				fmt.Println("[-] Hiçbir kullanıcı/şifre kombinasyonu başarılı olmadı.")
			}
		}

	case "nfs":
		if err := runNFS(&config); err != nil {
			fmt.Println("[-] NFS tarama sırasında hata oluştu:", err)
			os.Exit(1)
		}
	case "snmp":
		if err := runSNMP(&config); err != nil {
			fmt.Println("[-] SNMP tarama sırasında hata oluştu:", err)
			os.Exit(1)
		}
	case "pop3":
		res := pop3scan.ScanPOP3(config.Targets[0], config.Timeout)
		fmt.Println(res.String())
	case "imap":
		results := imap.RunIMAP(config.Targets[0], int(config.Timeout/time.Second))
		for _, r := range results {
			fmt.Println(r.String())
		}
	case "vnc":
		users, err := getUsers(config.Credentials)
		if err != nil {
			fmt.Println("[-] Kullanıcı listesi okunamadı:", err)
			break
		}
		passwords, err := getPasswords(config.Credentials)
		if err != nil {
			fmt.Println("[-] Şifre listesi okunamadı:", err)
			break
		}

		fmt.Printf("[*] VNC taraması başlatılıyor: %s\n", config.Targets[0])
		vncRes := vnc.ScanVNC(config.Targets[0], config.Timeout)
		fmt.Println(vncRes.String())

		// Eğer VNC auth destekliyorsa brute force başlat
		if vncRes.SupportsVNCAuth {
			fmt.Println("[*] Brute force başlatılıyor...")
			bruteResults := vnc.BruteForceVNCWithUsers(config.Targets[0], users, passwords, config.Timeout, config.Concurrency)

			successCount := 0
			for _, r := range bruteResults {
				if r.Success {
					successCount++
					fmt.Printf("%s[+] Başarılı giriş: %s:%s%s\n", utils.Green, r.Username, r.Password, utils.Reset)
				} else {
					fmt.Printf("%s[-] Başarısız giriş: %s:%s%s\n", utils.Red, r.Username, r.Password, utils.Reset)
				}
			}
			fmt.Printf("[*] Brute force tamamlandı. Toplam başarılı giriş: %d\n", successCount)
		} else {
			fmt.Println("[*] VNC Authentication desteklenmiyor veya yalnızca NoAuth mevcut, brute force atlanıyor.")
		}
	case "ntp":
		res := ntp.ScanNTP(config.Targets[0], config.Timeout)
		fmt.Println(res.String())
	case "telnet":
		// Banner okuma veya minimal kontrol
		fmt.Println("[*] Telnet taraması başlatılıyor...")
		fmt.Printf("[*] Hedef: %s, Port: 23\n", config.Targets[0])

		if config.Credentials.UserList != "" && config.Credentials.PassList != "" {
			users, _ := getUsers(config.Credentials)
			passwords, _ := getPasswords(config.Credentials)

			fmt.Println("[*] Telnet brute force başlatılıyor...")
			// Capture both return values, ignore stats with _
			found, _ := telnet.TelnetBruteForceConcurrent(config.Targets[0], 23, users, passwords, 3*time.Second, 5)

			if len(found) > 0 {
				fmt.Println("[+] Bulunan geçerli hesaplar:")
				for _, c := range found {
					fmt.Println("   ", c)
				}
			} else {
				fmt.Println("[-] Hiçbir kombinasyon başarılı olmadı.")
			}
		}

	case "ipmi":
		res := ipmi.ScanIPMI(config.Targets[0], config.Timeout)
		fmt.Println(res.String())

	default:
		fmt.Println("[-] Desteklenmeyen protokol! Sadece ftp, smb, nfs, snmp, pop3 ve imap desteklenmektedir.")
		os.Exit(1)
	}
}

func runFTP(config *ScanConfig) error {
	for _, target := range config.Targets {
		result := &ftp.FTPResult{
			Target: target,
			Port:   21,
		}

		banner, err := ftp.GetVersion(target, 21, config.Timeout)
		if err != nil {
			result.ErrorMessage = fmt.Sprintf("Banner alınamadı: %v", err)
		} else {
			result.Banner = banner
		}

		ok, err := ftp.SupportsExplicitTLS(target, 21, config.Timeout)
		if err != nil {
			result.ExplicitTLSSupp = false
		} else {
			result.ExplicitTLSSupp = ok
		}

		if config.Credentials.Anonymous {
			result.LoginAttempted = true
			result.Username = "anonymous"
			result.Password = "anonymous"
			ok, err := ftp.FTPLogin(target, 21, "anonymous", "anonymous", config.Timeout)
			result.LoginSuccess = ok
			if err != nil {
				result.ErrorMessage = fmt.Sprintf("Anonim login hatası: %v", err)
			}
			fmt.Println(result.String())
		}

		if config.Credentials.Username != "" && config.Credentials.Password != "" {
			result.LoginAttempted = true
			result.Username = config.Credentials.Username
			result.Password = config.Credentials.Password
			ok, err := ftp.SingleLogin(target, result.Username, result.Password, config.Timeout)
			result.LoginSuccess = ok
			if err != nil {
				result.ErrorMessage = fmt.Sprintf("Tek giriş hatası: %v", err)
			}
			fmt.Println(result.String())
		}

		hasUser := config.Credentials.Username != "" || config.Credentials.UserList != ""
		hasPass := config.Credentials.Password != "" || config.Credentials.PassList != ""
		if !hasUser || !hasPass {
			fmt.Println("[*] Kullanıcı adı veya şifre bilgisi sağlanmadığı için brute force atlanıyor.")
			continue
		}

		users, err := getUsers(config.Credentials)
		if err != nil {
			fmt.Printf("[-] Kullanıcı adı alınamadı: %v\n", err)
			continue
		}
		passwords, err := getPasswords(config.Credentials)
		if err != nil {
			fmt.Printf("[-] Şifre alınamadı: %v\n", err)
			continue
		}

		jobs := make(chan FTPJob)
		results := make(chan ftp.FTPResult)
		workerCount := config.Concurrency

		for i := 0; i < workerCount; i++ {
			go func() {
				for job := range jobs {
					ok, err := ftp.FTPLogin(job.Target, 21, job.Username, job.Password, config.Timeout)
					results <- ftp.FTPResult{
						Target:         job.Target,
						Port:           21,
						LoginAttempted: true,
						LoginSuccess:   ok,
						Username:       job.Username,
						Password:       job.Password,
						ErrorMessage: func() string {
							if err != nil {
								return err.Error()
							} else {
								return ""
							}
						}(),
					}
				}
			}()
		}

		go func() {
			for _, user := range users {
				for _, pass := range passwords {
					jobs <- FTPJob{Target: target, Username: user, Password: pass}
				}
			}
			close(jobs)
		}()

		totalJobs := len(users) * len(passwords)
		for i := 0; i < totalJobs; i++ {
			res := <-results
			fmt.Println(res.String())
		}
	}
	return nil
}

func runFTPAnonymous(config *ScanConfig) error {
	for _, target := range config.Targets {
		ok, err := ftp.FTPLogin(target, 21, "anonymous", "anonymous", config.Timeout)
		if ok {
			fmt.Printf("%s[+] FTP ANONYMOUS LOGIN başarılı: %s%s\n", utils.Green, target, utils.Reset)
		} else {
			if err != nil {
				fmt.Printf("%s[-] FTP ANONYMOUS LOGIN başarısız: %s -- Hata: %s%s\n", utils.Red, target, err.Error(), utils.Reset)
			} else {
				fmt.Printf("%s[-] FTP ANONYMOUS LOGIN başarısız: %s%s\n", utils.Red, target, utils.Reset)
			}
		}
	}
	return nil
}

func runFTPSingleLogin(config *ScanConfig, username, password string) error {
	for _, target := range config.Targets {
		ok, err := ftp.SingleLogin(target, username, password, config.Timeout)
		if ok {
			fmt.Printf("%s[+] TEK GİRİŞ başarılı: %s %s:%s%s\n", utils.Green, target, username, password, utils.Reset)
		} else {
			if err != nil {
				fmt.Printf("%s[-] TEK GİRİŞ başarısız: %s %s:%s -- Hata: %s%s\n", utils.Red, target, username, password, err.Error(), utils.Reset)
			} else {
				fmt.Printf("%s[-] TEK GİRİŞ başarısız: %s %s:%s%s\n", utils.Red, target, username, password, utils.Reset)
			}
		}
	}
	return nil
}

func runFTPBruteforceConcurrent(config *ScanConfig, users, passwords []string) error {
	jobs := make(chan FTPJob)
	results := make(chan FTPResult)

	workerCount := config.Concurrency

	for i := 0; i < workerCount; i++ {
		go func() {
			for job := range jobs {
				ok, err := ftp.FTPLogin(job.Target, 21, job.Username, job.Password, config.Timeout)
				results <- FTPResult{Job: job, Success: ok, Err: err}
			}
		}()
	}

	go func() {
		for _, target := range config.Targets {
			for _, user := range users {
				for _, pass := range passwords {
					jobs <- FTPJob{Target: target, Username: user, Password: pass}
				}
			}
		}
		close(jobs)
	}()

	totalJobs := len(config.Targets) * len(users) * len(passwords)
	for i := 0; i < totalJobs; i++ {
		res := <-results
		if res.Success {
			fmt.Printf("%s[+] FTP GİRİŞ başarılı: %s %s:%s%s\n", utils.Green, res.Job.Target, res.Job.Username, res.Job.Password, utils.Reset)
		} else {
			if res.Err != nil {
				fmt.Printf("%s[-] FTP GİRİŞ başarısız: %s %s:%s -- Hata: %s%s\n", utils.Red, res.Job.Target, res.Job.Username, res.Job.Password, res.Err.Error(), utils.Reset)
			} else {
				fmt.Printf("%s[-] FTP GİRİŞ başarısız: %s %s:%s%s\n", utils.Red, res.Job.Target, res.Job.Username, res.Job.Password, utils.Reset)
			}
		}
	}
	return nil
}

func getUsers(creds CredentialConfig) ([]string, error) {
	if creds.Username != "" {
		return []string{creds.Username}, nil
	}
	if creds.UserList != "" {
		return utils.ReadLines(creds.UserList)
	}
	return []string{}, nil
}

func getPasswords(creds CredentialConfig) ([]string, error) {
	if creds.Password != "" {
		return []string{creds.Password}, nil
	}
	if creds.PassList != "" {
		return utils.ReadLines(creds.PassList)
	}
	return []string{}, nil
}

func printHelp() {
	cReset := "\033[0m"
	cBold := "\033[1m"
	cCyan := "\033[36m"
	cYellow := "\033[33m"
	cGreen := "\033[32m"
	cRed := "\033[31m"

	fmt.Println(cBold + cCyan + "Enhanced Multi-Protocol Vulnerability Scanner" + cReset)
	fmt.Println(cCyan + "================================================" + cReset)
	fmt.Println()

	fmt.Println(cBold + "Usage:" + cReset)
	fmt.Println("  forftp.exe -protocol <protocol> [options]")
	fmt.Println()

	fmt.Println(cBold + "Available Protocols:" + cReset)
	fmt.Println("  " + cYellow + "ftp" + cReset + "     - FTP vulnerability scanning")
	fmt.Println("  " + cYellow + "smb" + cReset + "     - SMB vulnerability scanning")
	fmt.Println("  " + cYellow + "nfs" + cReset + "     - NFS vulnerability scanning")
	fmt.Println("  " + cYellow + "snmp" + cReset + "    - SNMP vulnerability scanning")
	fmt.Println("  " + cYellow + "imap" + cReset + "    - IMAP enumeration")
	fmt.Println("  " + cYellow + "ipmi" + cReset + "    - IPMI testing")
	fmt.Println("  " + cYellow + "ldap" + cReset + "    - LDAP authentication testing")
	fmt.Println("  " + cYellow + "mysql" + cReset + "   - MySQL brute force / info gathering")
	fmt.Println("  " + cYellow + "ntp" + cReset + "     - NTP server enumeration")
	fmt.Println("  " + cYellow + "pop3" + cReset + "    - POP3 authentication testing")
	fmt.Println("  " + cYellow + "redis" + cReset + "   - Redis info and auth testing")
	fmt.Println("  " + cYellow + "sip" + cReset + "     - SIP enumeration")
	fmt.Println("  " + cYellow + "telnet" + cReset + "  - Telnet brute force / banners")
	fmt.Println("  " + cYellow + "vnc" + cReset + "     - VNC authentication testing")
	fmt.Println()

	fmt.Println(cBold + "Target Options:" + cReset)
	fmt.Println("  -t <IP>           - Single target IP address")
	fmt.Println("  -T <file>         - File containing list of IP addresses")
	fmt.Println()

	fmt.Println(cBold + "Credential Options:" + cReset)
	fmt.Println("  -u <username>     - Single username")
	fmt.Println("  -p <password>     - Single password")
	fmt.Println("  -U <file>         - File containing usernames")
	fmt.Println("  -P <file>         - File containing passwords")
	fmt.Println("  -A                - Test anonymous login (FTP/SMB)")
	fmt.Println()

	fmt.Println(cBold + "Scan Options:" + cReset)
	fmt.Println("  -c <number>       - Number of concurrent workers (default: 10)")
	fmt.Println("  -timeout <sec>    - Connection timeout in seconds (default: 5)")
	fmt.Println("  -h                - Show this help message")
	fmt.Println()

	fmt.Println(cBold + "Examples:" + cReset)
	fmt.Println(cGreen + "  # LDAP scan with user/password files" + cReset)
	fmt.Println("  forftp.exe -protocol ldap -t 192.168.222.129 -U users.txt -P pass.txt")
	fmt.Println()
	fmt.Println(cGreen + "  # SMB scan with anonymous login" + cReset)
	fmt.Println("  forftp.exe -protocol smb -t 192.168.1.1 -A")
	fmt.Println()
	fmt.Println(cGreen + "  # VNC brute force" + cReset)
	fmt.Println("  forftp.exe -protocol vnc -t 192.168.1.1 -U users.txt -P pass.txt")
	fmt.Println()
	fmt.Println(cRed + cBold + "Note: Use responsibly and only on systems you own or have permission to test." + cReset)
}

func runNFS(config *ScanConfig) error {
	fmt.Println("[*] NFS taraması başlatıldı.")

	for _, target := range config.Targets {
		result := nfs.ScanNFS(target, config.Timeout)
		fmt.Println(result.String())
	}

	return nil
}

func runSNMP(config *ScanConfig) error {
	fmt.Println("[*] SNMP taraması başlatıldı.")

	for _, target := range config.Targets {
		fmt.Printf("\n[*] Scanning target: %s\n", target)
		fmt.Println("=" + strings.Repeat("=", len(target)+20))

		fmt.Println("\n[1] SNMP Version Enumeration and Community Discovery")
		fmt.Println("-" + strings.Repeat("-", 50))
		result := snmp.ScanSNMPComprehensive(target, 161, config.Timeout)
		if result.ErrorMessage != "" {
			fmt.Printf("[-] SNMP scan failed: %s\n", result.ErrorMessage)
			continue
		}

		fmt.Printf("[+] SNMP Version: %s\n", result.Version)

		fmt.Println("\n[2] Community String Enumeration")
		fmt.Println("-" + strings.Repeat("-", 30))
		if len(result.Communities) > 0 {
			fmt.Printf("[+] Found %d community strings:\n", len(result.Communities))
			for i, community := range result.Communities {
				fmt.Printf("    %d. %s - Access: %s (RO:%v, RW:%v)\n",
					i+1, community.Name, community.Access, community.ReadOnly, community.ReadWrite)
			}
		} else {
			fmt.Println("[-] No community strings found")
		}

		fmt.Println("\n[3] System Information")
		fmt.Println("-" + strings.Repeat("-", 20))
		if result.SystemInfo.SysDescr != "" {
			fmt.Printf("[+] System Description: %s\n", result.SystemInfo.SysDescr)
		}
		if result.SystemInfo.SysName != "" {
			fmt.Printf("[+] System Name: %s\n", result.SystemInfo.SysName)
		}
		if result.SystemInfo.SysContact != "" {
			fmt.Printf("[+] System Contact: %s\n", result.SystemInfo.SysContact)
		}
		if result.SystemInfo.SysLocation != "" {
			fmt.Printf("[+] System Location: %s\n", result.SystemInfo.SysLocation)
		}
		if result.SystemInfo.SysObjectID != "" {
			fmt.Printf("[+] System Object ID: %s\n", result.SystemInfo.SysObjectID)
		}
		if result.SystemInfo.SysUpTime != "" {
			fmt.Printf("[+] System Up Time: %s\n", result.SystemInfo.SysUpTime)
		}

		fmt.Println("\n[4] SNMP Walk Results")
		fmt.Println("-" + strings.Repeat("-", 20))
		if len(result.OIDs) > 0 {
			fmt.Printf("[+] Found %d OIDs:\n", len(result.OIDs))
			for i, oid := range result.OIDs {
				if i < 10 {
					fmt.Printf("    %d. %s = %s (%s)\n",
						i+1, oid.OID, oid.Value, oid.Description)
				}
			}
			if len(result.OIDs) > 10 {
				fmt.Printf("    ... and %d more OIDs\n", len(result.OIDs)-10)
			}
		} else {
			fmt.Println("[-] No OIDs found during walk")
		}

		fmt.Println("\n[5] Vulnerability Analysis")
		fmt.Println("-" + strings.Repeat("-", 25))
		if len(result.Vulnerabilities) > 0 {
			fmt.Printf("[+] Found %d vulnerabilities:\n", len(result.Vulnerabilities))
			for i, vuln := range result.Vulnerabilities {
				fmt.Printf("    %d. [%s] %s: %s\n",
					i+1, vuln.Severity, vuln.Type, vuln.Description)
				if vuln.Details != "" {
					fmt.Printf("        Details: %s\n", vuln.Details)
				}
			}
		} else {
			fmt.Println("[+] No vulnerabilities detected")
		}

		if len(result.Communities) == 0 {
			fmt.Println("\n[6] Brute Force Community Strings")
			fmt.Println("-" + strings.Repeat("-", 35))
			fmt.Printf("[*] No communities found, attempting brute force...\n")

			communities := []string{
				"public", "private", "community", "admin", "cisco", "hp", "3com",
				"read", "write", "manager", "monitor", "guest", "test", "demo",
				"default", "system", "network", "security", "snmp", "trap",
			}

			bruteResults := snmp.BruteForceSNMP(target, communities, config.Timeout)
			if len(bruteResults) > 0 {
				fmt.Printf("[+] Brute force found %d community strings\n", len(bruteResults))
				for _, comm := range bruteResults {
					fmt.Printf("    - %s (%s)\n", comm.Name, comm.Access)
				}
			} else {
				fmt.Println("[-] Brute force failed to find any community strings")
			}
		}

		fmt.Println("\n[7] Security Recommendations")
		fmt.Println("-" + strings.Repeat("-", 30))
		provideSNMPSecurityRecommendations(result)

		fmt.Println("\n" + strings.Repeat("=", 50))
	}
	return nil
}

func provideSNMPSecurityRecommendations(result *snmp.SNMPResult) {
	recommendations := []string{}

	if strings.Contains(result.Version, "SNMPv1") {
		recommendations = append(recommendations, "• Upgrade to SNMPv3 - SNMPv1 is insecure")
	}

	for _, community := range result.Communities {
		if isDefaultSNMPCommunity(community.Name) {
			recommendations = append(recommendations, fmt.Sprintf("• Change default community string '%s'", community.Name))
		}
		if community.ReadWrite {
			recommendations = append(recommendations, fmt.Sprintf("• Restrict write access for community '%s'", community.Name))
		}
	}

	if result.SystemInfo.SysContact != "" {
		recommendations = append(recommendations, "• Review system contact information exposure")
	}
	if result.SystemInfo.SysLocation != "" {
		recommendations = append(recommendations, "• Review system location information exposure")
	}

	if len(recommendations) == 0 {
		fmt.Println("[+] No immediate security issues detected")
	} else {
		fmt.Println("Security recommendations:")
		for _, rec := range recommendations {
			fmt.Printf("  %s\n", rec)
		}
	}
}

func isDefaultSNMPCommunity(community string) bool {
	defaults := []string{"public", "private", "community", "admin", "cisco", "hp", "3com"}
	for _, def := range defaults {
		if strings.ToLower(community) == def {
			return true
		}
	}
	return false
}

func printBanner() {
	fmt.Println(
		utils.BoldText(utils.Colorize("╔════════════════════════════════════════════════════════════════════════╗", utils.ColorCyan)))
	fmt.Println(
		utils.BoldText(utils.Colorize("║                                                                    ║", utils.ColorCyan)))
	fmt.Println(
		utils.BoldText(utils.Colorize("║   ███████╗ ██████╗ ██████╗ ███████╗███████╗██████╗ ███████╗        ║", utils.ColorCyan)))
	fmt.Println(
		utils.BoldText(utils.Colorize("║   ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝        ║", utils.ColorCyan)))
	fmt.Println(
		utils.BoldText(utils.Colorize("║   ███████╗██║   ██║██████╔╝█████╗  █████╗  ██████╔╝███████╗        ║", utils.ColorCyan)))
	fmt.Println(
		utils.BoldText(utils.Colorize("║   ╚════██║██║   ██║██╔══██╗██╔══╝  ██╔══╝  ██╔══██╗╚════██║        ║", utils.ColorCyan)))
	fmt.Println(
		utils.BoldText(utils.Colorize("║   ███████║╚██████╔╝██║  ██║███████╗███████╗██║  ██║███████║        ║", utils.ColorCyan)))
	fmt.Println(
		utils.BoldText(utils.Colorize("║   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝        ║", utils.ColorCyan)))
	fmt.Println(
		utils.BoldText(utils.Colorize("║                                                                    ║", utils.ColorCyan)))
	fmt.Println(
		utils.BoldText(utils.Colorize("║   FORFTP - Multi Protocol Vulnerability Scanner                    ║", utils.ColorYellow)))
	fmt.Println(
		utils.BoldText(utils.Colorize("║   Author: Privia | github.com/Privia                               ║", utils.ColorYellow)))
	fmt.Println(
		utils.BoldText(utils.Colorize("║   Supported: FTP, SMB, NFS, SNMP, POP3, IMAP ...                   ║", utils.ColorYellow)))
	fmt.Println(
		utils.BoldText(utils.Colorize("║                                                                    ║", utils.ColorCyan)))
	fmt.Println(
		utils.BoldText(utils.Colorize("╚════════════════════════════════════════════════════════════════════════╝", utils.ColorCyan)))
	fmt.Println()
}
