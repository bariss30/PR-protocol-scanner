package main

import (
	"SOREERS/scanner/ftp"
	"SOREERS/scanner/imap"
	"SOREERS/scanner/ipmi"
	ldapscan "SOREERS/scanner/ldap"
	mysqlscan "SOREERS/scanner/mysql"
	"SOREERS/scanner/nfs"
	"SOREERS/scanner/ntp"
	pop3scan "SOREERS/scanner/pop3"
	"SOREERS/scanner/redis"
	"SOREERS/scanner/smb"
	"SOREERS/scanner/snmp"
	"SOREERS/scanner/telnet"
	"SOREERS/scanner/vnc"
	"SOREERS/utils"
	"flag"
	"fmt"
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
	// 1. Flag Tanımları
	protocol := flag.String("protocol", "ftp", "Kullanılacak protokol")
	ip := flag.String("t", "", "Hedef IP adresi")
	ipList := flag.String("T", "", "IP listesi dosyası")
	timeout := flag.Int("timeout", 5, "Zaman aşımı (saniye)")
	concurrency := flag.Int("c", 10, "Eşzamanlı işlem sayısı")

	// Credential flags
	user := flag.String("u", "", "Kullanıcı adı")
	pass := flag.String("p", "", "Şifre")
	userList := flag.String("U", "", "Kullanıcı listesi")
	passList := flag.String("P", "", "Şifre listesi")
	anon := flag.Bool("A", false, "Anonim giriş")

	// Help flag'ini manuel tanımlamaya gerek yok ama kontrol için tutabiliriz
	// Go zaten -h ve --help'i otomatik algılar.

	// --- KRİTİK NOKTA: Varsayılan Help Mesajını Değiştirme ---
	// Bu satır, Go'nun standart 'Usage of...' çıktısı yerine senin fonksiyonunu kullanmasını sağlar.
	flag.Usage = func() {
		printHelp()
	}

	// 2. Flagleri İşle
	flag.Parse()

	// 3. Hiçbir parametre girilmediyse Help göster ve çık
	if flag.NFlag() == 0 {
		printHelp()
		os.Exit(0)
	}

	// 4. Hedef Kontrolü (IP veya Liste yoksa hata ver)
	if *ip == "" && *ipList == "" {
		fmt.Println(utils.Colorize("\n[!] HATA: Hedef belirtilmedi!", utils.ColorRed))
		fmt.Println("Lütfen bir hedef IP (-t) veya IP listesi (-T) belirtin.")
		fmt.Println("Yardım için: soreers.exe -h")
		os.Exit(1)
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
		fmt.Printf("[*] LDAP Taraması Başlatılıyor: %s\n", target)

		// 1. Kapsamlı Tarama
		result := ldapscan.ScanLDAP(target, config.Timeout)
		fmt.Println(result.String())

		// 2. Brute Force (Eğer kullanıcı/şifre listesi varsa)
		if config.Credentials.UserList != "" && config.Credentials.PassList != "" {
			users, _ := getUsers(config.Credentials)
			passwords, _ := getPasswords(config.Credentials)

			fmt.Println("[*] LDAP Brute Force başlatılıyor...")

			// DÜZELTME 1: config.Concurrency argümanı eklendi
			ldapResults := ldapscan.BruteForceLDAP(target, users, passwords, config.Timeout, config.Concurrency)

			successCount := 0
			if len(ldapResults) > 0 {
				fmt.Println("\n[+] Başarılı LDAP Girişleri:")
				for _, r := range ldapResults {
					// DÜZELTME 2: r.Error kontrolü yerine r.Success kullanılıyor
					if r.Success {
						successCount++
						fmt.Printf("%s    %s : %s%s\n", utils.Green, r.Username, r.Password, utils.Reset)
					}
				}
			} else {
				fmt.Println("[-] Hiçbir giriş başarılı olmadı.")
			}
			fmt.Printf("[*] Brute force tamamlandı. Toplam başarılı: %d\n", successCount)
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
					fmt.Println("    ", combo)
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
		// HATA NOTU: ntp paketi içinde func ScanNTP olarak (büyük harfle) tanımlı olduğundan emin olun.
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
			found, _ := telnet.TelnetBruteForceConcurrent(config.Targets[0], 23, users, passwords, 3*time.Second, 5)

			if len(found) > 0 {
				fmt.Println("[+] Bulunan geçerli hesaplar:")
				for _, c := range found {
					fmt.Println("    ", c)
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
	fmt.Println("[*] FTP kapsamlı taraması başlatılıyor...")

	for _, target := range config.Targets {
		// 1. OTOMATİK TARAMA (Banner, TLS, Anonymous)
		// Artık tek fonksiyonla hepsini yapıyoruz:
		result := ftp.ScanFTP(target, 21, config.Timeout)
		fmt.Println(result.String())

		// 2. KULLANICI / ŞİFRE BRUTE FORCE (İsteğe Bağlı)
		// Sadece kullanıcı listesi verilmişse çalışır.
		hasUser := config.Credentials.Username != "" || config.Credentials.UserList != ""
		hasPass := config.Credentials.Password != "" || config.Credentials.PassList != ""

		if hasUser && hasPass {
			fmt.Println("[*] Kimlik bilgileri algılandı, Brute Force başlatılıyor...")

			// Kullanıcı ve şifre listelerini hazırla
			users, _ := getUsers(config.Credentials)
			passwords, _ := getPasswords(config.Credentials)

			// Burada önceki brute force logic'i çağırıyoruz
			runFTPBruteforceConcurrent(config, users, passwords)
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
	// Color codes (can also be taken from utils package, but kept local here for convenience)
	// If you're using utils.Colorize, continue with that; here we format using strings.

	fmt.Println("\n" + utils.BoldText("USAGE:"))
	fmt.Printf("  soreers.exe -protocol <protocol> -t <target_ip> [options]\n")

	fmt.Println("\n" + utils.BoldText("BASIC OPTIONS:"))
	fmt.Printf("  %-25s %s\n", "-protocol <name>", "Target service to scan (ftp, smb, ssh, telnet, mysql, etc.)")
	fmt.Printf("  %-25s %s\n", "-t <ip>", "Single target IP address")
	fmt.Printf("  %-25s %s\n", "-T <file>", "File path containing a list of IP addresses")
	fmt.Printf("  %-25s %s\n", "-timeout <sec>", "Connection timeout in seconds (Default: 5)")
	fmt.Printf("  %-25s %s\n", "-c <number>", "Number of concurrent workers (Thread/Goroutine) (Default: 10)")

	fmt.Println("\n" + utils.BoldText("BRUTE FORCE OPTIONS:"))
	fmt.Printf("  %-25s %s\n", "-u <username>", "Single username")
	fmt.Printf("  %-25s %s\n", "-p <password>", "Single password")
	fmt.Printf("  %-25s %s\n", "-U <file>", "Username wordlist file")
	fmt.Printf("  %-25s %s\n", "-P <file>", "Password wordlist file")
	fmt.Printf("  %-25s %s\n", "-A", "Attempt anonymous login (FTP/SMB only)")

	fmt.Println("\n" + utils.BoldText(utils.Colorize("IMPORTANT WARNING (BRUTE FORCE):", utils.ColorYellow)))
	fmt.Println("  To start a brute force attack, both username and password must be provided.")
	fmt.Println("  If -u/-p or -U/-P parameters are not specified, only version detection and")
	fmt.Println("  anonymous login checks will be performed, password cracking will be " + utils.Colorize("SKIPPED.", utils.ColorRed))

	fmt.Println("\n" + utils.BoldText("EXAMPLE USAGE:"))
	fmt.Println("  1. FTP Version Scan Only:")
	fmt.Println("     soreers.exe -protocol ftp -t 192.168.1.10")
	fmt.Println()
	fmt.Println("  2. Telnet Brute Force:")
	fmt.Println("     soreers.exe -protocol telnet -t 192.168.1.10 -U users.txt -P pass.txt")
	fmt.Println()
	fmt.Println("  3. Fast Redis Scan (Using IP List):")
	fmt.Println("     soreers.exe -protocol redis -T iplist.txt -c 50")

	fmt.Println("\n" + utils.BoldText("SUPPORTED PROTOCOLS:"))
	protocols := []string{"ftp", "ssh", "telnet", "smb", "mysql", "redis", "vnc", "pop3", "imap", "snmp", "ntp", "ipmi", "ldap"}
	fmt.Print("  ")
	for i, p := range protocols {
		fmt.Printf("%s", p)
		if i < len(protocols)-1 {
			fmt.Print(", ")
		}
	}
	fmt.Println("\n")

}

func runNFS(config *ScanConfig) error {
	fmt.Println("[*] NFS taraması başlatıldı.")
	for _, target := range config.Targets {
		result := nfs.ScanNFS(target, config.Timeout)
		fmt.Println(result.String())
	}
	return nil
}

// ---------------------------------------------------------
// DÜZELTİLEN SNMP FONKSİYONU
// ---------------------------------------------------------
func runSNMP(config *ScanConfig) error {
	fmt.Println("[*] SNMP taraması başlatıldı.")

	for _, target := range config.Targets {
		fmt.Printf("\n[*] Scanning target: %s\n", target)
		fmt.Println("=" + strings.Repeat("=", len(target)+20))

		fmt.Println("\n[1] SNMP Version Enumeration and Community Discovery")
		fmt.Println("-" + strings.Repeat("-", 50))

		// NOT: snmp.ScanSNMPComprehensive fonksiyonunun snmp paketinde public (Büyük Harf) olması gerekir.
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
				// DÜZELTME: community bir string olarak işleniyor
				fmt.Printf("    %d. %s\n", i+1, community)
			}
		} else {
			fmt.Println("[-] No community strings found")
		}

		fmt.Println("\n[3] System Information")
		fmt.Println("-" + strings.Repeat("-", 20))

		// DÜZELTME: SystemInfo map erişimleri ["key"] şeklinde yapıldı
		if val, ok := result.SystemInfo["SysDescr"]; ok && val != "" {
			fmt.Printf("[+] System Description: %s\n", val)
		}
		if val, ok := result.SystemInfo["SysName"]; ok && val != "" {
			fmt.Printf("[+] System Name: %s\n", val)
		}
		if val, ok := result.SystemInfo["SysContact"]; ok && val != "" {
			fmt.Printf("[+] System Contact: %s\n", val)
		}
		if val, ok := result.SystemInfo["SysLocation"]; ok && val != "" {
			fmt.Printf("[+] System Location: %s\n", val)
		}
		if val, ok := result.SystemInfo["SysObjectID"]; ok && val != "" {
			fmt.Printf("[+] System Object ID: %s\n", val)
		}
		if val, ok := result.SystemInfo["SysUpTime"]; ok && val != "" {
			fmt.Printf("[+] System Up Time: %s\n", val)
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

			// DÜZELTME: Eksik olan Port argümanı (161) eklendi
			bruteResults := snmp.BruteForceSNMP(target, 161, communities, config.Timeout)

			if len(bruteResults) > 0 {
				fmt.Printf("[+] Brute force found %d community strings\n", len(bruteResults))
				for _, comm := range bruteResults {
					// DÜZELTME: comm bir string olarak işleniyor
					fmt.Printf("    - %s\n", comm)
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
		// DÜZELTME: community string olarak kullanıldı
		if isDefaultSNMPCommunity(community) {
			recommendations = append(recommendations, fmt.Sprintf("• Change default community string '%s'", community))
		}
		// RW kontrolü kaldırıldı çünkü string içinde erişim bilgisi yok.
	}

	// DÜZELTME: Map erişimi düzeltildi
	if val, ok := result.SystemInfo["SysContact"]; ok && val != "" {
		recommendations = append(recommendations, "• Review system contact information exposure")
	}
	if val, ok := result.SystemInfo["SysLocation"]; ok && val != "" {
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
	fmt.Println(utils.BoldText(utils.Colorize("╔══════════════════════════════════════════════════════════════╗", utils.ColorCyan)))
	fmt.Println(utils.BoldText(utils.Colorize("║                                                              ║", utils.ColorCyan)))
	fmt.Println(utils.BoldText(utils.Colorize("║   ███████╗ ██████╗ ██████╗ ███████╗███████╗██████╗ ███████╗  ║", utils.ColorCyan)))
	fmt.Println(utils.BoldText(utils.Colorize("║   ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝  ║", utils.ColorCyan)))
	fmt.Println(utils.BoldText(utils.Colorize("║   ███████╗██║   ██║██████╔╝█████╗  █████╗  ██████╔╝███████╗  ║", utils.ColorCyan)))
	fmt.Println(utils.BoldText(utils.Colorize("║   ╚════██║██║   ██║██╔══██╗██╔══╝  ██╔══╝  ██╔══██╗╚════██║  ║", utils.ColorCyan)))
	fmt.Println(utils.BoldText(utils.Colorize("║   ███████║╚██████╔╝██║  ██║███████╗███████╗██║  ██║███████║  ║", utils.ColorCyan)))
	fmt.Println(utils.BoldText(utils.Colorize("║   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝  ║", utils.ColorCyan)))
	fmt.Println(utils.BoldText(utils.Colorize("║                                                              ║", utils.ColorCyan)))
	fmt.Println(utils.BoldText(utils.Colorize("║   SOREERS - Multi Protocol Vulnerability Scanner             ║", utils.ColorYellow)))
	fmt.Println(utils.BoldText(utils.Colorize("╚══════════════════════════════════════════════════════════════╝", utils.ColorCyan)))
	fmt.Println(
		utils.BoldText(utils.Colorize("║   Author: Privia | github.com/Privia                               ║", utils.ColorYellow)))
	fmt.Println(
		utils.BoldText(utils.Colorize("║   Supported: FTP, SMB, NFS, SNMP, POP3, IMAP ...                   ║", utils.ColorYellow)))
	fmt.Println(
		utils.BoldText(utils.Colorize("║                                                                    ║", utils.ColorCyan)))
	fmt.Println(utils.BoldText(utils.Colorize("╚══════════════════════════════════════════════════════════════╝", utils.ColorCyan)))
	fmt.Println()
	// Renkli banner kodları buraya (kısaltıldı)

}
func runFTPBruteforceConcurrent(config *ScanConfig, users, passwords []string) error {
	jobs := make(chan FTPJob)
	results := make(chan FTPResult)

	workerCount := config.Concurrency

	// İşçileri (Workers) başlat
	for i := 0; i < workerCount; i++ {
		go func() {
			for job := range jobs {
				// Dikkat: Burada paket isminin "SOREERS" olduğundan emin olun
				ok, err := ftp.FTPLogin(job.Target, 21, job.Username, job.Password, config.Timeout)
				results <- FTPResult{Job: job, Success: ok, Err: err}
			}
		}()
	}

	// İşleri gönder
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

	// Sonuçları topla ve yazdır
	totalJobs := len(config.Targets) * len(users) * len(passwords)
	for i := 0; i < totalJobs; i++ {
		res := <-results
		if res.Success {
			fmt.Printf("%s[+] FTP GİRİŞ başarılı: %s %s:%s%s\n", utils.Green, res.Job.Target, res.Job.Username, res.Job.Password, utils.Reset)
		} else {
			// Hata varsa veya başarısızsa ekrana basıp basmamak size kalmış.
			// Genellikle sadece başarılıları görmek isteriz ama verbose mod için:
			// fmt.Printf("[-] Başarısız: %s:%s\n", res.Job.Username, res.Job.Password)
		}
	}
	return nil
}
