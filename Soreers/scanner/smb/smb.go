package smb

import (
	"SOREERS/utils"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

type SMBResult struct {
	Target          string
	Port            int
	Version         string
	SigningEnabled  bool
	SigningRequired bool
	ErrorMessage    string
	Dialects        []string
	SecurityMode    uint16

	// Kimlik Doğrulama Sonuçları
	GuestAccess bool // Guest (Misafir) girişi açık mı?
	NullSession bool // Null (Kullanıcı adı yok) girişi açık mı?
	HasSMB1     bool // SMBv1 tehlikesi var mı?

	Shares []ShareInfo // Bulunan paylaşımlar
}

type ShareInfo struct {
	Name  string
	Files []string
	Err   string
}

// SMB Header Constants
const (
	SMB1_PROTOCOL_ID = 0xFF534D42 // \xFFSMB
	SMB2_PROTOCOL_ID = 0xFE534D42 // \xFESMB

	SMB1_SECURITY_SIGNATURES_ENABLED  = 0x04
	SMB1_SECURITY_SIGNATURES_REQUIRED = 0x08

	SMB2_NEGOTIATE_SIGNING_ENABLED  = 0x0001
	SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002
)

// ScanSMB performs SMB scanning on the target
func ScanSMB(target string, port int, timeout time.Duration) *SMBResult {
	result := &SMBResult{
		Target: target,
		Port:   port,
	}

	// 1. Bağlantı Kur ve Versiyon/Signing Kontrolü Yap
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Bağlantı hatası: %v", err)
		return result
	}
	// Deadlineları ayarlayalım
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Önce SMB2/3 dene
	if err := trySMB2Negotiate(conn, result, timeout); err != nil {
		// Başarısızsa SMB1 dene
		_ = conn.Close()

		// Yeni bağlantı aç
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), timeout)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(timeout))
			if err := trySMB1Negotiate(conn, result, timeout); err == nil {
				result.HasSMB1 = true // SMB1 Tespit edildi!
			} else {
				result.ErrorMessage = "Protokol anlaşılamadı (Ne SMB1 ne SMB2)"
			}
		}
	} else {
		// SMB2 başarılı olduysa conn kapanmasın diye defer burada işe yaramaz,
		// negotiate fonksiyonunda okuma yapıldı bitti.
	}
	conn.Close() // Negotiate bitti, bağlantıyı kapat.

	// 2. NULL SESSION Kontrolü (Kullanıcı: "", Şifre: "")
	// Bu genelde bilgi sızdırmak için kullanılır (IPC$ share, user enum vb.)
	if checkLogin(target, port, "", "", timeout) {
		result.NullSession = true
	}

	// 3. GUEST SESSION ve PAYLAŞIM LİSTELEME (Kullanıcı: "guest", Şifre: "")
	shares, filesMap, err := listSharesAndFiles(target, port, "guest", "", timeout)
	if err == nil {
		result.GuestAccess = true
		// Paylaşımları Result'a ekle
		for _, name := range shares {
			info := ShareInfo{Name: name}
			if files, ok := filesMap[name]; ok {
				info.Files = files
			}
			result.Shares = append(result.Shares, info)
		}
	} else {
		// Guest başarısızsa ve Null Session başarılıysa, Null Session ile listelemeyi dene
		if result.NullSession {
			shares, filesMap, err := listSharesAndFiles(target, port, "", "", timeout)
			if err == nil {
				for _, name := range shares {
					info := ShareInfo{Name: name}
					if files, ok := filesMap[name]; ok {
						info.Files = files
					}
					result.Shares = append(result.Shares, info)
				}
			}
		}
	}

	return result
}

// checkLogin: Sadece giriş yapılıp yapılamadığını kontrol eder
func checkLogin(target string, port int, user, pass string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: pass,
		},
	}
	s, err := d.Dial(conn)
	if err != nil {
		return false
	}
	s.Logoff()
	return true
}

// listSharesAndFiles: Paylaşımları ve dosyaları listeler, struct döndürür (Print yapmaz)
func listSharesAndFiles(target string, port int, user, pass string, timeout time.Duration) ([]string, map[string][]string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: pass,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		return nil, nil, err
	}
	defer s.Logoff()

	shares, err := s.ListSharenames()
	if err != nil {
		return nil, nil, err
	}

	filesMap := make(map[string][]string)

	// Her paylaşımın içine girip bak (Read Only check)
	for _, share := range shares {
		fs, err := s.Mount(share)
		if err == nil {
			// Kök dizini oku
			files, err := fs.ReadDir(".")
			if err == nil {
				var fileList []string
				// İlk 5 dosyayı alalım, çok şişmesin
				count := 0
				for _, f := range files {
					if count >= 5 {
						fileList = append(fileList, "... (diğer dosyalar)")
						break
					}
					fileList = append(fileList, f.Name())
					count++
				}
				filesMap[share] = fileList
			}
			fs.Umount()
		}
	}
	return shares, filesMap, nil
}

// --- SMB Negotiation Logic (Değiştirilmedi, aynı mantık) ---

func trySMB2Negotiate(conn net.Conn, result *SMBResult, timeout time.Duration) error {
	negReq := createSMB2NegotiateRequest()
	if _, err := conn.Write(negReq); err != nil {
		return err
	}

	smbResponse, err := readNetBIOSPayload(conn, timeout)
	if err != nil {
		return err
	}

	if !isSMB2Response(smbResponse) {
		return fmt.Errorf("not SMB2")
	}

	result.Version = determineSMB2Version(smbResponse)
	enabled, required := checkSMB2Signing(smbResponse)
	result.SigningEnabled = enabled || required
	result.SigningRequired = required
	result.SecurityMode = getSMB2SecurityMode(smbResponse)

	// Dialect bilgisini temiz ekle
	result.Dialects = []string{result.Version}
	return nil
}

func trySMB1Negotiate(conn net.Conn, result *SMBResult, timeout time.Duration) error {
	negReq := createSMB1NegotiateRequest()
	if _, err := conn.Write(negReq); err != nil {
		return err
	}

	smbResponse, err := readNetBIOSPayload(conn, timeout)
	if err != nil {
		return err
	}

	if !isSMB1Response(smbResponse) {
		return fmt.Errorf("not SMB1")
	}

	result.Version = "SMBv1 (Tehlikeli!)"
	result.HasSMB1 = true

	if len(smbResponse) >= 36 {
		securityMode := smbResponse[35]
		result.SigningEnabled = (securityMode&SMB1_SECURITY_SIGNATURES_ENABLED) != 0 || (securityMode&SMB1_SECURITY_SIGNATURES_REQUIRED) != 0
		result.SigningRequired = (securityMode & SMB1_SECURITY_SIGNATURES_REQUIRED) != 0
	}
	return nil
}

// --- Packet Creation Helpers (Aynen korundu) ---
// (Bu kısımlar paket oluşturma için gerekli ve doğruydu, yer kaplamasın diye kısalttım
// ama siz dosyanızda önceki createSMB2NegotiateRequest vb. fonksiyonları tutun.
// Sadece createSMB1NegotiateRequest ve createSMB2NegotiateRequest fonksiyonlarını silmeyin.)

// ... (Buraya önceki kodunuzdaki createSMB2NegotiateRequest, createSMB1NegotiateRequest, readNetBIOSPayload vb. gelecek) ...
// ... (Eğer sildiyseniz önceki cevaptan o kısımları geri alıp buraya yapıştırın) ...

// AŞAĞIDAKİ YARDIMCI FONKSİYONLAR GEREKLİDİR (Kopyala-Yapıştır yaparken eksik olmasın):

func readNetBIOSPayload(conn net.Conn, timeout time.Duration) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	length := int(head[1])<<16 | int(head[2])<<8 | int(head[3])
	if length > 1<<20 {
		return nil, fmt.Errorf("invalid length")
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func isSMB2Response(data []byte) bool {
	return len(data) >= 4 && binary.BigEndian.Uint32(data[0:4]) == SMB2_PROTOCOL_ID
}

func isSMB1Response(data []byte) bool {
	return len(data) >= 4 && binary.BigEndian.Uint32(data[0:4]) == SMB1_PROTOCOL_ID
}

func determineSMB2Version(data []byte) string {
	if len(data) < 70 {
		return "SMB2"
	}
	rev := binary.LittleEndian.Uint16(data[68:70])
	switch rev {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	default:
		return fmt.Sprintf("SMB2 (0x%04x)", rev)
	}
}

func checkSMB2Signing(data []byte) (bool, bool) {
	if len(data) < 68 {
		return false, false
	}
	mode := binary.LittleEndian.Uint16(data[66:68])
	return (mode & SMB2_NEGOTIATE_SIGNING_ENABLED) != 0, (mode & SMB2_NEGOTIATE_SIGNING_REQUIRED) != 0
}

func getSMB2SecurityMode(data []byte) uint16 {
	if len(data) < 68 {
		return 0
	}
	return binary.LittleEndian.Uint16(data[66:68])
}

// createSMB2NegotiateRequest ve createSMB1NegotiateRequest fonksiyonlarını
// önceki kodunuzdan buraya eklemeyi unutmayın! (Çok uzun olduğu için tekrar yazmadım)

// --- Result String Output (Raporlama) ---

func (r *SMBResult) String() string {
	if r.ErrorMessage != "" {
		return fmt.Sprintf("%s %s %s",
			utils.Colorize("✗", utils.ColorRed),
			utils.BoldText("SMB Hata:"),
			utils.Colorize(r.ErrorMessage, utils.ColorRed))
	}
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(utils.BoldText(utils.Colorize("╔════════════════ SMB TARAMA SONUCU ═════════════════╗\n", utils.ColorBlue)))
	b.WriteString(fmt.Sprintf("║ %-20s : %s\n", "Hedef", fmt.Sprintf("%s:%d", r.Target, r.Port)))

	// Versiyon Bilgisi
	verColor := utils.ColorGreen
	if r.HasSMB1 {
		verColor = utils.ColorRed
	}
	b.WriteString(fmt.Sprintf("║ %-20s : %s\n", "Protokol Versiyonu", utils.Colorize(r.Version, verColor)))

	// SMBv1 Uyarısı
	if r.HasSMB1 {
		b.WriteString(fmt.Sprintf("║ %-20s : %s\n", "ZAFİYET UYARISI", utils.Colorize("KRİTİK: SMBv1 AÇIK (EternalBlue Riski)", utils.ColorRed)))
	}

	// Signing (İmzalama)
	signStatus := utils.Colorize("Zorunlu Değil (Riskli)", utils.ColorYellow)
	if r.SigningRequired {
		signStatus = utils.Colorize("Zorunlu (Güvenli)", utils.ColorGreen)
	}
	b.WriteString(fmt.Sprintf("║ %-20s : %s\n", "Mesaj İmzalama", signStatus))

	// Erişim Kontrolleri
	guestStatus := utils.Colorize("Kapalı", utils.ColorGreen)
	if r.GuestAccess {
		guestStatus = utils.Colorize("AÇIK (Dosyalar Okunabilir)", utils.ColorRed)
	}
	b.WriteString(fmt.Sprintf("║ %-20s : %s\n", "Guest Erişimi", guestStatus))

	nullStatus := utils.Colorize("Kapalı", utils.ColorGreen)
	if r.NullSession {
		nullStatus = utils.Colorize("AÇIK (Bilgi Sızdırabilir)", utils.ColorYellow)
	}
	b.WriteString(fmt.Sprintf("║ %-20s : %s\n", "Null Session", nullStatus))

	// Paylaşımlar
	if len(r.Shares) > 0 {
		b.WriteString(utils.BoldText(utils.Colorize("╟──────────────── BULUNAN PAYLAŞIMLAR ───────────────╢\n", utils.ColorBlue)))
		for _, s := range r.Shares {
			b.WriteString(fmt.Sprintf("║ • %-18s\n", utils.Colorize(s.Name, utils.ColorCyan)))
			if len(s.Files) > 0 {
				for _, f := range s.Files {
					b.WriteString(fmt.Sprintf("║    - %s\n", f))
				}
			}
		}
	}
	b.WriteString(utils.BoldText(utils.Colorize("╚════════════════════════════════════════════════════╝\n", utils.ColorBlue)))
	return b.String()
}

// SMBBruteForce (Aynen kalacak, main.go çağırıyor)
func SMBBruteForce(target string, port int, usersFile, passFile string, timeout time.Duration) ([]string, error) {
	users, err := readLines(usersFile)
	if err != nil {
		return nil, err
	}
	passwords, err := readLines(passFile)
	if err != nil {
		return nil, err
	}

	var found []string
	address := fmt.Sprintf("%s:%d", target, port)

	// Basit Brute Force
	for _, user := range users {
		for _, pass := range passwords {
			conn, err := net.DialTimeout("tcp", address, timeout)
			if err != nil {
				return nil, err
			}

			d := &smb2.Dialer{
				Initiator: &smb2.NTLMInitiator{
					User:     user,
					Password: pass,
				},
			}
			s, err := d.Dial(conn)
			if err == nil {
				found = append(found, fmt.Sprintf("%s:%s", user, pass))
				fmt.Printf("%s[+] Başarılı: %s:%s%s\n", utils.Green, user, pass, utils.Reset)
				s.Logoff()
			}
			conn.Close()
		}
	}
	return found, nil
}

func readLines(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var result []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			result = append(result, l)
		}
	}
	return result, nil
}

// --- EKSİK OLAN createSMB2NegotiateRequest vb. fonksiyonları BURAYA EKLEMELİSİNİZ ---
// (Önceki kodunuzdaki createSMB2NegotiateRequest ve createSMB1NegotiateRequest fonksiyonlarını
//
//	buraya mutlaka yapıştırın, onlar olmadan kod derlenmez.)
func createSMB2NegotiateRequest() []byte {
	// Build SMB2 Header (64 bytes)
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte{0xFE, 0x53, 0x4D, 0x42}) // ProtocolId \xFESMB
	binary.LittleEndian.PutUint16(hdr[4:6], 64)    // StructureSize
	binary.LittleEndian.PutUint16(hdr[12:14], 0)   // Command = NEGOTIATE

	// Dialects including 3.1.1
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}
	dialectBytes := &bytes.Buffer{}
	for _, d := range dialects {
		_ = binary.Write(dialectBytes, binary.LittleEndian, d)
	}

	// SMB2 NEGOTIATE Request fixed part (36 bytes)
	neg := make([]byte, 36)
	binary.LittleEndian.PutUint16(neg[0:2], 0x24)                  // StructureSize = 36
	binary.LittleEndian.PutUint16(neg[2:4], uint16(len(dialects))) // DialectCount
	binary.LittleEndian.PutUint16(neg[4:6], 0x0001)                // SecurityMode
	binary.LittleEndian.PutUint16(neg[6:8], 0x0000)                // Reserved
	binary.LittleEndian.PutUint32(neg[8:12], 0x00000000)           // Capabilities

	// Prepare negotiate contexts for SMB 3.1.1
	contextList := &bytes.Buffer{}
	contextCount := uint16(0)

	// Context 1: PREAUTH_INTEGRITY
	{
		data := &bytes.Buffer{}
		_ = binary.Write(data, binary.LittleEndian, uint16(1))      // HashCount
		_ = binary.Write(data, binary.LittleEndian, uint16(32))     // SaltLength
		_ = binary.Write(data, binary.LittleEndian, uint16(0x0001)) // SHA-512
		_, _ = data.Write(make([]byte, 32))                         // Salt

		padLen := (8 - (data.Len() % 8)) % 8
		if padLen > 0 {
			_, _ = data.Write(make([]byte, padLen))
		}

		_ = binary.Write(contextList, binary.LittleEndian, uint16(0x0001))     // Type
		_ = binary.Write(contextList, binary.LittleEndian, uint16(data.Len())) // Length
		_ = binary.Write(contextList, binary.LittleEndian, uint32(0))          // Reserved
		_, _ = contextList.Write(data.Bytes())
		contextCount++
	}

	// Context 2: ENCRYPTION_CAPABILITIES
	{
		data := &bytes.Buffer{}
		_ = binary.Write(data, binary.LittleEndian, uint16(2))      // CipherCount
		_ = binary.Write(data, binary.LittleEndian, uint16(0x0001)) // AES-128-CCM
		_ = binary.Write(data, binary.LittleEndian, uint16(0x0002)) // AES-128-GCM

		padLen := (8 - (data.Len() % 8)) % 8
		if padLen > 0 {
			_, _ = data.Write(make([]byte, padLen))
		}

		_ = binary.Write(contextList, binary.LittleEndian, uint16(0x0002))     // Type
		_ = binary.Write(contextList, binary.LittleEndian, uint16(data.Len())) // Length
		_ = binary.Write(contextList, binary.LittleEndian, uint32(0))          // Reserved
		_, _ = contextList.Write(data.Bytes())
		contextCount++
	}

	dialectsLen := dialectBytes.Len()
	current := 64 + len(neg) + dialectsLen
	pad := (8 - (current % 8)) % 8
	padding := make([]byte, pad)

	if contextCount > 0 {
		binary.LittleEndian.PutUint32(neg[28:32], uint32(64+len(neg)+dialectsLen+pad)) // Offset
		binary.LittleEndian.PutUint16(neg[32:34], contextCount)                        // Count
	}

	payload := make([]byte, 0, 64+len(neg)+dialectsLen+len(padding)+contextList.Len())
	payload = append(payload, hdr...)
	payload = append(payload, neg...)
	payload = append(payload, dialectBytes.Bytes()...)
	payload = append(payload, padding...)
	payload = append(payload, contextList.Bytes()...)

	// NetBIOS Header
	netbios := make([]byte, 4)
	netbios[0] = 0x00
	length := len(payload)
	netbios[1] = byte((length >> 16) & 0xFF)
	netbios[2] = byte((length >> 8) & 0xFF)
	netbios[3] = byte(length & 0xFF)

	return append(netbios, payload...)
}

func createSMB1NegotiateRequest() []byte {
	netbiosHeader := []byte{0x00, 0x00, 0x00, 0x00}

	smbHeader := []byte{
		0xFF, 0x53, 0x4D, 0x42, // Protocol
		0x72,                   // Command: Negotiate
		0x00, 0x00, 0x00, 0x00, // Status
		0x18,       // Flags
		0x53, 0x0C, // Flags2
		0x00, 0x00, // PID High
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, // Reserved
		0x00, 0x00, // TID
		0xFF, 0xFE, // PIDLow
		0x00, 0x00, // UID
		0x00, 0x00, // MID
	}

	dialects := []string{
		"\x02PC NETWORK PROGRAM 1.0",
		"\x02LANMAN1.0",
		"\x02Windows for Workgroups 3.1a",
		"\x02LM1.2X002",
		"\x02LANMAN2.1",
		"\x02NT LM 0.12",
		"\x02SMB 2.002",
		"\x02SMB 2.???",
	}

	byteCount := 0
	for _, d := range dialects {
		byteCount += len(d)
	}

	params := []byte{0x00} // WordCount
	params = append(params, byte(byteCount&0xFF), byte((byteCount>>8)&0xFF))
	for _, d := range dialects {
		params = append(params, []byte(d)...)
	}

	payload := append(smbHeader, params...)
	length := len(payload)
	netbiosHeader[1] = byte((length >> 16) & 0xFF)
	netbiosHeader[2] = byte((length >> 8) & 0xFF)
	netbiosHeader[3] = byte(length & 0xFF)

	return append(netbiosHeader, payload...)
}
