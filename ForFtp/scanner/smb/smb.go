package smb

import (
	"FORFTP/utils"
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
	Shares          []ShareInfo // yeni ekle!
}
type ShareInfo struct {
	Name  string
	Files []string
	Err   string // hata varsa
}

// SMBHeader represents the SMB header structure
type SMBHeader struct {
	Protocol    [4]byte
	Command     byte
	Status      uint32
	Flags       byte
	Flags2      uint16
	PIDHigh     uint16
	SecuritySig [8]byte
	Reserved    uint16
	TID         uint16
	PIDLow      uint16
	UID         uint16
	MID         uint16
}

// Constants for SMB versions and flags
const (
	SMB1_PROTOCOL_ID = 0xFF534D42 // \xFFSMB
	SMB2_PROTOCOL_ID = 0xFE534D42 // \xFESMB

	// SMB1 Security Mode flags
	SMB1_SECURITY_USER_LEVEL          = 0x01 // User level security
	SMB1_SECURITY_ENCRYPT_PASSWORD    = 0x02 // Encrypt passwords
	SMB1_SECURITY_SIGNATURES_ENABLED  = 0x04 // Security signatures enabled but not required
	SMB1_SECURITY_SIGNATURES_REQUIRED = 0x08 // Security signatures required

	// SMB2 Security Mode flags
	SMB2_NEGOTIATE_SIGNING_ENABLED  = 0x0001
	SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002
)

// ScanSMB performs SMB scanning on the target
func ScanSMB(target string, port int, timeout time.Duration) *SMBResult {
	fmt.Printf("Starting SMB scan for %s:%d\n", target, port)

	result := &SMBResult{
		Target: target,
		Port:   port,
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Connection failed: %v", err)
		return result
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Önce SMB2 ile dene
	if err := trySMB2Negotiate(conn, result, timeout); err != nil {
		fmt.Printf("SMB2 negotiation failed: %v\n", err)

		// SMB1 deneyelim
		_ = conn.Close()
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), timeout)
		if err != nil {
			result.ErrorMessage = fmt.Sprintf("Connection failed during SMB1 retry: %v", err)
			return result
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(timeout))

		if err := trySMB1Negotiate(conn, result, timeout); err != nil {
			result.ErrorMessage = fmt.Sprintf("Protocol negotiation failed: %v", err)
			return result
		}
	}

	// Artık go-smb2 ile guest bağlantı yapıp share'leri listele
	shares, guestErr := ListSharesAndFilesWithGuest(target, port, timeout)
	if guestErr != nil {
		if result.ErrorMessage != "" {
			result.ErrorMessage += " | "
		}
		result.ErrorMessage += "Guest share list error: " + guestErr.Error()
	} else {
		result.Dialects = append(result.Dialects, fmt.Sprintf("Shares: %v", shares))
	}

	return result
}

func trySMB2Negotiate(conn net.Conn, result *SMBResult, timeout time.Duration) error {
	// Send SMB2 NEGOTIATE (valid, with proper dialect count)
	negReq := createSMB2NegotiateRequest()
	if _, err := conn.Write(negReq); err != nil {
		return fmt.Errorf("failed to send SMB2 negotiate: %v", err)
	}

	// Read a single NetBIOS Session Service message
	smbResponse, err := readNetBIOSPayload(conn, timeout)
	if err != nil {
		return fmt.Errorf("failed to read SMB2 response: %v", err)
	}

	if !isSMB2Response(smbResponse) {
		return fmt.Errorf("not an SMB2 response")
	}

	// Parse SMB2 response
	result.Version = determineSMB2Version(smbResponse)
	enabled, required := checkSMB2Signing(smbResponse)
	// If required, then it is necessarily enabled from server perspective
	result.SigningEnabled = enabled || required
	result.SigningRequired = required
	result.SecurityMode = getSMB2SecurityMode(smbResponse)
	result.Dialects = parseSMB2Dialects(smbResponse)

	return nil
}

func trySMB1Negotiate(conn net.Conn, result *SMBResult, timeout time.Duration) error {
	// Send SMB1 NEGOTIATE
	negReq := createSMB1NegotiateRequest()
	if _, err := conn.Write(negReq); err != nil {
		return fmt.Errorf("failed to send SMB1 negotiate: %v", err)
	}

	// Read a single NetBIOS Session Service message
	smbResponse, err := readNetBIOSPayload(conn, timeout)
	if err != nil {
		return fmt.Errorf("failed to read SMB1 response: %v", err)
	}

	if !isSMB1Response(smbResponse) {
		return fmt.Errorf("not an SMB1 response")
	}

	// Parse SMB1 response
	result.Version = "SMB1"

	// SMB1 header is 32 bytes. Then WordCount (1 byte), DialectIndex (2 bytes), SecurityMode (1 byte)
	if len(smbResponse) >= 32+1+2+1 {
		wordCount := smbResponse[32]
		_ = wordCount // not strictly needed but kept for clarity

		dialectIndex := binary.LittleEndian.Uint16(smbResponse[33:35])
		result.Dialects = parseSMB1DialectsByIndex(dialectIndex)

		securityMode := smbResponse[35]
		result.SigningEnabled = (securityMode&SMB1_SECURITY_SIGNATURES_ENABLED) != 0 || (securityMode&SMB1_SECURITY_SIGNATURES_REQUIRED) != 0
		result.SigningRequired = (securityMode & SMB1_SECURITY_SIGNATURES_REQUIRED) != 0
	} else {
		return fmt.Errorf("SMB1 response too short to parse security mode")
	}

	return nil
}

// readNetBIOSPayload reads exactly one NetBIOS Session Service message payload (without the 4-byte NBSS header)
func readNetBIOSPayload(conn net.Conn, timeout time.Duration) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	if head[0] != 0x00 { // Session Message
		return nil, fmt.Errorf("unexpected NetBIOS message type: 0x%02x", head[0])
	}
	length := int(head[1])<<16 | int(head[2])<<8 | int(head[3])
	if length <= 0 || length > 1<<20 { // sanity
		return nil, fmt.Errorf("invalid NetBIOS length: %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func createSMB2NegotiateRequest() []byte {
	// Build SMB2 Header (64 bytes)
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte{0xFE, 0x53, 0x4D, 0x42}) // ProtocolId \xFESMB
	binary.LittleEndian.PutUint16(hdr[4:6], 64)    // StructureSize
	binary.LittleEndian.PutUint16(hdr[12:14], 0)   // Command = NEGOTIATE
	// Other header fields remain zero

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
	binary.LittleEndian.PutUint16(neg[4:6], 0x0001)                // SecurityMode: client supports signing
	binary.LittleEndian.PutUint16(neg[6:8], 0x0000)                // Reserved
	binary.LittleEndian.PutUint32(neg[8:12], 0x00000000)           // Capabilities
	// ClientGuid (16 bytes) left as zeros at neg[12:28]
	// We will set NegotiateContextOffset/Count below if we include contexts

	// Prepare negotiate contexts for SMB 3.1.1
	contextList := &bytes.Buffer{}
	contextCount := uint16(0)

	// Context 1: PREAUTH_INTEGRITY_CAPABILITIES (Type = 0x0001)
	{
		data := &bytes.Buffer{}
		_ = binary.Write(data, binary.LittleEndian, uint16(1))      // HashAlgorithmCount
		_ = binary.Write(data, binary.LittleEndian, uint16(32))     // SaltLength
		_ = binary.Write(data, binary.LittleEndian, uint16(0x0001)) // SHA-512
		_, _ = data.Write(make([]byte, 32))                         // Salt (zeros)

		// Pad data to 8-byte boundary
		padLen := (8 - (data.Len() % 8)) % 8
		if padLen > 0 {
			_, _ = data.Write(make([]byte, padLen))
		}

		// Write context header
		_ = binary.Write(contextList, binary.LittleEndian, uint16(0x0001))     // Type
		_ = binary.Write(contextList, binary.LittleEndian, uint16(data.Len())) // DataLength
		_ = binary.Write(contextList, binary.LittleEndian, uint32(0))          // Reserved
		_, _ = contextList.Write(data.Bytes())
		contextCount++
	}

	// Context 2: ENCRYPTION_CAPABILITIES (Type = 0x0002)
	{
		data := &bytes.Buffer{}
		_ = binary.Write(data, binary.LittleEndian, uint16(2))      // CipherCount
		_ = binary.Write(data, binary.LittleEndian, uint16(0x0001)) // AES-128-CCM
		_ = binary.Write(data, binary.LittleEndian, uint16(0x0002)) // AES-128-GCM

		// Pad to 8-byte boundary
		padLen := (8 - (data.Len() % 8)) % 8
		if padLen > 0 {
			_, _ = data.Write(make([]byte, padLen))
		}

		_ = binary.Write(contextList, binary.LittleEndian, uint16(0x0002))     // Type
		_ = binary.Write(contextList, binary.LittleEndian, uint16(data.Len())) // DataLength
		_ = binary.Write(contextList, binary.LittleEndian, uint32(0))          // Reserved
		_, _ = contextList.Write(data.Bytes())
		contextCount++
	}

	// Compute NegotiateContextOffset after dialects + padding
	// The offset is from the beginning of the SMB2 header (hdr start)
	dialectsLen := dialectBytes.Len()
	// Current offset from header start to end of dialects
	current := 64 + len(neg) + dialectsLen
	pad := (8 - (current % 8)) % 8
	padding := make([]byte, pad)

	if contextCount > 0 {
		binary.LittleEndian.PutUint32(neg[28:32], uint32(64+len(neg)+dialectsLen+pad)) // NegotiateContextOffset
		binary.LittleEndian.PutUint16(neg[32:34], contextCount)                        // NegotiateContextCount
		binary.LittleEndian.PutUint16(neg[34:36], 0)                                   // Reserved2
	} else {
		binary.LittleEndian.PutUint32(neg[28:32], 0)
		binary.LittleEndian.PutUint16(neg[32:34], 0)
		binary.LittleEndian.PutUint16(neg[34:36], 0)
	}

	payload := make([]byte, 0, 64+len(neg)+dialectsLen+len(padding)+contextList.Len())
	payload = append(payload, hdr...)
	payload = append(payload, neg...)
	payload = append(payload, dialectBytes.Bytes()...)
	payload = append(payload, padding...)
	payload = append(payload, contextList.Bytes()...)

	// NetBIOS Session Service header (big-endian 3-byte length)
	netbios := make([]byte, 4)
	netbios[0] = 0x00
	length := len(payload)
	netbios[1] = byte((length >> 16) & 0xFF)
	netbios[2] = byte((length >> 8) & 0xFF)
	netbios[3] = byte(length & 0xFF)

	return append(netbios, payload...)
}

func createSMB1NegotiateRequest() []byte {
	// NetBIOS Session Service header will be filled after payload constructed
	netbiosHeader := []byte{0x00, 0x00, 0x00, 0x00}

	// SMB1 Header (fixed 32 bytes)
	smbHeader := []byte{
		0xFF, 0x53, 0x4D, 0x42, // Protocol: \xFFSMB
		0x72,                   // Command: Negotiate Protocol
		0x00, 0x00, 0x00, 0x00, // NT Status
		0x18,       // Flags
		0x53, 0x0C, // Flags2: Extended Security + Unicode + NT Error Codes + Long Names
		0x00, 0x00, // PID High
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, // Reserved
		0x00, 0x00, // TID
		0xFF, 0xFE, // PIDLow
		0x00, 0x00, // UID
		0x00, 0x00, // MID
	}

	// Dialect strings
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

	params := []byte{0x00} // WordCount = 0 for request
	// ByteCount (2 bytes LE)
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

func isSMB2Response(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	protocolID := binary.BigEndian.Uint32(data[0:4])
	return protocolID == SMB2_PROTOCOL_ID
}

func isSMB1Response(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	protocolID := binary.BigEndian.Uint32(data[0:4])
	return protocolID == SMB1_PROTOCOL_ID
}

func determineSMB2Version(data []byte) string {
	// Data starts at SMB2 header
	if len(data) < 64+6 {
		return "SMB2"
	}
	// DialectRevision is at offset 64 + 4 in NEGOTIATE RESPONSE
	dialectRevision := binary.LittleEndian.Uint16(data[64+4 : 64+6])
	switch dialectRevision {
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
		return fmt.Sprintf("SMB2 (0x%04x)", dialectRevision)
	}
}

func checkSMB2Signing(data []byte) (enabled, required bool) {
	if len(data) < 64+4 {
		return false, false
	}
	// SecurityMode is at offset 64 + 2
	securityMode := binary.LittleEndian.Uint16(data[64+2 : 64+4])
	return (securityMode & SMB2_NEGOTIATE_SIGNING_ENABLED) != 0,
		(securityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED) != 0
}

func getSMB2SecurityMode(data []byte) uint16 {
	if len(data) < 64+4 {
		return 0
	}
	return binary.LittleEndian.Uint16(data[64+2 : 64+4])
}

func parseSMB2Dialects(data []byte) []string {
	var dialects []string
	if len(data) < 64+6 {
		return dialects
	}
	dialectRevision := binary.LittleEndian.Uint16(data[64+4 : 64+6])
	dialect := ""
	switch dialectRevision {
	case 0x0202:
		dialect = "SMB 2.0.2"
	case 0x0210:
		dialect = "SMB 2.1"
	case 0x0300:
		dialect = "SMB 3.0"
	case 0x0302:
		dialect = "SMB 3.0.2"
	case 0x0311:
		dialect = "SMB 3.1.1"
	default:
		dialect = fmt.Sprintf("Unknown (0x%04x)", dialectRevision)
	}
	dialects = append(dialects, dialect)
	return dialects
}

func parseSMB1DialectsByIndex(dialectIndex uint16) []string {
	var dialects []string
	switch dialectIndex {
	case 0:
		dialects = append(dialects, "PC NETWORK PROGRAM 1.0")
	case 1:
		dialects = append(dialects, "LANMAN1.0")
	case 2:
		dialects = append(dialects, "Windows for Workgroups 3.1a")
	case 3:
		dialects = append(dialects, "LM1.2X002")
	case 4:
		dialects = append(dialects, "LANMAN2.1")
	case 5:
		dialects = append(dialects, "NT LM 0.12")
	default:
		dialects = append(dialects, fmt.Sprintf("Unknown (%d)", dialectIndex))
	}
	return dialects
}

func (r *SMBResult) String() string {
	if r.ErrorMessage != "" {
		return fmt.Sprintf("%s %s %s",
			utils.Colorize("✗", utils.ColorRed),
			utils.BoldText("SMB Hata:"),
			utils.Colorize(r.ErrorMessage, utils.ColorRed))
	}
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(utils.BoldText(utils.Colorize("╔══════════════════════════════════════════════╗\n", utils.ColorBlue)))
	b.WriteString(fmt.Sprintf("%s %s:%d\n", utils.Colorize("Target:", utils.ColorYellow), r.Target, r.Port))
	b.WriteString(fmt.Sprintf("%s %s\n", utils.Colorize("Protokol Versiyonu:", utils.ColorYellow), utils.Colorize(r.Version, utils.ColorGreen)))
	b.WriteString(fmt.Sprintf("%s %v\n", utils.Colorize("İmzalama Aktif mi?:", utils.ColorYellow), r.SigningEnabled))
	b.WriteString(fmt.Sprintf("%s %v\n", utils.Colorize("İmzalama Zorunlu mu?:", utils.ColorYellow), r.SigningRequired))
	b.WriteString(fmt.Sprintf("%s %v\n", utils.Colorize("Desteklenen Dialectler:", utils.ColorYellow), r.Dialects))
	b.WriteString(fmt.Sprintf("%s 0x%04x\n", utils.Colorize("Security Mode (ham):", utils.ColorYellow), r.SecurityMode))

	// Paylaşımlar ve dosyalar
	if len(r.Shares) > 0 {
		b.WriteString(utils.BoldText(utils.Colorize("\nPaylaşımlar:\n", utils.ColorCyan)))
		for _, s := range r.Shares {
			b.WriteString(fmt.Sprintf("  %s %s\n", utils.Colorize("•", utils.ColorGreen), utils.Colorize(s.Name, utils.ColorWhite)))
			if len(s.Files) > 0 {
				b.WriteString(utils.Colorize("    Dosyalar:\n", utils.ColorYellow))
				for _, f := range s.Files {
					b.WriteString(fmt.Sprintf("      %s %s\n", utils.Colorize("-", utils.ColorCyan), utils.Colorize(f, utils.ColorWhite)))
				}
			}
			if s.Err != "" {
				b.WriteString(fmt.Sprintf("    %s %s\n", utils.Colorize("Hata:", utils.ColorRed), utils.Colorize(s.Err, utils.ColorRed)))
			}
		}
	}
	b.WriteString(utils.BoldText(utils.Colorize("╚══════════════════════════════════════════════╝\n", utils.ColorBlue)))
	return b.String()
}

func detectSMBVersion(data []byte) string {
	if len(data) < 4 {
		return "Unknown"
	}
	protocolID := data[0:4]

	if bytes.Equal(protocolID, []byte{0xFF, 0x53, 0x4D, 0x42}) { // \xFFSMB
		return detectSMB1Version(data)
	} else if bytes.Equal(protocolID, []byte{0xFE, 0x53, 0x4D, 0x42}) { // \xFESMB
		return detectSMB2Version(data)
	}

	return "Unknown"
}

func detectSMB1Version(data []byte) string {
	dialects := []string{
		"PC NETWORK PROGRAM 1.0",
		"LANMAN1.0",
		"Windows for Workgroups 3.1a",
		"LM1.2X002",
		"LANMAN2.1",
		"NT LM 0.12",
	}
	for _, d := range dialects {
		if strings.Contains(string(data), d) {
			return "SMB1 (" + d + ")"
		}
	}
	return "SMB1 (Unknown Dialect)"
}

func detectSMB2Version(data []byte) string {
	if len(data) < 64+6 {
		return "SMB2 (Invalid Packet)"
	}
	dialectRevision := binary.LittleEndian.Uint16(data[64+4 : 64+6])
	switch dialectRevision {
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
		return fmt.Sprintf("SMB2 (0x%04x)", dialectRevision)
	}
}

// ListSharesAndFilesWithGuest guest ile bağlanıp paylaşımları ve içindeki dosyaları listeler
func ListSharesAndFilesWithGuest(target string, port int, timeout time.Duration) ([]string, error) {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("TCP bağlantı hatası: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	dialer := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     "guest",
			Password: "",
			Domain:   "",
		},
	}

	smbConn, err := dialer.Dial(conn)
	if err != nil {
		return nil, fmt.Errorf("SMB guest bağlantı hatası: %w", err)
	}
	defer smbConn.Logoff()

	shares, err := smbConn.ListSharenames()
	if err != nil {
		return nil, fmt.Errorf("Paylaşımları listeleme hatası: %w", err)
	}

	fmt.Println("Bulunan paylaşımlar:")
	for _, shareName := range shares {
		fmt.Printf("- %s\n", shareName)

		share, err := smbConn.Mount(shareName)
		if err != nil {
			fmt.Printf("Paylaşım açılamadı: %v\n", err)
			continue
		}

		files, err := share.ReadDir("")
		if err != nil {
			fmt.Printf("Dosya/folderlar okunamadı: %v\n", err)
			_ = share.Umount()
			continue
		}

		fmt.Printf("Share: %s, Dosyalar:\n", shareName)
		for _, f := range files {
			fmt.Printf(" - %s\n", f.Name())
		}

		_ = share.Umount()
	}

	return shares, nil
}

// SMBBruteForce tries user:pass combinations from files
func SMBBruteForce(target string, port int, usersFile, passFile string, timeout time.Duration) ([]string, error) {
	users, err := readLines(usersFile)
	if err != nil {
		return nil, fmt.Errorf("kullanıcı listesi okunamadı: %w", err)
	}
	passwords, err := readLines(passFile)
	if err != nil {
		return nil, fmt.Errorf("şifre listesi okunamadı: %w", err)
	}

	var found []string
	address := fmt.Sprintf("%s:%d", target, port)

	for _, user := range users {
		for _, pass := range passwords {
			conn, err := net.DialTimeout("tcp", address, timeout)
			if err != nil {
				return found, fmt.Errorf("TCP bağlantı hatası: %w", err)
			}

			dialer := &smb2.Dialer{
				Initiator: &smb2.NTLMInitiator{
					User:     user,
					Password: pass,
					Domain:   "",
				},
			}

			smbConn, err := dialer.Dial(conn)
			if err == nil {
				// Başarılı giriş
				found = append(found, fmt.Sprintf("%s:%s", user, pass))
				fmt.Printf("[+] Başarılı: %s:%s\n", user, pass)
				_ = smbConn.Logoff()
			}
			_ = conn.Close()
		}
	}
	return found, nil
}

// küçük yardımcı fonksiyon: satır satır oku
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
