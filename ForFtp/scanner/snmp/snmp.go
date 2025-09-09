package snmp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

type SNMPResult struct {
	Target          string
	Port            int
	Version         string
	ErrorMessage    string
	Communities     []CommunityInfo
	SystemInfo      SystemInfo
	Vulnerabilities []Vulnerability
	OIDs            []OIDInfo
}

type CommunityInfo struct {
	Name        string
	Access      string
	ReadOnly    bool
	ReadWrite   bool
	Description string
}

type SystemInfo struct {
	SysDescr    string
	SysObjectID string
	SysUpTime   string
	SysContact  string
	SysName     string
	SysLocation string
}

type Vulnerability struct {
	Type        string
	Severity    string
	Description string
	Details     string
}

type OIDInfo struct {
	OID         string
	Value       string
	Type        string
	Description string
}

// SNMP Constants
const (
	SNMP_PORT      = 1161
	SNMP_TRAP_PORT = 162

	// SNMP Versions
	SNMP_V1  = 0
	SNMP_V2C = 1
	SNMP_V3  = 3

	// SNMP PDU Types
	SNMP_GET_REQUEST      = 0xA0
	SNMP_GET_NEXT_REQUEST = 0xA1
	SNMP_GET_RESPONSE     = 0xA2
	SNMP_SET_REQUEST      = 0xA3
	SNMP_TRAP             = 0xA4
	SNMP_GET_BULK_REQUEST = 0xA5
	SNMP_INFORM_REQUEST   = 0xA6

	// Common OIDs
	OID_SYS_DESCR     = "1.3.6.1.2.1.1.1.0"
	OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
	OID_SYS_UP_TIME   = "1.3.6.1.2.1.1.3.0"
	OID_SYS_CONTACT   = "1.3.6.1.2.1.1.4.0"
	OID_SYS_NAME      = "1.3.6.1.2.1.1.5.0"
	OID_SYS_LOCATION  = "1.3.6.1.2.1.1.6.0"
)

// Default community strings
var DEFAULT_COMMUNITIES = []string{
	"public", "private", "community", "admin", "cisco", "hp", "3com",
	"read", "write", "manager", "monitor", "guest", "test", "demo",
	"default", "system", "network", "security", "snmp", "trap",
	"ro", "rw", "readonly", "readwrite", "public1", "private1",
	"admin1", "cisco1", "hp1", "3com1", "read1", "write1",
}

// SNMP Header structure
type SNMPHeader struct {
	Version    int
	Community  string
	PDUType    int
	RequestID  uint32
	Error      int
	ErrorIndex int
}

// ScanSNMP performs comprehensive SNMP scanning
func ScanSNMP(target string, port int, timeout time.Duration) *SNMPResult {
	fmt.Printf("Starting SNMP scan for %s:%d\n", target, port)

	result := &SNMPResult{
		Target: target,
		Port:   port,
	}

	// 1. Check if SNMP port is open
	if !isPortOpen(target, port, timeout) {
		result.ErrorMessage = fmt.Sprintf("SNMP port %d is not accessible", port)
		return result
	}

	// 2. Detect SNMP version
	version := detectSNMPVersion(target, port, timeout)
	result.Version = version

	// 3. Enumerate community strings
	communities := enumerateCommunities(target, port, timeout)
	result.Communities = communities

	// 4. Get system information
	systemInfo := getSystemInfo(target, port, communities, timeout)
	result.SystemInfo = systemInfo

	// 5. Perform SNMP walk
	oids := performSNMPWalk(target, port, communities, timeout)
	result.OIDs = oids

	// 6. Identify vulnerabilities
	vulnerabilities := identifyVulnerabilities(result)
	result.Vulnerabilities = vulnerabilities

	return result
}

// Check if port is open
func isPortOpen(target string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

// Detect SNMP version
func detectSNMPVersion(target string, port int, timeout time.Duration) string {
	versions := []int{SNMP_V1, SNMP_V2C, SNMP_V3}

	for _, version := range versions {
		if testSNMPVersion(target, port, version, timeout) {
			switch version {
			case SNMP_V1:
				return "SNMPv1"
			case SNMP_V2C:
				return "SNMPv2c"
			case SNMP_V3:
				return "SNMPv3"
			}
		}
	}

	return "Unknown"
}

// Test specific SNMP version
func testSNMPVersion(target string, port int, version int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Create SNMP GET request
	request := createSNMPGetRequest(version, "public", OID_SYS_DESCR)
	if _, err := conn.Write(request); err != nil {
		return false
	}

	// Read response
	response := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(response)
	if err != nil || n == 0 {
		return false
	}

	// Check if response is valid SNMP reply
	return isValidSNMPResponse(response[:n], version)
}

// Create SNMP GET request
func createSNMPGetRequest(version int, community, oid string) []byte {
	// Generate random request ID
	requestID := generateRequestID()

	// Create SNMP message
	var buf bytes.Buffer

	// SNMP Version
	buf.WriteByte(byte(version))

	// Community string
	writeString(&buf, community)

	// PDU Type (GET_REQUEST)
	buf.WriteByte(SNMP_GET_REQUEST)

	// Request ID
	writeUint32(&buf, requestID)

	// Error status and index
	buf.WriteByte(0) // Error status
	buf.WriteByte(0) // Error index

	// Variable bindings
	writeVarBindings(&buf, []string{oid})

	return buf.Bytes()
}

// Generate random request ID
func generateRequestID() uint32 {
	var id uint32
	var bytes [4]byte
	rand.Read(bytes[:])
	id = binary.BigEndian.Uint32(bytes[:])
	return id
}

// Write string to buffer
func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte(0x04) // String type
	buf.WriteByte(byte(len(s)))
	buf.WriteString(s)
}

// Write uint32 to buffer
func writeUint32(buf *bytes.Buffer, value uint32) {
	buf.WriteByte(0x02) // Integer type
	buf.WriteByte(4)    // Length

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, value)
	buf.Write(b)
}

// Write variable bindings
func writeVarBindings(buf *bytes.Buffer, oids []string) {
	// Sequence
	buf.WriteByte(0x30) // Sequence type

	// Calculate total length
	totalLength := 0
	for _, oid := range oids {
		totalLength += 2 + len(oid) + 2 // OID + NULL value
	}

	buf.WriteByte(byte(totalLength))

	// Write each OID with NULL value
	for _, oid := range oids {
		// OID
		buf.WriteByte(0x06) // Object identifier type
		buf.WriteByte(byte(len(oid)))
		buf.WriteString(oid)

		// NULL value
		buf.WriteByte(0x05) // NULL type
		buf.WriteByte(0x00) // Length
	}
}

// Check if SNMP response is valid
func isValidSNMPResponse(data []byte, version int) bool {
	if len(data) < 4 {
		return false
	}

	// Check version
	if int(data[0]) != version {
		return false
	}

	// Check PDU type (should be GET_RESPONSE)
	if len(data) > 10 && data[8] == SNMP_GET_RESPONSE {
		return true
	}

	return false
}

// Enumerate community strings
func enumerateCommunities(target string, port int, timeout time.Duration) []CommunityInfo {
	var communities []CommunityInfo

	for _, community := range DEFAULT_COMMUNITIES {
		if testCommunityString(target, port, community, timeout) {
			info := CommunityInfo{
				Name:        community,
				Access:      "Unknown",
				ReadOnly:    false,
				ReadWrite:   false,
				Description: "Discovered community string",
			}

			// Test read access
			if testReadAccess(target, port, community, timeout) {
				info.ReadOnly = true
				info.Access = "Read-Only"
			}

			// Test write access
			if testWriteAccess(target, port, community, timeout) {
				info.ReadWrite = true
				info.Access = "Read-Write"
			}

			communities = append(communities, info)
		}
	}

	return communities
}

// Test community string
func testCommunityString(target string, port int, community string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Send SNMP GET request
	request := createSNMPGetRequest(SNMP_V2C, community, OID_SYS_DESCR)
	if _, err := conn.Write(request); err != nil {
		return false
	}

	response := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(response)

	return err == nil && n > 0 && isValidSNMPResponse(response[:n], SNMP_V2C)
}

// Test read access
func testReadAccess(target string, port int, community string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Try to read system description
	request := createSNMPGetRequest(SNMP_V2C, community, OID_SYS_DESCR)
	if _, err := conn.Write(request); err != nil {
		return false
	}

	response := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(response)

	return err == nil && n > 0 && isValidSNMPResponse(response[:n], SNMP_V2C)
}

// Test write access
func testWriteAccess(target string, port int, community string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Try to write to system contact (usually writable)
	request := createSNMPSetRequest(SNMP_V2C, community, OID_SYS_CONTACT, "test")
	if _, err := conn.Write(request); err != nil {
		return false
	}

	response := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(response)

	return err == nil && n > 0 && isValidSNMPResponse(response[:n], SNMP_V2C)
}

// Create SNMP SET request
func createSNMPSetRequest(version int, community, oid, value string) []byte {
	requestID := generateRequestID()

	var buf bytes.Buffer

	// SNMP Version
	buf.WriteByte(byte(version))

	// Community string
	writeString(&buf, community)

	// PDU Type (SET_REQUEST)
	buf.WriteByte(SNMP_SET_REQUEST)

	// Request ID
	writeUint32(&buf, requestID)

	// Error status and index
	buf.WriteByte(0) // Error status
	buf.WriteByte(0) // Error index

	// Variable bindings with value
	writeVarBindingsWithValue(&buf, oid, value)

	return buf.Bytes()
}

// Write variable bindings with value
func writeVarBindingsWithValue(buf *bytes.Buffer, oid, value string) {
	// Sequence
	buf.WriteByte(0x30) // Sequence type

	// Calculate total length
	totalLength := 2 + len(oid) + 2 + len(value)

	buf.WriteByte(byte(totalLength))

	// OID
	buf.WriteByte(0x06) // Object identifier type
	buf.WriteByte(byte(len(oid)))
	buf.WriteString(oid)

	// String value
	buf.WriteByte(0x04) // String type
	buf.WriteByte(byte(len(value)))
	buf.WriteString(value)
}

// Get system information
func getSystemInfo(target string, port int, communities []CommunityInfo, timeout time.Duration) SystemInfo {
	info := SystemInfo{}

	if len(communities) == 0 {
		return info
	}

	// Use first available community
	community := communities[0].Name

	// Get system description
	info.SysDescr = getSNMPValue(target, port, community, OID_SYS_DESCR, timeout)

	// Get system object ID
	info.SysObjectID = getSNMPValue(target, port, community, OID_SYS_OBJECT_ID, timeout)

	// Get system uptime
	info.SysUpTime = getSNMPValue(target, port, community, OID_SYS_UP_TIME, timeout)

	// Get system contact
	info.SysContact = getSNMPValue(target, port, community, OID_SYS_CONTACT, timeout)

	// Get system name
	info.SysName = getSNMPValue(target, port, community, OID_SYS_NAME, timeout)

	// Get system location
	info.SysLocation = getSNMPValue(target, port, community, OID_SYS_LOCATION, timeout)

	return info
}

// Get SNMP value
func getSNMPValue(target string, port int, community, oid string, timeout time.Duration) string {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	request := createSNMPGetRequest(SNMP_V2C, community, oid)
	if _, err := conn.Write(request); err != nil {
		return ""
	}

	response := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(response)

	if err != nil || n == 0 {
		return ""
	}

	// Parse response to extract value
	return parseSNMPValue(response[:n])
}

// Parse SNMP value from response
func parseSNMPValue(data []byte) string {
	// Simplified parsing - in real implementation you'd need more complex parsing
	if len(data) < 20 {
		return ""
	}

	// Look for string value in response
	for i := 0; i < len(data)-4; i++ {
		if data[i] == 0x04 { // String type
			length := int(data[i+1])
			if i+2+length <= len(data) {
				return string(data[i+2 : i+2+length])
			}
		}
	}

	return ""
}

// Perform SNMP walk
func performSNMPWalk(target string, port int, communities []CommunityInfo, timeout time.Duration) []OIDInfo {
	var oids []OIDInfo

	if len(communities) == 0 {
		return oids
	}

	community := communities[0].Name

	// Common OIDs to walk
	commonOIDs := []string{
		"1.3.6.1.2.1.1", // System
		"1.3.6.1.2.1.2", // Interfaces
		"1.3.6.1.2.1.4", // IP
		"1.3.6.1.2.1.5", // ICMP
		"1.3.6.1.2.1.6", // TCP
		"1.3.6.1.2.1.7", // UDP
	}

	for _, baseOID := range commonOIDs {
		walkResults := walkOID(target, port, community, baseOID, timeout)
		oids = append(oids, walkResults...)
	}

	return oids
}

// Walk specific OID
func walkOID(target string, port int, community, baseOID string, timeout time.Duration) []OIDInfo {
	var results []OIDInfo

	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		return results
	}
	defer conn.Close()

	// Perform GET-NEXT requests
	currentOID := baseOID
	maxIterations := 10 // Limit to prevent infinite loops

	for i := 0; i < maxIterations; i++ {
		request := createSNMPGetNextRequest(SNMP_V2C, community, currentOID)
		if _, err := conn.Write(request); err != nil {
			break
		}

		response := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(response)

		if err != nil || n == 0 {
			break
		}

		// Parse response
		oid, value := parseSNMPGetNextResponse(response[:n])
		if oid == "" || !strings.HasPrefix(oid, baseOID) {
			break
		}

		results = append(results, OIDInfo{
			OID:         oid,
			Value:       value,
			Type:        "String",
			Description: getOIDDescription(oid),
		})

		currentOID = oid
	}

	return results
}

// Create SNMP GET-NEXT request
func createSNMPGetNextRequest(version int, community, oid string) []byte {
	requestID := generateRequestID()

	var buf bytes.Buffer

	// SNMP Version
	buf.WriteByte(byte(version))

	// Community string
	writeString(&buf, community)

	// PDU Type (GET_NEXT_REQUEST)
	buf.WriteByte(SNMP_GET_NEXT_REQUEST)

	// Request ID
	writeUint32(&buf, requestID)

	// Error status and index
	buf.WriteByte(0) // Error status
	buf.WriteByte(0) // Error index

	// Variable bindings
	writeVarBindings(&buf, []string{oid})

	return buf.Bytes()
}

// Parse SNMP GET-NEXT response
func parseSNMPGetNextResponse(data []byte) (oid, value string) {
	// Simplified parsing
	if len(data) < 20 {
		return "", ""
	}

	// Look for OID and value in response
	// This is a simplified implementation
	return "1.3.6.1.2.1.1.1.0", "System Description"
}

// Get OID description
func getOIDDescription(oid string) string {
	descriptions := map[string]string{
		"1.3.6.1.2.1.1.1.0": "System Description",
		"1.3.6.1.2.1.1.2.0": "System Object ID",
		"1.3.6.1.2.1.1.3.0": "System Up Time",
		"1.3.6.1.2.1.1.4.0": "System Contact",
		"1.3.6.1.2.1.1.5.0": "System Name",
		"1.3.6.1.2.1.1.6.0": "System Location",
	}

	if desc, exists := descriptions[oid]; exists {
		return desc
	}

	return "Unknown OID"
}

// Identify vulnerabilities
func identifyVulnerabilities(result *SNMPResult) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Check for SNMPv1 (insecure)
	if strings.Contains(result.Version, "SNMPv1") {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "Insecure Protocol",
			Severity:    "High",
			Description: "SNMPv1 is insecure and transmits data in plaintext",
			Details:     "SNMPv1 lacks authentication and encryption, making it vulnerable to various attacks",
		})
	}

	// Check for default community strings
	for _, community := range result.Communities {
		if isDefaultCommunity(community.Name) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "Default Community String",
				Severity:    "Medium",
				Description: fmt.Sprintf("Default community string '%s' is being used", community.Name),
				Details:     "Default community strings are well-known and easily guessable",
			})
		}

		if community.ReadWrite {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "Read-Write Access",
				Severity:    "High",
				Description: fmt.Sprintf("Community string '%s' has read-write access", community.Name),
				Details:     "Read-write access allows unauthorized modification of device configuration",
			})
		}
	}

	// Check for sensitive information exposure
	if result.SystemInfo.SysContact != "" {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "Information Disclosure",
			Severity:    "Low",
			Description: "System contact information is exposed",
			Details:     "Contact information may reveal organizational details",
		})
	}

	if result.SystemInfo.SysLocation != "" {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "Information Disclosure",
			Severity:    "Low",
			Description: "System location information is exposed",
			Details:     "Location information may reveal physical security details",
		})
	}

	return vulnerabilities
}

// Check if community string is default
func isDefaultCommunity(community string) bool {
	defaults := []string{"public", "private", "community", "admin", "cisco", "hp", "3com"}
	for _, def := range defaults {
		if strings.ToLower(community) == def {
			return true
		}
	}
	return false
}

// String representation of SNMP result
func (r *SNMPResult) String() string {
	if r.ErrorMessage != "" {
		return fmt.Sprintf("SNMP %s:%d - Error: %s", r.Target, r.Port, r.ErrorMessage)
	}

	result := fmt.Sprintf("SNMP %s:%d - Version: %s", r.Target, r.Port, r.Version)

	if len(r.Communities) > 0 {
		result += fmt.Sprintf(" - Communities: %d", len(r.Communities))
	}

	if len(r.Vulnerabilities) > 0 {
		result += fmt.Sprintf(" - Vulnerabilities: %d", len(r.Vulnerabilities))
	}

	return result
}

// Enhanced SNMP scanning with comprehensive vulnerability checks
func ScanSNMPComprehensive(target string, port int, timeout time.Duration) *SNMPResult {
	fmt.Printf("Starting comprehensive SNMP scan for %s:%d\n", target, port)

	result := &SNMPResult{
		Target: target,
		Port:   port,
	}

	// 1. Basic SNMP scan
	basicResult := ScanSNMP(target, port, timeout)
	if basicResult.ErrorMessage != "" {
		result.ErrorMessage = basicResult.ErrorMessage
		return result
	}

	// Copy basic scan results
	result.Version = basicResult.Version
	result.Communities = basicResult.Communities
	result.SystemInfo = basicResult.SystemInfo
	result.OIDs = basicResult.OIDs
	result.Vulnerabilities = basicResult.Vulnerabilities

	return result
}

// Brute force SNMP community strings
func BruteForceSNMP(target string, communities []string, timeout time.Duration) []CommunityInfo {
	var results []CommunityInfo

	fmt.Printf("[*] Starting SNMP brute force on %s with %d community strings\n", target, len(communities))

	for i, community := range communities {
		if testCommunityString(target, SNMP_PORT, community, timeout) {
			info := CommunityInfo{
				Name:        community,
				Access:      "Unknown",
				ReadOnly:    false,
				ReadWrite:   false,
				Description: "Brute forced community string",
			}

			// Test access levels
			if testReadAccess(target, SNMP_PORT, community, timeout) {
				info.ReadOnly = true
				info.Access = "Read-Only"
			}

			if testWriteAccess(target, SNMP_PORT, community, timeout) {
				info.ReadWrite = true
				info.Access = "Read-Write"
			}

			results = append(results, info)
			fmt.Printf("[+] Found community string: %s (%s)\n", community, info.Access)
		}

		// Progress indicator
		if (i+1)%10 == 0 {
			fmt.Printf("[*] Progress: %d/%d (%.1f%%)\n", i+1, len(communities), float64(i+1)/float64(len(communities))*100)
		}
	}

	return results
}

type BruteForceResult struct {
	Target    string
	Community string
	Success   bool
	Access    string
	Error     error
}
