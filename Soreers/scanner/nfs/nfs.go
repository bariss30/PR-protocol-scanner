package nfs

import (
	"SOREERS/utils"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Result types

type NFSResult struct {
	Target          string
	VersionSummary  string
	NFSPrograms     []ProgramMapping
	MountdPort      int
	Exports         []ExportInfo
	PortmapperAlive bool
	Anonymous       bool
	ErrorMessage    string
}

type ProgramMapping struct {
	Program  uint32
	Version  uint32
	Protocol uint32 // 6=tcp, 17=udp
	Port     uint32
}

type ExportInfo struct {
	Path   string
	Groups []string
}

// Constants

const (
	programPortmap = 100000 // rpcbind v2 (portmapper)
	versionPortmap = 2

	programMountd = 100005 // mount
	programNFS    = 100003 // nfs

	// Portmapper procedures (v2)
	pmapNULL = 0
	pmapDUMP = 4

	// Mountd v3 procedures
	mountv3EXPORT = 5
)

// ScanNFS performs discovery using rpcbind and mountd EXPORTS
func ScanNFS(target string, timeout time.Duration) *NFSResult {
	res := &NFSResult{Target: target}

	alive := isPortOpen(target, 111, timeout)
	res.PortmapperAlive = alive
	if !alive {
		res.ErrorMessage = "rpcbind (111/tcp) is not reachable"
		return res
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, 111), timeout)
	if err != nil {
		res.ErrorMessage = fmt.Sprintf("connect rpcbind: %v", err)
		return res
	}
	defer conn.Close()

	// Query DUMP
	mappings, err := rpcbindDump(conn, timeout)
	if err != nil || len(mappings) == 0 {
		res.ErrorMessage = fmt.Sprintf("rpcbind dump failed: %v", err)
		return res
	}
	res.NFSPrograms = mappingsForProgram(mappings, programNFS)

	// Summarize versions
	versions := map[uint32]struct{}{}
	for _, m := range res.NFSPrograms {
		versions[m.Version] = struct{}{}
	}
	var vlist []string
	for v := range versions {
		vlist = append(vlist, fmt.Sprintf("v%d", v))
	}
	sort.Strings(vlist)
	if len(vlist) > 0 {
		res.VersionSummary = strings.Join(vlist, ", ")
	} else {
		res.VersionSummary = "unknown"
	}

	// Find mountd over TCP (protocol 6) and get port
	res.MountdPort = int(findProgramPortTCP(mappings, programMountd))
	if res.MountdPort > 0 {
		exps, anon, err := fetchExports(target, res.MountdPort, timeout)
		if err == nil {
			res.Exports = exps
			res.Anonymous = anon
		}
	}

	return res
}

func isPortOpen(host string, port int, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// rpc, xdr helpers

type rpcCall struct {
	XID       uint32
	Program   uint32
	Version   uint32
	Procedure uint32
}

const (
	rpcCallMsg  = 0
	rpcReplyMsg = 1

	authNULL = 0
)

func nextXID() uint32 { return 0x12345678 }

func buildRPCCall(req rpcCall, credFlavor uint32, credBody []byte, verfFlavor uint32, verfBody []byte, args []byte) []byte {
	// RPC header
	buf := new(bytes.Buffer)
	writeU32(buf, req.XID)
	writeU32(buf, rpcCallMsg)
	writeU32(buf, 2) // RPC version
	writeU32(buf, req.Program)
	writeU32(buf, req.Version)
	writeU32(buf, req.Procedure)
	// Credentials
	writeU32(buf, credFlavor)
	writeOpaque(buf, credBody)
	// Verifier
	writeU32(buf, verfFlavor)
	writeOpaque(buf, verfBody)
	// Arguments
	buf.Write(args)
	return wrapRecord(buf.Bytes())
}

func wrapRecord(payload []byte) []byte {
	// RPC over TCP record marking: MSB set indicates last fragment
	marker := uint32(0x80000000 | uint32(len(payload)))
	head := new(bytes.Buffer)
	writeU32(head, marker)
	return append(head.Bytes(), payload...)
}

func readRPCReply(conn net.Conn, timeout time.Duration) ([]byte, error) {
	// read fragments until MSB set
	var out []byte
	deadline := time.Now().Add(timeout)
	_ = conn.SetReadDeadline(deadline)
	for {
		var marker uint32
		if err := binary.Read(conn, binary.BigEndian, &marker); err != nil {
			return nil, err
		}
		last := (marker & 0x80000000) != 0
		length := int(marker & 0x7fffffff)
		if length <= 0 || length > 1<<20 {
			return nil, errors.New("invalid rpc fragment length")
		}
		frag := make([]byte, length)
		if _, err := ioReadFull(conn, frag); err != nil {
			return nil, err
		}
		out = append(out, frag...)
		if last {
			break
		}
	}
	return out, nil
}

func ioReadFull(r net.Conn, b []byte) (int, error) {
	read := 0
	for read < len(b) {
		n, err := r.Read(b[read:])
		if n > 0 {
			read += n
		}
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

func writeU32(buf *bytes.Buffer, v uint32) { _ = binary.Write(buf, binary.BigEndian, v) }

func writeOpaque(buf *bytes.Buffer, data []byte) {
	writeU32(buf, uint32(len(data)))
	buf.Write(data)
	pad := (4 - (len(data) % 4)) % 4
	if pad != 0 {
		buf.Write(make([]byte, pad))
	}
}

// XDR reader

type xdrReader struct{ *bytes.Reader }

func newXDR(b []byte) *xdrReader { return &xdrReader{bytes.NewReader(b)} }

func (x *xdrReader) u32() (uint32, error) {
	var v uint32
	if err := binary.Read(x, binary.BigEndian, &v); err != nil {
		return 0, err
	}
	return v, nil
}

func (x *xdrReader) bool() (bool, error) {
	v, err := x.u32()
	if err != nil {
		return false, err
	}
	return v != 0, nil
}

func (x *xdrReader) opaque() ([]byte, error) {
	l, err := x.u32()
	if err != nil {
		return nil, err
	}
	if l > 1<<20 {
		return nil, errors.New("xdr string too large")
	}
	data := make([]byte, l)
	if _, err := x.Read(data); err != nil {
		return nil, err
	}
	pad := (4 - (int(l) % 4)) % 4
	if pad > 0 {
		if _, err := x.Seek(int64(pad), 1); err != nil {
			return nil, err
		}
	}
	return data, nil
}

func (x *xdrReader) skipOpaque() error { _, err := x.opaque(); return err }

func (x *xdrReader) str() (string, error) {
	b, err := x.opaque()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// rpcbind DUMP

func rpcbindDump(conn net.Conn, timeout time.Duration) ([]ProgramMapping, error) {
	xid := nextXID()
	call := rpcCall{XID: xid, Program: programPortmap, Version: versionPortmap, Procedure: pmapDUMP}
	payload := buildRPCCall(call, authNULL, nil, authNULL, nil, nil)
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	reply, err := readRPCReply(conn, timeout)
	if err != nil {
		return nil, err
	}

	// Parse RPC reply header
	x := newXDR(reply)
	if _, err := x.u32(); err != nil {
		return nil, err
	} // xid
	mtype, err := x.u32()
	if err != nil || mtype != rpcReplyMsg {
		return nil, errors.New("not a reply")
	}
	// reply body: MSG_ACCEPTED path
	// skip reply state verifier etc
	// reply state
	_, err = x.u32()
	if err != nil {
		return nil, err
	} // reply stat (0 accepted / 1 denied)
	// verifier
	if _, err := x.u32(); err != nil {
		return nil, err
	}
	if err := x.skipOpaque(); err != nil {
		return nil, err
	}
	// accept stat
	astat, err := x.u32()
	if err != nil {
		return nil, err
	}
	if astat != 0 {
		return nil, errors.New("rpc accept not success")
	}

	// result: pmaplist (linked list via bool)
	var out []ProgramMapping
	for {
		more, err := x.bool()
		if err != nil {
			return nil, err
		}
		if !more {
			break
		}
		prog, err := x.u32()
		if err != nil {
			return nil, err
		}
		vers, err := x.u32()
		if err != nil {
			return nil, err
		}
		proto, err := x.u32()
		if err != nil {
			return nil, err
		}
		port, err := x.u32()
		if err != nil {
			return nil, err
		}
		out = append(out, ProgramMapping{Program: prog, Version: vers, Protocol: proto, Port: port})
	}
	return out, nil
}

func mappingsForProgram(all []ProgramMapping, program uint32) []ProgramMapping {
	var res []ProgramMapping
	for _, m := range all {
		if m.Program == program {
			res = append(res, m)
		}
	}
	return res
}

func findProgramPortTCP(all []ProgramMapping, program uint32) uint32 {
	best := uint32(0)
	for _, m := range all {
		if m.Program == program && m.Protocol == 6 { // TCP
			// prefer v3 over others
			if m.Version == 3 {
				return m.Port
			}
			best = m.Port
		}
	}
	return best
}

// fetchExports calls mountd EXPORT and parses export list

func fetchExports(target string, port int, timeout time.Duration) ([]ExportInfo, bool, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()

	call := rpcCall{XID: nextXID(), Program: programMountd, Version: 3, Procedure: mountv3EXPORT}
	payload := buildRPCCall(call, authNULL, nil, authNULL, nil, nil)
	if _, err := conn.Write(payload); err != nil {
		return nil, false, err
	}
	reply, err := readRPCReply(conn, timeout)
	if err != nil {
		return nil, false, err
	}

	x := newXDR(reply)
	if _, err := x.u32(); err != nil {
		return nil, false, err
	} // xid
	mtype, err := x.u32()
	if err != nil || mtype != rpcReplyMsg {
		return nil, false, errors.New("not a reply")
	}
	_, err = x.u32()
	if err != nil {
		return nil, false, err
	} // reply stat
	// verifier
	if _, err := x.u32(); err != nil {
		return nil, false, err
	}
	if err := x.skipOpaque(); err != nil {
		return nil, false, err
	}
	astat, err := x.u32()
	if err != nil {
		return nil, false, err
	}
	if astat != 0 {
		return nil, false, errors.New("rpc accept not success")
	}

	// result: export list (linked list)
	var exports []ExportInfo
	for {
		more, err := x.bool()
		if err != nil {
			return nil, true, err
		}
		if !more {
			break
		}
		path, err := x.str()
		if err != nil {
			return nil, true, err
		}
		var groups []string
		for {
			gmore, err := x.bool()
			if err != nil {
				return nil, true, err
			}
			if !gmore {
				break
			}
			gname, err := x.str()
			if err != nil {
				return nil, true, err
			}
			groups = append(groups, gname)
		}
		exports = append(exports, ExportInfo{Path: path, Groups: groups})
	}
	// If we reached here, anonymous (AUTH_NULL) worked
	return exports, true, nil
}
func (r *NFSResult) String() string {
	if r.ErrorMessage != "" {
		return fmt.Sprintf("%s %s %s",
			utils.Colorize("✗", utils.ColorRed),
			utils.BoldText("NFS Hata:"),
			utils.Colorize(r.ErrorMessage, utils.ColorRed))
	}
	var b strings.Builder
	b.WriteString(utils.BoldText(utils.Colorize("╔══════════════════════════════════════════════╗\n", utils.ColorCyan)))
	b.WriteString(fmt.Sprintf("%s %s\n", utils.Colorize("Target:", utils.ColorYellow), r.Target))
	b.WriteString(fmt.Sprintf("%s %v\n", utils.Colorize("rpcbind:", utils.ColorYellow), r.PortmapperAlive))
	if len(r.NFSPrograms) > 0 {
		b.WriteString(fmt.Sprintf("%s %s\n", utils.Colorize("NFS Versions:", utils.ColorYellow), utils.Colorize(r.VersionSummary, utils.ColorGreen)))
	}
	if r.MountdPort > 0 {
		b.WriteString(fmt.Sprintf("%s %d\n", utils.Colorize("mountd port:", utils.ColorYellow), r.MountdPort))
	}
	b.WriteString(fmt.Sprintf("%s %d\n", utils.Colorize("Exports:", utils.ColorYellow), len(r.Exports)))
	for _, e := range r.Exports {
		b.WriteString(fmt.Sprintf("  %s %s %s %s\n", utils.Colorize("•", utils.ColorCyan), utils.Colorize(e.Path, utils.ColorGreen), utils.Colorize("(groups: ", utils.ColorPurple)+utils.Colorize(strings.Join(e.Groups, ","), utils.ColorWhite)+utils.Colorize(")", utils.ColorPurple)))
	}
	b.WriteString(fmt.Sprintf("%s %v\n", utils.Colorize("Anonymous access:", utils.ColorYellow), r.Anonymous))
	b.WriteString(utils.BoldText(utils.Colorize("╚══════════════════════════════════════════════╝\n", utils.ColorCyan)))
	return b.String()
}
