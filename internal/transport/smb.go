package transport

import (
	"encoding/binary"
	"time"

	"github.com/mubix/ntlmscout/internal/der"
	"github.com/mubix/ntlmscout/internal/netx"
	"github.com/mubix/ntlmscout/internal/ntlm"
)

// SMBChallenge negotiates SMB and drives a SPNEGO SESSION_SETUP to extract the
// NTLM Type-2. It tries SMB2/3 first (every Windows since Vista) and falls back
// to SMB1 with extended security for legacy targets (Windows 2000/XP/2003 and
// old Samba) that do not speak SMB2.
func SMBChallenge(cfg *netx.Config, host string, port int, timeout time.Duration) []byte {
	if blob := smb2Challenge(cfg, host, port, timeout); blob != nil {
		return blob
	}
	cfg.Debugln("smb " + host + ": SMB2 yielded no challenge, trying SMB1 fallback")
	return smb1Challenge(cfg, host, port, timeout)
}

func smb2Challenge(cfg *netx.Config, host string, port int, timeout time.Duration) []byte {
	conn, err := cfg.DialTCP(host, port, timeout)
	if err != nil {
		cfg.Debugf("smb2 "+host, err)
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write(smb2NegotiateRequest()); err != nil {
		cfg.Debugf("smb2 negotiate "+host, err)
		return nil
	}
	if smbRecv(conn, timeout) == nil {
		return nil
	}
	if _, err := conn.Write(smb2SessionSetupRequest()); err != nil {
		cfg.Debugf("smb2 sessionsetup "+host, err)
		return nil
	}
	resp := smbRecv(conn, timeout)
	return ntlm.ExtractBlob(resp)
}

// smbRecv reads one NBSS-framed message (4-byte big-endian length, low 24 bits).
func smbRecv(conn interface {
	Read([]byte) (int, error)
	SetReadDeadline(time.Time) error
}, timeout time.Duration) []byte {
	hdr := readExactRD(conn, 4, timeout)
	if len(hdr) < 4 {
		return nil
	}
	length := int(binary.BigEndian.Uint32(hdr) & 0x00FFFFFF)
	if length <= 0 || length > 1<<20 {
		return nil
	}
	return readExactRD(conn, length, timeout)
}

// readExactRD is readExact but for the minimal interface used by smbRecv.
func readExactRD(conn interface {
	Read([]byte) (int, error)
	SetReadDeadline(time.Time) error
}, n int, timeout time.Duration) []byte {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, n)
	got := 0
	for got < n {
		m, err := conn.Read(buf[got:])
		got += m
		if err != nil {
			return buf[:got]
		}
	}
	return buf
}

func nbss(payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	copy(out[4:], payload)
	return out
}

func smb2Header(command uint16, messageID uint64) []byte {
	h := make([]byte, 64)
	copy(h[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(h[4:], 64)       // StructureSize
	binary.LittleEndian.PutUint16(h[6:], 1)        // CreditCharge
	binary.LittleEndian.PutUint16(h[12:], command) // Command
	binary.LittleEndian.PutUint16(h[14:], 31)      // CreditRequest
	binary.LittleEndian.PutUint64(h[24:], messageID)
	binary.LittleEndian.PutUint32(h[32:], 0xFEFF) // Reserved (ProcessId)
	return h
}

func smb2NegotiateRequest() []byte {
	hdr := smb2Header(0x0000, 0)
	body := make([]byte, 0, 64)
	body = binary.LittleEndian.AppendUint16(body, 36)     // StructureSize
	body = binary.LittleEndian.AppendUint16(body, 4)      // DialectCount
	body = binary.LittleEndian.AppendUint16(body, 0x0001) // SecurityMode = signing enabled
	body = binary.LittleEndian.AppendUint16(body, 0)      // Reserved
	body = binary.LittleEndian.AppendUint32(body, 0)      // Capabilities
	body = append(body, make([]byte, 16)...)              // ClientGuid
	body = binary.LittleEndian.AppendUint32(body, 0)      // NegotiateContextOffset
	body = binary.LittleEndian.AppendUint16(body, 0)      // NegotiateContextCount
	body = binary.LittleEndian.AppendUint16(body, 0)      // Reserved2
	// Dialects 2.0.2, 2.1, 3.0, 3.0.2 (avoid 3.1.1 preauth-integrity handshake).
	for _, d := range []uint16{0x0202, 0x0210, 0x0300, 0x0302} {
		body = binary.LittleEndian.AppendUint16(body, d)
	}
	return nbss(append(hdr, body...))
}

func smb2SessionSetupRequest() []byte {
	hdr := smb2Header(0x0001, 1)
	token := der.SPNEGONegTokenInit(ntlm.DefaultType1())
	const structSize = 25
	secOff := 64 + structSize - 1
	body := make([]byte, 0, 24+len(token))
	body = binary.LittleEndian.AppendUint16(body, structSize) // StructureSize
	body = append(body, 0)                                    // Flags
	body = append(body, 1)                                    // SecurityMode = signing enabled
	body = binary.LittleEndian.AppendUint32(body, 1)          // Capabilities = DFS
	body = binary.LittleEndian.AppendUint32(body, 0)          // Channel
	body = binary.LittleEndian.AppendUint16(body, uint16(secOff))
	body = binary.LittleEndian.AppendUint16(body, uint16(len(token)))
	body = binary.LittleEndian.AppendUint64(body, 0) // PreviousSessionId
	body = append(body, token...)
	return nbss(append(hdr, body...))
}

// ---- SMB1 fallback (extended security) ----

const (
	smb1CapUnicode   = 0x00000004
	smb1CapNTSmbs    = 0x00000010
	smb1CapStatus32  = 0x00000040
	smb1CapExtendSec = 0x80000000
	smb1Flags2       = 0xC800 // NT_STATUS | EXTENDED_SECURITY | UNICODE
)

func smb1Header(command byte) []byte {
	h := make([]byte, 32)
	copy(h[0:4], []byte{0xFF, 'S', 'M', 'B'})
	h[4] = command
	// status(5:9)=0, flags(9), flags2(10:12), PIDHigh(12:14), signature(14:22),
	// reserved(22:24), TID(24:26), PIDLow(26:28), UID(28:30), MID(30:32).
	binary.LittleEndian.PutUint16(h[10:], smb1Flags2)
	return h
}

func smb1NegotiateRequest() []byte {
	hdr := smb1Header(0x72) // SMB_COM_NEGOTIATE
	// WordCount = 0.
	body := []byte{0x00}
	// Dialect entries: buffer format 0x02 + null-terminated dialect string.
	dialects := []byte{}
	dialects = append(dialects, 0x02)
	dialects = append(dialects, []byte("NT LM 0.12")...)
	dialects = append(dialects, 0x00)
	bc := make([]byte, 2)
	binary.LittleEndian.PutUint16(bc, uint16(len(dialects)))
	body = append(body, bc...)
	body = append(body, dialects...)
	return nbss(append(hdr, body...))
}

func smb1SessionSetupRequest() []byte {
	hdr := smb1Header(0x73) // SMB_COM_SESSION_SETUP_ANDX
	token := der.SPNEGONegTokenInit(ntlm.DefaultType1())

	params := make([]byte, 0, 24)
	params = append(params, 0xFF, 0x00)                                   // AndXCommand=none, reserved
	params = binary.LittleEndian.AppendUint16(params, 0)                  // AndXOffset
	params = binary.LittleEndian.AppendUint16(params, 4356)               // MaxBufferSize
	params = binary.LittleEndian.AppendUint16(params, 50)                 // MaxMpxCount
	params = binary.LittleEndian.AppendUint16(params, 0)                  // VcNumber
	params = binary.LittleEndian.AppendUint32(params, 0)                  // SessionKey
	params = binary.LittleEndian.AppendUint16(params, uint16(len(token))) // SecurityBlobLength
	params = binary.LittleEndian.AppendUint32(params, 0)                  // Reserved
	params = binary.LittleEndian.AppendUint32(params,
		smb1CapUnicode|smb1CapNTSmbs|smb1CapStatus32|smb1CapExtendSec) // Capabilities

	wordCount := byte(len(params) / 2) // 12 words

	// Data: SecurityBlob, then a Unicode pad + empty NativeOS/NativeLanMan.
	data := append([]byte{}, token...)
	// Unicode alignment pad if needed, then two empty null-terminated wide strings.
	data = append(data, 0x00)       // padding for word alignment of unicode strings
	data = append(data, 0x00, 0x00) // NativeOS = ""
	data = append(data, 0x00, 0x00) // NativeLanMan = ""

	bc := make([]byte, 2)
	binary.LittleEndian.PutUint16(bc, uint16(len(data)))

	body := append([]byte{wordCount}, params...)
	body = append(body, bc...)
	body = append(body, data...)
	return nbss(append(hdr, body...))
}

func smb1Challenge(cfg *netx.Config, host string, port int, timeout time.Duration) []byte {
	conn, err := cfg.DialTCP(host, port, timeout)
	if err != nil {
		cfg.Debugf("smb1 "+host, err)
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write(smb1NegotiateRequest()); err != nil {
		cfg.Debugf("smb1 negotiate "+host, err)
		return nil
	}
	neg := smbRecv(conn, timeout)
	if neg == nil {
		return nil
	}
	if _, err := conn.Write(smb1SessionSetupRequest()); err != nil {
		cfg.Debugf("smb1 sessionsetup "+host, err)
		return nil
	}
	resp := smbRecv(conn, timeout)
	return ntlm.ExtractBlob(resp)
}
