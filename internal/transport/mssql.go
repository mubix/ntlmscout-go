package transport

import (
	"encoding/binary"
	"time"

	"github.com/mubix/ntlmscout/internal/netx"
	"github.com/mubix/ntlmscout/internal/ntlm"
)

// MSSQLChallenge performs a TDS PRELOGIN + LOGIN7 with integrated security and
// returns the raw NTLM Type-2 from the response.
func MSSQLChallenge(cfg *netx.Config, host string, port int, timeout time.Duration) []byte {
	conn, err := cfg.DialTCP(host, port, timeout)
	if err != nil {
		cfg.Debugf("mssql "+host, err)
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write(tdsPrelogin()); err != nil {
		cfg.Debugf("mssql prelogin "+host, err)
		return nil
	}
	tdsRecv(conn, timeout)
	if _, err := conn.Write(tdsLogin7SSPI()); err != nil {
		cfg.Debugf("mssql login7 "+host, err)
		return nil
	}
	resp := tdsRecv(conn, timeout)
	return ntlm.ExtractBlob(resp)
}

// tdsPacket wraps payload in a TDS packet (Type, Status=EOM, big-endian length).
func tdsPacket(ptype byte, payload []byte) []byte {
	out := make([]byte, 8+len(payload))
	out[0] = ptype
	out[1] = 1 // Status = EOM
	binary.BigEndian.PutUint16(out[2:], uint16(len(payload)+8))
	// SPID(2)=0, PacketID(1)=1, Window(1)=0
	out[6] = 1
	copy(out[8:], payload)
	return out
}

func tdsRecv(conn interface {
	Read([]byte) (int, error)
	SetReadDeadline(time.Time) error
}, timeout time.Duration) []byte {
	hdr := readExactRD(conn, 8, timeout)
	if len(hdr) < 8 {
		return nil
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length <= 8 {
		return nil
	}
	return readExactRD(conn, length-8, timeout)
}

func tdsPrelogin() []byte {
	ver := make([]byte, 6)
	binary.BigEndian.PutUint32(ver, 0x11000000) // v17.0
	// last 2 bytes (subbuild) already zero
	enc := []byte{0x02}  // ENCRYPT_NOT_SUP
	inst := []byte{0x00} // empty instance, null-terminated
	thread := []byte{0, 0, 0, 0}

	type opt struct {
		token byte
		data  []byte
	}
	options := []opt{{0x00, ver}, {0x01, enc}, {0x02, inst}, {0x03, thread}}

	var header, payload []byte
	running := 5*len(options) + 1 // each entry 5 bytes + 1 terminator
	for _, o := range options {
		e := make([]byte, 5)
		e[0] = o.token
		binary.BigEndian.PutUint16(e[1:], uint16(running))
		binary.BigEndian.PutUint16(e[3:], uint16(len(o.data)))
		header = append(header, e...)
		running += len(o.data)
		payload = append(payload, o.data...)
	}
	header = append(header, 0xFF)
	return tdsPacket(0x12, append(header, payload...))
}

func tdsLogin7SSPI() []byte {
	sspi := ntlm.DefaultType1()
	const fixed = 94
	appname := utf16leBytesLocal("ntlmscout")
	libname := utf16leBytesLocal("ntlmscout")

	var data []byte
	type off struct{ o, l int }
	offsets := map[string]off{}
	add := func(name string, blob []byte) {
		offsets[name] = off{fixed + len(data), len(blob)}
		data = append(data, blob...)
	}
	add("host", nil)
	add("user", nil)
	add("pass", nil)
	add("app", appname)
	add("server", nil)
	add("unused", nil)
	add("lib", libname)
	add("lang", nil)
	add("db", nil)
	sspiOff := fixed + len(data)
	data = append(data, sspi...)
	total := fixed + len(data)

	var b []byte
	b = binary.LittleEndian.AppendUint32(b, uint32(total))
	b = binary.LittleEndian.AppendUint32(b, 0x74000004) // TDSVersion 7.4
	b = binary.LittleEndian.AppendUint32(b, 4096)       // PacketSize
	b = binary.LittleEndian.AppendUint32(b, 0x07000000) // ClientProgVer
	b = binary.LittleEndian.AppendUint32(b, 0)          // ClientPID
	b = binary.LittleEndian.AppendUint32(b, 0)          // ConnectionID
	b = append(b, 0xE0)                                 // OptionFlags1
	b = append(b, 0x80)                                 // OptionFlags2 = fIntSecurity ON
	b = append(b, 0x00)                                 // TypeFlags
	b = append(b, 0x00)                                 // OptionFlags3
	b = binary.LittleEndian.AppendUint32(b, 0)          // ClientTimeZone
	b = binary.LittleEndian.AppendUint32(b, 0x00000409) // ClientLCID

	ol := func(name string, char bool) {
		e := offsets[name]
		b = binary.LittleEndian.AppendUint16(b, uint16(e.o))
		if char {
			b = binary.LittleEndian.AppendUint16(b, uint16(e.l/2))
		} else {
			b = binary.LittleEndian.AppendUint16(b, uint16(e.l))
		}
	}
	for _, n := range []string{"host", "user", "pass", "app", "server", "unused", "lib", "lang", "db"} {
		ol(n, true)
	}
	b = append(b, make([]byte, 6)...) // ClientID (MAC)
	b = binary.LittleEndian.AppendUint16(b, uint16(sspiOff))
	b = binary.LittleEndian.AppendUint16(b, uint16(len(sspi)))
	b = binary.LittleEndian.AppendUint16(b, 0) // AtchDBFile off
	b = binary.LittleEndian.AppendUint16(b, 0) // AtchDBFile len
	b = binary.LittleEndian.AppendUint16(b, 0) // ChangePassword off
	b = binary.LittleEndian.AppendUint16(b, 0) // ChangePassword len
	b = binary.LittleEndian.AppendUint32(b, 0) // cbSSPILong
	b = append(b, data...)
	return tdsPacket(0x10, b)
}

// utf16leBytesLocal encodes an ASCII/BMP string to UTF-16LE (local helper to
// avoid exporting from the ntlm package for this use).
func utf16leBytesLocal(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = binary.LittleEndian.AppendUint16(out, uint16(r))
	}
	return out
}
