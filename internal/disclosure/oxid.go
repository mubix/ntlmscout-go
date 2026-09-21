package disclosure

import (
	"encoding/binary"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/mubix/ntlmscout/internal/netx"
)

// UUID byte_le encodings of the IOXIDResolver interface and NDR transfer syntax.
var (
	uuidIOXID = []byte{0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a}
	uuidNDR   = []byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
)

func rpcCommonHeader(ptype byte, fragLen, callID uint32) []byte {
	h := []byte{5, 0, ptype, 0x03}        // rpc_vers, minor, ptype, pfc_flags(first|last)
	h = append(h, 0x10, 0x00, 0x00, 0x00) // NDR LE data representation
	h = binary.LittleEndian.AppendUint16(h, uint16(fragLen))
	h = binary.LittleEndian.AppendUint16(h, 0) // auth_len
	h = binary.LittleEndian.AppendUint32(h, callID)
	return h
}

func rpcBind() []byte {
	ctx := make([]byte, 0, 44)
	ctx = binary.LittleEndian.AppendUint16(ctx, 0) // p_cont_id
	ctx = append(ctx, 1, 0)                        // n_transfer=1, reserved
	ctx = append(ctx, uuidIOXID...)
	ctx = binary.LittleEndian.AppendUint16(ctx, 0) // if_vers major
	ctx = binary.LittleEndian.AppendUint16(ctx, 0) // if_vers minor
	ctx = append(ctx, uuidNDR...)
	ctx = binary.LittleEndian.AppendUint16(ctx, 2) // xfer major
	ctx = binary.LittleEndian.AppendUint16(ctx, 0) // xfer minor

	body := make([]byte, 0, 12+len(ctx))
	body = binary.LittleEndian.AppendUint16(body, 5840) // max_xmit
	body = binary.LittleEndian.AppendUint16(body, 5840) // max_recv
	body = binary.LittleEndian.AppendUint32(body, 0)    // assoc_group
	body = append(body, 1, 0)                           // n_context_elem=1, reserved
	body = binary.LittleEndian.AppendUint16(body, 0)    // reserved2
	body = append(body, ctx...)
	return append(rpcCommonHeader(11, uint32(16+len(body)), 1), body...)
}

func rpcRequest(opnum uint16, stub []byte) []byte {
	body := make([]byte, 0, 8+len(stub))
	body = binary.LittleEndian.AppendUint32(body, uint32(len(stub))) // alloc_hint
	body = binary.LittleEndian.AppendUint16(body, 0)                 // cont_id
	body = binary.LittleEndian.AppendUint16(body, opnum)
	body = append(body, stub...)
	return append(rpcCommonHeader(0, uint32(16+len(body)), 2), body...)
}

func rpcRecv(conn interface {
	Read([]byte) (int, error)
	SetReadDeadline(time.Time) error
}, timeout time.Duration) []byte {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	hdr := make([]byte, 16)
	got := 0
	for got < 16 {
		m, err := conn.Read(hdr[got:])
		got += m
		if err != nil {
			return nil
		}
	}
	frag := int(binary.LittleEndian.Uint16(hdr[8:10]))
	if frag < 16 {
		return hdr[:got]
	}
	body := make([]byte, 0, frag-16)
	rem := frag - 16
	buf := make([]byte, rem)
	read := 0
	for read < rem {
		m, err := conn.Read(buf[read:])
		read += m
		if err != nil {
			break
		}
	}
	body = append(body, buf[:read]...)
	return append(hdr, body...)
}

// OXIDResolve queries IOXIDResolver::ServerAlive2 (TCP 135) and returns every
// interface binding as an address (Internal nil for non-IP hostname strings).
func OXIDResolve(cfg *netx.Config, host string, port int, timeout time.Duration) []Address {
	conn, err := cfg.DialTCP(host, port, timeout)
	if err != nil {
		cfg.Debugf("oxid "+host, err)
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write(rpcBind()); err != nil {
		cfg.Debugf("oxid bind "+host, err)
		return nil
	}
	ack := rpcRecv(conn, timeout)
	if len(ack) < 3 || ack[2] != 12 { // ptype 12 = bind_ack
		return nil
	}
	if _, err := conn.Write(rpcRequest(5, nil)); err != nil { // ServerAlive2
		cfg.Debugf("oxid request "+host, err)
		return nil
	}
	resp := rpcRecv(conn, timeout)
	if len(resp) < 24 {
		return nil
	}
	return parseServerAlive2(resp[24:])
}

func parseServerAlive2(stub []byte) []Address {
	var addrs []string
	func() {
		defer func() { _ = recover() }() // parsing is best-effort
		off := 4                         // skip COMVERSION
		off += 4                         // skip unique-ptr referent id
		off += 4                         // skip conformant max_count
		if off+4 > len(stub) {
			return
		}
		num := int(binary.LittleEndian.Uint16(stub[off:]))
		off += 2
		secoff := int(binary.LittleEndian.Uint16(stub[off:]))
		off += 2
		if off+num*2 > len(stub) || secoff*2 > num*2 {
			return
		}
		warr := stub[off : off+num*2]
		sbind := warr[:secoff*2]
		i := 0
		for i+2 <= len(sbind) {
			tower := binary.LittleEndian.Uint16(sbind[i:])
			if tower == 0 {
				break
			}
			i += 2
			start := i
			for i+2 <= len(sbind) && (sbind[i] != 0 || sbind[i+1] != 0) {
				i += 2
			}
			s := decodeUTF16LE(sbind[start:i])
			i += 2
			if s = strings.TrimSpace(s); s != "" {
				addrs = append(addrs, s)
			}
		}
	}()

	if len(addrs) == 0 { // fallback: scrape address-looking tokens
		text := decodeUTF16LE(stub)
		addrs = findIPs(text)
	}

	out := make([]Address, 0, len(addrs))
	seen := map[string]bool{}
	for _, a := range addrs {
		a = strings.TrimSpace(strings.Trim(a, "\x00"))
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		internal := isInternalAddr(a)
		out = append(out, Address{Address: a, Internal: internal, IsIP: internal != nil})
	}
	return out
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}
