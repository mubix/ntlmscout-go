package transport

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/mubix/ntlmscout/internal/der"
	"github.com/mubix/ntlmscout/internal/netx"
	"github.com/mubix/ntlmscout/internal/ntlm"
)

// RDPChallenge drives RDP CredSSP/NLA: X.224 connection request negotiating
// SSL|HYBRID, a TLS upgrade, then a CredSSP TSRequest carrying the SPNEGO
// NegTokenInit; it returns the raw NTLM Type-2 from the reply.
func RDPChallenge(cfg *netx.Config, host string, port int, timeout time.Duration) []byte {
	conn, err := cfg.DialTCP(host, port, timeout)
	if err != nil {
		cfg.Debugf("rdp "+host, err)
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write(RDPX224CR()); err != nil {
		cfg.Debugf("rdp x224 "+host, err)
		return nil
	}
	cc := readTPKT(conn, timeout)
	// Inspect the X.224 Connection Confirm: if the server rejected the request
	// or selected standard RDP security (no TLS), don't attempt a TLS handshake
	// -- that only yields a confusing "not a TLS handshake" error.
	if !rdpNegotiationAllowsTLS(cfg, host, cc) {
		return nil
	}
	tconn, err := cfg.WrapTLS(conn, host, timeout)
	if err != nil {
		cfg.Debugf("rdp tls "+host, err)
		return nil
	}
	if _, err := tconn.Write(credsspTSRequest(der.SPNEGONegTokenInit(ntlm.DefaultType1()))); err != nil {
		cfg.Debugf("rdp tsrequest "+host, err)
		return nil
	}
	resp := readUntilSig(tconn, timeout)
	return ntlm.ExtractBlob(resp)
}

// RDPX224CR builds the RDP X.224 Connection Request negotiating SSL|HYBRID.
func RDPX224CR() []byte {
	neg := make([]byte, 8)
	neg[0] = 0x01 // TYPE_RDP_NEG_REQ
	neg[1] = 0x00 // flags
	binary.LittleEndian.PutUint16(neg[2:], 0x0008)
	binary.LittleEndian.PutUint32(neg[4:], 0x00000003) // PROTOCOL_SSL | PROTOCOL_HYBRID

	x224 := make([]byte, 0, 7+len(neg))
	x224 = append(x224, byte(6+len(neg))) // LI
	x224 = append(x224, 0xE0)             // CR
	x224 = append(x224, 0x00, 0x00)       // DST-REF
	x224 = append(x224, 0x00, 0x00)       // SRC-REF
	x224 = append(x224, 0x00)             // class
	x224 = append(x224, neg...)

	tpkt := make([]byte, 4)
	tpkt[0] = 0x03
	tpkt[1] = 0x00
	binary.BigEndian.PutUint16(tpkt[2:], uint16(4+len(x224)))
	return append(tpkt, x224...)
}

// rdpNegotiationAllowsTLS parses the X.224 Connection Confirm's RDP negotiation
// response. It returns false when the server sent an RDP_NEG_FAILURE or selected
// PROTOCOL_RDP (standard security, no TLS). When it can't tell, it returns true
// so the TLS attempt still happens (no regression versus not parsing at all).
func rdpNegotiationAllowsTLS(cfg *netx.Config, host string, cc []byte) bool {
	// X.224 CC: [LI][0xD0][dst-ref:2][src-ref:2][class:1] then optional
	// RDP_NEG_* (type:1, flags:1, length:2, data:4).
	if len(cc) < 7+8 {
		return true // no negotiation structure present; try TLS
	}
	negType := cc[7]
	data := binary.LittleEndian.Uint32(cc[11:15])
	switch negType {
	case 0x03: // TYPE_RDP_NEG_FAILURE
		cfg.Debugln(fmt.Sprintf("rdp %s: negotiation failure (code %d); TLS/CredSSP not offered", host, data))
		return false
	case 0x02: // TYPE_RDP_NEG_RSP
		if data == 0x00000000 { // PROTOCOL_RDP -- standard RDP security, no TLS
			cfg.Debugln("rdp " + host + ": standard RDP security only (no TLS/CredSSP)")
			return false
		}
	}
	return true
}

// readTPKT reads one TPKT-framed unit (4-byte header, big-endian total length).
func readTPKT(conn net.Conn, timeout time.Duration) []byte {
	hdr := readExact(conn, 4, timeout)
	if len(hdr) < 4 {
		return nil
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length <= 4 {
		return nil
	}
	return readExact(conn, length-4, timeout)
}

// ReadTPKTPreamble performs the X.224 exchange on conn so a caller can then
// upgrade to TLS (used by the RDP certificate-disclosure probe).
func ReadTPKTPreamble(conn net.Conn, timeout time.Duration) error {
	if _, err := conn.Write(RDPX224CR()); err != nil {
		return err
	}
	readTPKT(conn, timeout)
	return nil
}

func credsspTSRequest(spnegoToken []byte) []byte {
	negoToken := der.TLV(0xA0, der.TLV(0x04, spnegoToken))
	negoData := der.TLV(0x30, negoToken)
	negoTokens := der.TLV(0xA1, der.TLV(0x30, negoData))
	version := der.TLV(0xA0, der.Int(6))
	return der.TLV(0x30, append(version, negoTokens...))
}
