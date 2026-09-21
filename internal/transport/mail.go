package transport

import (
	"encoding/base64"
	"net"
	"regexp"
	"time"

	"github.com/mubix/ntlmscout/internal/netx"
	"github.com/mubix/ntlmscout/internal/ntlm"
)

var (
	reSMTP334 = regexp.MustCompile(`334\s+([A-Za-z0-9+/=]+)`)
	rePlus    = regexp.MustCompile(`\+\s+([A-Za-z0-9+/=]+)`)
	reNNTP381 = regexp.MustCompile(`38[13]\s+([A-Za-z0-9+/=]+)`)
	reNNTP383 = regexp.MustCompile(`383\s+([A-Za-z0-9+/=]+)`)
)

func b64d(s []byte) []byte {
	out, err := base64.StdEncoding.DecodeString(string(s))
	if err != nil {
		return nil
	}
	return out
}

// SMTPChallenge performs EHLO (+optional STARTTLS) then AUTH NTLM and returns
// the raw Type-2 from the 334 reply. It tries inline (SASL-IR) first and falls
// back to the two-step exchange for stricter servers.
func SMTPChallenge(cfg *netx.Config, host string, port int, useTLS bool, timeout time.Duration) []byte {
	conn, err := cfg.Connect(host, port, useTLS, timeout)
	if err != nil {
		cfg.Debugf("smtp "+host, err)
		return nil
	}
	defer conn.Close()

	recvSome(conn, 8192, timeout) // banner
	conn.Write([]byte("EHLO ntlmscout\r\n"))
	ehlo := recvSome(conn, 8192, timeout)
	if !useTLS && containsFold(ehlo, "STARTTLS") {
		conn.Write([]byte("STARTTLS\r\n"))
		recvSome(conn, 8192, timeout)
		if tconn, terr := cfg.WrapTLS(conn, host, timeout); terr == nil {
			conn = tconn
			conn.Write([]byte("EHLO ntlmscout\r\n"))
			recvSome(conn, 8192, timeout)
		} else {
			cfg.Debugf("smtp starttls "+host, terr)
		}
	}
	// Inline (SASL-IR) first.
	conn.Write([]byte("AUTH NTLM " + ntlm.DefaultType1B64 + "\r\n"))
	resp := readLine(conn, timeout)
	if m := reSMTP334.FindSubmatch(resp); m != nil {
		return b64d(m[1])
	}
	// Two-step fallback.
	if hasPrefixB(resp, "334") {
		conn.Write([]byte(ntlm.DefaultType1B64 + "\r\n"))
		resp = readLine(conn, timeout)
		if m := reSMTP334.FindSubmatch(resp); m != nil {
			return b64d(m[1])
		}
	}
	return nil
}

// IMAPChallenge performs (STARTTLS then) AUTHENTICATE NTLM.
func IMAPChallenge(cfg *netx.Config, host string, port int, useTLS bool, timeout time.Duration) []byte {
	conn, err := cfg.Connect(host, port, useTLS, timeout)
	if err != nil {
		cfg.Debugf("imap "+host, err)
		return nil
	}
	defer conn.Close()

	recvSome(conn, 8192, timeout)
	if !useTLS {
		conn.Write([]byte("a0 STARTTLS\r\n"))
		r := recvSome(conn, 8192, timeout)
		if containsFold(r, "OK") {
			if tconn, terr := cfg.WrapTLS(conn, host, timeout); terr == nil {
				conn = tconn
			} else {
				cfg.Debugf("imap starttls "+host, terr)
			}
		}
	}
	conn.Write([]byte("a1 AUTHENTICATE NTLM\r\n"))
	cont := readLine(conn, timeout)
	if !hasPrefixB(cont, "+") {
		return nil
	}
	conn.Write([]byte(ntlm.DefaultType1B64 + "\r\n"))
	resp := readLine(conn, timeout)
	if m := rePlus.FindSubmatch(resp); m != nil {
		return b64d(m[1])
	}
	return nil
}

// POP3Challenge performs (STLS then) AUTH NTLM.
func POP3Challenge(cfg *netx.Config, host string, port int, useTLS bool, timeout time.Duration) []byte {
	conn, err := cfg.Connect(host, port, useTLS, timeout)
	if err != nil {
		cfg.Debugf("pop3 "+host, err)
		return nil
	}
	defer conn.Close()

	recvSome(conn, 8192, timeout)
	if !useTLS {
		conn.Write([]byte("STLS\r\n"))
		r := readLine(conn, timeout)
		if hasPrefixB(r, "+OK") {
			if tconn, terr := cfg.WrapTLS(conn, host, timeout); terr == nil {
				conn = tconn
			} else {
				cfg.Debugf("pop3 stls "+host, terr)
			}
		}
	}
	conn.Write([]byte("AUTH NTLM\r\n"))
	cont := readLine(conn, timeout)
	if !hasPrefixB(cont, "+") {
		return nil
	}
	conn.Write([]byte(ntlm.DefaultType1B64 + "\r\n"))
	resp := readLine(conn, timeout)
	if m := rePlus.FindSubmatch(resp); m != nil {
		return b64d(m[1])
	}
	return nil
}

// NNTPChallenge tries AUTHINFO GENERIC NTLM (381 continuation) then RFC 4643
// SASL (383 continuation, inline IR).
func NNTPChallenge(cfg *netx.Config, host string, port int, useTLS bool, timeout time.Duration) []byte {
	conn, err := cfg.Connect(host, port, useTLS, timeout)
	if err != nil {
		cfg.Debugf("nntp "+host, err)
		return nil
	}
	defer conn.Close()

	recvSome(conn, 8192, timeout)
	// Primary: AUTHINFO GENERIC NTLM.
	conn.Write([]byte("AUTHINFO GENERIC NTLM\r\n"))
	resp := readLine(conn, timeout)
	if hasPrefixB(resp, "381") {
		conn.Write([]byte(ntlm.DefaultType1B64 + "\r\n"))
		resp = readLine(conn, timeout)
		if m := reNNTP381.FindSubmatch(resp); m != nil {
			return b64d(m[1])
		}
	}
	// Fallback: SASL NTLM inline IR.
	conn.Write([]byte("AUTHINFO SASL NTLM " + ntlm.DefaultType1B64 + "\r\n"))
	resp = readLine(conn, timeout)
	if m := reNNTP383.FindSubmatch(resp); m != nil {
		return b64d(m[1])
	}
	return nil
}

// ---- small byte helpers ----

func hasPrefixB(b []byte, p string) bool {
	if len(b) < len(p) {
		return false
	}
	for i := 0; i < len(p); i++ {
		if b[i] != p[i] {
			return false
		}
	}
	return true
}

func containsFold(b []byte, sub string) bool {
	up := make([]byte, len(b))
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		up[i] = c
	}
	return indexOf(up, []byte(sub)) >= 0
}

var _ net.Conn
