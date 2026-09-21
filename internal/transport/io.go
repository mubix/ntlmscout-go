// Package transport implements the per-protocol handlers that elicit an NTLM
// Type-2 CHALLENGE from a service. Each handler returns the raw bytes that
// contain the NTLMSSP token (or nil); the caller locates the signature with
// ntlm.ExtractBlob.
//
// Every handler is written defensively: connect and read errors are reported
// through the debug logger and turned into a nil result rather than a panic, so
// a filtered port or an unexpected banner never aborts a scan. Where a service
// speaks more than one dialect (e.g. inline vs two-step SASL, SMB2 vs SMB1),
// the handler tries the modern path first and falls back, so old targets still
// yield a challenge.
package transport

import (
	"net"
	"time"
)

// recvSome reads up to n bytes with a timeout, returning what arrived (possibly
// empty) rather than an error on timeout.
func recvSome(conn net.Conn, n int, timeout time.Duration) []byte {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, n)
	m, err := conn.Read(buf)
	if err != nil {
		return buf[:m]
	}
	return buf[:m]
}

// readLine reads until a newline (or EOF/timeout/64KiB cap).
func readLine(conn net.Conn, timeout time.Duration) []byte {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var buf []byte
	one := make([]byte, 1)
	for {
		m, err := conn.Read(one)
		if m > 0 {
			buf = append(buf, one[0])
			if one[0] == '\n' {
				break
			}
			if len(buf) > 65536 {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return buf
}

// readExact reads exactly n bytes or returns what was read before an error.
func readExact(conn net.Conn, n int, timeout time.Duration) []byte {
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

// readUntilSig accumulates bytes until the NTLMSSP signature appears or the
// connection stalls / hits the cap.
func readUntilSig(conn net.Conn, timeout time.Duration) []byte {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var buf []byte
	chunk := make([]byte, 4096)
	for len(buf) < 262144 {
		m, err := conn.Read(chunk)
		if m > 0 {
			buf = append(buf, chunk[:m]...)
			if containsSig(buf) {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return buf
}

// readAll reads until EOF/timeout up to cap bytes.
func readAll(conn net.Conn, cap int, timeout time.Duration) []byte {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var buf []byte
	chunk := make([]byte, 4096)
	for len(buf) < cap {
		m, err := conn.Read(chunk)
		if m > 0 {
			buf = append(buf, chunk[:m]...)
		}
		if err != nil {
			break
		}
	}
	return buf
}

var ntlmSig = []byte("NTLMSSP\x00")

func containsSig(b []byte) bool {
	return indexOf(b, ntlmSig) >= 0
}

func indexOf(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		ok := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}
