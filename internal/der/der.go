// Package der implements the minimal subset of ASN.1 DER/BER encoding and
// decoding that ntlmscout needs to wrap NTLMSSP tokens in SPNEGO/GSSAPI and to
// hand-build LDAP and CredSSP (RDP/NLA) messages.
//
// It is deliberately tiny and dependency-free: we only ever emit or walk the
// exact structures the tool requires, so a full ASN.1 library would be
// overkill and would pull in more surface area than we want in a security
// scanner that must build cleanly on old toolchains.
package der

// Len encodes a DER length octet sequence (definite form) for n.
func Len(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte(n & 0xFF)}, out...)
		n >>= 8
	}
	return append([]byte{byte(0x80 | len(out))}, out...)
}

// TLV wraps content in a tag/length/value triple.
func TLV(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, Len(len(content))...)
	out = append(out, content...)
	return out
}

// Int encodes an integer as a DER INTEGER (tag 0x02).
func Int(n int) []byte {
	if n == 0 {
		return TLV(0x02, []byte{0x00})
	}
	var out []byte
	v := n
	for v > 0 {
		out = append([]byte{byte(v & 0xFF)}, out...)
		v >>= 8
	}
	// Prepend a zero byte if the high bit is set (keep it positive).
	if out[0]&0x80 != 0 {
		out = append([]byte{0x00}, out...)
	}
	return TLV(0x02, out)
}

// OID encodes a dotted object identifier string as a DER OBJECT IDENTIFIER.
func OID(parts []int) []byte {
	if len(parts) < 2 {
		return TLV(0x06, nil)
	}
	body := []byte{byte(40*parts[0] + parts[1])}
	for _, p := range parts[2:] {
		if p == 0 {
			body = append(body, 0x00)
			continue
		}
		var stack []int
		for p > 0 {
			stack = append([]int{p & 0x7F}, stack...)
			p >>= 7
		}
		for i := 0; i < len(stack)-1; i++ {
			stack[i] |= 0x80
		}
		for _, s := range stack {
			body = append(body, byte(s))
		}
	}
	return TLV(0x06, body)
}

// ReadLen decodes a DER/BER length starting at b[i]. It returns the decoded
// length and the index just past the length octets. ok is false if the buffer
// is truncated.
func ReadLen(b []byte, i int) (length, next int, ok bool) {
	if i >= len(b) {
		return 0, i, false
	}
	n := int(b[i])
	i++
	if n < 0x80 {
		return n, i, true
	}
	k := n & 0x7F
	if i+k > len(b) {
		return 0, i, false
	}
	val := 0
	for j := 0; j < k; j++ {
		val = (val << 8) | int(b[i+j])
	}
	return val, i + k, true
}
