package ntlm

import "encoding/binary"

// utf16leBytes encodes a string to UTF-16LE bytes.
func utf16leBytes(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		// BMP-only encoding is sufficient for hostnames/usernames; surrogate
		// pairs are handled correctly by ranging over runes below.
		if r > 0xFFFF {
			r1, r2 := surrogatePair(r)
			out = binary.LittleEndian.AppendUint16(out, r1)
			out = binary.LittleEndian.AppendUint16(out, r2)
			continue
		}
		out = binary.LittleEndian.AppendUint16(out, uint16(r))
	}
	return out
}

func surrogatePair(r rune) (uint16, uint16) {
	r -= 0x10000
	return uint16(0xD800 + (r >> 10)), uint16(0xDC00 + (r & 0x3FF))
}

// BuildType3 assembles an NTLM Type-3 (AUTHENTICATE) message given a precomputed
// NTLMv2 response (proof + blob). The LM response and session key are empty,
// matching the reference implementation.
func BuildType3(domain, user string, ntResp []byte, workstation string) []byte {
	const flags = 0x00088205 // UNICODE|REQUEST_TARGET|NTLM|ALWAYS_SIGN|EXT_SESSION_SEC
	lm := make([]byte, 24)
	dom := utf16leBytes(domain)
	usr := utf16leBytes(user)
	wks := utf16leBytes(workstation)
	skey := []byte{}

	base := 64
	var fields, payload []byte
	off := base
	for _, data := range [][]byte{lm, ntResp, dom, usr, wks, skey} {
		fields = binary.LittleEndian.AppendUint16(fields, uint16(len(data)))
		fields = binary.LittleEndian.AppendUint16(fields, uint16(len(data)))
		fields = binary.LittleEndian.AppendUint32(fields, uint32(off))
		payload = append(payload, data...)
		off += len(data)
	}
	hdr := append([]byte{}, Sig...)
	hdr = binary.LittleEndian.AppendUint32(hdr, 3)
	hdr = append(hdr, fields...)
	hdr = binary.LittleEndian.AppendUint32(hdr, flags)
	return append(hdr, payload...)
}
