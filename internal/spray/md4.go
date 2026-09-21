// Package spray implements ntlmscout's opt-in authentication-spray mode: it
// sends real credentials (NTLM Type-3 or HTTP Basic) to the single most
// effective endpoint on each target, using password-spray ordering (one
// password across every account per round) so no account exceeds one attempt
// per round. It never relays or cracks -- it only validates credentials and
// reports valid / cleanly-rejected / inconclusive verdicts.
package spray

import "encoding/binary"

// md4 computes the MD4 digest. OpenSSL 3 dropped MD4 from its default provider
// and Go's stdlib never shipped it, so we implement RFC 1320 directly to keep
// the tool dependency-free.
func md4(msg []byte) []byte {
	lrot := func(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }
	h := [4]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476}
	ml := uint64(len(msg)) * 8
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0x00)
	}
	msg = binary.LittleEndian.AppendUint64(msg, ml)

	f := func(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
	g := func(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
	hh := func(x, y, z uint32) uint32 { return x ^ y ^ z }

	for off := 0; off < len(msg); off += 64 {
		var X [16]uint32
		for i := 0; i < 16; i++ {
			X[i] = binary.LittleEndian.Uint32(msg[off+i*4:])
		}
		a, b, c, d := h[0], h[1], h[2], h[3]
		for _, i := range []int{0, 4, 8, 12} {
			a = lrot(a+f(b, c, d)+X[i], 3)
			d = lrot(d+f(a, b, c)+X[i+1], 7)
			c = lrot(c+f(d, a, b)+X[i+2], 11)
			b = lrot(b+f(c, d, a)+X[i+3], 19)
		}
		for _, i := range []int{0, 1, 2, 3} {
			a = lrot(a+g(b, c, d)+X[i]+0x5A827999, 3)
			d = lrot(d+g(a, b, c)+X[i+4]+0x5A827999, 5)
			c = lrot(c+g(d, a, b)+X[i+8]+0x5A827999, 9)
			b = lrot(b+g(c, d, a)+X[i+12]+0x5A827999, 13)
		}
		for _, i := range []int{0, 2, 1, 3} {
			a = lrot(a+hh(b, c, d)+X[i]+0x6ED9EBA1, 3)
			d = lrot(d+hh(a, b, c)+X[i+8]+0x6ED9EBA1, 9)
			c = lrot(c+hh(d, a, b)+X[i+4]+0x6ED9EBA1, 11)
			b = lrot(b+hh(c, d, a)+X[i+12]+0x6ED9EBA1, 15)
		}
		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
	}
	out := make([]byte, 16)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], h[i])
	}
	return out
}
