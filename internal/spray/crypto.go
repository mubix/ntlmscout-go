package spray

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"time"
)

func utf16le(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r > 0xFFFF {
			r -= 0x10000
			out = binary.LittleEndian.AppendUint16(out, uint16(0xD800+(r>>10)))
			out = binary.LittleEndian.AppendUint16(out, uint16(0xDC00+(r&0x3FF)))
			continue
		}
		out = binary.LittleEndian.AppendUint16(out, uint16(r))
	}
	return out
}

// ntowfv2 computes NTOWFv2 = HMAC-MD5(MD4(UTF16LE(password)), UTF16LE(UPPER(user)+domain)).
func ntowfv2(password, user, domain string) []byte {
	nt := md4(utf16le(password))
	h := hmac.New(md5.New, nt)
	h.Write(utf16le(strings.ToUpper(user) + domain))
	return h.Sum(nil)
}

// ntlmv2Response builds the NTLMv2 response (proof || blob) for a challenge.
func ntlmv2Response(ntV2, serverChallenge, targetInfo []byte) []byte {
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64(time.Now().Unix()+11644473600)*10000000)
	cc := make([]byte, 8)
	_, _ = rand.Read(cc)
	blob := []byte{0x01, 0x01, 0, 0, 0, 0, 0, 0}
	blob = append(blob, ts...)
	blob = append(blob, cc...)
	blob = append(blob, 0, 0, 0, 0)
	blob = append(blob, targetInfo...)
	blob = append(blob, 0, 0, 0, 0)
	h := hmac.New(md5.New, ntV2)
	h.Write(serverChallenge)
	h.Write(blob)
	proof := h.Sum(nil)
	return append(proof, blob...)
}
