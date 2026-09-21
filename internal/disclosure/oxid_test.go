package disclosure

import (
	"encoding/binary"
	"testing"
)

// buildServerAlive2Stub crafts an IObjectExporter::ServerAlive2 response stub
// (the bytes after the 24-byte RPC response preamble) carrying a DUALSTRINGARRAY
// with several STRINGBINDINGs, as a multi-homed host would return.
func buildServerAlive2Stub(addrs []string) []byte {
	wchars := func(s string) []byte {
		out := make([]byte, 0, len(s)*2+2)
		for _, r := range s {
			out = binary.LittleEndian.AppendUint16(out, uint16(r))
		}
		out = append(out, 0x00, 0x00) // null terminator
		return out
	}

	// String bindings: each is wTowerId (0x0007 = ncacn_ip_tcp) + wide addr + NUL.
	var sb []byte
	for _, a := range addrs {
		sb = binary.LittleEndian.AppendUint16(sb, 0x0007)
		sb = append(sb, wchars(a)...)
	}
	sb = append(sb, 0x00, 0x00) // string-binding array terminator

	secoffWords := len(sb) / 2

	// Minimal (ignored) security bindings section + terminator.
	sec := []byte{0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	arr := append(sb, sec...)
	numWords := len(arr) / 2

	stub := make([]byte, 0, 12+len(arr))
	stub = append(stub, 0x05, 0x00, 0x07, 0x00)                     // COMVERSION
	stub = binary.LittleEndian.AppendUint32(stub, 0x00020000)       // referent id
	stub = binary.LittleEndian.AppendUint32(stub, uint32(numWords)) // NDR max_count
	stub = binary.LittleEndian.AppendUint16(stub, uint16(numWords))
	stub = binary.LittleEndian.AppendUint16(stub, uint16(secoffWords))
	stub = append(stub, arr...)
	return stub
}

func TestParseServerAlive2MultiHomed(t *testing.T) {
	want := []string{"192.168.1.5", "10.0.0.5", "172.16.9.9", "fe80::1", "MULTIHOME01"}
	got := parseServerAlive2(buildServerAlive2Stub(want))

	if len(got) != len(want) {
		t.Fatalf("got %d bindings, want %d: %+v", len(got), len(want), got)
	}
	byAddr := map[string]Address{}
	for _, a := range got {
		byAddr[a.Address] = a
	}
	for _, w := range want {
		if _, ok := byAddr[w]; !ok {
			t.Errorf("missing interface %q", w)
		}
	}
	// IP bindings classified as IPs; the hostname is not.
	if !byAddr["10.0.0.5"].IsIP || byAddr["10.0.0.5"].Internal == nil || !*byAddr["10.0.0.5"].Internal {
		t.Errorf("10.0.0.5 not classified internal IP: %+v", byAddr["10.0.0.5"])
	}
	if !byAddr["fe80::1"].IsIP || byAddr["fe80::1"].Internal == nil || !*byAddr["fe80::1"].Internal {
		t.Errorf("fe80::1 not classified internal IPv6: %+v", byAddr["fe80::1"])
	}
	if byAddr["MULTIHOME01"].IsIP {
		t.Errorf("hostname wrongly classified as IP: %+v", byAddr["MULTIHOME01"])
	}
}
