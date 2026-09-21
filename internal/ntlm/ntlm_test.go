package ntlm

import (
	"encoding/binary"
	"testing"
)

// buildTestChallenge crafts a Type-2 CHALLENGE for round-trip parsing tests.
func buildTestChallenge() []byte {
	targetName := utf16leBytes("CORP")

	// Target info AV pairs.
	var ti []byte
	av := func(id uint16, val []byte) {
		ti = binary.LittleEndian.AppendUint16(ti, id)
		ti = binary.LittleEndian.AppendUint16(ti, uint16(len(val)))
		ti = append(ti, val...)
	}
	av(avNbDomainName, utf16leBytes("CORP"))
	av(avNbComputerName, utf16leBytes("DC01"))
	av(avDnsDomainName, utf16leBytes("corp.example.com"))
	av(avDnsComputerName, utf16leBytes("dc01.corp.example.com"))
	av(avDnsTreeName, utf16leBytes("corp.example.com"))
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, 133000000000000000)
	av(avTimestamp, ts)
	av(avEOL, nil)

	flags := uint32(0x00000001 | 0x00000200 | 0x00008000 | 0x00010000 | 0x00800000 | 0x02000000)

	header := make([]byte, 48)
	copy(header, Sig)
	binary.LittleEndian.PutUint32(header[8:], 2) // type 2

	version := []byte{10, 0}
	version = binary.LittleEndian.AppendUint16(version, 17763)
	version = append(version, 0, 0, 0, 0x0f)

	tnOff := 56
	tiOff := tnOff + len(targetName)

	binary.LittleEndian.PutUint16(header[12:], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(header[14:], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(header[16:], uint32(tnOff))
	binary.LittleEndian.PutUint32(header[20:], flags)
	// server challenge header[24:32], reserved header[32:40]
	binary.LittleEndian.PutUint16(header[40:], uint16(len(ti)))
	binary.LittleEndian.PutUint16(header[42:], uint16(len(ti)))
	binary.LittleEndian.PutUint32(header[44:], uint32(tiOff))

	blob := append(header, version...)
	blob = append(blob, targetName...)
	blob = append(blob, ti...)
	return blob
}

func TestParseChallenge(t *testing.T) {
	blob := buildTestChallenge()
	c, err := ParseChallenge(blob)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if c.TargetType != "domain" {
		t.Errorf("target_type = %q, want domain", c.TargetType)
	}
	if c.TargetName != "CORP" {
		t.Errorf("target_name = %q, want CORP", c.TargetName)
	}
	if c.TargetInfo == nil {
		t.Fatal("target info nil")
	}
	if c.TargetInfo.NbComputerName != "DC01" {
		t.Errorf("nb computer = %q", c.TargetInfo.NbComputerName)
	}
	if c.TargetInfo.DnsComputerName != "dc01.corp.example.com" {
		t.Errorf("dns computer = %q", c.TargetInfo.DnsComputerName)
	}
	if c.Version == nil {
		t.Fatal("version nil")
	}
	// build 17763 is shared between a client and server SKU; without host-level
	// evidence we report both rather than guessing from the target type.
	if c.Version.Product != "Windows 10 1809 / Windows Server 2019" {
		t.Errorf("product = %q, want combined client/server", c.Version.Product)
	}
	if c.Version.ClientCandidate != "Windows 10 1809" || c.Version.ServerCandidate != "Windows Server 2019" {
		t.Errorf("candidates = %q / %q", c.Version.ClientCandidate, c.Version.ServerCandidate)
	}
	if c.TargetInfo.Timestamp == nil {
		t.Error("timestamp not decoded")
	}
}

func TestVersionAmbiguousShowsBoth(t *testing.T) {
	vb := []byte{10, 0}
	vb = binary.LittleEndian.AppendUint16(vb, 17763)
	vb = append(vb, 0, 0, 0, 0x0f)
	// The target type no longer forces a client-vs-server guess: a shared build
	// reports both candidates regardless of TARGET_TYPE.
	for _, tt := range []string{"server", "domain", ""} {
		v := ParseVersion(vb, tt)
		if v.Product != "Windows 10 1809 / Windows Server 2019" {
			t.Errorf("target %q -> %q, want combined", tt, v.Product)
		}
	}
	// A build unique to one SKU still reports a single product.
	vb2 := []byte{10, 0}
	vb2 = binary.LittleEndian.AppendUint16(vb2, 20348)
	vb2 = append(vb2, 0, 0, 0, 0x0f)
	if v := ParseVersion(vb2, "server"); v.Product != "Windows Server 2022" {
		t.Errorf("unique server build -> %q, want Windows Server 2022", v.Product)
	}
}

func TestBuildType1(t *testing.T) {
	msg := DefaultType1()
	if !hasPrefix(msg, Sig) {
		t.Fatal("missing NTLMSSP signature")
	}
	if binary.LittleEndian.Uint32(msg[8:12]) != 1 {
		t.Error("message type != 1")
	}
	if binary.LittleEndian.Uint32(msg[12:16]) != DefaultType1Flags {
		t.Error("flags mismatch")
	}
	// VERSION bit set => 8-byte version block appended (total 40).
	if len(msg) != 40 {
		t.Errorf("len = %d, want 40", len(msg))
	}
}

func TestExtractBlob(t *testing.T) {
	prefix := []byte("HTTP garbage \x00\x01")
	blob := buildTestChallenge()
	found := ExtractBlob(append(prefix, blob...))
	if found == nil || !hasPrefix(found, Sig) {
		t.Fatal("extract failed")
	}
}
