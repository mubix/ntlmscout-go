package der

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestOID(t *testing.T) {
	// SPNEGO 1.3.6.1.5.5.2 -> 06 06 2b 06 01 05 05 02
	got := hex.EncodeToString(OID([]int{1, 3, 6, 1, 5, 5, 2}))
	if got != "06062b0601050502" {
		t.Errorf("SPNEGO OID = %s", got)
	}
	// NTLMSSP 1.3.6.1.4.1.311.2.2.10 -> 06 0a 2b 06 01 04 01 82 37 02 02 0a
	got = hex.EncodeToString(OID([]int{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}))
	if got != "060a2b060104018237020"+"20a" {
		t.Errorf("NTLMSSP OID = %s", got)
	}
}

func TestIntEncoding(t *testing.T) {
	if got := Int(0); !bytes.Equal(got, []byte{0x02, 0x01, 0x00}) {
		t.Errorf("Int(0) = %x", got)
	}
	if got := Int(3); !bytes.Equal(got, []byte{0x02, 0x01, 0x03}) {
		t.Errorf("Int(3) = %x", got)
	}
	// High-bit value gets a leading zero byte to stay positive.
	if got := Int(128); !bytes.Equal(got, []byte{0x02, 0x02, 0x00, 0x80}) {
		t.Errorf("Int(128) = %x", got)
	}
}

func TestLenLongForm(t *testing.T) {
	if got := Len(200); !bytes.Equal(got, []byte{0x81, 0xC8}) {
		t.Errorf("Len(200) = %x", got)
	}
	if got := Len(0x1234); !bytes.Equal(got, []byte{0x82, 0x12, 0x34}) {
		t.Errorf("Len(0x1234) = %x", got)
	}
}

func TestReadLen(t *testing.T) {
	l, n, ok := ReadLen([]byte{0x81, 0xC8}, 0)
	if !ok || l != 200 || n != 2 {
		t.Errorf("ReadLen long = (%d,%d,%v)", l, n, ok)
	}
	l, n, ok = ReadLen([]byte{0x05}, 0)
	if !ok || l != 5 || n != 1 {
		t.Errorf("ReadLen short = (%d,%d,%v)", l, n, ok)
	}
}
