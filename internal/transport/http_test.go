package transport

import (
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mubix/ntlmscout/internal/netx"
	"github.com/mubix/ntlmscout/internal/ntlm"
)

func makeType2() []byte {
	tn := utf16("CORP")
	var ti []byte
	av := func(id uint16, v []byte) {
		ti = binary.LittleEndian.AppendUint16(ti, id)
		ti = binary.LittleEndian.AppendUint16(ti, uint16(len(v)))
		ti = append(ti, v...)
	}
	av(2, utf16("CORP"))             // NbDomainName
	av(1, utf16("EXCH01"))           // NbComputerName
	av(4, utf16("corp.example.com")) // DnsDomainName
	av(0, nil)                       // EOL
	flags := uint32(0x00000001 | 0x00010000 | 0x00800000)
	h := make([]byte, 48)
	copy(h, ntlm.Sig)
	binary.LittleEndian.PutUint32(h[8:], 2)
	tnOff := 48
	tiOff := tnOff + len(tn)
	binary.LittleEndian.PutUint16(h[12:], uint16(len(tn)))
	binary.LittleEndian.PutUint16(h[14:], uint16(len(tn)))
	binary.LittleEndian.PutUint32(h[16:], uint32(tnOff))
	binary.LittleEndian.PutUint32(h[20:], flags)
	binary.LittleEndian.PutUint16(h[40:], uint16(len(ti)))
	binary.LittleEndian.PutUint16(h[42:], uint16(len(ti)))
	binary.LittleEndian.PutUint32(h[44:], uint32(tiOff))
	blob := append(h, tn...)
	blob = append(blob, ti...)
	return blob
}

func utf16(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = binary.LittleEndian.AppendUint16(out, uint16(r))
	}
	return out
}

func TestHTTPProbeExtractsChallenge(t *testing.T) {
	t2 := base64.StdEncoding.EncodeToString(makeType2())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "NTLM") {
			w.Header().Set("WWW-Authenticate", "NTLM "+t2)
		} else {
			w.Header().Set("WWW-Authenticate", "NTLM")
		}
		w.Header().Set("X-FEServer", "EXCH-FE-01")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := &netx.Config{}
	blob, names, _ := HTTPProbe(cfg, srv.URL+"/ews/", "", 5*time.Second)
	if blob == nil {
		t.Fatal("no NTLM blob extracted")
	}
	c, err := ntlm.ParseChallenge(blob)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.TargetInfo == nil || c.TargetInfo.NbComputerName != "EXCH01" {
		t.Errorf("bad challenge decode: %+v", c.TargetInfo)
	}
	if names["X-FEServer"] != "EXCH-FE-01" {
		t.Errorf("exchange header not captured: %v", names)
	}
}
