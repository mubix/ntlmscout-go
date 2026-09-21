package spray

import "encoding/hex"

import "testing"

func TestMD4KnownAnswers(t *testing.T) {
	cases := map[string]string{
		"":    "31d6cfe0d16ae931b73c59d7e0c089c0",
		"abc": "a448017aaf21d8525fc10ae87aa6729d",
	}
	for in, want := range cases {
		got := hex.EncodeToString(md4([]byte(in)))
		if got != want {
			t.Errorf("md4(%q) = %s, want %s", in, got, want)
		}
	}
}

// MS-NLMP 4.2.4.1.1 test vector for NTOWFv2.
func TestNTOWFv2Vector(t *testing.T) {
	got := hex.EncodeToString(ntowfv2("Password", "User", "Domain"))
	want := "0c868a403bfd7a93a3001ef22ef02e3f"
	if got != want {
		t.Errorf("NTOWFv2 = %s, want %s", got, want)
	}
}

func TestIdentity(t *testing.T) {
	cases := []struct {
		user, domain          string
		wantD, wantU, wantDis string
	}{
		{"alice@corp.com", "CORP", "", "alice@corp.com", "alice@corp.com"},
		{"CORP\\bob", "IGNORED", "CORP", "bob", "CORP\\bob"},
		{"carol", "CORP", "CORP", "carol", "CORP\\carol"},
		{"dave", "", "", "dave", "dave"},
	}
	for _, c := range cases {
		d, u, dis := identity(c.user, c.domain)
		if d != c.wantD || u != c.wantU || dis != c.wantDis {
			t.Errorf("identity(%q,%q) = (%q,%q,%q), want (%q,%q,%q)",
				c.user, c.domain, d, u, dis, c.wantD, c.wantU, c.wantDis)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := map[int]string{200: "valid", 302: "valid", 403: "valid", 401: "invalid", 407: "invalid", 500: "error", -1: "error"}
	for st, want := range cases {
		if got := classify(st); got != want {
			t.Errorf("classify(%d) = %s, want %s", st, got, want)
		}
	}
}
