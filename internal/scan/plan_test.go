package scan

import (
	"strings"
	"testing"
)

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"host", "host", 0},
		{"host:445", "host", 445},
		{"10.0.0.1:389", "10.0.0.1", 389},
		{"[2001:db8::1]", "2001:db8::1", 0},
		{"[2001:db8::1]:445", "2001:db8::1", 445},
		{"fe80::1", "fe80::1", 0},
	}
	for _, c := range cases {
		h, p := splitHostPort(c.in)
		if h != c.host || p != c.port {
			t.Errorf("splitHostPort(%q) = (%q,%d), want (%q,%d)", c.in, h, p, c.host, c.port)
		}
	}
}

func TestExpandPrefixV4(t *testing.T) {
	hosts := expandTargets([]string{"10.0.0.0/30"})
	// /30 -> .0 .1 .2 .3; hosts() drops network(.0) and broadcast(.3).
	want := []string{"10.0.0.1", "10.0.0.2"}
	if strings.Join(hosts, ",") != strings.Join(want, ",") {
		t.Errorf("expand /30 = %v, want %v", hosts, want)
	}
}

func TestExpandPrefixTooLarge(t *testing.T) {
	hosts := expandTargets([]string{"10.0.0.0/8"}) // ~16M addresses, over guard
	if len(hosts) != 0 {
		t.Errorf("expected skip of oversized range, got %d hosts", len(hosts))
	}
}

func TestNormalizePaths(t *testing.T) {
	out := normalizePaths([]string{"/owa", "/EWS/Exchange.asmx", "/OWA", "/_windows/default.aspx?ReturnUrl=/"})
	joined := strings.Join(out, "|")
	if !strings.Contains(joined, "/owa/") {
		t.Errorf("directory path not normalised: %v", out)
	}
	if strings.Contains(joined, "/EWS/Exchange.asmx/") {
		t.Errorf("file path wrongly got trailing slash: %v", out)
	}
	// query-string path must not get a trailing slash and dupes removed (/owa == /OWA)
	if strings.Count(joined, "/owa/") != 1 {
		t.Errorf("case-insensitive dedupe failed: %v", out)
	}
}

func TestPlanBareHostFullSweep(t *testing.T) {
	opts := &Options{Targets: []string{"example.test"}, NoDiscover: true, NoInternalIP: true, Net: nil}
	jobs, err := planTargets(opts)
	if err != nil {
		t.Fatal(err)
	}
	protos := map[string]bool{}
	for _, j := range jobs {
		protos[j.proto] = true
	}
	for _, want := range []string{"smb", "ldap", "ldaps", "rdp", "mssql", "smtp", "http", "https"} {
		if !protos[want] {
			t.Errorf("full sweep missing protocol %q", want)
		}
	}
}

func TestPlanDisclosureJobs(t *testing.T) {
	opts := &Options{Targets: []string{"example.test"}, NoDiscover: true, Net: nil}
	jobs, _ := planTargets(opts)
	protos := map[string]bool{}
	for _, j := range jobs {
		protos[j.proto] = true
	}
	for _, want := range []string{"iisip", "tlscert", "rdpcert", "oxid"} {
		if !protos[want] {
			t.Errorf("disclosure plan missing %q", want)
		}
	}
}
