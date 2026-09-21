package disclosure

import "testing"

func TestIsInternalAddr(t *testing.T) {
	cases := []struct {
		in   string
		want interface{} // true/false/nil
	}{
		{"10.0.0.5", true},
		{"172.16.9.1", true},
		{"172.32.0.1", false},
		{"192.168.1.1", true},
		{"169.254.1.1", true},
		{"127.0.0.1", true},
		{"100.64.0.1", true},
		{"8.8.8.8", false},
		{"203.0.113.10", false},
		{"fe80::1", true},
		{"fd00::1", true},
		{"2001:db8::1", false},
		{"not-an-ip", nil},
		{"999.1.1.1", nil},
	}
	for _, c := range cases {
		got := isInternalAddr(c.in)
		switch want := c.want.(type) {
		case bool:
			if got == nil || *got != want {
				t.Errorf("isInternalAddr(%q) = %v, want %v", c.in, ptrStr(got), want)
			}
		case nil:
			if got != nil {
				t.Errorf("isInternalAddr(%q) = %v, want nil", c.in, *got)
			}
		}
	}
}

func ptrStr(b *bool) string {
	if b == nil {
		return "nil"
	}
	if *b {
		return "true"
	}
	return "false"
}
