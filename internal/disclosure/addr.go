// Package disclosure implements the adjacent, unauthenticated information leaks
// that recover data the NTLM CHALLENGE itself cannot: the host's internal IP
// address (IIS Host-header disclosure / WebDAV PROPFIND and the RPC
// IOXIDResolver::ServerAlive2 interface enumeration) and the names in a
// server's TLS/RDP certificate.
package disclosure

import (
	"regexp"
	"strconv"
	"strings"
)

// Address is a disclosed network address. Internal is nil when the value is not
// an IP (e.g. a hostname string from an OXID binding).
type Address struct {
	Address  string `json:"address"`
	Internal *bool  `json:"internal,omitempty"`
	IsIP     bool   `json:"is_ip"`
	Source   string `json:"source,omitempty"`
}

// Name is a disclosed hostname (cert CN/SAN, Exchange header, OXID binding).
type Name struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

var (
	ipv4Re = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	ipv6Re = regexp.MustCompile(`\b((?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4})\b`)
)

func boolPtr(b bool) *bool { return &b }

// isInternalAddr reports whether a is a private/loopback/link-local/CGNAT
// address. It returns nil when a is not an IP at all.
func isInternalAddr(a string) *bool {
	a = strings.Split(a, "[")[0]
	a = strings.Split(a, "%")[0]
	a = strings.Trim(strings.TrimSpace(a), "/")
	if m := regexp.MustCompile(`^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$`).FindStringSubmatch(a); m != nil {
		o := make([]int, 4)
		for i := 0; i < 4; i++ {
			o[i], _ = strconv.Atoi(m[i+1])
			if o[i] > 255 {
				return nil
			}
		}
		switch {
		case o[0] == 10:
			return boolPtr(true)
		case o[0] == 172 && o[1] >= 16 && o[1] <= 31:
			return boolPtr(true)
		case o[0] == 192 && o[1] == 168:
			return boolPtr(true)
		case o[0] == 169 && o[1] == 254:
			return boolPtr(true)
		case o[0] == 127:
			return boolPtr(true)
		case o[0] == 100 && o[1] >= 64 && o[1] <= 127:
			return boolPtr(true)
		}
		return boolPtr(false)
	}
	al := strings.ToLower(a)
	if strings.Contains(al, ":") {
		if strings.HasPrefix(al, "fe80") || strings.HasPrefix(al, "fc") ||
			strings.HasPrefix(al, "fd") || strings.HasPrefix(al, "::1") {
			return boolPtr(true)
		}
		return boolPtr(false)
	}
	return nil
}

func findIPs(text string) []string {
	var out []string
	out = append(out, ipv4Re.FindAllString(text, -1)...)
	for _, m := range ipv6Re.FindAllStringSubmatch(text, -1) {
		out = append(out, m[1])
	}
	return out
}
