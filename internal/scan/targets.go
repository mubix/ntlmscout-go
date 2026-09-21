package scan

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// cidrMax bounds CIDR expansion so a huge range can't blow up the job list.
const cidrMax = 65536

// splitHostPort splits a target into (host, port) where port==0 means unset.
// It handles IPv6 literals: "[2001:db8::1]", "[2001:db8::1]:445", "fe80::1".
func splitHostPort(token string) (string, int) {
	token = strings.TrimSpace(token)
	if strings.HasPrefix(token, "[") {
		host, rest, _ := strings.Cut(token[1:], "]")
		if strings.HasPrefix(rest, ":") {
			if p, err := strconv.Atoi(rest[1:]); err == nil {
				return host, p
			}
		}
		return host, 0
	}
	if strings.Count(token, ":") == 1 {
		h, p, _ := strings.Cut(token, ":")
		if n, err := strconv.Atoi(p); err == nil {
			return h, n
		}
		return token, 0
	}
	return token, 0
}

// urlHost brackets an IPv6 literal for use inside a URL.
func urlHost(host string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// expandTargets expands bare CIDR entries into host IPs, passing everything
// else through unchanged.
func expandTargets(raw []string) []string {
	var out []string
	for _, t := range raw {
		if !strings.Contains(t, "://") && strings.Contains(t, "/") && !strings.HasPrefix(t, "[") {
			prefix, err := netip.ParsePrefix(t)
			if err != nil {
				out = append(out, t)
				continue
			}
			hosts := expandPrefix(prefix)
			if hosts == nil {
				fmt.Fprintf(os.Stderr, "[!] skipping %s -- range too large to expand (> %d addresses)\n", t, cidrMax)
				continue
			}
			out = append(out, hosts...)
			continue
		}
		out = append(out, t)
	}
	return out
}

// expandPrefix returns the usable host addresses in a prefix, or nil if the
// range exceeds cidrMax. Mirrors Python's network.hosts() (falls back to all
// addresses for /31, /32 and single-host v6).
func expandPrefix(p netip.Prefix) []string {
	p = p.Masked()
	bits := p.Addr().BitLen() - p.Bits()
	if bits > 20 { // 2^20 == 1048576, definitely over the guard for any base
		return nil
	}
	total := uint64(1) << uint(bits)
	if total > cidrMax {
		return nil
	}
	var addrs []string
	addr := p.Addr()
	for i := uint64(0); i < total; i++ {
		addrs = append(addrs, addr.String())
		addr = addr.Next()
		if !addr.IsValid() {
			break
		}
	}
	// Emulate .hosts(): for a range with >2 addresses, drop network & broadcast
	// for IPv4 (Python's ip_network.hosts() excludes them); keep all otherwise.
	if p.Addr().Is4() && len(addrs) > 2 {
		return addrs[1 : len(addrs)-1]
	}
	return addrs
}
