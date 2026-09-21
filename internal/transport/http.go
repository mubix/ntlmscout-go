package transport

import (
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mubix/ntlmscout/internal/netx"
	"github.com/mubix/ntlmscout/internal/ntlm"
)

// Exchange/IIS response headers that leak internal server names even on a 401.
var exchangeNameHdrs = []string{"X-FEServer", "X-CalculatedBETarget", "X-BEServer", "X-DiagInfo"}
var exchangeInfoHdrs = []string{"X-OWA-Version", "X-AspNet-Version", "X-Powered-By", "Server"}

var ntlmHeaderRe = regexp.MustCompile(`(?:NTLM|Negotiate)\s+([A-Za-z0-9+/=]+)`)

// httpClient builds an HTTP client that does not follow redirects and uses the
// permissive TLS config and optional proxy.
func httpClient(cfg *netx.Config, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:       cfg.TLSConfig(""),
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	// Let the standard library set ServerName per-host from the URL.
	tr.TLSClientConfig.ServerName = ""
	if cfg.HasProxy() {
		if u, err := url.Parse(cfg.ProxyURL()); err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// httpFetch issues a GET carrying an NTLM Type-1 Authorization header and
// returns the response headers (including those on a 401).
func httpFetch(cfg *netx.Config, rawURL, hostHeader string, timeout time.Duration) http.Header {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		cfg.Debugf("http "+rawURL, err)
		return nil
	}
	req.Header.Set("Authorization", "NTLM "+ntlm.DefaultType1B64)
	req.Header.Set("User-Agent", "Mozilla/5.0 (ntlmscout)")
	if hostHeader != "" {
		req.Host = hostHeader
	}
	resp, err := httpClient(cfg, timeout).Do(req)
	if err != nil {
		cfg.Debugf("http "+rawURL, err)
		return nil
	}
	defer resp.Body.Close()
	// We only need headers; discard the body.
	_, _ = resp.Body.Read(make([]byte, 0))
	return resp.Header
}

// ntlmFromHeaders extracts and decodes an NTLM token from WWW-Authenticate.
func ntlmFromHeaders(h http.Header) []byte {
	if h == nil {
		return nil
	}
	for _, auth := range h.Values("WWW-Authenticate") {
		if m := ntlmHeaderRe.FindStringSubmatch(auth); m != nil {
			if b, err := base64.StdEncoding.DecodeString(m[1]); err == nil {
				return b
			}
		}
	}
	return nil
}

// HTTPChallenge returns just the raw NTLM token from an HTTP(S) endpoint.
func HTTPChallenge(cfg *netx.Config, rawURL, hostHeader string, timeout time.Duration) []byte {
	return ntlmFromHeaders(httpFetch(cfg, rawURL, hostHeader, timeout))
}

// HTTPProbe returns the NTLM token plus any Exchange/IIS name and info headers.
func HTTPProbe(cfg *netx.Config, rawURL, hostHeader string, timeout time.Duration) (blob []byte, names, info map[string]string) {
	h := httpFetch(cfg, rawURL, hostHeader, timeout)
	if h == nil {
		return nil, nil, nil
	}
	blob = ntlmFromHeaders(h)
	names = map[string]string{}
	info = map[string]string{}
	for _, k := range exchangeNameHdrs {
		if v := h.Get(k); v != "" {
			names[k] = v
		}
	}
	for _, k := range exchangeInfoHdrs {
		if v := h.Get(k); v != "" {
			info[k] = v
		}
	}
	if len(names) == 0 {
		names = nil
	}
	if len(info) == 0 {
		info = nil
	}
	return blob, names, info
}

// ensure tls import is used even if the transport config changes.
var _ = tls.VersionTLS10

// splitMulti splits a header value on ';' or ',' for Exchange multi-name fields.
func splitMulti(v string) []string {
	f := strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == ',' })
	out := make([]string, 0, len(f))
	for _, s := range f {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
