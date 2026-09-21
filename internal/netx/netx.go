// Package netx centralises all outbound network behaviour: raw TCP connects
// (optionally tunnelled through an HTTP CONNECT proxy), a deliberately
// permissive TLS configuration for fingerprinting legacy/self-signed services,
// and leveled debug logging.
//
// A single *Config is created from CLI flags and threaded through every probe,
// so there is no hidden global state.
package netx

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config carries runtime toggles for connections and diagnostics.
type Config struct {
	// Proxy is an "host:port" HTTP CONNECT proxy, or "" for direct connects.
	Proxy string
	// VerifyTLS turns on certificate verification. Off by default because
	// targets routinely use internal or self-signed certificates.
	VerifyTLS bool
	// Debug surfaces otherwise-swallowed errors to DebugOut.
	Debug bool
	// DebugOut receives debug lines (defaults to os.Stderr).
	DebugOut io.Writer

	mu sync.Mutex
}

func (c *Config) debugOut() io.Writer {
	if c.DebugOut != nil {
		return c.DebugOut
	}
	return os.Stderr
}

// Debugf writes a diagnostic line when Debug is enabled. where is a short
// context label ("smb 10.0.0.5:445"); err is the underlying error.
func (c *Config) Debugf(where string, err error) {
	if !c.Debug || err == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintf(c.debugOut(), "[debug] %s: %v\n", where, err)
}

// Debugln writes a free-form diagnostic line when Debug is enabled.
func (c *Config) Debugln(msg string) {
	if !c.Debug {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintf(c.debugOut(), "[debug] %s\n", msg)
}

// HasProxy reports whether an HTTP CONNECT proxy is configured.
func (c *Config) HasProxy() bool { return c.Proxy != "" }

// ProxyURL returns the proxy as an http:// URL, or "" if none.
func (c *Config) ProxyURL() string {
	if c.Proxy == "" {
		return ""
	}
	return "http://" + c.Proxy
}

// DialTCP opens a TCP connection to host:port, tunnelling through the HTTP
// CONNECT proxy when one is configured.
func (c *Config) DialTCP(host string, port int, timeout time.Duration) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if c.Proxy == "" {
		return net.DialTimeout("tcp", addr, timeout)
	}
	conn, err := net.DialTimeout("tcp", c.Proxy, timeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	req := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port, host, port)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	// Read the proxy response headers.
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT read failed: %w", err)
	}
	if !strings.Contains(statusLine, " 200 ") {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %q", strings.TrimSpace(statusLine))
	}
	// Drain until the blank line that ends the headers.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	_ = conn.SetDeadline(time.Time{})
	// If the proxy buffered extra bytes, wrap so they are not lost.
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

// bufferedConn preserves bytes the bufio.Reader read past the CONNECT headers.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// TLSConfig returns the TLS configuration. When verification is off (the
// default) it is intentionally permissive so we can still handshake with old or
// hardened endpoints: verification disabled, TLS 1.0 minimum, and a broad
// cipher-suite list including legacy CBC/3DES/RC4 suites for ancient servers.
//
// Note: Go's crypto/tls cannot negotiate SSLv3 or export-grade ciphers, so a
// handful of pre-2008 SSLv3-only services remain unreachable; --debug will show
// the handshake error in that case.
func (c *Config) TLSConfig(serverName string) *tls.Config {
	if c.VerifyTLS {
		return &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
	}
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       legacyCipherSuites(),
	}
}

// legacyCipherSuites returns a broad list (secure + legacy) so we can complete
// a handshake with old servers when fingerprinting. Only applies to TLS <= 1.2;
// TLS 1.3 suites are fixed by the runtime.
func legacyCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	}
}

// WrapTLS performs a TLS handshake over an existing connection (used for
// STARTTLS upgrades and the RDP CredSSP preamble). timeout bounds the
// handshake.
func (c *Config) WrapTLS(conn net.Conn, serverName string, timeout time.Duration) (*tls.Conn, error) {
	tconn := tls.Client(conn, c.TLSConfig(serverName))
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	if err := tconn.Handshake(); err != nil {
		return nil, err
	}
	if timeout > 0 {
		_ = conn.SetDeadline(time.Time{})
	}
	return tconn, nil
}

// Connect dials host:port and, when useTLS is set, immediately upgrades to TLS.
func (c *Config) Connect(host string, port int, useTLS bool, timeout time.Duration) (net.Conn, error) {
	conn, err := c.DialTCP(host, port, timeout)
	if err != nil {
		return nil, err
	}
	if !useTLS {
		return conn, nil
	}
	tconn, err := c.WrapTLS(conn, host, timeout)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return tconn, nil
}
