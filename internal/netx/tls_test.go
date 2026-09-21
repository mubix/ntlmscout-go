package netx

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"
)

// selfSignedCert generates an ephemeral RSA self-signed certificate for tests.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "legacy.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"legacy.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// legacyServer starts a TLS listener pinned to exactly one old protocol
// version and returns its host, port and a stop func.
func legacyServer(t *testing.T, version uint16) (string, int, func()) {
	t.Helper()
	cert := selfSignedCert(t)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   version,
		MaxVersion:   version,
		// Offer a CBC suite that exists in TLS 1.0/1.1.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// Force the handshake, then close.
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				c.Close()
			}(c)
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return host, port, func() { ln.Close() }
}

func TestLegacyTLSVersionsNegotiate(t *testing.T) {
	cases := []struct {
		name    string
		version uint16
		want    uint16
	}{
		{"TLS1.0", tls.VersionTLS10, tls.VersionTLS10},
		{"TLS1.1", tls.VersionTLS11, tls.VersionTLS11},
		{"TLS1.2", tls.VersionTLS12, tls.VersionTLS12},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host, port, stop := legacyServer(t, c.version)
			defer stop()

			// Default (fingerprinting) config: verification off, TLS 1.0 minimum.
			cfg := &Config{}
			conn, err := cfg.Connect(host, port, true, 5*time.Second)
			if err != nil {
				t.Fatalf("permissive Connect to %s server failed: %v", c.name, err)
			}
			defer conn.Close()
			tc, ok := conn.(*tls.Conn)
			if !ok {
				t.Fatal("expected *tls.Conn")
			}
			if got := tc.ConnectionState().Version; got != c.want {
				t.Errorf("negotiated version = 0x%04x, want 0x%04x", got, c.want)
			}
		})
	}
}

// TestVerifyModeRejectsLegacy proves the permissive default is what enables
// legacy reach: with --verify-tls (MinVersion 1.2) a TLS 1.0 server is refused.
func TestVerifyModeRejectsLegacy(t *testing.T) {
	host, port, stop := legacyServer(t, tls.VersionTLS10)
	defer stop()

	cfg := &Config{VerifyTLS: true}
	conn, err := cfg.Connect(host, port, true, 5*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("verify mode unexpectedly connected to a TLS 1.0-only server")
	}
}
