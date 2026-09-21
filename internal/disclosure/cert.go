package disclosure

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/mubix/ntlmscout/internal/der"
	"github.com/mubix/ntlmscout/internal/netx"
	"github.com/mubix/ntlmscout/internal/transport"
)

type certInfo struct {
	CN       string
	DNSNames []string
	IPs      []string
}

// getCertDER grabs the server certificate (DER). For RDP it performs the X.224
// preamble before the TLS handshake.
func getCertDER(cfg *netx.Config, host string, port int, timeout time.Duration, rdp bool) []byte {
	conn, err := cfg.DialTCP(host, port, timeout)
	if err != nil {
		cfg.Debugf(fmt.Sprintf("get_cert %s:%d", host, port), err)
		return nil
	}
	defer conn.Close()
	if rdp {
		if err := transport.ReadTPKTPreamble(conn, timeout); err != nil {
			cfg.Debugf("get_cert x224 "+host, err)
			return nil
		}
	}
	tconn := tls.Client(conn, cfg.TLSConfig(host))
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := tconn.Handshake(); err != nil {
		cfg.Debugf(fmt.Sprintf("get_cert handshake %s:%d", host, port), err)
		return nil
	}
	certs := tconn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	return certs[0].Raw
}

// parseCert extracts CN + SAN dNSName/iPAddress. It uses crypto/x509 first and
// falls back to a permissive hand-rolled DER walk for certificates x509
// rejects (old or malformed certs on legacy hosts).
func parseCert(raw []byte) certInfo {
	if c, err := x509.ParseCertificate(raw); err == nil {
		info := certInfo{CN: c.Subject.CommonName, DNSNames: c.DNSNames}
		for _, ip := range c.IPAddresses {
			info.IPs = append(info.IPs, ip.String())
		}
		// Mirror the reference tool: reject a CN that is clearly not a hostname
		// (CA/description names have spaces; a bare "*" is meaningless).
		if strings.Contains(info.CN, " ") || strings.TrimSpace(info.CN) == "*" {
			info.CN = ""
		}
		return info
	}
	return parseCertManual(raw)
}

// CertDisclosure returns internal-address entries and disclosed-name entries
// recovered from a TLS (or RDP) certificate.
func CertDisclosure(cfg *netx.Config, host string, port int, timeout time.Duration, rdp bool) ([]Address, []Name) {
	raw := getCertDER(cfg, host, port, timeout, rdp)
	if raw == nil {
		return nil, nil
	}
	info := parseCert(raw)
	src := "TLS cert"
	if rdp {
		src = "RDP cert"
	}
	var ips []Address
	for _, ip := range info.IPs {
		ips = append(ips, Address{Address: ip, Internal: isInternalAddr(ip), IsIP: true, Source: src + " SAN"})
	}
	var names []Name
	seen := map[string]bool{}
	all := []string{}
	if info.CN != "" {
		all = append(all, info.CN)
	}
	all = append(all, info.DNSNames...)
	for _, nm := range all {
		if nm == "" || seen[strings.ToLower(nm)] {
			continue
		}
		seen[strings.ToLower(nm)] = true
		suffix := " SAN"
		if nm == info.CN {
			suffix = " CN"
		}
		names = append(names, Name{Name: nm, Source: src + suffix})
	}
	return ips, names
}

// parseCertManual is the dependency-free DER fallback (ported from the
// reference implementation) for certs crypto/x509 cannot parse.
func parseCertManual(raw []byte) certInfo {
	var info certInfo
	// Common Name OID 2.5.4.3 == 06 03 55 04 03. Take the LAST match (subject
	// CN follows issuer CN in the structure).
	cnOID := []byte{0x06, 0x03, 0x55, 0x04, 0x03}
	last := -1
	for i := 0; i+len(cnOID) <= len(raw); i++ {
		if bytesEqual(raw[i:i+len(cnOID)], cnOID) {
			last = i
		}
	}
	if last >= 0 {
		j := last + len(cnOID)
		if j < len(raw) && (raw[j] == 0x0C || raw[j] == 0x13 || raw[j] == 0x16 || raw[j] == 0x14) {
			ln, k, ok := der.ReadLen(raw, j+1)
			if ok && k+ln <= len(raw) {
				info.CN = string(raw[k : k+ln])
			}
		}
		if strings.Contains(info.CN, " ") || strings.TrimSpace(info.CN) == "*" {
			info.CN = ""
		}
	}
	// subjectAltName OID 2.5.29.17 == 06 03 55 1D 11.
	sanOID := []byte{0x06, 0x03, 0x55, 0x1d, 0x11}
	m := indexOfBytes(raw, sanOID)
	if m >= 0 {
		j := m + len(sanOID)
		if j < len(raw) && raw[j] == 0x01 { // optional critical BOOLEAN
			j += 3
		}
		if j < len(raw) && raw[j] == 0x04 { // OCTET STRING wrapper
			_, jj, ok := der.ReadLen(raw, j+1)
			j = jj
			if ok && j < len(raw) && raw[j] == 0x30 { // SEQUENCE OF GeneralName
				seqLen, k, ok := der.ReadLen(raw, j+1)
				if ok {
					j = k
					end := j + seqLen
					for j < end && j < len(raw) {
						tag := raw[j]
						j++
						ln, k, ok := der.ReadLen(raw, j)
						if !ok || k+ln > len(raw) {
							break
						}
						val := raw[k : k+ln]
						j = k + ln
						switch tag {
						case 0x82: // dNSName
							info.DNSNames = append(info.DNSNames, string(val))
						case 0x87: // iPAddress
							if ln == 4 {
								info.IPs = append(info.IPs, fmt.Sprintf("%d.%d.%d.%d", val[0], val[1], val[2], val[3]))
							} else if ln == 16 {
								parts := make([]string, 8)
								for x := 0; x < 8; x++ {
									parts[x] = fmt.Sprintf("%x", int(val[x*2])<<8|int(val[x*2+1]))
								}
								info.IPs = append(info.IPs, strings.Join(parts, ":"))
							}
						}
					}
				}
			}
		}
	}
	return info
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func indexOfBytes(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if bytesEqual(haystack[i:i+len(needle)], needle) {
			return i
		}
	}
	return -1
}
