package scan

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/mubix/ntlmscout/internal/disclosure"
	"github.com/mubix/ntlmscout/internal/netx"
	"github.com/mubix/ntlmscout/internal/ntlm"
	"github.com/mubix/ntlmscout/internal/transport"
)

// runProtocol dispatches to the right transport handler and returns raw bytes.
func runProtocol(cfg *netx.Config, proto, host string, port int, url string, timeout time.Duration) []byte {
	switch proto {
	case "http", "https":
		if url == "" {
			p := port
			if p == 0 {
				if proto == "https" {
					p = 443
				} else {
					p = 80
				}
			}
			url = fmt.Sprintf("%s://%s:%d/", proto, urlHost(host), p)
		}
		return transport.HTTPChallenge(cfg, url, "", timeout)
	case "smb":
		return transport.SMBChallenge(cfg, host, orDefault(port, 445), timeout)
	case "mssql":
		return transport.MSSQLChallenge(cfg, host, orDefault(port, 1433), timeout)
	case "smtp":
		return transport.SMTPChallenge(cfg, host, orDefault(port, 25), false, timeout)
	case "smtps":
		return tlsFirst(cfg, transport.SMTPChallenge, host, orDefault(port, 465), timeout)
	case "imap":
		return transport.IMAPChallenge(cfg, host, orDefault(port, 143), false, timeout)
	case "imaps":
		return tlsFirst(cfg, transport.IMAPChallenge, host, orDefault(port, 993), timeout)
	case "pop3":
		return transport.POP3Challenge(cfg, host, orDefault(port, 110), false, timeout)
	case "pop3s":
		return tlsFirst(cfg, transport.POP3Challenge, host, orDefault(port, 995), timeout)
	case "nntp":
		return transport.NNTPChallenge(cfg, host, orDefault(port, 119), false, timeout)
	case "nntps":
		return transport.NNTPChallenge(cfg, host, orDefault(port, 563), true, timeout)
	case "ldap":
		return transport.LDAPChallenge(cfg, host, orDefault(port, 389), false, timeout)
	case "ldaps":
		return transport.LDAPChallenge(cfg, host, orDefault(port, 636), true, timeout)
	case "rdp":
		return transport.RDPChallenge(cfg, host, orDefault(port, 3389), timeout)
	}
	return nil
}

type mailHandler func(*netx.Config, string, int, bool, time.Duration) []byte

// tlsFirst tries implicit TLS then falls back to plaintext+STARTTLS, for the
// common case of a misconfigured 465/993/995.
func tlsFirst(cfg *netx.Config, h mailHandler, host string, port int, timeout time.Duration) []byte {
	if blob := h(cfg, host, port, true, timeout); blob != nil {
		return blob
	}
	return h(cfg, host, port, false, timeout)
}

// probe runs a single job and returns an assembled Result.
func probe(cfg *netx.Config, j job, timeout time.Duration) Result {
	switch j.proto {
	case "oxid":
		return probeOXID(cfg, j.host, orDefault(j.port, 135), timeout)
	case "iisip":
		return probeIISIP(cfg, j.host, j.port, j.url, timeout)
	case "tlscert":
		return probeCert(cfg, j.host, orDefault(j.port, 443), timeout, false)
	case "rdpcert":
		return probeCert(cfg, j.host, orDefault(j.port, 3389), timeout, true)
	}

	target := j.url
	if target == "" {
		if j.port != 0 {
			target = fmt.Sprintf("%s:%d", j.host, j.port)
		} else {
			target = j.host + ":"
		}
	}
	r := Result{Target: target, Protocol: j.proto, Host: j.host, Port: j.port, URL: j.url}
	t0 := time.Now()

	var names, info map[string]string
	var raw []byte
	if j.proto == "http" || j.proto == "https" {
		url := j.url
		if url == "" {
			p := j.port
			if p == 0 {
				if j.proto == "https" {
					p = 443
				} else {
					p = 80
				}
			}
			url = fmt.Sprintf("%s://%s:%d/", j.proto, urlHost(j.host), p)
			r.URL = url
			r.Target = url
		}
		raw, names, info = transport.HTTPProbe(cfg, url, "", timeout)
	} else {
		raw = runProtocol(cfg, j.proto, j.host, j.port, j.url, timeout)
	}

	if raw == nil {
		r.Error = "no NTLM challenge returned"
	} else {
		blob := raw
		if !startsWithSig(raw) {
			blob = ntlm.ExtractBlob(raw)
		}
		if blob == nil {
			r.Error = "NTLMSSP signature not found in response"
		} else if parsed, err := ntlm.ParseChallenge(blob); err != nil {
			r.Error = err.Error()
		} else {
			r.Success = true
			r.NTLM = parsed
			r.Fingerprint = buildFingerprint(parsed)
			r.SecurityPosture = assessPosture(parsed)
			if parsed.TargetInfo != nil && parsed.TargetInfo.Timestamp != nil {
				serverDT := ntlm.FileTimeToTime(parsed.TargetInfo.Timestamp.FileTime)
				skew := serverDT.Sub(time.Now().UTC()).Seconds()
				skew = math.Round(skew*10) / 10
				r.Fingerprint.ServerTimeUTC = parsed.TargetInfo.Timestamp.UTC
				r.Fingerprint.TimeSkewSeconds = &skew
			}
		}
	}

	if len(names) > 0 {
		for hdr, val := range names {
			for _, nm := range splitNames(val) {
				r.DisclosedNames = append(r.DisclosedNames, disclosure.Name{Name: nm, Source: hdr + " header"})
			}
		}
		r.Success = true // an unauthenticated disclosure still counts
	}
	if len(info) > 0 {
		r.HTTPInfo = info
	}

	if j.proto == "ldap" || j.proto == "ldaps" {
		useTLS := j.proto == "ldaps"
		p := j.port
		if p == 0 {
			if useTLS {
				p = 636
			} else {
				p = 389
			}
		}
		if rd := transport.LDAPRootDSE(cfg, j.host, p, useTLS, timeout); rd.Len() > 0 {
			r.RootDSE = rd
			r.Success = true
		}
	}

	r.ElapsedMs = int(time.Since(t0).Milliseconds())
	return r
}

func probeOXID(cfg *netx.Config, host string, port int, timeout time.Duration) Result {
	r := Result{Target: fmt.Sprintf("oxid://%s:%d", host, port), Protocol: "oxid", Host: host, Port: port}
	t0 := time.Now()
	addrs := disclosure.OXIDResolve(cfg, host, port, timeout)
	if len(addrs) > 0 {
		r.Success = true
		for _, a := range addrs {
			if a.IsIP {
				r.InternalAddresses = append(r.InternalAddresses, a)
			} else {
				r.DisclosedNames = append(r.DisclosedNames, disclosure.Name{Name: a.Address, Source: "OXID ServerAlive2"})
			}
		}
	} else {
		r.Error = "no bindings returned"
	}
	r.ElapsedMs = int(time.Since(t0).Milliseconds())
	return r
}

func probeIISIP(cfg *netx.Config, host string, port int, url string, timeout time.Duration) Result {
	useTLS := strings.HasPrefix(url, "https") || port == 443 || port == 8443 || port == 5986
	p := port
	if p == 0 {
		if useTLS {
			p = 443
		} else {
			p = 80
		}
	}
	r := Result{Target: fmt.Sprintf("iis-ip://%s:%d", host, p), Protocol: "iisip", Host: host, Port: p}
	t0 := time.Now()
	addrs := disclosure.IISInternalIP(cfg, host, p, useTLS, timeout)
	if len(addrs) > 0 {
		r.Success = true
		r.InternalAddresses = addrs
	} else {
		r.Error = "no internal IP disclosed"
	}
	r.ElapsedMs = int(time.Since(t0).Milliseconds())
	return r
}

func probeCert(cfg *netx.Config, host string, port int, timeout time.Duration, rdp bool) Result {
	label := "tlscert"
	if rdp {
		label = "rdpcert"
	}
	r := Result{Target: fmt.Sprintf("%s://%s:%d", label, host, port), Protocol: label, Host: host, Port: port}
	t0 := time.Now()
	ips, names := disclosure.CertDisclosure(cfg, host, port, timeout, rdp)
	if len(ips) > 0 || len(names) > 0 {
		r.Success = true
		r.InternalAddresses = ips
		r.DisclosedNames = names
	} else {
		r.Error = "no cert names recovered"
	}
	r.ElapsedMs = int(time.Since(t0).Milliseconds())
	return r
}

func buildFingerprint(c *ntlm.Challenge) *Fingerprint {
	fp := &Fingerprint{
		TargetRealm:     c.TargetName,
		TargetRealmType: c.TargetType,
	}
	if ti := c.TargetInfo; ti != nil {
		fp.NetbiosComputer = ti.NbComputerName
		fp.NetbiosDomain = ti.NbDomainName
		fp.DNSComputer = ti.DnsComputerName
		fp.DNSDomain = ti.DnsDomainName
		fp.DNSForest = ti.DnsTreeName
		fp.SPN = ti.TargetName
		if ti.SingleHost != nil && ti.SingleHost.MachineID != "" {
			fp.MachineID = ti.SingleHost.MachineID
		}
	}
	if c.Version != nil {
		fp.OS = c.Version.Product
		fp.OSClient = c.Version.ClientCandidate
		fp.OSServer = c.Version.ServerCandidate
		fp.OSBuild = fmt.Sprintf("%d.%d.%d", c.Version.Major, c.Version.Minor, c.Version.Build)
	}
	return fp
}

func assessPosture(c *ntlm.Challenge) *SecurityPosture {
	flags := c.NegotiateFlags
	p := &SecurityPosture{}
	p.SigningOffered = ntlm.HasFlag(flags, "NTLMSSP_NEGOTIATE_ALWAYS_SIGN") || ntlm.HasFlag(flags, "NTLMSSP_NEGOTIATE_SIGN")

	var ti *ntlm.TargetInfo = c.TargetInfo
	if ti != nil && ti.ChannelBindings != nil {
		p.ChannelBindingPresent = ti.ChannelBindings.Present
	}

	var weak []string
	if ntlm.HasFlag(flags, "NTLMSSP_NEGOTIATE_LM_KEY") {
		weak = append(weak, "LM_KEY")
	}
	if ntlm.HasFlag(flags, "NTLMSSP_NEGOTIATE_NTLM") && !ntlm.HasFlag(flags, "NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY") {
		weak = append(weak, "NTLMv1 (no ExtendedSessionSecurity)")
	}
	p.WeakCryptoOffered = weak

	// TARGET_TYPE_DOMAIN vs TARGET_TYPE_SERVER is the authoritative signal for
	// domain membership. DOMAIN => the account database is a domain (the host is
	// domain-joined; this is true for members AND DCs). SERVER => the account
	// database is local (standalone / workgroup), and the NetBIOS/DNS "domain"
	// fields just echo the machine's own name -- so NB-host == NB-domain on a
	// standalone box is expected, NOT a Domain Controller signal.
	var nbC, nbD, dnsC, dnsD string
	if ti != nil {
		nbC, nbD, dnsC, dnsD = ti.NbComputerName, ti.NbDomainName, ti.DnsComputerName, ti.DnsDomainName
	}
	switch c.TargetType {
	case "domain":
		p.DomainJoined = true
	case "server":
		p.Standalone = true
	default:
		// No explicit target type: treat the host as domain-joined only when a
		// NetBIOS/DNS domain is present AND differs from the host's own name.
		if (nbD != "" && !strings.EqualFold(nbD, nbC)) ||
			(dnsD != "" && dnsC != "" && !strings.EqualFold(dnsD, dnsC)) {
			p.DomainJoined = true
		} else if nbD != "" || dnsD != "" {
			p.Standalone = true
		}
	}
	return p
}

func startsWithSig(b []byte) bool {
	sig := ntlm.Sig
	if len(b) < len(sig) {
		return false
	}
	for i := range sig {
		if b[i] != sig[i] {
			return false
		}
	}
	return true
}

func splitNames(v string) []string {
	f := strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == ',' })
	var out []string
	for _, s := range f {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
