package transport

import (
	"strings"
	"time"

	"github.com/mubix/ntlmscout/internal/der"
	"github.com/mubix/ntlmscout/internal/netx"
	"github.com/mubix/ntlmscout/internal/ntlm"
)

// RootDSEAttr is one attribute read from the anonymous rootDSE.
type RootDSEAttr struct {
	Key    string   `json:"key"`
	Values []string `json:"values"`
}

// RootDSE is an ordered set of rootDSE attributes.
type RootDSE []RootDSEAttr

// Get returns the first value for key, or "".
func (r RootDSE) Get(key string) string {
	for _, a := range r {
		if strings.EqualFold(a.Key, key) && len(a.Values) > 0 {
			return a.Values[0]
		}
	}
	return ""
}

// Len reports how many attributes were read.
func (r RootDSE) Len() int { return len(r) }

// rootDSEAttrs are the anonymously-readable attributes worth pulling from a DC.
var rootDSEAttrs = []string{
	"defaultNamingContext", "rootDomainNamingContext",
	"configurationNamingContext", "dnsHostName", "serverName",
	"domainFunctionality", "forestFunctionality",
	"domainControllerFunctionality", "ldapServiceName",
	"supportedSASLMechanisms",
}

// LDAPChallenge performs a SASL GSS-SPNEGO bind and returns the raw NTLM Type-2
// from serverSaslCreds.
func LDAPChallenge(cfg *netx.Config, host string, port int, useTLS bool, timeout time.Duration) []byte {
	conn, err := cfg.Connect(host, port, useTLS, timeout)
	if err != nil {
		cfg.Debugf("ldap "+host, err)
		return nil
	}
	defer conn.Close()
	if _, err := conn.Write(ldapSASLBind("GSS-SPNEGO")); err != nil {
		cfg.Debugf("ldap bind "+host, err)
		return nil
	}
	resp := readUntilSig(conn, timeout)
	return ntlm.ExtractBlob(resp)
}

func ldapSASLBind(mech string) []byte {
	creds := der.SPNEGONegTokenInit(ntlm.DefaultType1())
	sasl := der.TLV(0xA3, append(der.TLV(0x04, []byte(mech)), der.TLV(0x04, creds)...)) // [3] SaslCredentials
	bindBody := append(der.Int(3), der.TLV(0x04, nil)...)
	bindBody = append(bindBody, sasl...)
	bindReq := der.TLV(0x60, bindBody) // [APPLICATION 0]
	return der.TLV(0x30, append(der.Int(1), bindReq...))
}

func ldapAnonBind() []byte {
	body := append(der.Int(3), der.TLV(0x04, nil)...)
	body = append(body, der.TLV(0x80, nil)...) // [0] simple auth, empty password
	return der.TLV(0x30, append(der.Int(1), der.TLV(0x60, body)...))
}

func ldapSearchRootDSE(attrs []string) []byte {
	var attrSeq []byte
	for _, a := range attrs {
		attrSeq = append(attrSeq, der.TLV(0x04, []byte(a))...)
	}
	body := der.TLV(0x04, nil)                                       // baseObject ""
	body = append(body, der.TLV(0x0A, []byte{0x00})...)              // scope = baseObject
	body = append(body, der.TLV(0x0A, []byte{0x00})...)              // derefAliases = never
	body = append(body, der.Int(0)...)                               // sizeLimit
	body = append(body, der.Int(0)...)                               // timeLimit
	body = append(body, der.TLV(0x01, []byte{0x00})...)              // typesOnly = FALSE
	body = append(body, der.TLV(0x87, []byte("objectClass"))...)     // filter: present
	body = append(body, der.TLV(0x30, attrSeq)...)                   // attribute list
	return der.TLV(0x30, append(der.Int(2), der.TLV(0x63, body)...)) // msgID 2, SearchRequest
}

// LDAPRootDSE performs an anonymous rootDSE read.
func LDAPRootDSE(cfg *netx.Config, host string, port int, useTLS bool, timeout time.Duration) RootDSE {
	conn, err := cfg.Connect(host, port, useTLS, timeout)
	if err != nil {
		cfg.Debugf("ldap-rootdse "+host, err)
		return nil
	}
	defer conn.Close()
	if _, err := conn.Write(ldapAnonBind()); err != nil {
		cfg.Debugf("ldap-rootdse bind "+host, err)
		return nil
	}
	recvSome(conn, 8192, timeout) // bindResponse (ignored)
	if _, err := conn.Write(ldapSearchRootDSE(rootDSEAttrs)); err != nil {
		cfg.Debugf("ldap-rootdse search "+host, err)
		return nil
	}
	data := readAll(conn, 65536, timeout)
	return parseRootDSE(data, rootDSEAttrs)
}

// parseRootDSE pulls each attribute's value(s) out of the searchResEntry.
func parseRootDSE(data []byte, attrs []string) RootDSE {
	var out RootDSE
	for _, a := range attrs {
		name := []byte(a)
		marker := append([]byte{0x04, byte(len(name))}, name...)
		i := indexOf(data, marker)
		if i < 0 {
			continue
		}
		j := i + 2 + len(name)
		if j >= len(data) || data[j] != 0x31 { // SET OF values
			continue
		}
		setLen, k, ok := der.ReadLen(data, j+1)
		if !ok {
			continue
		}
		var vals []string
		p, end := k, k+setLen
		for p < end && p < len(data) && data[p] == 0x04 {
			vlen, q, ok := der.ReadLen(data, p+1)
			if !ok || q+vlen > len(data) {
				break
			}
			vals = append(vals, string(data[q:q+vlen]))
			p = q + vlen
		}
		if len(vals) > 0 {
			out = append(out, RootDSEAttr{Key: a, Values: vals})
		}
	}
	return out
}
