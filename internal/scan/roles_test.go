package scan

import (
	"testing"

	"github.com/mubix/ntlmscout/internal/ntlm"
	"github.com/mubix/ntlmscout/internal/transport"
)

func challenge(targetType, nbHost, nbDom, dnsHost, dnsDom string) *ntlm.Challenge {
	return &ntlm.Challenge{
		TargetType: targetType,
		TargetInfo: &ntlm.TargetInfo{
			NbComputerName:  nbHost,
			NbDomainName:    nbDom,
			DnsComputerName: dnsHost,
			DnsDomainName:   dnsDom,
		},
	}
}

// A standalone/workgroup box (TARGET_TYPE_SERVER) reports NB host == NB domain.
// That must NOT be read as a Domain Controller (the bug seen with CASEY /
// REDTEAMOPS / WIN-NU5D7602FF9), and it is not domain-joined.
func TestPostureStandaloneNotDC(t *testing.T) {
	p := assessPosture(challenge("server", "CASEY", "CASEY", "casey", "casey"))
	if p.DomainJoined {
		t.Error("standalone host wrongly marked domain-joined")
	}
	if !p.Standalone {
		t.Error("standalone host not marked standalone")
	}
}

func TestPostureDomainMember(t *testing.T) {
	p := assessPosture(challenge("domain", "WS01", "CORP", "ws01.corp.local", "corp.local"))
	if !p.DomainJoined || p.Standalone {
		t.Errorf("domain member posture wrong: joined=%v standalone=%v", p.DomainJoined, p.Standalone)
	}
}

func TestResolveRolesStandaloneVsMemberVsDC(t *testing.T) {
	results := []Result{
		// Standalone RDP host (the false-positive case).
		{Host: "10.0.0.11", Protocol: "rdp", Port: 3389, Success: true,
			NTLM:            challenge("server", "CASEY", "CASEY", "casey", "casey"),
			SecurityPosture: assessPosture(challenge("server", "CASEY", "CASEY", "casey", "casey"))},
		// Domain member over SMB.
		{Host: "10.0.0.29", Protocol: "smb", Port: 445, Success: true,
			NTLM:            challenge("domain", "MEMBER", "CORP", "member.corp.local", "corp.local"),
			SecurityPosture: assessPosture(challenge("domain", "MEMBER", "CORP", "member.corp.local", "corp.local"))},
		// Real DC: an LDAP service answered (rootDSE read).
		{Host: "10.0.0.10", Protocol: "ldap", Port: 389, Success: true,
			NTLM:            challenge("domain", "DC1", "CORP", "dc1.corp.local", "corp.local"),
			SecurityPosture: assessPosture(challenge("domain", "DC1", "CORP", "dc1.corp.local", "corp.local")),
			RootDSE:         transport.RootDSE{{Key: "dnsHostName", Values: []string{"dc1.corp.local"}}}},
	}
	roles := resolveHostRoles(results)
	if got := roles["10.0.0.11"].Role; got != "Standalone" {
		t.Errorf("standalone host role = %q, want Standalone", got)
	}
	if got := roles["10.0.0.29"].Role; got != "Domain member" {
		t.Errorf("member host role = %q, want Domain member", got)
	}
	if r := roles["10.0.0.10"]; r.Role != "Domain Controller" || r.Confidence != "confirmed" {
		t.Errorf("DC role = %q/%q, want Domain Controller/confirmed", r.Role, r.Confidence)
	}
}
