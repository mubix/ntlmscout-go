// Package scan ties the transports and disclosure modules together: it plans
// the set of probes for a target list, prunes closed ports, dispatches probes
// concurrently, assembles per-probe Results, resolves host roles, and renders
// the report in text/JSON/NDJSON/CSV/hosts-file form.
package scan

import (
	"time"

	"github.com/mubix/ntlmscout/internal/disclosure"
	"github.com/mubix/ntlmscout/internal/netx"
	"github.com/mubix/ntlmscout/internal/ntlm"
	"github.com/mubix/ntlmscout/internal/transport"
)

// Fingerprint is the flattened, report-friendly view of a parsed challenge.
type Fingerprint struct {
	TargetRealm     string   `json:"target_realm,omitempty"`
	TargetRealmType string   `json:"target_realm_type,omitempty"`
	NetbiosComputer string   `json:"netbios_computer,omitempty"`
	NetbiosDomain   string   `json:"netbios_domain,omitempty"`
	DNSComputer     string   `json:"dns_computer,omitempty"`
	DNSDomain       string   `json:"dns_domain,omitempty"`
	DNSForest       string   `json:"dns_forest,omitempty"`
	OS              string   `json:"os,omitempty"`
	OSClient        string   `json:"os_client_candidate,omitempty"`
	OSServer        string   `json:"os_server_candidate,omitempty"`
	OSBuild         string   `json:"os_build,omitempty"`
	MachineID       string   `json:"machine_id,omitempty"`
	SPN             string   `json:"spn,omitempty"`
	ServerTimeUTC   string   `json:"server_time_utc,omitempty"`
	TimeSkewSeconds *float64 `json:"time_skew_seconds,omitempty"`
}

// SecurityPosture holds passive posture observations from the challenge.
type SecurityPosture struct {
	SigningOffered        bool     `json:"signing_offered"`
	ChannelBindingPresent bool     `json:"channel_binding_present"`
	WeakCryptoOffered     []string `json:"weak_crypto_offered"`
	DomainJoined          bool     `json:"domain_joined"`
	Standalone            bool     `json:"standalone"`
}

// Role is a host-level role determination.
type Role struct {
	Role       string   `json:"role"`
	Confidence string   `json:"confidence"`
	Reasons    []string `json:"reasons"`
}

// Result is the outcome of a single probe.
type Result struct {
	Target            string               `json:"target"`
	Protocol          string               `json:"protocol"`
	Host              string               `json:"host"`
	Port              int                  `json:"port"`
	URL               string               `json:"url,omitempty"`
	Success           bool                 `json:"success"`
	NTLM              *ntlm.Challenge      `json:"ntlm,omitempty"`
	Fingerprint       *Fingerprint         `json:"fingerprint,omitempty"`
	SecurityPosture   *SecurityPosture     `json:"security_posture,omitempty"`
	InternalAddresses []disclosure.Address `json:"internal_addresses,omitempty"`
	DisclosedNames    []disclosure.Name    `json:"disclosed_names,omitempty"`
	HTTPInfo          map[string]string    `json:"http_info,omitempty"`
	RootDSE           transport.RootDSE    `json:"rootdse,omitempty"`
	Error             string               `json:"error,omitempty"`
	ElapsedMs         int                  `json:"elapsed_ms"`
}

// Options carries the resolved CLI configuration for a recon run.
type Options struct {
	Targets      []string
	InputList    string
	NoDiscover   bool
	NoInternalIP bool
	Threads      int
	Timeout      time.Duration
	Quiet        bool
	Verbose      bool
	NoSummary    bool

	Output    string // detailed per-host log
	JSON      string
	NDJSON    string
	CSV       string
	HostsFile string

	Net *netx.Config
}

// job is one planned probe.
type job struct {
	proto string
	host  string
	port  int
	url   string
}
