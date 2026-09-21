// Package ntlm implements NTLMSSP message construction and parsing with no
// external dependencies. It builds the Type-1 (NEGOTIATE) and Type-3
// (AUTHENTICATE) messages and fully decodes the Type-2 (CHALLENGE) that a
// server returns: negotiate flags, the OS version block, and every AV_PAIR in
// the target-info field (NetBIOS/DNS host & domain, forest/tree name, server
// timestamp, MachineID, channel bindings, ...).
//
// Protocol details follow Microsoft's [MS-NLMP] and Eric Glass's davenport
// NTLM notes; the field layout is intentionally identical to the reference
// Python implementation so behaviour matches byte-for-byte.
package ntlm

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
	"unicode/utf16"
)

// Sig is the 8-byte NTLMSSP signature that every message begins with.
var Sig = []byte("NTLMSSP\x00")

// DefaultType1Flags is the battle-tested NEGOTIATE flag set used by NTLMRecon,
// Metasploit and nuclei:
//
//	UNICODE | OEM | REQUEST_TARGET | NTLM | ALWAYS_SIGN | EXT_SESSION_SEC |
//	VERSION | 128 | KEY_EXCH | 56
//
// Setting VERSION together with a stamped version block reliably coaxes the
// server into returning its own VERSION in the CHALLENGE.
const (
	DefaultType1Flags = 0xE2088207
	FlagVersion       = 0x02000000
)

// BuildType1 builds a raw NTLM Type-1 (NEGOTIATE) message. withVersion controls
// whether a stamped version block is appended; pass a nil pointer to derive it
// from the VERSION bit in flags (the normal case).
func BuildType1(flags uint32, withVersion *bool) []byte {
	wv := flags&FlagVersion != 0
	if withVersion != nil {
		wv = *withVersion
	}
	msg := make([]byte, 0, 40)
	msg = append(msg, Sig...)
	msg = le32(msg, 1)                        // MessageType = 1
	msg = le32(msg, flags)                    // NegotiateFlags
	msg = append(msg, 0, 0, 0, 0, 0, 0, 0, 0) // DomainName fields (empty)
	msg = append(msg, 0, 0, 0, 0, 0, 0, 0, 0) // Workstation fields (empty)
	if wv {
		// ProductMajor.Minor + Build(LE u16) + reserved(3) + NTLMRevision(0x0f).
		// 10.0.19041.
		msg = append(msg, 10, 0)
		msg = le16(msg, 19041)
		msg = append(msg, 0, 0, 0, 0x0f)
	}
	return msg
}

// DefaultType1 returns a Type-1 built with the default flag set.
func DefaultType1() []byte { return BuildType1(DefaultType1Flags, nil) }

// DefaultType1B64 is the base64 form used inline in HTTP/SASL exchanges.
var DefaultType1B64 = base64.StdEncoding.EncodeToString(DefaultType1())

// negotiateFlag pairs a flag name with its bit, in a fixed order so the decoded
// flag-name list is deterministic.
type negotiateFlag struct {
	Name string
	Bit  uint32
}

// NegotiateFlags is the ordered list of NTLMSSP NEGOTIATE flags we decode.
var NegotiateFlags = []negotiateFlag{
	{"NTLMSSP_NEGOTIATE_UNICODE", 0x00000001},
	{"NTLM_NEGOTIATE_OEM", 0x00000002},
	{"NTLMSSP_REQUEST_TARGET", 0x00000004},
	{"NTLMSSP_NEGOTIATE_SIGN", 0x00000010},
	{"NTLMSSP_NEGOTIATE_SEAL", 0x00000020},
	{"NTLMSSP_NEGOTIATE_DATAGRAM", 0x00000040},
	{"NTLMSSP_NEGOTIATE_LM_KEY", 0x00000080},
	{"NTLMSSP_NEGOTIATE_NTLM", 0x00000200},
	{"NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED", 0x00001000},
	{"NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED", 0x00002000},
	{"NTLMSSP_NEGOTIATE_ALWAYS_SIGN", 0x00008000},
	{"NTLMSSP_TARGET_TYPE_DOMAIN", 0x00010000},
	{"NTLMSSP_TARGET_TYPE_SERVER", 0x00020000},
	{"NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY", 0x00080000},
	{"NTLMSSP_NEGOTIATE_IDENTIFY", 0x00100000},
	{"NTLMSSP_REQUEST_NON_NT_SESSION_KEY", 0x00400000},
	{"NTLMSSP_NEGOTIATE_TARGET_INFO", 0x00800000},
	{"NTLMSSP_NEGOTIATE_VERSION", 0x02000000},
	{"NTLMSSP_NEGOTIATE_128", 0x20000000},
	{"NTLMSSP_NEGOTIATE_KEY_EXCH", 0x40000000},
	{"NTLMSSP_NEGOTIATE_56", 0x80000000},
}

// HasFlag reports whether the named NEGOTIATE flag is set in flags. It is the
// single source of truth for posture checks.
func HasFlag(flags uint32, name string) bool {
	for _, f := range NegotiateFlags {
		if f.Name == name {
			return flags&f.Bit != 0
		}
	}
	return false
}

// AV_PAIR ids.
const (
	avEOL             = 0x0000
	avNbComputerName  = 0x0001
	avNbDomainName    = 0x0002
	avDnsComputerName = 0x0003
	avDnsDomainName   = 0x0004
	avDnsTreeName     = 0x0005
	avFlags           = 0x0006
	avTimestamp       = 0x0007
	avSingleHost      = 0x0008
	avTargetName      = 0x0009
	avChannelBindings = 0x000A
)

var avNames = map[uint16]string{
	0x0000: "MsvAvEOL",
	0x0001: "MsvAvNbComputerName",
	0x0002: "MsvAvNbDomainName",
	0x0003: "MsvAvDnsComputerName",
	0x0004: "MsvAvDnsDomainName",
	0x0005: "MsvAvDnsTreeName",
	0x0006: "MsvAvFlags",
	0x0007: "MsvAvTimestamp",
	0x0008: "MsvAvSingleHost",
	0x0009: "MsvAvTargetName",
	0x000A: "MsvAvChannelBindings",
}

// AVName returns the friendly name for an AV_PAIR id.
func AVName(id uint16) string {
	if n, ok := avNames[id]; ok {
		return n
	}
	return fmt.Sprintf("AvId_0x%04x", id)
}

// FlagsAV decodes an MsvAvFlags value.
type FlagsAV struct {
	Value uint32   `json:"value"`
	Flags []string `json:"flags"`
}

// TimestampAV decodes an MsvAvTimestamp value.
type TimestampAV struct {
	FileTime uint64 `json:"filetime"`
	UTC      string `json:"utc"`
}

// SingleHostAV decodes an MsvAvSingleHost value.
type SingleHostAV struct {
	MachineID string `json:"machine_id,omitempty"`
	Raw       string `json:"raw,omitempty"`
}

// ChannelBindingAV decodes an MsvAvChannelBindings value.
type ChannelBindingAV struct {
	Hash    string `json:"hash"`
	Present bool   `json:"present"`
}

// RawPair is one AV_PAIR as name/id/hex, preserving wire order.
type RawPair struct {
	Name string `json:"name"`
	ID   uint16 `json:"id"`
	Hex  string `json:"hex"`
}

// TargetInfo holds the decoded AV_PAIR block.
type TargetInfo struct {
	NbComputerName  string            `json:"nb_computer_name,omitempty"`
	NbDomainName    string            `json:"nb_domain_name,omitempty"`
	DnsComputerName string            `json:"dns_computer_name,omitempty"`
	DnsDomainName   string            `json:"dns_domain_name,omitempty"`
	DnsTreeName     string            `json:"dns_tree_name,omitempty"`
	TargetName      string            `json:"target_name,omitempty"`
	Flags           *FlagsAV          `json:"flags,omitempty"`
	Timestamp       *TimestampAV      `json:"timestamp,omitempty"`
	SingleHost      *SingleHostAV     `json:"single_host,omitempty"`
	ChannelBindings *ChannelBindingAV `json:"channel_bindings,omitempty"`
	Other           map[string]string `json:"other,omitempty"`
}

// Version holds the decoded OS version block plus the friendly product mapping.
type Version struct {
	Major           int    `json:"major"`
	Minor           int    `json:"minor"`
	Build           int    `json:"build"`
	NTLMRevision    int    `json:"ntlm_revision"`
	Product         string `json:"product"`
	ClientCandidate string `json:"client_candidate,omitempty"`
	ServerCandidate string `json:"server_candidate,omitempty"`
	String          string `json:"string"`
}

// Challenge is a fully parsed NTLM Type-2 message.
type Challenge struct {
	TargetName         string      `json:"target_name,omitempty"`
	TargetType         string      `json:"target_type,omitempty"`
	ServerChallenge    string      `json:"server_challenge"`
	NegotiateFlags     uint32      `json:"negotiate_flags"`
	NegotiateFlagNames []string    `json:"negotiate_flag_names"`
	Version            *Version    `json:"version,omitempty"`
	TargetInfo         *TargetInfo `json:"target_info,omitempty"`
	RawAVPairs         []RawPair   `json:"raw_av_pairs,omitempty"`
	RawBlobB64         string      `json:"raw_blob_b64"`
}

// utf16le decodes a UTF-16LE byte slice, falling back to a latin-1-ish decode
// so we never fail on malformed data (we are fingerprinting, not validating).
func utf16le(b []byte) string {
	if len(b)%2 != 0 {
		// odd length can't be UTF-16; treat as latin-1
		return latin1(b)
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16))
}

func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// FileTimeToTime converts a Windows FILETIME (100ns ticks since 1601-01-01 UTC)
// to a time.Time.
func FileTimeToTime(ft uint64) time.Time {
	// 11644473600 seconds between 1601-01-01 and 1970-01-01.
	const epochDiff = 11644473600
	sec := int64(ft/10000000) - epochDiff
	nsec := int64(ft%10000000) * 100
	return time.Unix(sec, nsec).UTC()
}

var buildMap = map[int][2]string{
	2600:  {"Windows XP", ""},
	3790:  {"Windows XP x64", "Windows Server 2003 / 2003 R2"},
	6000:  {"Windows Vista", ""},
	6001:  {"Windows Vista SP1", "Windows Server 2008"},
	6002:  {"Windows Vista SP2", "Windows Server 2008 SP2"},
	7600:  {"Windows 7", "Windows Server 2008 R2"},
	7601:  {"Windows 7 SP1", "Windows Server 2008 R2 SP1"},
	9200:  {"Windows 8", "Windows Server 2012"},
	9600:  {"Windows 8.1", "Windows Server 2012 R2"},
	10240: {"Windows 10 1507", ""},
	10586: {"Windows 10 1511", ""},
	14393: {"Windows 10 1607", "Windows Server 2016"},
	15063: {"Windows 10 1703", ""},
	16299: {"Windows 10 1709", "Windows Server 1709"},
	17134: {"Windows 10 1803", "Windows Server 1803"},
	17763: {"Windows 10 1809", "Windows Server 2019"},
	18362: {"Windows 10 1903", ""},
	18363: {"Windows 10 1909", ""},
	19041: {"Windows 10 2004", ""},
	19042: {"Windows 10 20H2", ""},
	19043: {"Windows 10 21H1", ""},
	19044: {"Windows 10 21H2", ""},
	19045: {"Windows 10 22H2", ""},
	20348: {"", "Windows Server 2022"},
	22000: {"Windows 11 21H2", ""},
	22621: {"Windows 11 22H2", ""},
	22631: {"Windows 11 23H2", ""},
	25398: {"", "Windows Server 23H2"},
	26100: {"Windows 11 24H2", "Windows Server 2025"},
	26200: {"Windows 11 25H2", ""},
}

var approxMap = map[[2]int][2]string{
	{5, 1}:  {"Windows XP", ""},
	{5, 2}:  {"", "Windows Server 2003"},
	{6, 0}:  {"Windows Vista", "Windows Server 2008"},
	{6, 1}:  {"Windows 7", "Windows Server 2008 R2"},
	{6, 2}:  {"Windows 8", "Windows Server 2012"},
	{6, 3}:  {"Windows 8.1", "Windows Server 2012 R2"},
	{10, 0}: {"Windows 10/11", "Windows Server 2016+"},
}

// ParseVersion decodes the 8-byte version block. targetType ("domain"/"server"
// /"") disambiguates builds shared between a client and server SKU.
func ParseVersion(vb []byte, targetType string) *Version {
	if len(vb) < 8 || allZero(vb[:8]) {
		return nil
	}
	major := int(vb[0])
	minor := int(vb[1])
	build := int(binary.LittleEndian.Uint16(vb[2:4]))
	ntlmRev := int(vb[7])
	pair, ok := buildMap[build]
	client, server := "", ""
	if ok {
		client, server = pair[0], pair[1]
	}
	if client == "" && server == "" {
		if ap, ok := approxMap[[2]int{major, minor}]; ok {
			client, server = ap[0], ap[1]
		} else {
			client = "Unknown"
		}
	}
	// A build number that is shared between a client and server SKU (e.g. 7601 =
	// Windows 7 SP1 AND Server 2008 R2 SP1) cannot be disambiguated from the NTLM
	// CHALLENGE alone: the NTLM TARGET_TYPE flag distinguishes domain-joined from
	// standalone, NOT workstation from server (a domain-joined Windows 10 client
	// sets TARGET_TYPE_DOMAIN just like a server does). So we do not guess -- we
	// report both candidates and let the caller refine using host-level evidence
	// (a confirmed DC is definitively a server).
	_ = targetType
	var product string
	switch {
	case client != "" && server != "":
		product = client + " / " + server
	case client != "":
		product = client
	default:
		product = server
	}
	return &Version{
		Major: major, Minor: minor, Build: build, NTLMRevision: ntlmRev,
		Product: product, ClientCandidate: client, ServerCandidate: server,
		String: fmt.Sprintf("%d.%d.%d (%s)", major, minor, build, product),
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// ParseTargetInfo decodes an AV_PAIR block into a TargetInfo plus the ordered
// raw pairs.
func ParseTargetInfo(ti []byte) (*TargetInfo, []RawPair) {
	out := &TargetInfo{}
	var raw []RawPair
	off := 0
	for off+4 <= len(ti) {
		avID := binary.LittleEndian.Uint16(ti[off:])
		avLen := int(binary.LittleEndian.Uint16(ti[off+2:]))
		start := off + 4
		if start+avLen > len(ti) {
			break
		}
		val := ti[start : start+avLen]
		off = start + avLen
		name := AVName(avID)
		if avID == avEOL {
			break
		}
		switch avID {
		case avNbComputerName:
			out.NbComputerName = utf16le(val)
		case avNbDomainName:
			out.NbDomainName = utf16le(val)
		case avDnsComputerName:
			out.DnsComputerName = utf16le(val)
		case avDnsDomainName:
			out.DnsDomainName = utf16le(val)
		case avDnsTreeName:
			out.DnsTreeName = utf16le(val)
		case avTargetName:
			out.TargetName = utf16le(val)
		case avFlags:
			fl := uint32(0)
			pad := padRight(val, 4)
			fl = binary.LittleEndian.Uint32(pad)
			var meanings []string
			if fl&0x1 != 0 {
				meanings = append(meanings, "account auth constrained")
			}
			if fl&0x2 != 0 {
				meanings = append(meanings, "client provides MIC")
			}
			if fl&0x4 != 0 {
				meanings = append(meanings, "SPN from untrusted source")
			}
			out.Flags = &FlagsAV{Value: fl, Flags: meanings}
		case avTimestamp:
			ft := binary.LittleEndian.Uint64(padRight(val, 8))
			dt := FileTimeToTime(ft)
			out.Timestamp = &TimestampAV{FileTime: ft, UTC: dt.Format("2006-01-02 15:04:05.000000")}
		case avSingleHost:
			// Single_Host_Data: Size(4) Z4(4) CustomData(8) MachineID(32).
			if len(val) >= 48 {
				out.SingleHost = &SingleHostAV{MachineID: hex.EncodeToString(val[16:48])}
			} else {
				out.SingleHost = &SingleHostAV{Raw: hex.EncodeToString(val)}
			}
		case avChannelBindings:
			out.ChannelBindings = &ChannelBindingAV{
				Hash:    hex.EncodeToString(val),
				Present: !allZero(val),
			}
		default:
			if out.Other == nil {
				out.Other = map[string]string{}
			}
			out.Other[name] = hex.EncodeToString(val)
		}
		raw = append(raw, RawPair{Name: name, ID: avID, Hex: hex.EncodeToString(val)})
	}
	return out, raw
}

func padRight(b []byte, n int) []byte {
	if len(b) >= n {
		return b[:n]
	}
	out := make([]byte, n)
	copy(out, b)
	return out
}

// ParseChallenge parses an NTLMSSP CHALLENGE (Type-2). blob must start at the
// NTLMSSP signature.
func ParseChallenge(blob []byte) (*Challenge, error) {
	if len(blob) < 48 || !hasPrefix(blob, Sig) {
		return nil, fmt.Errorf("not an NTLMSSP message")
	}
	msgType := binary.LittleEndian.Uint32(blob[8:12])
	if msgType != 2 {
		return nil, fmt.Errorf("not a CHALLENGE message (type=%d)", msgType)
	}
	tnLen := int(binary.LittleEndian.Uint16(blob[12:14]))
	tnOff := int(binary.LittleEndian.Uint32(blob[16:20]))
	flags := binary.LittleEndian.Uint32(blob[20:24])
	serverChallenge := blob[24:32]
	tiLen := int(binary.LittleEndian.Uint16(blob[40:42]))
	tiOff := int(binary.LittleEndian.Uint32(blob[44:48]))

	targetType := ""
	if flags&0x00010000 != 0 {
		targetType = "domain"
	} else if flags&0x00020000 != 0 {
		targetType = "server"
	}

	var version *Version
	if len(blob) >= 56 {
		version = ParseVersion(blob[48:56], targetType)
	}

	targetName := ""
	if tnLen > 0 && tnOff+tnLen <= len(blob) {
		tn := blob[tnOff : tnOff+tnLen]
		if flags&0x1 != 0 {
			targetName = utf16le(tn)
		} else {
			targetName = latin1(tn)
		}
	}

	var ti *TargetInfo
	var rawPairs []RawPair
	if tiLen > 0 && tiOff+tiLen <= len(blob) {
		ti, rawPairs = ParseTargetInfo(blob[tiOff : tiOff+tiLen])
	}

	var flagNames []string
	for _, f := range NegotiateFlags {
		if flags&f.Bit != 0 {
			flagNames = append(flagNames, f.Name)
		}
	}

	return &Challenge{
		TargetName:         targetName,
		TargetType:         targetType,
		ServerChallenge:    hex.EncodeToString(serverChallenge),
		NegotiateFlags:     flags,
		NegotiateFlagNames: flagNames,
		Version:            version,
		TargetInfo:         ti,
		RawAVPairs:         rawPairs,
		RawBlobB64:         base64.StdEncoding.EncodeToString(blob),
	}, nil
}

// ExtractBlob finds the NTLMSSP signature inside an arbitrary buffer and
// returns everything from that offset onward, or nil if not present.
func ExtractBlob(raw []byte) []byte {
	idx := indexOf(raw, Sig)
	if idx < 0 {
		return nil
	}
	return raw[idx:]
}

func hasPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := range prefix {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

func indexOf(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func le16(b []byte, v uint16) []byte {
	return append(b, byte(v), byte(v>>8))
}

func le32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}
