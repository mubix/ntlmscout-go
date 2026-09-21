package scan

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/mubix/ntlmscout/internal/transport"
)

// ANSI colors, applied only to interactive terminals.
const (
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cCyan   = "\033[36m"
	cDim    = "\033[2m"
	cBold   = "\033[1m"
	cReset  = "\033[0m"
)

func colorize(s, code string, enable bool) string {
	if enable {
		return code + s + cReset
	}
	return s
}

// useColor reports whether w is an interactive terminal.
func useColor(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// secureCreate opens a file for writing with owner-only permissions.
func secureCreate(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
}

// AD functional-level number -> Windows version.
var funcLevel = map[string]string{
	"0": "2000", "1": "2003 interim", "2": "2003", "3": "2008",
	"4": "2008 R2", "5": "2012", "6": "2012 R2", "7": "2016",
}

type fpPair struct{ Label, Value string }

// fpPairs returns the ordered non-empty fingerprint fields for display.
func fpPairs(fp *Fingerprint) []fpPair {
	if fp == nil {
		return nil
	}
	var out []fpPair
	add := func(label, val string) {
		if val != "" {
			out = append(out, fpPair{label, val})
		}
	}
	add("Realm", fp.TargetRealm)
	add("Realm type", fp.TargetRealmType)
	add("NetBIOS host", fp.NetbiosComputer)
	add("NetBIOS domain", fp.NetbiosDomain)
	add("DNS host", fp.DNSComputer)
	add("DNS domain", fp.DNSDomain)
	add("DNS forest", fp.DNSForest)
	add("OS", fp.OS)
	add("OS build", fp.OSBuild)
	add("SPN", fp.SPN)
	add("Machine ID", fp.MachineID)
	add("Server time (UTC)", fp.ServerTimeUTC)
	if fp.TimeSkewSeconds != nil {
		add("Time skew (s)", strconv.FormatFloat(*fp.TimeSkewSeconds, 'f', 1, 64))
	}
	return out
}

func fpScore(r Result) int {
	n := 0
	for range fpPairs(r.Fingerprint) {
		n++
	}
	return n
}

func internalAddrString(addrs []addrLike) string {
	var parts []string
	for _, a := range addrs {
		s := a.Addr
		if a.Internal != nil && *a.Internal {
			s += " (internal)"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

type addrLike struct {
	Addr     string
	Internal *bool
}

// hostLine is the concise one-liner printed the first time a host is confirmed.
func hostLine(r Result) string {
	fp := r.Fingerprint
	var bits []string
	if fp != nil {
		if fp.NetbiosDomain != "" && fp.NetbiosComputer != "" {
			bits = append(bits, fp.NetbiosDomain+"\\"+fp.NetbiosComputer)
		}
		if fp.DNSComputer != "" {
			bits = append(bits, fp.DNSComputer)
		}
		if fp.OS != "" {
			bits = append(bits, fp.OS)
		}
	}
	for _, a := range r.InternalAddresses {
		if a.Internal != nil && *a.Internal {
			bits = append(bits, "internal: "+a.Address)
			break
		}
	}
	return fmt.Sprintf("[+] %s  %s", r.Host, strings.Join(bits, "  "))
}

// fmtText renders one result for verbose live output.
func fmtText(r Result) string {
	if !r.Success {
		return fmt.Sprintf("[-] %-40s %-6s -> %s", r.Target, r.Protocol, orStr(r.Error, "failed"))
	}
	if len(r.InternalAddresses) > 0 || (len(r.DisclosedNames) > 0 && r.NTLM == nil) {
		var bits []string
		if len(r.InternalAddresses) > 0 {
			var al []addrLike
			for _, a := range r.InternalAddresses {
				al = append(al, addrLike{a.Address, a.Internal})
			}
			bits = append(bits, "addrs: "+internalAddrString(al))
		}
		if len(r.DisclosedNames) > 0 {
			var ns []string
			for _, n := range r.DisclosedNames {
				ns = append(ns, n.Name)
			}
			bits = append(bits, "names: "+strings.Join(ns, ", "))
		}
		return fmt.Sprintf("[+] %s (%s) %s", r.Target, r.Protocol, strings.Join(bits, " | "))
	}
	lines := []string{fmt.Sprintf("[+] %s (%s)", r.Target, r.Protocol)}
	for _, p := range fpPairs(r.Fingerprint) {
		lines = append(lines, fmt.Sprintf("      %-18s: %s", p.Label, p.Value))
	}
	if sp := r.SecurityPosture; sp != nil {
		var obs []string
		if sp.SigningOffered {
			obs = append(obs, "signing offered")
		} else {
			obs = append(obs, "signing not offered")
		}
		if sp.ChannelBindingPresent {
			obs = append(obs, "channel-binding present")
		} else {
			obs = append(obs, "channel-binding absent")
		}
		if len(sp.WeakCryptoOffered) > 0 {
			obs = append(obs, "WEAK: "+strings.Join(sp.WeakCryptoOffered, ", "))
		}
		lines = append(lines, fmt.Sprintf("      %-18s: %s", "Posture", strings.Join(obs, " | ")))
	}
	return strings.Join(lines, "\n")
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// printHostSummaries writes the grouped per-host summary block.
func printHostSummaries(results []Result, roles map[string]Role, out io.Writer, full bool) {
	uc := useColor(out)
	byHost := map[string][]Result{}
	var order []string
	for _, r := range results {
		if !r.Success {
			continue
		}
		if _, ok := byHost[r.Host]; !ok {
			order = append(order, r.Host)
		}
		byHost[r.Host] = append(byHost[r.Host], r)
	}
	if len(order) == 0 {
		return
	}
	for _, host := range order {
		rs := byHost[host]
		rep := rs[0]
		for _, r := range rs {
			if fpScore(r) > fpScore(rep) {
				rep = r
			}
		}
		fp := rep.Fingerprint
		hasInternal := false
		for _, r := range rs {
			if len(r.InternalAddresses) > 0 {
				hasInternal = true
				break
			}
		}
		if !full && (fp == nil || len(fpPairs(fp)) == 0) && !hasInternal {
			continue
		}
		ident := host
		if fp != nil {
			if fp.DNSComputer != "" {
				ident = fp.DNSComputer
			} else if fp.NetbiosComputer != "" {
				ident = fp.NetbiosComputer
			}
		}
		fmt.Fprint(out, "\n"+strings.Repeat("=", 72)+"\n")
		fmt.Fprintf(out, "  HOST: %s   (%s)\n", host, ident)
		fmt.Fprint(out, strings.Repeat("-", 72)+"\n")

		internal := []struct{ addr, src string }{}
		seenAddr := map[string]bool{}
		for _, r := range rs {
			for _, a := range r.InternalAddresses {
				if seenAddr[a.Address] {
					continue
				}
				seenAddr[a.Address] = true
				src := a.Source
				if src == "" {
					src = r.Protocol
				}
				internal = append(internal, struct{ addr, src string }{a.Address, src})
			}
		}
		fmt.Fprintf(out, "  %-18s: %s\n", "External address", host)
		if len(internal) > 0 {
			var shown string
			if full {
				var parts []string
				for _, e := range internal {
					parts = append(parts, fmt.Sprintf("%s (%s)", e.addr, e.src))
				}
				shown = strings.Join(parts, ", ")
			} else {
				var parts []string
				for _, e := range internal {
					parts = append(parts, e.addr)
				}
				shown = strings.Join(parts, ", ")
			}
			fmt.Fprintf(out, "  %-18s: %s\n", "Internal address", shown)
		}
		role := roles[host]
		dcConfirmed := roleIsConfirmedDC(role)
		for _, p := range fpPairs(fp) {
			// Refine an ambiguous client/server OS build to the server SKU when
			// the host is a confirmed Domain Controller (definitively a server).
			if p.Label == "OS" && dcConfirmed && fp != nil && fp.OSServer != "" && fp.OSClient != "" {
				p.Value = fp.OSServer
			}
			fmt.Fprintf(out, "  %-18s: %s\n", p.Label, p.Value)
		}
		if role.Role != "" && role.Role != "Unknown" {
			var val string
			if role.Role == "Domain Controller" {
				q := "likely"
				if role.Confidence == "confirmed" {
					q = "confirmed"
				}
				val = "Domain Controller (" + q + ")"
			} else {
				val = role.Role
			}
			if full && len(role.Reasons) > 0 {
				val += " -- " + strings.Join(role.Reasons, "; ")
			}
			fmt.Fprintf(out, "  %-18s: %s\n", "Role", val)
		}
		if rep.SecurityPosture != nil && len(rep.SecurityPosture.WeakCryptoOffered) > 0 {
			fmt.Fprintf(out, "  %-18s: %s\n", "Weak crypto", strings.Join(rep.SecurityPosture.WeakCryptoOffered, ", "))
		}
		// rootDSE
		var rd = firstRootDSE(rs)
		if rd != nil {
			if v := rd.Get("dnsHostName"); v != "" {
				fmt.Fprintf(out, "  %-18s: %s\n", "LDAP dnsHostName", v)
			}
			if v := rd.Get("defaultNamingContext"); v != "" {
				fmt.Fprintf(out, "  %-18s: %s\n", "Naming context", v)
			}
			dl := funcLevel[rd.Get("domainFunctionality")]
			fl := funcLevel[rd.Get("forestFunctionality")]
			if dl != "" || fl != "" {
				fmt.Fprintf(out, "  %-18s: domain %s  /  forest %s\n", "Functional level", orStr(dl, "?"), orStr(fl, "?"))
			}
		}
		if full {
			names := []struct{ nm, src string }{}
			seenN := map[string]bool{}
			for _, r := range rs {
				for _, a := range r.DisclosedNames {
					if seenN[a.Name] {
						continue
					}
					seenN[a.Name] = true
					src := a.Source
					if src == "" {
						src = r.Protocol
					}
					names = append(names, struct{ nm, src string }{a.Name, src})
				}
			}
			if len(names) > 0 {
				fmt.Fprintf(out, "  %-18s: %d\n", "Disclosed names", len(names))
				for _, e := range names {
					fmt.Fprintf(out, "      - %s [%s]\n", e.nm, e.src)
				}
			}
		}
		// NTLM-disclosing endpoints only.
		probeOnly := map[string]bool{"iisip": true, "oxid": true, "tlscert": true, "rdpcert": true}
		sorted := append([]Result{}, rs...)
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].Protocol != sorted[j].Protocol {
				return sorted[i].Protocol < sorted[j].Protocol
			}
			return sorted[i].URL < sorted[j].URL
		})
		var eps []string
		for _, r := range sorted {
			if probeOnly[r.Protocol] || r.NTLM == nil {
				continue
			}
			ep := r.URL
			if ep == "" {
				ep = fmt.Sprintf("%s://%s:%d", r.Protocol, r.Host, r.Port)
			}
			eps = append(eps, ep)
		}
		if len(eps) > 0 {
			row := fmt.Sprintf("  NTLM endpoints identified: %d", len(eps))
			fmt.Fprintln(out, colorize(row, cRed, uc))
			for _, e := range eps {
				fmt.Fprintf(out, "      - %s\n", e)
			}
		}
	}
	fmt.Fprint(out, strings.Repeat("=", 72)+"\n")
}

func firstRootDSE(rs []Result) *rootDSEView {
	for _, r := range rs {
		if r.RootDSE.Len() > 0 {
			v := rootDSEView(r.RootDSE)
			return &v
		}
	}
	return nil
}

// rootDSEView reuses the transport RootDSE Get helper.
type rootDSEView = transport.RootDSE

// csvColumns matches the reference tool's CSV layout.
var csvColumns = []string{
	"target", "protocol", "host", "port", "success",
	"target_realm", "target_realm_type", "netbios_computer",
	"netbios_domain", "dns_computer", "dns_domain", "dns_forest",
	"os", "os_build", "machine_id", "server_time_utc",
	"time_skew_seconds", "domain_role", "role_confidence", "signing",
	"channel_binding", "weak_crypto", "internal_addresses",
	"disclosed_names", "elapsed_ms", "error",
}

func writeCSV(results []Result, path string, roles map[string]Role) error {
	f, err := secureCreate(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write(csvColumns); err != nil {
		return err
	}
	for _, r := range results {
		fp := r.Fingerprint
		sp := r.SecurityPosture
		role := roles[r.Host]
		var ias, dns []string
		for _, a := range r.InternalAddresses {
			ias = append(ias, a.Address)
		}
		for _, n := range r.DisclosedNames {
			dns = append(dns, n.Name)
		}
		row := map[string]string{
			"target": r.Target, "protocol": r.Protocol, "host": r.Host,
			"port": itoaOrEmpty(r.Port), "success": strconv.FormatBool(r.Success),
			"elapsed_ms": strconv.Itoa(r.ElapsedMs), "error": r.Error,
			"domain_role": role.Role, "role_confidence": role.Confidence,
			"internal_addresses": strings.Join(ias, ";"),
			"disclosed_names":    strings.Join(dns, ";"),
		}
		if sp != nil {
			row["signing"] = strconv.FormatBool(sp.SigningOffered)
			row["channel_binding"] = strconv.FormatBool(sp.ChannelBindingPresent)
			row["weak_crypto"] = strings.Join(sp.WeakCryptoOffered, ";")
		}
		if fp != nil {
			row["target_realm"] = fp.TargetRealm
			row["target_realm_type"] = fp.TargetRealmType
			row["netbios_computer"] = fp.NetbiosComputer
			row["netbios_domain"] = fp.NetbiosDomain
			row["dns_computer"] = fp.DNSComputer
			row["dns_domain"] = fp.DNSDomain
			row["dns_forest"] = fp.DNSForest
			row["os"] = fp.OS
			row["os_build"] = fp.OSBuild
			row["machine_id"] = fp.MachineID
			row["server_time_utc"] = fp.ServerTimeUTC
			if fp.TimeSkewSeconds != nil {
				row["time_skew_seconds"] = strconv.FormatFloat(*fp.TimeSkewSeconds, 'f', 1, 64)
			}
		}
		rec := make([]string, len(csvColumns))
		for i, c := range csvColumns {
			rec[i] = row[c]
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	return nil
}

func itoaOrEmpty(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

// writeHostsFile emits a NetExec-style hosts file.
func writeHostsFile(results []Result, path string, roles map[string]Role) (int, error) {
	var lines []string
	seen := map[string]bool{}
	for _, r := range results {
		if !r.Success || r.Fingerprint == nil {
			continue
		}
		fp := r.Fingerprint
		ip := r.Host
		var names []string
		if fp.DNSComputer != "" {
			names = append(names, fp.DNSComputer)
		}
		if fp.NetbiosComputer != "" {
			short := fp.NetbiosComputer
			if fp.DNSComputer == "" || !strings.EqualFold(short, strings.Split(fp.DNSComputer, ".")[0]) {
				names = append(names, short)
			}
		}
		if roles[ip].Role == "Domain Controller" && fp.DNSDomain != "" {
			names = append(names, fp.DNSDomain)
		}
		if len(names) == 0 {
			continue
		}
		var low []string
		for _, n := range names {
			low = append(low, strings.ToLower(n))
		}
		key := ip + "|" + strings.Join(low, " ")
		if seen[key] {
			continue
		}
		seen[key] = true
		lines = append(lines, ip+"\t"+strings.Join(names, " "))
	}
	f, err := secureCreate(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if len(lines) > 0 {
		fmt.Fprintln(f, strings.Join(lines, "\n"))
	}
	return len(lines), nil
}

func writeJSON(results []Result, roles map[string]Role, path string) error {
	f, err := secureCreate(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]interface{}{"results": results, "roles": roles})
}

func writeNDJSON(results []Result, path string) error {
	f, err := secureCreate(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range results {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}
