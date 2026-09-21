package scan

import (
	"sort"
	"strconv"
	"strings"
)

var dcProtocols = map[string]bool{"ldap": true, "ldaps": true}

// resolveHostRoles determines a per-host role from host-level evidence.
//
//   - Domain Controller (confirmed): an LDAP/GC service actually answered
//     (NTLM bind or anonymous rootDSE). This is the ONLY way a DC is claimed --
//     there is no name-based heuristic, because "NB host == NB domain" is the
//     signature of a standalone/workgroup box, not a DC.
//   - Domain member: the NTLM CHALLENGE reported TARGET_TYPE_DOMAIN and no DC
//     service was seen.
//   - Standalone (workgroup): the CHALLENGE reported TARGET_TYPE_SERVER (the
//     account database is local, not a domain).
//   - Unknown: not enough data.
func resolveHostRoles(results []Result) map[string]Role {
	byHost := map[string][]Result{}
	var order []string
	for _, r := range results {
		if _, ok := byHost[r.Host]; !ok {
			order = append(order, r.Host)
		}
		byHost[r.Host] = append(byHost[r.Host], r)
	}
	roles := map[string]Role{}
	for _, host := range order {
		rs := byHost[host]
		var svc []Result
		gc := false
		domainJoined := false
		standalone := false
		for _, r := range rs {
			if !r.Success {
				continue
			}
			if r.NTLM != nil && r.SecurityPosture != nil {
				if r.SecurityPosture.DomainJoined {
					domainJoined = true
				}
				if r.SecurityPosture.Standalone {
					standalone = true
				}
			}
			if dcProtocols[r.Protocol] && (r.NTLM != nil || r.RootDSE.Len() > 0) {
				svc = append(svc, r)
				if r.Port == 3268 || r.Port == 3269 {
					gc = true
				}
			}
		}
		switch {
		case len(svc) > 0:
			set := map[string]bool{}
			for _, r := range svc {
				name := r.Protocol
				if name == "" {
					name = strconv.Itoa(r.Port)
				}
				set[name] = true
			}
			names := make([]string, 0, len(set))
			for n := range set {
				names = append(names, n)
			}
			sort.Strings(names)
			label := "LDAP"
			if gc {
				label = "Global Catalog/LDAP"
			}
			roles[host] = Role{Role: "Domain Controller", Confidence: "confirmed",
				Reasons: []string{label + " service responding (" + strings.Join(names, ", ") + ")"}}
		case domainJoined:
			roles[host] = Role{Role: "Domain member", Confidence: "confirmed",
				Reasons: []string{"domain-joined (TARGET_TYPE_DOMAIN); no DC service observed (LDAP/GC/Kerberos not seen)"}}
		case standalone:
			roles[host] = Role{Role: "Standalone", Confidence: "confirmed",
				Reasons: []string{"workgroup / not domain-joined (NTLM TARGET_TYPE_SERVER -- local account database)"}}
		default:
			roles[host] = Role{Role: "Unknown"}
		}
	}
	return roles
}

// roleIsConfirmedDC reports whether a resolved role is a confirmed DC (used to
// refine an ambiguous client/server OS build to the server SKU).
func roleIsConfirmedDC(r Role) bool {
	return r.Role == "Domain Controller" && r.Confidence == "confirmed"
}
