package scan

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// httpPathsRaw is the merged, de-duplicated endpoint-discovery wordlist.
// Sources: pwnfoo/NTLMRecon, praetorian-inc/NTLMRecon, nyxgeek/ntlmscan,
// nyxgeek/lyncsmash, plus Exchange/ADFS/ADCS/SharePoint/WinRM paths from MS docs.
var httpPathsRaw = []string{
	"/",
	// Exchange (OWA / EWS / EAS / MAPI / RPC / Autodiscover)
	"/autodiscover/", "/Autodiscover/Autodiscover.xml",
	"/Autodiscover/AutodiscoverService.svc/root", "/autodiscover/autodiscover.svc",
	"/EWS/", "/EWS/Exchange.asmx", "/EWS/Services.wsdl",
	"/ecp/", "/owa/", "/owa/auth/", "/OAB/", "/mapi/", "/mapi/nspi/",
	"/mapi/emsmdb/", "/Microsoft-Server-ActiveSync/", "/Rpc/", "/rpc/rpcproxy.dll",
	"/RpcWithCert/", "/PowerShell/", "/API/", "/Exchange/", "/Exchweb/",
	"/Public/", "/aspnet_client/",
	// Skype for Business / Lync
	"/abs/", "/abs/handler/", "/CertProv/", "/Conf/", "/dialin/", "/GroupExpansion/",
	"/GroupExpansion/service.svc", "/HybridConfig/", "/mcx/", "/mcx/mcxservice.svc",
	"/meet/", "/meeting/", "/PassiveAuth/", "/PersistentChat/", "/PhoneConferencing/",
	"/Reach/sip.svc", "/RequestHandler/", "/RequestHandlerExt/",
	"/Rgs/", "/RgsClients/", "/scheduler/", "/Ucwa/", "/ucwa/v1/applications",
	"/UnifiedMessaging/", "/WebTicket/", "/WebTicket/WebTicketService.svc",
	"/iwa/authenticated.aspx", "/iwa/iwa_test.aspx",
	// AD FS
	"/adfs/ls/", "/adfs/ls/wia", "/adfs/ls/idpinitiatedsignon.aspx",
	"/adfs/services/trust/", "/adfs/services/trust/2005/windowstransport",
	"/adfs/services/trust/13/windowstransport",
	"/internal_windows_authentication/",
	// AD Certificate Services
	"/CertEnroll/", "/CertSrv/", "/certsrv/mscep/", "/ocsp/",
	// Updates / misc service endpoints
	"/AutoUpdate/", "/deviceupdatefiles_ext/", "/deviceupdatefiles_int/",
	"/debug/", "/Etc/", "/reports/", "/sso/", "/remote/", "/wsman",
	"/_windows/default.aspx?ReturnUrl=/",
	// SharePoint / generic IIS
	"/_vti_bin/", "/_vti_bin/lists.asmx", "/_layouts/", "/_layouts/15/",
	"/sharepoint/", "/wss/", "/my/", "/sites/", "/search/",
}

var fileMarkers = []string{".xml", ".svc", ".asmx", ".aspx", ".dll", ".wsdl", ".txt"}

// httpPaths is the normalised wordlist (directory-style paths get a trailing /).
var httpPaths = normalizePaths(httpPathsRaw)

func normalizePaths(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		last := p
		if i := strings.LastIndex(p, "/"); i >= 0 {
			last = p[i+1:]
		}
		hasFileMarker := false
		for _, m := range fileMarkers {
			if strings.HasSuffix(strings.ToLower(p), m) {
				hasFileMarker = true
				break
			}
		}
		if !strings.Contains(p, "?") && !strings.HasSuffix(p, "/") && !hasFileMarker && !strings.Contains(last, ".") {
			p += "/"
		}
		k := strings.ToLower(p)
		if !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	return out
}

// portProtocol maps a well-known port to its NTLM-capable protocol.
var portProtocol = map[int]string{
	80: "http", 443: "https", 8080: "http", 8443: "https",
	445: "smb", 139: "smb", 1433: "mssql", 25: "smtp", 587: "smtp",
	465: "smtps", 143: "imap", 993: "imaps", 110: "pop3", 995: "pop3s",
	119: "nntp", 563: "nntps", 389: "ldap", 636: "ldaps",
	3268: "ldap", 3269: "ldaps", // Global Catalog (DC-only)
	3389: "rdp", 5985: "http", 5986: "https",
}

var tlsDefaultPort = map[string]int{
	"https": 443, "ldaps": 636, "imaps": 993, "pop3s": 995, "smtps": 465, "nntps": 563,
}

var winrmPorts = map[int]bool{5985: true, 5986: true}

var defaultPort = map[string]int{
	"http": 80, "https": 443, "smb": 445, "mssql": 1433,
	"smtp": 25, "smtps": 465, "imap": 143, "imaps": 993,
	"pop3": 110, "pop3s": 995, "nntp": 119, "nntps": 563,
	"ldap": 389, "ldaps": 636, "rdp": 3389,
	"iisip": 443, "tlscert": 443, "rdpcert": 3389, "oxid": 135,
}

func jobPort(proto string, port int) int {
	if port != 0 {
		return port
	}
	return defaultPort[proto]
}

// planTargets expands the target list into the full set of probes.
func planTargets(opts *Options) ([]job, error) {
	raw := append([]string{}, opts.Targets...)
	if opts.InputList != "" {
		f, err := os.Open(opts.InputList)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				raw = append(raw, line)
			}
		}
		f.Close()
	}
	raw = expandTargets(raw)
	discover := !opts.NoDiscover
	var jobs []job

	for _, t := range raw {
		if strings.Contains(t, "://") {
			scheme, rest, _ := strings.Cut(t, "://")
			scheme = strings.ToLower(scheme)
			hostport, _, _ := strings.Cut(rest, "/")
			host, port := splitHostPort(hostport)
			pathPart := rest[len(hostport):]
			hasPath := pathPart != "" && pathPart != "/"
			switch scheme {
			case "http", "https":
				if discover && !hasPath {
					for _, p := range httpPaths {
						jobs = append(jobs, job{scheme, host, port, fmt.Sprintf("%s://%s%s", scheme, hostport, p)})
					}
				} else {
					jobs = append(jobs, job{scheme, host, port, t})
				}
			case "smb":
				jobs = append(jobs, job{"smb", host, orDefault(port, 445), ""})
			case "mssql":
				jobs = append(jobs, job{"mssql", host, orDefault(port, 1433), ""})
			case "smtp", "smtps", "imap", "imaps", "pop3", "pop3s", "nntp", "nntps", "ldap", "ldaps", "rdp":
				jobs = append(jobs, job{scheme, host, port, ""})
			default:
				jobs = append(jobs, job{scheme, host, port, t})
			}
			continue
		}
		host, port := splitHostPort(t)
		if port != 0 {
			proto := portProtocol[port]
			if proto == "" {
				proto = "http"
			}
			jobs = addHost(jobs, proto, host, port, discover)
		} else {
			ports := make([]int, 0, len(portProtocol))
			for p := range portProtocol {
				ports = append(ports, p)
			}
			sort.Ints(ports)
			for _, p := range ports {
				jobs = addHost(jobs, portProtocol[p], host, p, discover)
			}
		}
	}

	if !opts.NoInternalIP {
		jobs = append(jobs, planDisclosure(jobs)...)
	}
	return jobs, nil
}

func orDefault(port, def int) int {
	if port != 0 {
		return port
	}
	return def
}

func addHost(jobs []job, proto, host string, port int, discover bool) []job {
	if (proto == "http" || proto == "https") && winrmPorts[port] {
		// WinRM: a single /wsman probe, not the OWA wordlist.
		jobs = append(jobs, job{proto, host, port, fmt.Sprintf("%s://%s:%d/wsman", proto, urlHost(host), port)})
	} else if (proto == "http" || proto == "https") && discover {
		for _, p := range httpPaths {
			jobs = append(jobs, job{proto, host, port, fmt.Sprintf("%s://%s:%d%s", proto, urlHost(host), port, p)})
		}
	} else {
		url := ""
		if proto == "http" || proto == "https" {
			url = fmt.Sprintf("%s://%s:%d/", proto, urlHost(host), port)
		}
		jobs = append(jobs, job{proto, host, port, url})
	}
	return jobs
}

func planDisclosure(jobs []job) []job {
	var extra []job
	httpSeen := map[string]bool{}
	tlsSeen := map[string]bool{}
	hostSeen := map[string]bool{}
	for _, j := range jobs {
		if j.proto == "http" || j.proto == "https" {
			p := j.port
			if p == 0 {
				if j.proto == "https" {
					p = 443
				} else {
					p = 80
				}
			}
			key := fmt.Sprintf("%s:%d", j.host, p)
			if !httpSeen[key] {
				httpSeen[key] = true
				extra = append(extra, job{"iisip", j.host, p, fmt.Sprintf("%s://%s:%d", j.proto, urlHost(j.host), p)})
			}
		}
		if def, ok := tlsDefaultPort[j.proto]; ok {
			p := orDefault(j.port, def)
			key := fmt.Sprintf("%s:%d", j.host, p)
			if !tlsSeen[key] {
				tlsSeen[key] = true
				extra = append(extra, job{"tlscert", j.host, p, ""})
			}
		} else if j.proto == "rdp" {
			p := orDefault(j.port, 3389)
			key := fmt.Sprintf("%s:%d", j.host, p)
			if !tlsSeen[key] {
				tlsSeen[key] = true
				extra = append(extra, job{"rdpcert", j.host, p, ""})
			}
		}
	}
	for _, j := range jobs {
		if !hostSeen[j.host] {
			hostSeen[j.host] = true
			extra = append(extra, job{"oxid", j.host, 135, ""})
		}
	}
	return extra
}

// pruneClosedPorts drops jobs whose TCP port isn't open (one fast connect per
// unique host:port). Skipped when a proxy is configured.
func pruneClosedPorts(opts *Options, jobs []job) ([]job, int) {
	if opts.Net.HasProxy() {
		return jobs, 0
	}
	type hp struct {
		host string
		port int
	}
	unique := map[hp]bool{}
	for _, j := range jobs {
		p := jobPort(j.proto, j.port)
		if p != 0 {
			unique[hp{j.host, p}] = true
		}
	}
	connectTimeout := opts.Timeout
	if connectTimeout > 3*time.Second {
		connectTimeout = 3 * time.Second
	}
	open := map[hp]bool{}
	var mu sync.Mutex
	sem := make(chan struct{}, opts.Threads)
	var wg sync.WaitGroup
	for k := range unique {
		wg.Add(1)
		sem <- struct{}{}
		go func(k hp) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := opts.Net.DialTCP(k.host, k.port, connectTimeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				open[k] = true
				mu.Unlock()
			}
		}(k)
	}
	wg.Wait()
	var live []job
	for _, j := range jobs {
		if open[hp{j.host, jobPort(j.proto, j.port)}] {
			live = append(live, j)
		}
	}
	return live, len(unique) - len(open)
}
