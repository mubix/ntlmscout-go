// Command ntlmscout enumerates the information disclosed by internet-exposed
// NTLM endpoints. It is a dependency-free Go port of BoydHacks' ntlmscout with
// feature parity plus cross-platform builds, an SMB1 fallback, richer debug
// output, and graceful interruption.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mubix/ntlmscout/internal/netx"
	"github.com/mubix/ntlmscout/internal/scan"
	"github.com/mubix/ntlmscout/internal/spray"
)

// version is overridable at build time with -ldflags "-X main.version=...".
var version = "1.1.0"

const banner = `
          __  __                                __
   ____  / /_/ /___ ___  ______________  __  __/ /_
  / __ \/ __/ / __ ` + "`" + `__ \/ ___/ ___/ __ \/ / / / __/
 / / / / /_/ / / / / / (__  ) /__/ /_/ / /_/ / /_
/_/ /_/\__/_/_/ /_/ /_/____/\___/\____/\__,_/\__/
`

// parsed CLI arguments.
type args struct {
	targets      []string
	inputList    string
	noDiscover   bool
	noInternalIP bool

	spray     bool
	users     []string
	passwords []string
	domain    string
	auth      string
	sprayPath string
	delay     float64
	jitter    float64

	output    string
	json      string
	ndjson    string
	csv       string
	hostsFile string
	verbose   bool
	noSummary bool
	quiet     bool

	threads   int
	timeout   float64
	proxy     string
	verifyTLS bool
	debug     bool

	showHelp    bool
	showVersion bool
}

func printBanner(quiet bool) {
	if quiet {
		return
	}
	tty := isTTY(os.Stderr)
	b := banner
	if tty {
		b = "\033[36m" + banner + "\033[0m"
	}
	fmt.Fprintln(os.Stderr, b)
	fmt.Fprintln(os.Stderr, "   hunting exposed NTLM")
	fmt.Fprint(os.Stderr, "   BoydHacks port  ·  github.com/mubix/ntlmscout\n\n")
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func usage() string {
	return `ntlmscout ` + version + ` -- enumerate information disclosed by exposed NTLM endpoints.

USAGE:
  ntlmscout [options] <target> [<target> ...]

TARGETS:
  A bare host/IP triggers a full sweep of every NTLM-capable port. You can also
  pass a URL (https://host/ews/), a scheme target (smb://10.0.0.5, ldaps://dc),
  a host:port, or a CIDR range (10.0.0.0/24). Protocols: http https smb mssql
  smtp smtps imap imaps pop3 pop3s nntp nntps ldap ldaps rdp.

  -I, --input-list FILE     file with one target per line

RECON SCOPE (default: full sweep of all ports):
      --no-discover         skip the HTTP path wordlist; probe site roots only
      --no-internal-ip      skip internal-disclosure checks (IIS Host-header/
                            PROPFIND, TLS+RDP cert names, Exchange headers, OXID)

SPRAY MODE:
      --spray               AUTH SPRAY mode: send real creds. Requires -u and -p.
  -u, --user USER|FILE      username or userlist file (repeatable)
  -p, --password PASS|FILE  password or password-list file (repeatable)
      --domain DOMAIN       AD domain to qualify usernames (auto-learned if omitted)
      --auth ntlm|basic     spray auth method (default ntlm)
      --spray-path PATH     force a specific endpoint path to spray
      --delay SECONDS       wait between password rounds (lockout safety)
      --jitter SECONDS      random 0..N seconds added per attempt

OUTPUT:
  -o, --output, --log FILE  detailed per-host log (every disclosing endpoint)
      --json FILE           write full JSON results
      --ndjson FILE         write newline-delimited JSON (one object per line)
      --csv FILE            write results as CSV (one row per probe)
      --generate-hosts-file FILE   NetExec-style hosts file from discovered names
  -v, --verbose             print the full fingerprint block for every hit
      --no-summary          skip the grouped per-host summary
  -q, --quiet               suppress banner and per-probe stderr

BEHAVIOR:
  -t, --threads N           concurrency (default 20)
      --timeout SECONDS     per-probe timeout (default 10)
      --proxy HOST:PORT     tunnel through an HTTP CONNECT proxy (SOCKS not supported)
      --verify-tls          verify TLS certificates (off by default for self-signed)
      --debug               surface swallowed errors and probe fallbacks
      --version             print version and exit
  -h, --help                show this help

EXAMPLES:
  ntlmscout 203.0.113.10
  ntlmscout mail.example.com
  ntlmscout https://mail.example.com/ews/
  ntlmscout 10.0.0.0/24 -I targets.txt --json results.json
  ntlmscout -I targets.txt --proxy 127.0.0.1:8080
  ntlmscout --spray -I hosts.txt -u users.txt -p 'Winter2026!' --delay 1800
`
}

// valueFlags maps a flag name to whether it consumes the next argument.
func parseArgs(argv []string) (*args, error) {
	a := &args{auth: "ntlm", threads: 20, timeout: 10}
	i := 0
	next := func(name string) (string, error) {
		i++
		if i >= len(argv) {
			return "", fmt.Errorf("flag %s requires a value", name)
		}
		return argv[i], nil
	}
	for ; i < len(argv); i++ {
		arg := argv[i]
		if arg == "" {
			continue
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			a.targets = append(a.targets, arg)
			continue
		}
		// Support --flag=value.
		name := arg
		inlineVal := ""
		hasInline := false
		if strings.HasPrefix(arg, "--") {
			if eq := strings.Index(arg, "="); eq >= 0 {
				name = arg[:eq]
				inlineVal = arg[eq+1:]
				hasInline = true
			}
		}
		getVal := func(flag string) (string, error) {
			if hasInline {
				return inlineVal, nil
			}
			return next(flag)
		}
		switch name {
		case "-h", "--help":
			a.showHelp = true
		case "--version":
			a.showVersion = true
		case "-I", "--input-list":
			v, err := getVal(name)
			if err != nil {
				return nil, err
			}
			a.inputList = v
		case "--no-discover":
			a.noDiscover = true
		case "--no-internal-ip":
			a.noInternalIP = true
		case "--spray":
			a.spray = true
		case "-u", "--user":
			v, err := getVal(name)
			if err != nil {
				return nil, err
			}
			a.users = append(a.users, v)
		case "-p", "--password":
			v, err := getVal(name)
			if err != nil {
				return nil, err
			}
			a.passwords = append(a.passwords, v)
		case "--domain":
			v, err := getVal(name)
			if err != nil {
				return nil, err
			}
			a.domain = v
		case "--auth":
			v, err := getVal(name)
			if err != nil {
				return nil, err
			}
			if v != "ntlm" && v != "basic" {
				return nil, fmt.Errorf("--auth must be ntlm or basic")
			}
			a.auth = v
		case "--spray-path":
			v, err := getVal(name)
			if err != nil {
				return nil, err
			}
			a.sprayPath = v
		case "--delay":
			v, err := getVal(name)
			if err != nil {
				return nil, err
			}
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return nil, fmt.Errorf("--delay: %v", err)
			}
			a.delay = f
		case "--jitter":
			v, err := getVal(name)
			if err != nil {
				return nil, err
			}
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return nil, fmt.Errorf("--jitter: %v", err)
			}
			a.jitter = f
		case "-o", "--output", "--log":
			v, err := getVal(name)
			if err != nil {
				return nil, err
			}
			a.output = v
		case "--json":
			v, err := getVal(name)
			if err != nil {
				return nil, err
			}
			a.json = v
		case "--ndjson":
			v, err := getVal(name)
			if err != nil {
				return nil, err
			}
			a.ndjson = v
		case "--csv":
			v, err := getVal(name)
			if err != nil {
				return nil, err
			}
			a.csv = v
		case "--generate-hosts-file":
			v, err := getVal(name)
			if err != nil {
				return nil, err
			}
			a.hostsFile = v
		case "-v", "--verbose":
			a.verbose = true
		case "--no-summary":
			a.noSummary = true
		case "-q", "--quiet":
			a.quiet = true
		case "-t", "--threads":
			v, err := getVal(name)
			if err != nil {
				return nil, err
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return nil, fmt.Errorf("--threads must be a positive integer")
			}
			a.threads = n
		case "--timeout":
			v, err := getVal(name)
			if err != nil {
				return nil, err
			}
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || f <= 0 {
				return nil, fmt.Errorf("--timeout must be a positive number")
			}
			a.timeout = f
		case "--proxy":
			v, err := getVal(name)
			if err != nil {
				return nil, err
			}
			a.proxy = v
		case "--verify-tls":
			a.verifyTLS = true
		case "--debug":
			a.debug = true
		default:
			return nil, fmt.Errorf("unknown flag: %s", arg)
		}
	}
	return a, nil
}

func normalizeProxy(p string) string {
	p = p[strings.LastIndex(p, "://")+1:]
	if strings.HasPrefix(p, "//") {
		p = p[2:]
	}
	return strings.TrimRight(p, "/")
}

func main() {
	a, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		fmt.Fprintln(os.Stderr, "    (see -h for full help)")
		os.Exit(2)
	}
	if a.showHelp {
		fmt.Fprint(os.Stdout, usage())
		return
	}
	if a.showVersion {
		fmt.Printf("ntlmscout %s\n", version)
		return
	}

	cfg := &netx.Config{VerifyTLS: a.verifyTLS, Debug: a.debug, DebugOut: os.Stderr}
	if a.proxy != "" {
		cfg.Proxy = normalizeProxy(a.proxy)
	}

	printBanner(a.quiet)

	if len(a.targets) == 0 && a.inputList == "" {
		fmt.Fprint(os.Stderr, usage())
		fmt.Fprintln(os.Stderr, "[!] no targets given -- try: ntlmscout 1.1.1.1")
		os.Exit(2)
	}
	// Catch the common slip of passing a target file as a positional arg.
	for _, t := range a.targets {
		if fi, err := os.Stat(t); err == nil && !fi.IsDir() {
			fmt.Fprintf(os.Stderr, "[!] '%s' looks like a file -- did you mean:  -I %s\n", t, t)
			os.Exit(2)
		}
	}

	timeout := time.Duration(a.timeout * float64(time.Second))

	if a.spray {
		os.Exit(spray.Run(&spray.Options{
			Targets:   a.targets,
			InputList: a.inputList,
			Users:     a.users,
			Passwords: a.passwords,
			Domain:    a.domain,
			Auth:      a.auth,
			SprayPath: a.sprayPath,
			Delay:     a.delay,
			Jitter:    a.jitter,
			Threads:   a.threads,
			Timeout:   timeout,
			Output:    a.output,
			JSON:      a.json,
			Verbose:   a.verbose,
			Net:       cfg,
		}))
	}

	os.Exit(scan.RunRecon(&scan.Options{
		Targets:      a.targets,
		InputList:    a.inputList,
		NoDiscover:   a.noDiscover,
		NoInternalIP: a.noInternalIP,
		Threads:      a.threads,
		Timeout:      timeout,
		Quiet:        a.quiet,
		Verbose:      a.verbose,
		NoSummary:    a.noSummary,
		Output:       a.output,
		JSON:         a.json,
		NDJSON:       a.ndjson,
		CSV:          a.csv,
		HostsFile:    a.hostsFile,
		Net:          cfg,
	}))
}
