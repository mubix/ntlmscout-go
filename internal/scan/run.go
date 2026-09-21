package scan

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
)

// RunRecon executes the default recon mode and returns a process exit code.
func RunRecon(opts *Options) int {
	jobs, err := planTargets(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		return 2
	}
	planned := len(jobs)
	hostSet := map[string]bool{}
	portSet := map[string]bool{}
	for _, j := range jobs {
		hostSet[j.host] = true
		portSet[fmt.Sprintf("%s:%d", j.host, jobPort(j.proto, j.port))] = true
	}
	hosts := len(hostSet)

	if !opts.Quiet {
		proxy := "off"
		if opts.Net.HasProxy() {
			proxy = "on"
		}
		fmt.Fprintf(os.Stderr, "[*] recon  ·  %d host(s)  ·  %d threads  ·  %gs timeout  ·  proxy %s\n",
			hosts, opts.Threads, opts.Timeout.Seconds(), proxy)
		fmt.Fprintf(os.Stderr, "[*] checking %d host:port(s) for open services ...\n", len(portSet))
	}

	jobs, closed := pruneClosedPorts(opts, jobs)
	total := len(jobs)
	if !opts.Quiet {
		if closed > 0 {
			fmt.Fprintf(os.Stderr, "[*] %d closed port(s) skipped  ·  %d/%d probes live\n", closed, total, planned)
		}
		fmt.Fprintln(os.Stderr, "[*] scouting exposed NTLM, please stand by ...")
	}

	showProgress := !opts.Quiet && !opts.Verbose && useColor(os.Stderr)
	clearProgress := func() {
		if showProgress {
			fmt.Fprint(os.Stderr, "\r\033[K")
		}
	}

	// Ctrl-C: stop dispatching and report what we have.
	var canceled int32
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		<-sigCh
		atomic.StoreInt32(&canceled, 1)
		fmt.Fprintln(os.Stderr, "\n[!] interrupted -- finishing in-flight probes and reporting partial results ...")
	}()

	var (
		mu        sync.Mutex
		results   []Result
		announced = map[string]bool{}
		done      int64
	)
	sem := make(chan struct{}, opts.Threads)
	var wg sync.WaitGroup

	for _, j := range jobs {
		if atomic.LoadInt32(&canceled) == 1 {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()
			r := probe(opts.Net, j, opts.Timeout)
			mu.Lock()
			results = append(results, r)
			n := atomic.AddInt64(&done, 1)
			if !opts.Quiet {
				if opts.Verbose {
					// Print the full fingerprint block once per host; subsequent
					// NTLM hits on the same host (often dozens of HTTP vdirs)
					// collapse to a one-line endpoint note so the stream stays
					// readable. Failures and non-NTLM disclosures print as-is.
					if r.Success && r.NTLM != nil && announced[r.Host] {
						ep := r.URL
						if ep == "" {
							ep = fmt.Sprintf("%s://%s:%d", r.Protocol, r.Host, r.Port)
						}
						fmt.Printf("[+] %s (%s)  [+ %s already fingerprinted]\n", ep, r.Protocol, r.Host)
					} else {
						fmt.Println(fmtText(r))
						if r.Success {
							fmt.Println()
						}
						if r.Success && r.NTLM != nil {
							announced[r.Host] = true
						}
					}
				} else if r.Success && !announced[r.Host] && (r.Fingerprint != nil || len(r.InternalAddresses) > 0) {
					announced[r.Host] = true
					clearProgress()
					fmt.Println(hostLine(r))
				}
				if showProgress {
					fmt.Fprintf(os.Stderr, "\r\033[K[*] scouting... %d/%d probes  |  %d misconfigured host(s) found",
						n, total, len(announced))
				}
			}
			mu.Unlock()
		}(j)
	}
	wg.Wait()
	clearProgress()

	roles := resolveHostRoles(results)
	ntlmEndpoints := 0
	ntlmHosts := map[string]bool{}
	for _, r := range results {
		if r.NTLM != nil {
			ntlmEndpoints++
			ntlmHosts[r.Host] = true
		}
	}

	if !opts.Quiet {
		if !opts.NoSummary {
			printHostSummaries(results, roles, os.Stdout, opts.Verbose)
		}
		uc := useColor(os.Stdout)
		if ntlmEndpoints > 0 {
			fmt.Println(colorize(fmt.Sprintf("[+] %d exposed NTLM endpoint(s) on %d of %d host(s).",
				ntlmEndpoints, len(ntlmHosts), hosts), cGreen, uc))
		} else {
			fmt.Println(colorize(fmt.Sprintf("[-] No exposed NTLM endpoints found across %d host(s).", hosts), cYellow, uc))
		}
	}

	writeOutputs(opts, results, roles)
	return 0
}

func writeOutputs(opts *Options, results []Result, roles map[string]Role) {
	if opts.JSON != "" {
		if err := writeJSON(results, roles, opts.JSON); err != nil {
			fmt.Fprintf(os.Stderr, "[!] JSON write failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "[*] JSON written to %s\n", opts.JSON)
		}
	}
	if opts.NDJSON != "" {
		if err := writeNDJSON(results, opts.NDJSON); err != nil {
			fmt.Fprintf(os.Stderr, "[!] NDJSON write failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "[*] NDJSON written to %s\n", opts.NDJSON)
		}
	}
	if opts.CSV != "" {
		if err := writeCSV(results, opts.CSV, roles); err != nil {
			fmt.Fprintf(os.Stderr, "[!] CSV write failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "[*] CSV written to %s\n", opts.CSV)
		}
	}
	if opts.HostsFile != "" {
		if n, err := writeHostsFile(results, opts.HostsFile, roles); err != nil {
			fmt.Fprintf(os.Stderr, "[!] hosts file write failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "[*] Hosts file (%d entries) written to %s\n", n, opts.HostsFile)
		}
	}
	if opts.Output != "" {
		f, err := secureCreate(opts.Output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] log write failed: %v\n", err)
			return
		}
		printHostSummaries(results, roles, f, true)
		f.Close()
		fmt.Fprintf(os.Stderr, "[*] Detailed log written to %s\n", opts.Output)
	}
}
