```
          __  __                                __
   ____  / /_/ /___ ___  ______________  __  __/ /_
  / __ \/ __/ / __ `__ \/ ___/ ___/ __ \/ / / / __/
 / / / / /_/ / / / / / (__  ) /__/ /_/ / /_/ / /_
/_/ /_/\__/_/_/ /_/ /_/____/\___/\____/\__,_/\__/

   hunting exposed NTLM  ·  Go edition
   github.com/mubix/ntlmscout
```

# ntlmscout (Go)

**One tool to squeeze every drop of information out of internet-exposed NTLM endpoints.**

An unauthenticated NTLM negotiation leaks a surprising amount of internal Active
Directory detail before a single credential is ever sent. `ntlmscout` sends an
NTLM Type-1 (NEGOTIATE) message across a wide range of transports, fully decodes
the Type-2 (CHALLENGE) that comes back, and pulls out everything: internal
NetBIOS/DNS host and domain names, the AD forest, the OS build (mapped to a
friendly Windows version), the server clock (and skew), negotiate flags, and
every AV_PAIR, then enriches it with adjacent unauthenticated disclosures and an
optional, lockout-safe password spray.

This is a dependency-free **Go** reimplementation of
[BoydHacks' original Python `ntlmscout`](https://github.com/boydhacks/ntlmscout),
built to compile to a single static binary for **Linux, macOS (Intel + Apple
Silicon), and Windows (x64 + ARM64)** with feature parity plus a few
improvements (see [What's different](#whats-different-from-the-python-original)).

Standard library only. No `go get` of third-party packages. One binary.

## Features

- **Every transport in one tool:** HTTP(S) (with endpoint discovery), SMB2/3
  (with an SMB1 fallback for legacy hosts), MSSQL/TDS, SMTP, IMAP, POP3, NNTP,
  LDAP(S), and RDP/CredSSP (NLA).
- **Deep Type-2 decode:** NetBIOS + DNS host/domain, forest/tree name, OS build
  -> friendly name (client vs. server disambiguated), server timestamp + clock
  skew, SPN, MachineID, channel bindings, and full negotiate-flag breakdown.
- **Interprets, not just dumps:** honest **member vs. Domain Controller**
  classification (a DC is only claimed when a DC service actually answers), and a
  security-posture read (SMB/LDAP signing, EPA/channel-binding, NTLMv1/LM weak
  crypto).
- **Recovers the internal IP:** the one thing NTLM itself can't give you, via
  IIS Host-header disclosure (CVE-2000-0649), WebDAV PROPFIND, RPC
  `IOXIDResolver::ServerAlive2` (TCP 135), and TLS/RDP certificate IP SANs.
- **Extra disclosures:** TLS/RDP certificate CN + SANs, Exchange
  `X-FEServer`/`X-CalculatedBETarget` header leaks, and anonymous **LDAP
  rootDSE** enrichment (naming contexts, `dnsHostName`, AD functional levels).
- **Fast:** a port-liveness gate skips every probe on a closed port, so filtered
  hosts don't cost you a wall of timeouts.
- **Legacy-friendly:** probes fail over between dialects (inline vs two-step
  SASL, SMB2 -> SMB1) and TLS is negotiated permissively (TLS 1.0+ with legacy
  cipher suites) so old, self-signed and hardened endpoints still hand-shake.
- **Lockout-safe spray mode:** password-spray ordering (one password across all
  users per round), NTLM Type-3 or HTTP Basic against the most effective
  endpoint, with a clear valid / invalid / inconclusive verdict.
- **Report-ready output:** grouped per-host summary plus JSON, NDJSON, CSV, and
  a NetExec-style hosts file. Output files are written with owner-only
  permissions.
- **Debuggable:** `--debug` surfaces every otherwise-swallowed connection and
  parse error, plus the probe fallbacks it took, so unusual targets can be
  diagnosed and new probes developed.

## Install

### Download a release binary

Grab the binary for your platform from the [releases](https://github.com/mubix/ntlmscout/releases)
page and run it, there is nothing to install.

### Build from source

Requires Go 1.21 or newer.

```bash
git clone https://github.com/mubix/ntlmscout
cd ntlmscout
go build -o ntlmscout ./cmd/ntlmscout
./ntlmscout --help
```

Or with the Makefile (builds all platforms into `dist/`):

```bash
make            # build for the host
make release    # cross-compile linux/darwin/windows (amd64+arm64)
make test       # run the unit tests
```

### Install with `go install`

```bash
go install github.com/mubix/ntlmscout/cmd/ntlmscout@latest
```

## Usage

```bash
# recon a single IP or host (full sweep of every NTLM-capable port)
ntlmscout 203.0.113.10
ntlmscout mail.example.com

# a specific endpoint, or a whole range, or a target list
ntlmscout https://mail.example.com/ews/
ntlmscout 10.0.0.0/24
ntlmscout -I targets.txt --json results.json

# route everything through Burp / a CONNECT proxy
ntlmscout -I targets.txt --proxy 127.0.0.1:8080

# diagnose an odd target
ntlmscout --debug -v smb://10.0.0.5

# lockout-safe password spray against the best endpoint
ntlmscout --spray -I hosts.txt -u users.txt -p 'Winter2026!' --delay 1800
```

Recon is a **full sweep by default**. Trim it with `--no-discover` (skip the HTTP
path wordlist) or `--no-internal-ip` (skip the cert/OXID/IIS checks). See
`--help` for the full menu.

## Example output

```
========================================================================
  HOST: 203.0.113.10   (EXCH01.corp.example.com)
------------------------------------------------------------------------
  External address  : 203.0.113.10
  Internal address  : 10.0.0.25
  Realm             : CORP
  Realm type        : domain
  NetBIOS host      : EXCH01
  NetBIOS domain    : CORP
  DNS host          : EXCH01.corp.example.com
  DNS domain        : corp.example.com
  DNS forest        : corp.example.com
  OS                : Windows Server 2019
  OS build          : 10.0.17763
  Server time (UTC) : 2026-01-01 12:00:00
  Time skew (s)     : -0.1
  Role              : Domain member
  NTLM endpoints identified: 4
      - https://203.0.113.10/ews/
      - https://203.0.113.10/rpc/
      - https://203.0.113.10/autodiscover/
      - smb://203.0.113.10:445
========================================================================

[+] 4 exposed NTLM endpoint(s) on 1 of 1 host(s).
```

Add `-o log.txt` for a full per-field log, or `--json`/`--csv` for
machine-readable output.

## Spray safety

Spray mode is opt-in and hardwired to **password-spray ordering:** one password
is tried across every account per round, so no account ever sees more than one
attempt per round. Set `--delay` to the target's lockout observation window and
confirm the lockout policy before running. It reports valid, cleanly-rejected,
and inconclusive results separately so a negative result is trustworthy rather
than an artifact of a broken oracle.

## What's different from the Python original

`ntlmscout` (Go) aims for behavioural parity with the reference implementation.
The port also adds:

- **Single static binary** per OS/arch (Linux, macOS x86-64 + arm64, Windows
  x64 + arm64), no interpreter required on the target.
- **SMB1 fallback.** When a host doesn't answer SMB2/3, ntlmscout retries with an
  SMB1 SESSION_SETUP_ANDX (extended security) so pre-Vista Windows and old Samba
  still yield a challenge. (`--debug` reports when the fallback is used.)
- **Legacy-tolerant TLS by design.** TLS 1.0 minimum with a broad cipher list so
  old and hardened services still handshake. (Go's TLS stack cannot speak SSLv3
  or export ciphers, so a small set of pre-2008 SSLv3-only endpoints remain
  unreachable, `--debug` shows the handshake error when that happens.)
- **Graceful interruption.** Ctrl-C stops dispatching new probes and reports the
  partial results gathered so far.
- **Richer `--debug`.** Every swallowed error and probe fallback is logged with a
  short context label so unfamiliar responses can be diagnosed and new probes
  developed.
- **`--version`.**

## TLS and legacy reach

By default (no `--verify-tls`) ntlmscout is deliberately permissive so it can
fingerprint old, self-signed and hardened endpoints: certificate verification
is off, the minimum version is set to TLS 1.0, and a broad cipher list
(including CBC, 3DES and RC4 suites) is offered.

What that reaches, and what it does not:

| Protocol | Reached? | Notes |
|----------|----------|-------|
| TLS 1.3 / 1.2 | yes | Default and modern hosts. |
| TLS 1.1 | yes | Verified by the test suite (`internal/netx`). |
| TLS 1.0 | yes | Verified by the test suite. Enabled only because verification is off; `--verify-tls` raises the floor to 1.2. |
| SSLv3 | no | Go's `crypto/tls` removed SSLv3 in Go 1.14. `--debug` shows the handshake error. |
| SSLv2 | no | Go never implemented SSLv2. |

An older Go toolchain is **not** a fix for SSLv3: Go ≤1.13 could negotiate it,
but pinning the tool to an end-of-life, unpatched compiler is not worth it and
still gives nothing for SSLv2 or export-grade ciphers.

If SSLv3/SSLv2 reach ever becomes necessary, the practical path is to send a
hand-rolled `ClientHello` and read the server's cleartext certificate off the
wire without completing the handshake (the certificate is unencrypted in every
protocol below TLS 1.3), rather than changing the Go version. That is a
possible future addition, not part of this release.

## Architecture

```
cmd/ntlmscout          CLI + argument parsing
internal/ntlm          NTLMSSP Type-1/2/3 build & CHALLENGE decode, version map
internal/der           minimal ASN.1 DER + SPNEGO/GSSAPI wrapping
internal/netx          dialing, HTTP CONNECT proxy, legacy TLS, debug logging
internal/transport     per-protocol probes (http/smb/mssql/mail/ldap/rdp)
internal/disclosure    IIS internal-IP, RPC OXID, TLS/RDP cert parsing
internal/scan          target planning, dispatch, role resolution, reporting
internal/spray         MD4/NTLMv2 crypto + lockout-safe spray engine
```

Run the tests with `go test ./...`. They include MD4 and MS-NLMP NTOWFv2
known-answer vectors, a Type-2 round-trip, DER encoding checks, and an
end-to-end HTTP challenge test.

## Legal

This tool is for authorized security testing and research only. You are
responsible for ensuring you have explicit permission to scan and, in spray
mode, to authenticate against every target. The authors accept no liability for
misuse.

## Credits & acknowledgements

This is a Go port of **[ntlmscout](https://github.com/boydhacks/ntlmscout)** by
**BoydHacks (David Boyd):** the design, transports, wordlist and decoding
approach are his. The original in turn stands on the shoulders of:

- **NTLMRecon:** [pwnfoo / Sachin Kamath](https://github.com/pwnfoo/NTLMRecon)
  and [Praetorian](https://github.com/praetorian-inc/NTLMRecon).
- **ntlmscan:** [nyxgeek (TrustedSec)](https://github.com/nyxgeek/ntlmscan) and
  [lyncsmash](https://github.com/nyxgeek/lyncsmash).
- **ntlm_challenger:** [nopfor](https://github.com/nopfor/ntlm_challenger).
- **nmap `*-ntlm-info` NSE scripts:** Justin Cacak and Tom Sellers.
- **NetExec / CrackMapExec:** the [NetExec team](https://github.com/Pennyw0rth/NetExec)
  and byt3bl33d3r.
- **Impacket:** [Fortra/SecureAuth](https://github.com/fortra/impacket), and
  **pyspnego:** [@jborean93](https://github.com/jborean93/pyspnego).
- **MailSniper:** [@dafthack (Beau Bullock)](https://github.com/dafthack/MailSniper).
- **The Hacker Recipes** and the wider AD community.

Protocol details follow Microsoft's **[MS-NLMP]** Open Specification and Eric
Glass's classic [davenport NTLM notes](http://davenport.sourceforge.net/ntlm.html).
The IIS internal-IP disclosure is **CVE-2000-0649**.

If your work belongs here and it's been missed, open an issue, credit is due.
