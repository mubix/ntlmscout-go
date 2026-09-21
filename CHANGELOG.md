# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-09-20

Fixes from a live /24 lab scan.

### Fixed

- **Standalone/workgroup hosts were misreported as "Domain Controller (likely)".**
  The name-based DC heuristic ("NetBIOS host == NetBIOS domain" / "server FQDN
  == domain DNS name") fired on standalone boxes, where the "domain" is just the
  machine's own name. That heuristic is removed. Role is now driven by the NTLM
  TARGET_TYPE flag: TARGET_TYPE_SERVER => **Standalone** (new role, not
  domain-joined), TARGET_TYPE_DOMAIN => Domain member, and Domain Controller is
  claimed only when an LDAP/GC service actually answers (unchanged).
- **`domain_joined` was set from the mere presence of a NetBIOS/DNS domain**, so
  standalone hosts looked domain-joined. It now follows TARGET_TYPE (with a
  conservative fallback when the flag is absent).
- **Domain-joined workstations were mislabeled as Server SKUs.** A build number
  shared between a client and server SKU (e.g. 6.1.7601 = Windows 7 SP1 /
  Server 2008 R2 SP1) was disambiguated from TARGET_TYPE, but every domain-joined
  machine — workstation or server — sets TARGET_TYPE_DOMAIN. Shared builds now
  report **both** candidates (e.g. "Windows 7 SP1 / Windows Server 2008 R2 SP1");
  the summary refines to the server SKU only for confirmed Domain Controllers.

### Changed

- **RDP:** the X.224 Connection Confirm is now parsed; hosts that reject the
  request or select standard RDP security (no TLS) are skipped cleanly instead
  of producing a "first record does not look like a TLS handshake" error.
- **Verbose (`-v`) output** prints a host's full fingerprint block once, then
  collapses further NTLM hits on that host to a one-line endpoint note (a host
  exposing dozens of HTTP vdirs no longer repeats the whole block per path).

## [1.0.0] - 2026-09-19

Initial release: a dependency-free Go reimplementation of BoydHacks'
[`ntlmscout`](https://github.com/boydhacks/ntlmscout) with feature parity.

### Added

- NTLM Type-1/2/3 construction and full CHALLENGE (Type-2) decoding: negotiate
  flags, OS version → friendly Windows name, NetBIOS/DNS host & domain, forest
  tree name, server timestamp + clock skew, SPN, MachineID, channel bindings and
  every AV_PAIR.
- Transports: HTTP(S) with endpoint discovery, SMB2/3, MSSQL/TDS, SMTP, IMAP,
  POP3, NNTP, LDAP(S) with anonymous rootDSE, and RDP/CredSSP (NLA).
- Internal-address disclosure: IIS Host-header (CVE-2000-0649) + WebDAV PROPFIND,
  RPC `IOXIDResolver::ServerAlive2` (TCP 135), and TLS/RDP certificate IP SANs.
- Extra disclosures: TLS/RDP certificate CN + SANs and Exchange FE/BE headers.
- Member vs. Domain Controller classification and passive security-posture read
  (signing, channel binding, weak crypto).
- Port-liveness gate, concurrent probing, and grouped per-host reporting plus
  JSON / NDJSON / CSV / NetExec-style hosts-file output (owner-only perms).
- Opt-in, lockout-safe password-spray mode (NTLM Type-3 or HTTP Basic) with
  password-spray ordering and valid / invalid / inconclusive verdicts.
- HTTP CONNECT proxy support and permissive TLS for self-signed/legacy services.

### Improvements over the Python original

- Single static binary for Linux, macOS (amd64 + arm64) and Windows
  (amd64 + arm64); no interpreter on the target.
- SMB1 SESSION_SETUP_ANDX fallback when a host does not speak SMB2/3.
- Legacy-tolerant TLS (TLS 1.0+ with a broad cipher-suite list).
- Graceful Ctrl-C: stop dispatching and report partial results.
- Expanded `--debug` output covering swallowed errors and probe fallbacks.
- `--version` flag.

### TLS reach

- TLS 1.0, 1.1, 1.2 and 1.3 are reachable in the default (non-`--verify-tls`)
  mode; TLS 1.0/1.1 negotiation is covered by regression tests in
  `internal/netx`. `--verify-tls` raises the minimum to TLS 1.2.

### Known limitations

- Go's `crypto/tls` cannot negotiate SSLv3 (removed in Go 1.14) or SSLv2 (never
  implemented), nor export-grade ciphers, so SSLv2/SSLv3-only endpoints are
  unreachable over TLS. `--debug` shows the handshake error when this occurs.
  A raw cleartext-certificate grab would be the way to add SSLv2/SSLv3 cert
  disclosure without changing the Go toolchain; it is not part of this release.

[1.1.0]: https://github.com/mubix/ntlmscout/releases/tag/v1.1.0
[1.0.0]: https://github.com/mubix/ntlmscout/releases/tag/v1.0.0
