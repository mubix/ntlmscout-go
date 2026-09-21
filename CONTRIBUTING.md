# Contributing

Thanks for helping improve `ntlmscout`.

## Ground rules

- **Standard library only.** A core goal is a dependency-free, single static
  binary. Do not add third-party module requirements; if something needs a
  helper, implement the minimal piece needed (as with MD4 and the DER helpers).
- **Keep Go 1.21 compatible.** `go.mod` targets 1.21 so the tool builds on older
  toolchains and distros. Avoid newer stdlib APIs.
- **Assume old targets.** Probes should fail over rather than assume a modern
  server. If you add or change a probe, try the modern dialect first and fall
  back (see the SMB2→SMB1 and inline→two-step SASL patterns), and route any
  swallowed error through `cfg.Debugf` so `--debug` can diagnose it.
- **No new panics on the hot path.** A malformed response from one host must
  never abort a scan.

## Development

```bash
make test     # go test ./...
make vet      # go vet ./...
make fmt      # gofmt -w .
make build    # host binary
make release  # cross-compile all platforms into dist/
```

Please run `make test vet fmt` before opening a PR. CI runs the same checks plus
a cross-compile matrix.

## Tests

Wire-format code must ship with a test. Prefer deterministic tests:

- known-answer vectors for crypto (see `internal/spray/crypto_test.go`),
- hand-built message round-trips for parsers (`internal/ntlm/ntlm_test.go`),
- `httptest`-based servers for transport behaviour (`internal/transport/http_test.go`).

## Adding a probe / disclosure

1. Put the wire logic in `internal/transport` (challenge elicitation) or
   `internal/disclosure` (adjacent leaks).
2. Register it in `internal/scan/plan.go` (ports/planning) and
   `internal/scan/probe.go` (dispatch + result assembly).
3. Add a test and document the behaviour in the README.

## Scope & ethics

`ntlmscout` is for authorized testing. Please don't submit features whose only
purpose is to attack third parties without consent (mass exploitation,
credential relay, etc.). Recon, decoding, and safe validation are in scope.
