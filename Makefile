BINARY  := ntlmscout
PKG     := ./cmd/ntlmscout
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo 1.0.0)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath
GOSRC   := go.mod $(shell find . -name '*.go' -not -path './dist/*')

# sha256sum(1) on Linux, shasum(1) on macOS.
SHASUM := $(shell command -v sha256sum 2>/dev/null || echo "shasum -a 256")

# ---- Cross-compile matrix -------------------------------------------------
# Platforms someone would plausibly run a network scanner on, not every pair
# `go tool dist list` offers. All build with CGO_ENABLED=0 and a pure-Go
# toolchain. Notably absent on purpose: aix, dragonfly, illumos, netbsd,
# plan9, solaris, the IBM/exotic linux arches (s390x, ppc64, loong64,
# mips64), and js/wasip1 wasm (compiles, but has no outbound TCP stack, so it
# cannot actually scan). android/{386,amd64,arm} and ios/* need external cgo
# linking against a platform SDK and cannot be cross-compiled here at all.

# Desktops and servers -- the bulk of real use.
PLATFORMS_TIER1 := \
	linux/amd64 linux/arm64 linux/386 linux/arm \
	darwin/amd64 darwin/arm64 \
	windows/amd64 windows/arm64 windows/386

# Appliances, drop boxes and phones. Still real, just less common:
#   freebsd  -- pfSense / OPNsense / TrueNAS
#   openbsd  -- firewalls and jump hosts
#   android/arm64 -- Termux on a handset (pure-Go, unlike the other android arches)
#   linux/mips*   -- OpenWRT routers used as drop boxes
#   linux/riscv64 -- SBCs
PLATFORMS_EXTRA := \
	freebsd/amd64 freebsd/arm64 \
	openbsd/amd64 openbsd/arm64 \
	android/arm64 \
	linux/mips linux/mipsle \
	linux/riscv64

# What `make release` builds. Override to narrow it:
#   make release PLATFORMS="linux/arm64 windows/amd64"
PLATFORMS := $(PLATFORMS_TIER1) $(PLATFORMS_EXTRA)

# os/arch -> file extension, then -> dist/ path.
ext     = $(if $(filter windows/%,$(1)),.exe,)
outfile = dist/$(BINARY)-$(subst /,-,$(1))$(call ext,$(1))

# One build rule per platform, so `make -j` can run them in parallel.
define PLATFORM_RULE
$(call outfile,$(1)): $$(GOSRC)
	@mkdir -p dist
	@echo "  GO      $$@"
	@GOOS=$(word 1,$(subst /, ,$(1))) GOARCH=$(word 2,$(subst /, ,$(1))) CGO_ENABLED=0 \
		go build $$(GOFLAGS) -ldflags "$$(LDFLAGS)" -o $$@ $$(PKG)
endef
$(foreach p,$(PLATFORMS),$(eval $(call PLATFORM_RULE,$(p))))

.PHONY: all build test vet fmt clean release release-tier1 checksums list-platforms

all: build

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

clean:
	rm -rf $(BINARY) dist

# Full matrix. Run with -j to parallelize: make -j8 release
release: $(foreach p,$(PLATFORMS),$(call outfile,$(p)))
	@$(MAKE) --no-print-directory checksums
	@echo "done -> dist/ ($(words $(PLATFORMS)) targets)"

# Just the mainstream desktop/server platforms.
release-tier1: $(foreach p,$(PLATFORMS_TIER1),$(call outfile,$(p)))
	@$(MAKE) --no-print-directory checksums
	@echo "done -> dist/ ($(words $(PLATFORMS_TIER1)) targets)"

checksums:
	@cd dist && $(SHASUM) $(BINARY)-* > SHA256SUMS && echo "  SHA256  dist/SHA256SUMS"

list-platforms:
	@echo "tier1: $(PLATFORMS_TIER1)"
	@echo "extra: $(PLATFORMS_EXTRA)"
