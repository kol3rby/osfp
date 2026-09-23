# osfp — build, test and cross-compilation.
#
# Every binary is built with CGO_ENABLED=0: the Solaris/illumos and AIX targets
# are only reachable that way, and a pure-Go build is what keeps them working.
#
# This file avoids GNU make extensions, because the systems osfp targets ship
# BSD make, and macOS still ships GNU make 3.81: neither $(shell ...) nor != is
# used, since the first is GNU-only and the second needs GNU make 4.0, so the
# commands behind VERSION and COMMIT are left for the recipe's shell to run; the
# environment is set per command rather than with export, which BSD make parses
# as a variable named "export CGO_ENABLED"; and nothing refers to MAKEFILE_LIST.
#
# Building osfp needs none of this in any case — "go build ./cmd/osfp" is the
# whole story. This file is a developer convenience.

BIN        = osfp
PKG        = ./cmd/osfp
DIST       = dist
# Command substitutions, expanded by the shell each time a recipe uses them.
# "make VERSION=v1.2.3" still overrides them with a plain value.
VERSION    = $$(git describe --tags --always --dirty 2>/dev/null || echo devel)
COMMIT     = $$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS    = -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)
GOFLAGS    = -trimpath
FUZZTIME   ?= 30s

# CGO_ENABLED travels with each command instead of being exported once.
GO         = CGO_ENABLED=0 go

# The release matrix. "make release" fails as soon as one target breaks: the
# Solaris/AIX support is lost silently the day a bad dependency lands in
# go.mod, and this matrix is the only reliable guard against that.
PLATFORMS  = \
	linux/amd64 linux/arm64 linux/386 linux/arm \
	freebsd/amd64 freebsd/arm64 \
	openbsd/amd64 \
	netbsd/amd64 \
	solaris/amd64 \
	illumos/amd64 \
	darwin/amd64 darwin/arm64 \
	aix/ppc64

MANPAGES   = docs/man/osfp.1 docs/man/osfp-baseline.1 docs/man/osfp-compare.1

.PHONY: all build test race fuzz vet vet-all fmt fmt-check lint man-lint cross release checksums clean help

all: fmt-check vet test build

build: ## Build the binary for the host platform
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN) $(PKG)

test: ## Run the test suite
	$(GO) test ./...

race: ## Run the tests under the race detector (needs cgo and a C toolchain)
	@# The scan pipeline is the one place where a data race could silently
	@# corrupt a fingerprint, so this override of CGO_ENABLED=0 is deliberate.
	CGO_ENABLED=1 go test -race ./...

fuzz: ## Run every fuzz target for FUZZTIME (default 30s)
	@set -e; \
	for pkg in $$($(GO) list ./...); do \
		for target in $$($(GO) test -list 'Fuzz.*' $$pkg | grep '^Fuzz' || true); do \
			echo "== $$pkg $$target"; \
			$(GO) test $$pkg -run '^$$' -fuzz "^$$target$$" -fuzztime $(FUZZTIME); \
		done; \
	done

vet: ## Run go vet
	$(GO) vet ./...

fmt: ## Rewrite the sources with gofmt
	gofmt -s -w .

fmt-check: ## Fail if any source file is not gofmt-clean
	@out=$$(gofmt -s -l .); \
	if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi

lint: fmt-check vet ## Formatting and vet checks

man-lint: ## Check the manual pages (needs mandoc)
	mandoc -Tlint -W warning $(MANPAGES)

vet-all: ## Run go vet for every target of the release matrix
	@# Cross-compiling proves the code builds; vetting proves the build-tagged
	@# files are also correct on targets no CI runner can execute.
	@set -e; \
	for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		printf '%-16s' "$$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch $(GO) vet ./... && echo ok; \
	done

cross: ## Type-check and build every target of the release matrix
	@set -e; \
	for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		printf '%-16s' "$$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
			-o /dev/null $(PKG) && echo ok; \
	done

release: clean ## Build the release binaries and their checksums
	@set -e; mkdir -p $(DIST); \
	for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		out=$(DIST)/$(BIN)-$(VERSION)-$$os-$$arch; \
		printf '%-16s' "$$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
			-o $$out $(PKG) && echo "$$out"; \
	done
	@# The binary is static, so the third-party notices have to ship with it:
	@# that is the one obligation the permissive licences involved do impose.
	@# The manual pages and the changelog travel with it for the same reason:
	@# a static binary is often all that reaches the machine.
	@cp LICENSE THIRD-PARTY-LICENSES CHANGELOG.md $(MANPAGES) $(DIST)/
	@# -s keeps GNU make from announcing that it entered and left a directory
	@# it never changed. It is POSIX, so BSD make honours it too.
	@$(MAKE) -s checksums

checksums: ## Write dist/SHA256SUMS
	@cd $(DIST) && \
	files="$$(ls $(BIN)-$(VERSION)-* *.1) LICENSE THIRD-PARTY-LICENSES CHANGELOG.md"; \
	if command -v sha256sum >/dev/null 2>&1; then sha256sum $$files > SHA256SUMS; \
	else shasum -a 256 $$files > SHA256SUMS; fi && \
	echo "$(DIST)/SHA256SUMS"

clean: ## Remove build artefacts
	rm -rf $(DIST) $(BIN)

help: ## List the targets
	@grep -hE '^[a-z-]+:.*##' Makefile | sed 's/:.*## /\t/' | expand -t 14
