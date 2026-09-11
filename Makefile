# Set V to 1 for verbose output from the Makefile
Q=$(if $V,,@)
SRC=$(shell find . -type f -name '*.go')

# Tool paths
GOIMPORTS=golang.org/x/tools/cmd/goimports
GOLANGCI_LINT=github.com/golangci/golangci-lint/v2/cmd/golangci-lint
GOLANGCI_LINT_CONFIG_URL=https://raw.githubusercontent.com/smallstep/workflows/main/.golangci.yml
GOTESTSUM=gotest.tools/gotestsum
GOVULNCHECK=golang.org/x/vuln/cmd/govulncheck

all: lint test

ci: test

.PHONY: all ci

#########################################
# Bootstrapping
#########################################

bootstra%:
	@echo "Nothing to bootstrap"

.PHONY: bootstrap

#########################################
# Test
#########################################

test: defaulttest simulatortest combinecoverage

defaulttest:
	$Q $(GOFLAGS) go tool $(GOTESTSUM) -- -coverpkg=./... -coverprofile=defaultcoverage.out -covermode=atomic ./...

simulatortest:
	$Q $(GOFLAGS) CGO_ENABLED=1 go tool $(GOTESTSUM) -- -coverpkg=./tpm/...,./kms/tpmkms -coverprofile=simulatorcoverage.out -covermode=atomic -tags tpmsimulator ./tpm ./kms/tpmkms

combinecoverage:
	cat defaultcoverage.out > coverage.out
	tail -n +2 simulatorcoverage.out >> coverage.out

race:
	$Q $(GOFLAGS) go tool $(GOTESTSUM) -- -race ./...

.PHONY: test defaulttest simulatortest combinecoverage race

#########################################
# Linting
#########################################

fmt:
	$Q go tool $(GOIMPORTS) --local go.step.sm/crypto -l -w $(SRC)

lint: golint govulncheck

golint: SHELL:=/bin/bash
golint:
	$Q LOG_LEVEL=error go tool $(GOLANGCI_LINT) run --config <(curl -s $(GOLANGCI_LINT_CONFIG_URL)) --timeout=30m

govulncheck:
	$Q go tool $(GOVULNCHECK) ./...

.PHONY: fmt lint golint govulncheck

#########################################
# Go generate
#########################################

generate:
	$Q go generate ./...

.PHONY: generate
