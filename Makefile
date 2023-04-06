# Set V to 1 for verbose output from the Makefile
Q=$(if $V,,@)
SRC=$(shell find . -type f -name '*.go')

all: lint test

ci: test

.PHONY: all ci

#########################################
# Bootstrapping
#########################################

bootstra%:
	$Q curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin latest
	$Q go install golang.org/x/vuln/cmd/govulncheck@latest
	$Q go install gotest.tools/gotestsum@latest

.PHONY: bootstrap

#########################################
# Test
#########################################

test: defaulttest simulatortest combinecoverage

defaulttest:
	$Q $(GOFLAGS) gotestsum -- -coverpkg=./... -coverprofile=defaultcoverage.out -covermode=atomic ./...

simulatortest:
	$Q $(GOFLAGS) CGO_ENALBED=1 gotestsum -- -coverpkg=./tpm -coverprofile=simulatorcoverage.out -covermode=atomic -tags tpmsimulator ./tpm

combinecoverage:
	cat defaultcoverage.out simulatorcoverage.out > coverage.out

race:
	$Q $(GOFLAGS) gotestsum -- -race ./...

.PHONY: test defaulttest simulatortest combinecoverage race

#########################################
# Linting
#########################################

fmt:
	$Q goimports -l -w $(SRC)

lint: SHELL:=/bin/bash
lint:
	$Q LOG_LEVEL=error golangci-lint run --config <(curl -s https://raw.githubusercontent.com/smallstep/workflows/master/.golangci.yml) --timeout=30m
	$Q govulncheck ./...

.PHONY: fmt lint

#########################################
# Go generate
#########################################

generate:
	$Q go generate ./...

.PHONY: generate
