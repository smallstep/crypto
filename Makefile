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

test:
	$Q $(GOFLAGS) gotestsum -- -coverprofile=coverage.out -short -covermode=atomic ./...

tpmtest:
	$Q $(GOFLAGS) CGO_ENALBED=1 gotestsum -- -coverprofile=tpmcoverage.out -short -covermode=atomic -tags tpmsimulator ./tpm 

race:
	$Q $(GOFLAGS) gotestsum -- -race ./...

.PHONY: test tpmtest race

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
