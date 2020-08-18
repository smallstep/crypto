# Set V to 1 for verbose output from the Makefile
Q=$(if $V,,@)

all: lint test

.PHONY: all

#########################################
# Bootstrapping
#########################################

bootstrap:
	$Q GO111MODULE=on go get github.com/golangci/golangci-lint/cmd/golangci-lint@v1.30.0

.PHONY: bootstrap

#########################################
# Test
#########################################

test:
	$Q $(GOFLAGS) go test -coverprofile=coverage.out ./...

race:
	$Q $(GOFLAGS) go test -race ./...

.PHONY: test race

#########################################
# Linting
#########################################

fmt:
	$Q gofmt -l -w $(SRC)

lint:
	$Q LOG_LEVEL=error golangci-lint run --timeout=30m

.PHONY: lint fmt

