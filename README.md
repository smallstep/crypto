# crypto

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/smallstep/crypto)](https://goreportcard.com/report/github.com/smallstep/crypto)
[![Build Status](https://travis-ci.com/smallstep/crypto.svg?branch=master)](https://travis-ci.com/smallstep/crypto)
[![codecov](https://codecov.io/gh/smallstep/crypto/branch/master/graph/badge.svg)](https://codecov.io/gh/smallstep/crypto)
[![Documentation](https://godoc.org/go.step.sm/crypto?status.svg)](https://pkg.go.dev/mod/go.step.sm/crypto)

Crypto is a collection of packages used in [smallstep](https://smallstep.com) products. See:

* [step](https://github.com/smallstep/cli): A zero trust swiss army knife for
  working with X509, OAuth, JWT, OATH OTP, etc.
* [step-ca](https://github.com/smallstep/certificates): A private certificate
  authority (X.509 & SSH) & ACME server for secure automated certificate
  management, so you can use TLS everywhere & SSO for SSH.

## Usage

To add this to a project just run:

```sh
go get go.step.sm/crypto
```

## Packages

### x509util

Package `x509util` implements utilities to build X.509 certificates based on JSON
templates.

### sshutil

Package `sshutil` implements utilities to build SSH certificates based on JSON
templates.

### keyutil

Package `keyutil` implements utilities to generate cryptographic keys.

### pemutil

Package `pemutil` implements utilities to parse keys and certificate. It also
includes a method to serialize keys, X.509 certificates and certificate requests
to PEM.

### randutil

Package `randutil` provides methods to generate random strings and salts.

### jose

Package `jose` is a wrapper for `gopkg.in/square/go-jose.v2` and implements
utilities to parse and generate JWT, JWK and JWKSets.
