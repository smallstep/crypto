# crypto

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/smallstep/crypto)](https://goreportcard.com/report/github.com/smallstep/crypto)
[![CI](https://github.com/smallstep/crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/smallstep/crypto/actions/workflows/ci.yml)
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

Package `pemutil` implements utilities to parse keys and certificates. It also
includes a method to serialize keys, X.509 certificates and certificate requests
to PEM.

### randutil

Package `randutil` provides methods to generate random strings and salts.

### tlsutil

Package `tlsutil` provides utilities to configure tls client and servers.

### jose

Package `jose` is a wrapper for `github.com/go-jose/go-jose/v3` and implements
utilities to parse and generate JWT, JWK and JWKSets.

### x25519

Package `x25519` adds support for X25519 keys and the
[XEdDSA](https://signal.org/docs/specifications/xeddsa/) signature scheme.

### minica

Package `minica` implements a simple certificate authority.

### kms

Package `kms` implements interfaces to perform cryptographic operations like
signing certificates using cloud-based key management systems, PKCS #11 modules,
or just a YubiKey or an ssh-agent. On the cloud it supports:

* [Amazon AWS KMS](https://aws.amazon.com/kms/)
* [Google Cloud Key Management](https://cloud.google.com/security-key-management)
* [Microsoft Azure Key Vault](https://azure.microsoft.com/en-us/services/key-vault/)

### fingerprint

Package `fingerprint` provides methods for creating and encoding X.509
certificate, SSH certificate and SSH key fingerprints.

### tpm

Package `tpm` provides an abstraction over and utilities for interacting
with TPMs. It can be used to retrieve TPM information, retrieve its Endorsement
Keys (EK) and associated certifiates, create and operate on Attestation Keys (AK), 
and create and operate on (attested) application keys. The `storage` subpackage 
provides an interface and concrete implementations offering a transparent 
persistence mechanism for Attestation and application keys.