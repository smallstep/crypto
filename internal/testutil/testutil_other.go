//go:build !go1.27

package testutil

import "crypto/x509"

func clearRawSignatureAlgorithm(*x509.CertificateRequest) {}
