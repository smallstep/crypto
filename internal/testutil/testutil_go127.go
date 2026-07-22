//go:build go1.27

package testutil

import "crypto/x509"

// clearRawSignatureAlgorithm zeroes the RawSignatureAlgorithm field, which was
// added to x509.CertificateRequest in a Go 1.27. Reflection is used so the tests
// keep compiling against Go versions that don't have the field yet.
func clearRawSignatureAlgorithm(csr *x509.CertificateRequest) {
	csr.RawSignatureAlgorithm = nil
}
