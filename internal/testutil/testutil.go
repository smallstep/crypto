package testutil

import (
	"crypto/x509"
)

// ClearRawSignatureAlgorithmFromCSR zeroes the RawSignatureAlgorithm field, which was
// added to x509.CertificateRequest in a Go 1.27. On older go versions, it's a
// no-op.
func ClearRawSignatureAlgorithmFromCSR(csr *x509.CertificateRequest) {
	clearRawSignatureAlgorithm(csr)
}
