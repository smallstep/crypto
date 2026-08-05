//go:build !go1.27 && !nocloudkms

package cloudkms

import (
	"crypto/x509"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"go.step.sm/crypto/kms/apiv1"
)

func patchSignatureAlgorithmMapping(m map[apiv1.SignatureAlgorithm]interface{}) map[apiv1.SignatureAlgorithm]interface{} {
	return m
}

func patchCryptoKeyVersionMapping(m map[kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm]x509.SignatureAlgorithm) map[kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm]x509.SignatureAlgorithm {
	return m
}
