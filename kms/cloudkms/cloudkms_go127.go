//go:build go1.27 && !nocloudkms

package cloudkms

import (
	"crypto/x509"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"go.step.sm/crypto/kms/apiv1"
)

func patchSignatureAlgorithmMapping(m map[apiv1.SignatureAlgorithm]interface{}) map[apiv1.SignatureAlgorithm]interface{} {
	m[apiv1.MLDSA44] = kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44
	m[apiv1.MLDSA65] = kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65
	m[apiv1.MLDSA87] = kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87
	return m
}

func patchCryptoKeyVersionMapping(m map[kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm]x509.SignatureAlgorithm) map[kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm]x509.SignatureAlgorithm {
	m[kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44] = x509.MLDSA44
	m[kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65] = x509.MLDSA65
	m[kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87] = x509.MLDSA87
	return m
}
