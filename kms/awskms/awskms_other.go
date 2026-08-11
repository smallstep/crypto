//go:build !go1.27

package awskms

import "go.step.sm/crypto/kms/apiv1"

func patchSignatureAlgorithmMapping(m map[apiv1.SignatureAlgorithm]interface{}) map[apiv1.SignatureAlgorithm]interface{} {
	return m
}
