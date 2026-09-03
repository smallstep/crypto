//go:build !go1.27

package awskms

import "go.step.sm/crypto/kms/apiv1"

func patchSignatureAlgorithmMapping(m map[apiv1.SignatureAlgorithm]any) map[apiv1.SignatureAlgorithm]any {
	return m
}
