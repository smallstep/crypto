//go:build go1.27

package awskms

import (
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"go.step.sm/crypto/kms/apiv1"
)

func patchSignatureAlgorithmMapping(m map[apiv1.SignatureAlgorithm]interface{}) map[apiv1.SignatureAlgorithm]interface{} {
	m[apiv1.MLDSA44] = types.KeySpecMlDsa44
	m[apiv1.MLDSA65] = types.KeySpecMlDsa65
	m[apiv1.MLDSA87] = types.KeySpecMlDsa87
	return m
}
