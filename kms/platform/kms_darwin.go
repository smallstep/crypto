package platform

import (
	"context"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/mackms"
)

var _ apiv1.SearchableKeyManager = (*KMS)(nil)

func newKMS(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	if opts.Type == apiv1.TPMKMS {
		return newTPMKMS(ctx, opts)
	}

	km, err := mackms.New(ctx, opts)
	if err != nil {
		return nil, err
	}

	return &KMS{
		backend: km,
	}, nil
}

func (k *KMS) SearchKeys(req *apiv1.SearchKeysRequest) (*apiv1.SearchKeysResponse, error) {
	if km, ok := k.backend.(apiv1.SearchableKeyManager); ok {
		return km.SearchKeys(req)
	}

	return nil, apiv1.NotImplementedError{}
}
