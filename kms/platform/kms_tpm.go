package platform

import (
	"context"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/tpmkms"
	"go.step.sm/crypto/tpm"
)

var _ apiv1.Attester = (*KMS)(nil)

func newTPMKMS(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	km, err := tpmkms.New(ctx, opts)
	if err != nil {
		return nil, err
	}

	return &KMS{
		backend: km,
	}, nil
}

func NewWithTPM(ctx context.Context, t *tpm.TPM, opts ...tpmkms.Option) (*KMS, error) {
	km, err := tpmkms.NewWithTPM(ctx, t, opts...)
	if err != nil {
		return nil, err
	}

	return &KMS{
		backend: km,
	}, nil
}

func (k *KMS) CreateAttestation(req *apiv1.CreateAttestationRequest) (*apiv1.CreateAttestationResponse, error) {
	if km, ok := k.backend.(apiv1.Attester); ok {
		return km.CreateAttestation(req)
	}

	return nil, apiv1.NotImplementedError{}
}
