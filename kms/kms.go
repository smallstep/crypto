package kms

import (
	"context"

	"github.com/pkg/errors"
	"go.step.sm/crypto/kms/apiv1"

	// Enable default implementation
	"go.step.sm/crypto/kms/softkms"
)

// KeyManager is the interface implemented by all the KMS.
type KeyManager = apiv1.KeyManager

// CertificateManager is the interface implemented by the KMS that can load and
// store x509.Certificates.
type CertificateManager = apiv1.CertificateManager

// Options are the KMS options. They represent the kms object in the ca.json.
type Options = apiv1.Options

// Type represents the KMS type used.
type Type = apiv1.Type

// Default is the implementation of the default KMS.
var Default = &softkms.SoftKMS{}

// New initializes a new KMS from the given type.
func New(ctx context.Context, opts apiv1.Options) (KeyManager, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	typ, err := opts.GetType()
	if err != nil {
		return nil, err
	}
	fn, ok := apiv1.LoadKeyManagerNewFunc(typ)
	if !ok {
		return nil, errors.Errorf("unsupported kms type '%s'", typ)
	}
	return fn(ctx, opts)
}
