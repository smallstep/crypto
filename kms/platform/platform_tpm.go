//go:build linux || windows

package platform

import (
	"context"
	"fmt"
	"strings"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/tpmkms"
	"go.step.sm/crypto/kms/uri"
)

func newKMS(ctx context.Context, o apiv1.Options) (*KMS, error) {
	k, err := tpmkms.New(ctx, apiv1.Options{
		Type:             o.Type,
		URI:              strings.Replace(o.URI, "kms:", "tpmkms:", 1),
		StorageDirectory: o.StorageDirectory,
	})
	if err != nil {
		return nil, fmt.Errorf("error initializing tpmkms: %w", err)
	}
	// On TPMs the real signature algorithm will be determined at sign time,
	// we only need to define one that will create an RSA key.
	return &KMS{
		backend:       k,
		defaultSigAlg: apiv1.SHA256WithRSA,
		defaultBits:   2048,
	}, nil
}

func createURI(rawuri string) (string, error) {
	u, err := uri.ParseWithScheme(Scheme, rawuri)
	if err != nil {
		return "", err
	}
	var name string
	if name = u.Get("name"); name == "" {
		return "", fmt.Errorf("error parsing %q: name is required", rawuri)
	}
	return uri.New(tpmkms.Scheme, u.Values).String(), nil
}
