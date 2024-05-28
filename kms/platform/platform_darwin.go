package platform

import (
	"context"
	"fmt"
	"net/url"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/mackms"
	"go.step.sm/crypto/kms/uri"
)

func newKMS(ctx context.Context, _ apiv1.Options) (*KMS, error) {
	k, err := mackms.New(ctx, apiv1.Options{})
	if err != nil {
		return nil, fmt.Errorf("error initializing mackms: %w", err)
	}
	return &KMS{
		backend:       k,
		defaultSigAlg: apiv1.ECDSAWithSHA256,
		defaultBits:   0,
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
	v := url.Values{
		"label": []string{name},
	}
	if u.GetBool("ak") {
		v.Set("se", "true")
	}
	return uri.New(mackms.Scheme, v).String(), nil
}
