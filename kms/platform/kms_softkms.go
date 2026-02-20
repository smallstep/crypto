package platform

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/softkms"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/pemutil"
)

func newSoftKMS(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	km, err := softkms.New(ctx, opts)
	if err != nil {
		return nil, err
	}

	return &KMS{
		typ:              apiv1.SoftKMS,
		backend:          &softKMS{SoftKMS: km},
		transformToURI:   transformToSoftKMS,
		transformFromURI: transformFromSoftKMS,
	}, nil
}

type softKMS struct {
	*softkms.SoftKMS
}

func (k *softKMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	name := filename(req.Name)
	if name == "" {
		return nil, fmt.Errorf("createKeyRequest 'name' cannot be empty")
	}

	resp, err := k.SoftKMS.CreateKey(req)
	if err != nil {
		return nil, err
	}

	if _, err := pemutil.Serialize(resp.PrivateKey, pemutil.ToFile(name, 0o600)); err != nil {
		return nil, err
	}

	return resp, nil
}

func (k *softKMS) DeleteKey(req *apiv1.DeleteKeyRequest) error {
	name := filename(req.Name)
	if name == "" {
		return fmt.Errorf("deleteKeyRequest 'name' cannot be empty")
	}

	return os.Remove(name)
}

func (k *softKMS) StoreCertificate(req *apiv1.StoreCertificateRequest) error {
	name := filename(req.Name)
	switch {
	case name == "":
		return fmt.Errorf("storeCertificateRequest 'name' cannot be empty")
	case req.Certificate == nil:
		return fmt.Errorf("storeCertificateRequest 'certificate' cannot be empty")
	}

	return os.WriteFile(name, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: req.Certificate.Raw,
	}), 0o600)
}

func (k *softKMS) StoreCertificateChain(req *apiv1.StoreCertificateChainRequest) error {
	name := filename(req.Name)
	switch {
	case name == "":
		return fmt.Errorf("storeCertificateChainRequest 'name' cannot be empty")
	case len(req.CertificateChain) == 0:
		return fmt.Errorf("storeCertificateChainRequest 'certificateChain' cannot be empty")
	}

	var buf bytes.Buffer
	for _, crt := range req.CertificateChain {
		if err := pem.Encode(&buf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: crt.Raw,
		}); err != nil {
			return err
		}
	}

	return os.WriteFile(name, buf.Bytes(), 0o600)
}

func (k *softKMS) DeleteCertificate(req *apiv1.DeleteCertificateRequest) error {
	name := filename(req.Name)
	if name == "" {
		return fmt.Errorf("deleteCertificateRequest 'name' cannot be empty")
	}

	return os.Remove(name)
}

func filename(s string) string {
	if u, err := uri.ParseWithScheme(softkms.Scheme, s); err == nil {
		if f := u.Get("path"); f != "" {
			return f
		}
		switch {
		case u.Path != "":
			return u.Path
		default:
			return u.Opaque
		}
	}
	return s
}

func transformToSoftKMS(u *kmsURI) string {
	if u.name != "" {
		return uri.NewOpaque(softkms.Scheme, u.name).String()
	}
	return uri.NewOpaque(softkms.Scheme, u.uri.Path).String()
}

func transformFromSoftKMS(rawuri string) (string, error) {
	return uri.New(Scheme, url.Values{
		"name": []string{rawuri},
	}).String(), nil
}
