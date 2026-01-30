package platform

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
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
		backend:      &softKMS{SoftKMS: km},
		transformURI: transformToSoftKMS,
	}, nil
}

type softKMS struct {
	*softkms.SoftKMS
}

func (k *softKMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	resp, err := k.SoftKMS.CreateKey(req)
	if err != nil {
		return nil, err
	}

	if _, err := pemutil.Serialize(resp.PrivateKey, pemutil.ToFile(resp.Name, 0o600)); err != nil {
		return nil, err
	}

	return resp, nil
}

func (k *softKMS) DeleteKey(req *apiv1.DeleteKeyRequest) error {
	if req.Name == "" {
		return fmt.Errorf("deleteKeyRequest 'name' cannot be empty")
	}

	return os.Remove(filename(req.Name))
}

func (k *softKMS) StoreCertificate(req *apiv1.StoreCertificateRequest) error {
	switch {
	case req.Name == "":
		return fmt.Errorf("storeCertificateRequest 'name' cannot be empty")
	case req.Certificate == nil:
		return fmt.Errorf("storeCertificateRequest 'certificate' cannot be empty")
	}

	return os.WriteFile(filename(req.Name), pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: req.Certificate.Raw,
	}), 0o600)
}

func (k *softKMS) StoreCertificateChain(req *apiv1.StoreCertificateChainRequest) error {
	switch {
	case req.Name == "":
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

	return os.WriteFile(filename(req.Name), buf.Bytes(), 0o600)
}

func (k *softKMS) DeleteCertificate(req *apiv1.DeleteCertificateRequest) error {
	if req.Name == "" {
		return fmt.Errorf("deleteCertificateRequest 'name' cannot be empty")
	}

	return os.Remove(filename(req.Name))
}

func filename(s string) string {
	if u, err := uri.ParseWithScheme(Scheme, s); err == nil {
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
	return uri.NewOpaque(softkms.Scheme, u.name).String()
}
