package platform

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"syscall"

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
	if req.Name == "" {
		return nil, fmt.Errorf("createKeyRequest 'name' cannot be empty")
	}

	resp, err := k.SoftKMS.CreateKey(req)
	if err != nil {
		return nil, err
	}

	if _, err := pemutil.Serialize(resp.PrivateKey, pemutil.ToFile(req.Name, 0o600)); err != nil {
		return nil, err
	}

	return resp, nil
}

func (k *softKMS) DeleteKey(req *apiv1.DeleteKeyRequest) error {
	if req.Name == "" {
		return fmt.Errorf("deleteKeyRequest 'name' cannot be empty")
	}

	if err := os.Remove(req.Name); err != nil {
		return toKMSError(err, "key not found")
	}

	return nil
}

func (k *softKMS) StoreCertificate(req *apiv1.StoreCertificateRequest) error {
	switch {
	case req.Name == "":
		return fmt.Errorf("storeCertificateRequest 'name' cannot be empty")
	case req.Certificate == nil:
		return fmt.Errorf("storeCertificateRequest 'certificate' cannot be empty")
	}

	return os.WriteFile(req.Name, pem.EncodeToMemory(&pem.Block{
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

	return os.WriteFile(req.Name, buf.Bytes(), 0o600)
}

func (k *softKMS) DeleteCertificate(req *apiv1.DeleteCertificateRequest) error {
	if req.Name == "" {
		return fmt.Errorf("deleteCertificateRequest 'name' cannot be empty")
	}

	if err := os.Remove(req.Name); err != nil {
		return toKMSError(err, "certificate not found")
	}

	return nil
}

func transformToSoftKMS(rawuri string) (string, error) {
	u, err := parseURI(rawuri)
	if err != nil {
		return "", err
	}

	if u.hw {
		return "", fmt.Errorf("error parsing uri: hw is not supported")
	}

	switch {
	case u.uri.Has("name"):
		return u.name, nil
	case u.uri.Has("path"):
		return u.uri.Get("path"), nil
	case u.uri.Path != "":
		return u.uri.Path, nil
	case u.uri.Opaque != "":
		return u.uri.Opaque, nil
	default:
		return "", nil
	}
}

func transformFromSoftKMS(path string) (string, error) {
	uv := url.Values{}
	if path != "" {
		uv.Set(nameKey, path)
	}
	return uri.New(Scheme, uv).String(), nil
}

func toKMSError(err error, message string) error {
	switch {
	case errors.Is(err, os.ErrNotExist), errors.Is(err, syscall.ENOENT):
		return apiv1.NotFoundError{
			Message: message,
		}
	default:
		return err
	}
}
