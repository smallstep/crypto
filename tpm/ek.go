package tpm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/google/go-attestation/attest"
)

// EK models a TPM Endorsement Key. The EK can be used to
// identify a specific TPM. The EK is certified by a TPM
// manufacturer.
type EK struct {
	public         crypto.PublicKey
	certificate    *x509.Certificate
	certificateURL string
}

// Public returns the EK public key.
func (ek *EK) Public() crypto.PublicKey {
	return ek.public
}

// Certificate returns the EK certificate. This
// can return nil.
func (ek *EK) Certificate() *x509.Certificate {
	return ek.certificate
}

// CertificateURL returns the URL from which the EK
// certificate can be retrieved. Not all EKs have a
// certificate URL.
func (ek *EK) CertificateURL() string {
	return ek.certificateURL
}

// Fingerprint returns the EK public key fingerprint.
// The fingerprint is the base64 encoded SHA256 of
// the EK public key.
func (ek *EK) Fingerprint() (string, error) {
	fp, err := generateKeyID(ek.public)
	if err != nil {
		return "", fmt.Errorf("failed generating EK public key ID: %w", err)
	}
	return "sha256:" + base64.StdEncoding.EncodeToString(fp), nil
}

func generateKeyID(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("error marshaling public key: %w", err)
	}
	hash := sha256.Sum256(b)
	return hash[:], nil
}

// MarshalJSON marshals the EK to JSON.
func (ek *EK) MarshalJSON() ([]byte, error) {
	var der []byte
	if ek.certificate != nil {
		der = ek.certificate.Raw
	}
	fp, err := ek.Fingerprint()
	if err != nil {
		return nil, fmt.Errorf("failed getting EK fingerprint: %w", err)
	}
	o := struct {
		Type        string `json:"type"`
		Fingerprint string `json:"fingerprint"`
		DER         []byte `json:"der,omitempty"`
		URL         string `json:"url,omitempty"`
	}{
		Type:        ek.Type(),
		Fingerprint: fp,
		DER:         der,
		URL:         ek.certificateURL,
	}
	return json.Marshal(o)
}

// PEM returns the EK certificate as a PEM
// formatted string. It returns an error if
// the EK doesn't have a certificate.
func (ek *EK) PEM() (string, error) {
	if ek.certificate == nil {
		return "", fmt.Errorf("EK %q does not have a certificate", ek.Type())
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ek.certificate.Raw,
	}); err != nil {
		return "", fmt.Errorf("failed encoding EK certificate to PEM: %w", err)
	}

	return buf.String(), nil
}

// Type returns the EK public key type description.
func (ek *EK) Type() string {
	return keyType(ek.public)
}

func keyType(p crypto.PublicKey) string {
	switch t := p.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", t.Size()*8)
	case *ecdsa.PublicKey:
		switch size := t.Curve.Params().BitSize; size {
		case 256, 384, 521:
			return fmt.Sprintf("ECDSA P-%d", size)
		default:
			return fmt.Sprintf("unexpected ECDSA size: %d", size)
		}
	default:
		return fmt.Sprintf("unsupported public key type: %T", p)
	}
}

// GetEKs returns a slice of TPM EKs. It will return an error
// when interaction with the TPM fails. It will loop through
// the TPM EKs and download the EK certificate if it's available
// online. The TPM EKs don't change after the first lookup, so
// the result is cached for future lookups.
func (t *TPM) GetEKs(ctx context.Context) ([]*EK, error) {
	if len(t.eks) == 0 {
		if err := t.Open(ctx); err != nil {
			return nil, fmt.Errorf("failed opening TPM: %w", err)
		}
		defer t.Close(ctx)

		eks, err := t.attestTPM.EKs()
		if err != nil {
			return nil, fmt.Errorf("failed getting EKs: %w", err)
		}

		// an arbitrary limit, so that we don't start making a large number of HTTP requests (if needed)
		if len(eks) > t.downloader.maxDownloads {
			return nil, fmt.Errorf("number of EKs (%d) bigger than the maximum allowed number (%d) of downloads", len(eks), t.downloader.maxDownloads)
		}

		result := make([]*EK, 0, len(eks))
		for _, ek := range eks {
			ekCert := ek.Certificate
			ekURL := ek.CertificateURL
			// TODO(hs): handle case for which ekURL is empty, but TPM is from a manufacturer
			// that hosts EK certificates online.
			if ekCert == nil && ekURL != "" {
				u, err := t.prepareEKCertifiateURL(ctx, ekURL)
				if err != nil {
					return nil, fmt.Errorf("failed preparing EK certificate URL: %w", err)
				}
				ekURL = u.String()
				ekCert, err = t.downloadEKCertifiate(ctx, u)
				if err != nil {
					return nil, fmt.Errorf("failed downloading EK certificate: %w", err)
				}
			}

			result = append(result, &EK{
				public:         ek.Public,
				certificate:    ekCert,
				certificateURL: ekURL,
			})
		}

		// cache the result
		t.eks = result
	}

	// return the cached EKs
	return t.eks, nil
}

func (t *TPM) prepareEKCertifiateURL(ctx context.Context, ekURL string) (*url.URL, error) {
	var u *url.URL
	var err error
	u, err = url.Parse(ekURL)
	if err != nil {
		return nil, fmt.Errorf("failed parsing EK certificate URL %q: %w", ekURL, err)
	}

	info, err := t.Info(internalCall(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed getting TPM info: %w", err)
	}

	if info.Manufacturer.ASCII == "INTC" {
		// Ensure the URL is in the right format; for Intel TPMs, the path
		// parameter contains the base64 encoding of the hash of the public key,
		// potentially containing padding characters, which will results in a 403,
		// if not transformed to `%3D`. The below has currently only be tested for
		// Intel TPMs, which connect to https://ekop.intel.com/ekcertservice. It may
		// be different for other TPM manufacturers. Ideally, I think this should be fixed in
		// the underlying TPM library to contain the right URL? The `intelEKURL` already
		// seems to do URLEncoding, though.
		// TODO: do this just for Intel URLs; and check for other TPM manufacturer URLs
		s := u.String()
		h := path.Base(s)
		h = strings.ReplaceAll(h, "=", "%3D") // TODO(hs): no better function in Go to do this in paths? https://github.com/golang/go/issues/27559;
		s = s[:strings.LastIndex(s, "/")+1] + h

		u, err = url.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("failed parsing EK certificate URL %q: %w", s, err)
		}
	}

	return u, nil
}

func (t *TPM) downloadEKCertifiate(ctx context.Context, ekURL *url.URL) (*x509.Certificate, error) {
	return t.downloader.downloadEKCertifiate(ctx, ekURL)
}

type intelEKCertResponse struct {
	Pubhash     string `json:"pubhash"`
	Certificate string `json:"certificate"`
}

type downloader struct {
	enabled      bool
	maxDownloads int
}

func (d *downloader) downloadEKCertifiate(ctx context.Context, ekURL *url.URL) (*x509.Certificate, error) {
	if !d.enabled {
		// if downloads are disabled, don't try to download at all
		return nil, nil //nolint:nilnil // a nill *x509.Certificate is valid
	}

	r, err := http.Get(ekURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed retrieving EK certificate from %q: %w", ekURL, err)
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http request to %q failed with status %d", ekURL, r.StatusCode)
	}

	var c intelEKCertResponse // TODO(hs): handle different manufacturers
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		return nil, fmt.Errorf("failed decoding EK certificate response: %w", err)
	}

	cb, err := base64.RawURLEncoding.DecodeString(strings.ReplaceAll(c.Certificate, "%3D", "")) // strip padding; decode raw // TODO(hs): this is for Intel; might be different for others
	if err != nil {
		return nil, fmt.Errorf("failed base64 decoding EK certificate response: %w", err)
	}

	ekCert, err := attest.ParseEKCertificate(cb)
	if err != nil {
		return nil, fmt.Errorf("failed parsing EK certificate: %w", err)
	}

	return ekCert, nil
}
