package tpm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
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

// MarshalJSON marshals the EK to JSON.
func (ek *EK) MarshalJSON() ([]byte, error) {
	var der []byte
	if ek.certificate != nil {
		der = ek.certificate.Raw
	}
	o := struct {
		Type string `json:"type"`
		DER  []byte `json:"der,omitempty"`
		URL  string `json:"url,omitempty"`
	}{
		Type: ek.Type(),
		DER:  der,
		URL:  ek.certificateURL,
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

type intelEKCertResponse struct {
	Pubhash     string `json:"pubhash"`
	Certificate string `json:"certificate"`
}

// GetEKs returns a slice of TPM EKs. It will return an error
// when interaction with the TPM fails. It will loop through
// the TPM EKs and download the EK certificate if it's available
// online.
func (t *TPM) GetEKs(ctx context.Context) ([]*EK, error) {
	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	eks, err := t.attestTPM.EKs()
	if err != nil {
		return nil, fmt.Errorf("failed getting EKs: %w", err)
	}

	// an arbitrary limit, so that we don't start making a large number of HTTP requests (if needed)
	maxNumberOfEKs := 10
	if len(eks) > maxNumberOfEKs {
		return nil, fmt.Errorf("number of EKs (%d) bigger than the maximum allowed %d", len(eks), maxNumberOfEKs)
	}

	result := make([]*EK, 0, len(eks))
	for _, ek := range eks {
		ekCert := ek.Certificate
		ekURL := ek.CertificateURL
		if ekCert == nil && ekURL != "" {
			var u *url.URL
			u, err = url.Parse(ekURL)
			if err != nil {
				return nil, fmt.Errorf("error parsing EK certificate URL %q: %w", ekURL, err)
			}

			// Ensure the URL is in the right format; for Intel TPMs, the path
			// parameter contains the base64 encoding of the hash of the public key,
			// potentially containing padding characters, which will results in a 403,
			// if not transformed to `%3D`. The below has currently only be tested for
			// Intel TPMs, which connect to https://ekop.intel.com/ekcertservice. It may
			// be different for other URLs. Ideally, I think this should be fixed in
			// the underlying TPM library to contain the right URL? The `intelEKURL` already
			// seems to do URLEncoding, though. Why do we still get an `=` then?
			// TODO: do this just for Intel URLs; and check for other TPM manufacturer URLs
			s := u.String()
			h := path.Base(s)
			h = strings.ReplaceAll(h, "=", "%3D") // TODO(hs): no better function in Go to do this in paths? https://github.com/golang/go/issues/27559;
			s = s[:strings.LastIndex(s, "/")+1] + h

			u, err = url.Parse(s)
			if err != nil {
				return nil, fmt.Errorf("error parsing reconstructed EK certificate URL: %w", err)
			}

			var r *http.Response
			ekURL = u.String()
			r, err = http.Get(ekURL) //nolint:gosec // URL originally comes from TPM. In the end it's user supplied, but not trivial to abuse
			if err != nil {
				return nil, fmt.Errorf("error retrieving EK certificate from %q: %w", ekURL, err)
			}
			defer r.Body.Close() //nolint:gocritic // number of requests is limited, so resource leak is limited

			if r.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("http request to %q failed with status %d", ekURL, r.StatusCode)
			}

			var c intelEKCertResponse
			if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
				return nil, fmt.Errorf("error decoding EK certificate response: %w", err)
			}

			cb, err := base64.URLEncoding.DecodeString(c.Certificate)
			if err != nil {
				return nil, fmt.Errorf("error base64 decoding EK certificate response: %w", err)
			}

			ekCert, err = attest.ParseEKCertificate(cb)
			if err != nil {
				return nil, fmt.Errorf("error parsing EK certificate: %w", err)
			}
		}

		result = append(result, &EK{
			public:         ek.Public,
			certificate:    ekCert,
			certificateURL: ekURL,
		})
	}

	return result, nil
}
