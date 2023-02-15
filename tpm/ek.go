package tpm

import (
	"bytes"
	"context"
	"crypto"
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

type EK struct {
	Public         crypto.PublicKey
	Certificate    *x509.Certificate
	CertificateURL string
}

func (ek EK) MarshalJSON() ([]byte, error) {
	type out struct {
		Type string `json:"type"`
		PEM  string `json:"pem,omitempty"`
		URL  string `json:"url,omitempty"`
	}
	var pemString string
	var err error
	if ek.Certificate != nil {
		if pemString, err = ek.PEM(); err != nil {
			return nil, err
		}
	}
	o := out{
		Type: fmt.Sprintf("%T", ek.Public), // TODO: proper description string; on EK struct
		PEM:  pemString,
		URL:  ek.CertificateURL,
	}
	return json.Marshal(o)
}

func (ek EK) PEM() (string, error) {
	if ek.Certificate == nil {
		return "", fmt.Errorf("EK %T does not have a certificate", ek) // TODO: proper string for the type of EK
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ek.Certificate.Raw,
	}); err != nil {
		return "", fmt.Errorf("failed encoding EK certificate to PEM: %w", err)
	}

	return buf.String(), nil
}

type intelEKCertResponse struct {
	Pubhash     string `json:"pubhash"`
	Certificate string `json:"certificate"`
}

func (t *TPM) GetEKs(ctx context.Context) ([]EK, error) {
	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	at, err := attest.OpenTPM(t.attestConfig)
	if err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer at.Close()

	eks, err := at.EKs()
	if err != nil {
		return nil, fmt.Errorf("failed getting EKs: %w", err)
	}

	// an arbitrary limit, so that we don't start making a huge number of HTTP requests (if needed)
	maxNumberOfEKs := 10
	if len(eks) > maxNumberOfEKs {
		return nil, fmt.Errorf("number of EKs (%d) bigger than the maximum allowed %d", len(eks), maxNumberOfEKs)
	}

	result := make([]EK, 0, len(eks))
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

		result = append(result, EK{
			Public:         ek.Public,
			Certificate:    ekCert,
			CertificateURL: ekURL,
		})
	}

	return result, nil
}
