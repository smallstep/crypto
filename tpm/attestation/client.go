package attestation

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/smallstep/go-attestation/attest"
	"go.step.sm/crypto/tpm"
)

type Client struct {
	client  http.Client
	baseURL *url.URL
}

type Options struct {
	rootCAs  *x509.CertPool
	insecure bool
}

type Option func(o *Options) error

// WithRootsFile can be used to set the trusted roots when
// setting up a TLS connection.
func WithRootsFile(filename string) Option {
	return func(o *Options) error {
		if filename == "" {
			return nil
		}
		data, err := os.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("failed reading %q: %w", filename, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return fmt.Errorf("failed parsing %q: no certificates found", filename)
		}
		o.rootCAs = pool
		return nil
	}
}

// WithInsecure disables TLS server certificate chain checking.
// In general this shouldn't be used, but it can be of use in
// during development and testing.
func WithInsecure() Option {
	return func(o *Options) error {
		o.insecure = true
		return nil
	}
}

// NewClient creates a new Client that can be used to perform remote
// attestation.
func NewClient(tpmAttestationCABaseURL string, options ...Option) (*Client, error) {
	u, err := url.Parse(tpmAttestationCABaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed parsing attestation CA base URL: %w", err)
	}

	opts := &Options{}
	for _, o := range options {
		if err := o(opts); err != nil {
			return nil, fmt.Errorf("failed applying option to attestation client: %w", err)
		}
	}

	client := http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				RootCAs:            opts.rootCAs,
				InsecureSkipVerify: opts.insecure, //nolint:gosec // intentional insecure if provided as option
			},
		},
	}

	return &Client{
		client:  client,
		baseURL: u,
	}, nil
}

// Attest performs remote attestation using the AK backed by TPM t.
//
// TODO: support multiple EKs again? Currently selection of the EK is left
// to the caller.
func (ac *Client) Attest(ctx context.Context, t *tpm.TPM, ek *tpm.EK, ak *tpm.AK) ([]*x509.Certificate, error) {
	// TODO(hs): what about performing attestation for an existing AK identifier and/or cert, but
	// with a different Attestation CA? It seems sensible to enroll with that other Attestation CA,
	// but it needs capturing some knowledge about the Attestation CA with the AK (cert). Possible to
	// derive that from the intermediate and/or root CA and/or fingerprint, somehow? Or the attestation URI?

	info, err := t.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving info from TPM: %w", err)
	}

	attestParams, err := ak.AttestationParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed getting AK attestation parameters: %w", err)
	}

	attResp, err := ac.attest(ctx, info, ek, attestParams)
	if err != nil {
		return nil, fmt.Errorf("failed attesting AK: %w", err)
	}

	encryptedCredentials := tpm.EncryptedCredential{
		Credential: attResp.Credential,
		Secret:     attResp.Secret,
	}

	// activate the credential with the TPM
	secret, err := ak.ActivateCredential(ctx, encryptedCredentials)
	if err != nil {
		return nil, fmt.Errorf("failed activating credential: %w", err)
	}

	secretResp, err := ac.secret(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("failed validating secret: %w", err)
	}

	akChain := make([]*x509.Certificate, len(secretResp.CertificateChain))
	for i, certBytes := range secretResp.CertificateChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("failed parsing certificate: %w", err)
		}
		akChain[i] = cert
	}

	return akChain, nil
}

type tpmInfo struct {
	Version         attest.TPMVersion `json:"version,omitempty"`
	Manufacturer    string            `json:"manufacturer,omitempty"`
	Model           string            `json:"model,omitempty"`
	FirmwareVersion string            `json:"firmwareVersion,omitempty"`
}

type attestationParameters struct {
	Public                  []byte `json:"public,omitempty"`
	UseTCSDActivationFormat bool   `json:"useTCSDActivationFormat,omitempty"`
	CreateData              []byte `json:"createData,omitempty"`
	CreateAttestation       []byte `json:"createAttestation,omitempty"`
	CreateSignature         []byte `json:"createSignature,omitempty"`
}

type attestationRequest struct {
	TPMInfo      tpmInfo               `json:"tpmInfo"`
	EKPub        []byte                `json:"ek,omitempty"`
	EKCerts      [][]byte              `json:"ekCerts,omitempty"`
	AKCert       []byte                `json:"akCert,omitempty"`
	AttestParams attestationParameters `json:"params"`
}

type attestationResponse struct {
	Credential []byte `json:"credential"`
	Secret     []byte `json:"secret"` // encrypted secret
}

// attest performs the HTTP POST request to the `/attest` endpoint of the
// Attestation CA.
func (ac *Client) attest(ctx context.Context, info *tpm.Info, ek *tpm.EK, attestParams attest.AttestationParameters) (*attestationResponse, error) {
	var ekCerts [][]byte
	var ekPub []byte
	var err error

	// TODO: support multiple EKs again? Currently selection of the EK is left
	// to the caller.
	if ekCert := ek.Certificate(); ekCert != nil {
		ekCerts = append(ekCerts, ekCert.Raw)
	}
	if ekPub, err = x509.MarshalPKIXPublicKey(ek.Public()); err != nil {
		return nil, fmt.Errorf("failed marshaling public key: %w", err)
	}

	ar := attestationRequest{
		TPMInfo: tpmInfo{
			Version:         attest.TPMVersion20,
			Manufacturer:    strconv.FormatUint(uint64(info.Manufacturer.ID), 10),
			Model:           info.VendorInfo,
			FirmwareVersion: info.FirmwareVersion.String(),
		},
		EKCerts: ekCerts,
		EKPub:   ekPub,
		AttestParams: attestationParameters{
			Public:                  attestParams.Public,
			UseTCSDActivationFormat: attestParams.UseTCSDActivationFormat,
			CreateData:              attestParams.CreateData,
			CreateAttestation:       attestParams.CreateAttestation,
			CreateSignature:         attestParams.CreateSignature,
		},
	}

	body, err := json.Marshal(ar)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling attestation request: %w", err)
	}

	attestURL := ac.baseURL.JoinPath("attest").String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, attestURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed creating POST http request for %q: %w", attestURL, err)
	}

	resp, err := ac.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed performing attestation request with Attestation CA %q: %w", attestURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST %q failed with HTTP status %q", attestURL, resp.Status)
	}

	var attResp attestationResponse
	if err := json.NewDecoder(resp.Body).Decode(&attResp); err != nil {
		return nil, fmt.Errorf("failed decoding attestation response: %w", err)
	}

	return &attResp, nil
}

type secretRequest struct {
	Secret []byte `json:"secret"` // decrypted secret
}

type secretResponse struct {
	CertificateChain [][]byte `json:"chain"`
}

// secret performs the HTTP POST request to the `/secret` endpoint of the
// Attestation CA.
func (ac *Client) secret(ctx context.Context, secret []byte) (*secretResponse, error) {
	sr := secretRequest{
		Secret: secret,
	}

	body, err := json.Marshal(sr)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling secret request: %w", err)
	}

	secretURL := ac.baseURL.JoinPath("secret").String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, secretURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed creating POST http request for %q: %w", secretURL, err)
	}

	resp, err := ac.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed performing secret request with attestation CA %q: %w", secretURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST %q failed with HTTP status %q", secretURL, resp.Status)
	}

	var secretResp secretResponse
	if err := json.NewDecoder(resp.Body).Decode(&secretResp); err != nil {
		return nil, fmt.Errorf("failed decoding secret response: %w", err)
	}

	return &secretResp, nil
}
