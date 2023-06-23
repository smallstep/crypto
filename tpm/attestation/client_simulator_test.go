//go:build tpmsimulator
// +build tpmsimulator

package attestation

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/go-attestation/attest"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/simulator"
	"go.step.sm/crypto/tpm/storage"
)

func newSimulatedTPM(t *testing.T) *tpm.TPM {
	t.Helper()
	tmpDir := t.TempDir()
	instance, err := tpm.New(withSimulator(t), tpm.WithStore(storage.NewDirstore(tmpDir)))
	require.NoError(t, err)
	return instance
}

func withSimulator(t *testing.T) tpm.NewTPMOption {
	t.Helper()
	var sim simulator.Simulator
	t.Cleanup(func() {
		if sim == nil {
			return
		}
		err := sim.Close()
		require.NoError(t, err)
	})
	sim, err := simulator.New()
	require.NoError(t, err)
	err = sim.Open()
	require.NoError(t, err)
	return tpm.WithSimulator(sim)
}

// getPreferredEK returns the first RSA TPM EK found. If no RSA
// EK exists, it returns the first ECDSA EK found.
func getPreferredEK(eks []*tpm.EK) (ek *tpm.EK) {
	var fallback *tpm.EK
	for _, ek = range eks {
		if _, isRSA := ek.Public().(*rsa.PublicKey); isRSA {
			return
		}
		if fallback == nil {
			fallback = ek
		}
	}
	return fallback
}

func mustParseURL(t *testing.T, urlString string) *url.URL {
	t.Helper()
	u, err := url.Parse(urlString)
	require.NoError(t, err)
	return u
}

func TestClient_Attest(t *testing.T) {
	ctx := context.Background()
	instance := newSimulatedTPM(t)
	ak, err := instance.CreateAK(ctx, "ak1")
	require.NoError(t, err)
	require.NoError(t, err)
	eks, err := instance.GetEKs(ctx)
	require.NoError(t, err)
	ek := getPreferredEK(eks)
	ca, err := minica.New(
		minica.WithGetSignerFunc(
			func() (crypto.Signer, error) {
				return keyutil.GenerateSigner("RSA", "", 2048)
			},
		),
	)
	require.NoError(t, err)
	akPub := ak.Public()
	require.Implements(t, (*crypto.PublicKey)(nil), akPub)
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "testak",
		},
		PublicKey: akPub,
	}
	validAKCert, err := ca.Sign(template)
	require.NoError(t, err)
	require.NotNil(t, validAKCert)
	type fields struct {
		client  *http.Client
		baseURL *url.URL
	}
	type args struct {
		ctx context.Context
		t   *tpm.TPM
		ek  *tpm.EK
		ak  *tpm.AK
	}
	type test struct {
		fields fields
		server *httptest.Server
		args   args
		want   []*x509.Certificate
		expErr error
	}
	tests := map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			params, err := ak.AttestationParameters(context.Background())
			require.NoError(t, err)
			require.NotNil(t, params)
			activation := attest.ActivationParameters{
				TPMVersion: attest.TPMVersion20,
				EK:         ek.Public(),
				AK:         params,
			}
			expectedSecret, encryptedCredentials, err := activation.Generate()
			require.NoError(t, err)
			akChain := [][]byte{
				validAKCert.Raw,
				ca.Intermediate.Raw,
			}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/attest":
					var ar attestationRequest
					err := json.NewDecoder(r.Body).Decode(&ar)
					require.NoError(t, err)
					parsedEK, err := x509.ParsePKIXPublicKey(ar.EKPub)
					require.NoError(t, err)
					assert.Equal(t, ek.Public(), parsedEK)
					attestParams := attest.AttestationParameters{
						Public:                  ar.AttestParams.Public,
						UseTCSDActivationFormat: ar.AttestParams.UseTCSDActivationFormat,
						CreateData:              ar.AttestParams.CreateData,
						CreateAttestation:       ar.AttestParams.CreateAttestation,
						CreateSignature:         ar.AttestParams.CreateSignature,
					}
					activationParams := attest.ActivationParameters{
						TPMVersion: ar.TPMInfo.Version,
						EK:         parsedEK,
						AK:         attestParams,
					}
					assert.Equal(t, activation, activationParams)
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(&attestationResponse{
						Credential: encryptedCredentials.Credential,
						Secret:     encryptedCredentials.Secret,
					})
				case "/secret":
					var sr secretRequest
					err := json.NewDecoder(r.Body).Decode(&sr)
					require.NoError(t, err)
					assert.Equal(t, expectedSecret, sr.Secret)
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(&secretResponse{
						CertificateChain: akChain,
					})
				default:
					t.Errorf("unexpected %q request to %q", r.Method, r.URL)
				}
			})
			s := httptest.NewServer(handler)
			return test{
				server: s,
				fields: fields{
					client:  http.DefaultClient,
					baseURL: mustParseURL(t, s.URL),
				},
				args: args{
					ctx: ctx,
					t:   instance,

					ek: ek,
					ak: ak,
				},
				want: []*x509.Certificate{
					validAKCert,
					ca.Intermediate,
				},
				expErr: nil,
			}
		},
		"fail/attest": func(t *testing.T) test {
			params, err := ak.AttestationParameters(context.Background())
			require.NoError(t, err)
			require.NotNil(t, params)
			activation := attest.ActivationParameters{
				TPMVersion: attest.TPMVersion20,
				EK:         ek.Public(),
				AK:         params,
			}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/attest":
					var ar attestationRequest
					err := json.NewDecoder(r.Body).Decode(&ar)
					require.NoError(t, err)
					parsedEK, err := x509.ParsePKIXPublicKey(ar.EKPub)
					require.NoError(t, err)
					assert.Equal(t, ek.Public(), parsedEK)
					attestParams := attest.AttestationParameters{
						Public:                  ar.AttestParams.Public,
						UseTCSDActivationFormat: ar.AttestParams.UseTCSDActivationFormat,
						CreateData:              ar.AttestParams.CreateData,
						CreateAttestation:       ar.AttestParams.CreateAttestation,
						CreateSignature:         ar.AttestParams.CreateSignature,
					}
					activationParams := attest.ActivationParameters{
						TPMVersion: ar.TPMInfo.Version,
						EK:         parsedEK,
						AK:         attestParams,
					}
					assert.Equal(t, activation, activationParams)
					w.WriteHeader(http.StatusBadRequest)
				case "/secret":
					t.Errorf("unexpectedly requested /secret endpoint")
				default:
					t.Errorf("unexpected %q request to %q", r.Method, r.URL)
				}
			})
			s := httptest.NewServer(handler)
			return test{
				server: s,
				fields: fields{
					client:  http.DefaultClient,
					baseURL: mustParseURL(t, s.URL),
				},
				args: args{
					ctx: ctx,
					t:   instance,

					ek: ek,
					ak: ak,
				},
				want:   nil,
				expErr: fmt.Errorf(`failed attesting AK: POST %q failed with HTTP status "400 Bad Request"`, fmt.Sprintf("%s/attest", s.URL)),
			}
		},
		"fail/secret": func(t *testing.T) test {
			params, err := ak.AttestationParameters(context.Background())
			require.NoError(t, err)
			require.NotNil(t, params)
			activation := attest.ActivationParameters{
				TPMVersion: attest.TPMVersion20,
				EK:         ek.Public(),
				AK:         params,
			}
			expectedSecret, encryptedCredentials, err := activation.Generate()
			require.NoError(t, err)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/attest":
					var ar attestationRequest
					err := json.NewDecoder(r.Body).Decode(&ar)
					require.NoError(t, err)
					parsedEK, err := x509.ParsePKIXPublicKey(ar.EKPub)
					require.NoError(t, err)
					assert.Equal(t, ek.Public(), parsedEK)
					attestParams := attest.AttestationParameters{
						Public:                  ar.AttestParams.Public,
						UseTCSDActivationFormat: ar.AttestParams.UseTCSDActivationFormat,
						CreateData:              ar.AttestParams.CreateData,
						CreateAttestation:       ar.AttestParams.CreateAttestation,
						CreateSignature:         ar.AttestParams.CreateSignature,
					}
					activationParams := attest.ActivationParameters{
						TPMVersion: ar.TPMInfo.Version,
						EK:         parsedEK,
						AK:         attestParams,
					}
					assert.Equal(t, activation, activationParams)
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(&attestationResponse{
						Credential: encryptedCredentials.Credential,
						Secret:     encryptedCredentials.Secret,
					})
				case "/secret":
					var sr secretRequest
					err := json.NewDecoder(r.Body).Decode(&sr)
					require.NoError(t, err)
					assert.Equal(t, expectedSecret, sr.Secret)
					w.WriteHeader(http.StatusForbidden)
				default:
					t.Errorf("unexpected %q request to %q", r.Method, r.URL)
				}
			})
			s := httptest.NewServer(handler)
			return test{
				server: s,
				fields: fields{
					client:  http.DefaultClient,
					baseURL: mustParseURL(t, s.URL),
				},
				args: args{
					ctx: ctx,
					t:   instance,

					ek: ek,
					ak: ak,
				},
				want:   nil,
				expErr: fmt.Errorf(`failed validating secret: POST %q failed with HTTP status "403 Forbidden"`, fmt.Sprintf("%s/secret", s.URL)),
			}
		},
		"fail/pars-ak-certificate-chain": func(t *testing.T) test {
			params, err := ak.AttestationParameters(context.Background())
			require.NoError(t, err)
			require.NotNil(t, params)
			activation := attest.ActivationParameters{
				TPMVersion: attest.TPMVersion20,
				EK:         ek.Public(),
				AK:         params,
			}
			expectedSecret, encryptedCredentials, err := activation.Generate()
			require.NoError(t, err)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/attest":
					var ar attestationRequest
					err := json.NewDecoder(r.Body).Decode(&ar)
					require.NoError(t, err)
					parsedEK, err := x509.ParsePKIXPublicKey(ar.EKPub)
					require.NoError(t, err)
					assert.Equal(t, ek.Public(), parsedEK)
					attestParams := attest.AttestationParameters{
						Public:                  ar.AttestParams.Public,
						UseTCSDActivationFormat: ar.AttestParams.UseTCSDActivationFormat,
						CreateData:              ar.AttestParams.CreateData,
						CreateAttestation:       ar.AttestParams.CreateAttestation,
						CreateSignature:         ar.AttestParams.CreateSignature,
					}
					activationParams := attest.ActivationParameters{
						TPMVersion: ar.TPMInfo.Version,
						EK:         parsedEK,
						AK:         attestParams,
					}
					assert.Equal(t, activation, activationParams)
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(&attestationResponse{
						Credential: encryptedCredentials.Credential,
						Secret:     encryptedCredentials.Secret,
					})
				case "/secret":
					var sr secretRequest
					err := json.NewDecoder(r.Body).Decode(&sr)
					require.NoError(t, err)
					assert.Equal(t, expectedSecret, sr.Secret)
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(&secretResponse{
						CertificateChain: [][]byte{[]byte("this-is-no-certificate")},
					})
				default:
					t.Errorf("unexpected %q request to %q", r.Method, r.URL)
				}
			})
			s := httptest.NewServer(handler)
			return test{
				server: s,
				fields: fields{
					client:  http.DefaultClient,
					baseURL: mustParseURL(t, s.URL),
				},
				args: args{
					ctx: ctx,
					t:   instance,

					ek: ek,
					ak: ak,
				},
				want:   nil,
				expErr: errors.New(`failed parsing certificate: x509: malformed certificate`),
			}
		},
	}
	for name, tt := range tests {
		tc := tt(t)
		t.Run(name, func(t *testing.T) {
			ac := &Client{
				client:  tc.fields.client,
				baseURL: tc.fields.baseURL,
			}
			if tc.server != nil {
				defer tc.server.Close()
			}
			got, err := ac.Attest(tc.args.ctx, tc.args.t, tc.args.ek, tc.args.ak)
			if tc.expErr != nil {
				assert.EqualError(t, err, tc.expErr.Error())
				assert.Nil(t, got)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
