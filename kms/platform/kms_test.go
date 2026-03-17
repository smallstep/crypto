package platform

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"
)

var (
	platformKeyName     string
	platformCertName    string
	platformMissingName string
)

func TestMain(m *testing.M) {
	suffix, err := randutil.Alphanumeric(8)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	platformKeyName = "kms:name=test-" + suffix
	platformCertName = "kms:name=test-" + suffix
	platformMissingName = "kms:name=test-missing-" + suffix

	if runtime.GOOS == "darwin" {
		platformKeyName += ";tag=com.smallstep.test." + suffix
	}

	os.Exit(m.Run())
}

func shouldSkipNow(t *testing.T, km *KMS) {
	t.Helper()

	if km != nil && km.Type() != apiv1.SoftKMS && km.SkipTests() {
		t.SkipNow()
	}
}

func mustKMS(t *testing.T, rawuri string) *KMS {
	t.Helper()

	km, err := New(t.Context(), apiv1.Options{
		URI: rawuri,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, km.Close())
	})
	return km
}

func mustSigner(t *testing.T, path string) crypto.Signer {
	t.Helper()

	signer, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)

	_, err = pemutil.Serialize(signer, pemutil.ToFile(path, 0o600))
	require.NoError(t, err)

	return signer
}

func mustReadSigner(t *testing.T, path string) crypto.Signer {
	t.Helper()

	k, err := pemutil.Read(path)
	require.NoError(t, err)

	signer, ok := k.(crypto.Signer)
	require.True(t, ok)

	return signer
}

func mustCertificate(t *testing.T, path string) []*x509.Certificate {
	t.Helper()

	ca, err := minica.New()
	require.NoError(t, err)

	signer, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)

	cert, err := ca.Sign(&x509.Certificate{
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		PublicKey:   signer.Public(),
		DNSNames:    []string{"example.com"},
	})
	require.NoError(t, err)

	if path != "" {
		var buf bytes.Buffer
		require.NoError(t, pem.Encode(&buf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}))
		require.NoError(t, pem.Encode(&buf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ca.Intermediate.Raw,
		}))

		require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
	}

	return []*x509.Certificate{
		cert, ca.Intermediate,
	}
}

func mustCertificateWithKey(t *testing.T, key crypto.PublicKey) []*x509.Certificate {
	t.Helper()

	ca, err := minica.New()
	require.NoError(t, err)

	// skipped platform
	if key == nil {
		return []*x509.Certificate{ca.Intermediate}
	}

	cert, err := ca.Sign(&x509.Certificate{
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		PublicKey:   key,
		DNSNames:    []string{"example.com"},
	})
	require.NoError(t, err)

	return []*x509.Certificate{
		cert, ca.Intermediate,
	}
}

func mustSuffix(t *testing.T) string {
	t.Helper()
	suffix, err := randutil.Alphanumeric(8)
	require.NoError(t, err)
	return suffix
}

type createOptions struct {
	name                 string
	noCleanup            bool
	noCleanupCertificate bool
}

type createFuncOption func(*createOptions)

func withName(s string) createFuncOption {
	return func(co *createOptions) {
		co.name = s
	}
}

func withNoCleanup() createFuncOption {
	return func(co *createOptions) {
		co.noCleanup = true
		co.noCleanupCertificate = true
	}
}

func withNoCleanupCertificate() createFuncOption {
	return func(co *createOptions) {
		co.noCleanupCertificate = true
	}
}

func mustCreatePlatformKey(t *testing.T, km *KMS, opts ...createFuncOption) *apiv1.CreateKeyResponse {
	t.Helper()

	o := new(createOptions)
	o.name = platformKeyName
	for _, fn := range opts {
		fn(o)
	}

	if km.SkipTests() {
		return &apiv1.CreateKeyResponse{}
	}

	resp, err := km.CreateKey(&apiv1.CreateKeyRequest{
		Name: o.name,
	})
	require.NoError(t, err)

	if !o.noCleanup {
		t.Cleanup(func() {
			assert.NoError(t, km.DeleteKey(&apiv1.DeleteKeyRequest{
				Name: resp.Name,
			}))
		})
	}

	return resp
}

func mustCreatePlatformCertificate(t *testing.T, km *KMS, opts ...createFuncOption) []*x509.Certificate {
	t.Helper()

	o := new(createOptions)
	o.name = platformCertName
	for _, fn := range opts {
		fn(o)
	}

	ca, err := minica.New()
	require.NoError(t, err)

	if km.SkipTests() {
		return []*x509.Certificate{
			ca.Intermediate,
		}
	}

	key := mustCreatePlatformKey(t, km, opts...)
	cert, err := ca.Sign(&x509.Certificate{
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		PublicKey:   key.PublicKey,
		DNSNames:    []string{"example.com"},
	})
	require.NoError(t, err)

	require.NoError(t, km.StoreCertificateChain(&apiv1.StoreCertificateChainRequest{
		Name: o.name,
		CertificateChain: []*x509.Certificate{
			cert, ca.Intermediate,
		},
	}))
	if !o.noCleanupCertificate {
		t.Cleanup(func() {
			assert.NoError(t, km.DeleteCertificate(&apiv1.DeleteCertificateRequest{
				Name: o.name,
			}))
		})
	}

	// Always delete the intermediate on macOS
	if typ := km.Type(); typ == apiv1.MacKMS {
		t.Cleanup(func() {
			assert.NoError(t, km.DeleteCertificate(&apiv1.DeleteCertificateRequest{
				Name: uri.New(Scheme, url.Values{
					"serial": []string{ca.Intermediate.SerialNumber.String()},
				}).String(),
			}))
		})
	}

	return []*x509.Certificate{
		cert, ca.Intermediate,
	}
}

func mustPermanentIdentifier(t *testing.T, pub crypto.PublicKey) *url.URL {
	t.Helper()

	b, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)

	keyID := sha256.Sum256(b)
	return &url.URL{
		Scheme: "urn",
		Opaque: "ek:sha256:" + base64.StdEncoding.EncodeToString(keyID[:]),
	}
}

type attestationClient struct {
	chain []*x509.Certificate
	err   error
}

func mustAttestationClient(chain []*x509.Certificate, err error) *attestationClient {
	return &attestationClient{
		chain: chain,
		err:   err,
	}
}

func (c *attestationClient) Attest(ctx context.Context) ([]*x509.Certificate, error) {
	if _, ok := apiv1.AttestSignerFromContext(ctx); !ok {
		return nil, fmt.Errorf("signer is not in context")
	}
	return c.chain, c.err
}

func TestNew(t *testing.T) {
	platformKMS := mustPlatformKMS(t)
	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name      string
		args      args
		assert    func(*testing.T, *KMS)
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", args{t.Context(), apiv1.Options{}}, func(t *testing.T, k *KMS) {
			shouldSkipNow(t, platformKMS)
			assert.Equal(t, platformKMS.Type(), k.Type())
		}, assert.NoError},
		{"ok softkms uri", args{t.Context(), apiv1.Options{URI: "kms:backend=softkms"}}, func(t *testing.T, k *KMS) {
			assert.Equal(t, apiv1.SoftKMS, k.Type())
		}, assert.NoError},
		{"ok softkms type", args{t.Context(), apiv1.Options{Type: apiv1.SoftKMS}}, func(t *testing.T, k *KMS) {
			assert.Equal(t, apiv1.SoftKMS, k.Type())
		}, assert.NoError},
		{"fail parse", args{t.Context(), apiv1.Options{URI: "foo:backend=softkms"}}, func(t *testing.T, k *KMS) {
			assert.Nil(t, k)
		}, assert.Error},
		{"fail backend", args{t.Context(), apiv1.Options{URI: "kms:backend=unknown"}}, func(t *testing.T, k *KMS) {
			assert.Nil(t, k)
		}, assert.Error},
		{"fail type", args{t.Context(), apiv1.Options{Type: apiv1.Type("unknown")}}, func(t *testing.T, k *KMS) {
			assert.Nil(t, k)
		}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.ctx, tt.args.opts)
			tt.assertion(t, err)
			tt.assert(t, got)
		})
	}
}

func TestKMS_Type(t *testing.T) {
	softKMS := mustKMS(t, "kms:backend=softkms")
	assert.Equal(t, apiv1.SoftKMS, softKMS.Type())
}

func TestKMS_Close(t *testing.T) {
	softKMS, err := New(t.Context(), apiv1.Options{
		URI: "kms:backend=softkms",
	})
	require.NoError(t, err)
	assert.NoError(t, softKMS.Close())
}

func TestKMS_GetPublicKey(t *testing.T) {
	dir := t.TempDir()
	privateKeyPath := filepath.Join(dir, "private.key")
	signer := mustSigner(t, privateKeyPath)
	softKMS := mustKMS(t, "kms:backend=softkms")

	platformKMS := mustPlatformKMS(t)
	platformKey := mustCreatePlatformKey(t, platformKMS)

	type args struct {
		req *apiv1.GetPublicKeyRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		want      crypto.PublicKey
		assertion assert.ErrorAssertionFunc
	}{
		// Platform KMS
		{"ok platform", platformKMS, args{&apiv1.GetPublicKeyRequest{
			Name: platformKey.Name,
		}}, platformKey.PublicKey, assert.NoError},
		{"fail platform missing", platformKMS, args{&apiv1.GetPublicKeyRequest{
			Name: platformMissingName,
		}}, nil, assert.Error},
		{"fail platform name", platformKMS, args{&apiv1.GetPublicKeyRequest{
			Name: "kms:something=test",
		}}, nil, assert.Error},

		// SoftKMS
		{"ok SoftKMS", softKMS, args{&apiv1.GetPublicKeyRequest{
			Name: "kms:name=" + privateKeyPath,
		}}, signer.Public(), assert.NoError},
		{"ok SoftKMS escape", softKMS, args{&apiv1.GetPublicKeyRequest{
			Name: "kms:name=" + url.QueryEscape(privateKeyPath),
		}}, signer.Public(), assert.NoError},
		{"ok SoftKMS path", softKMS, args{&apiv1.GetPublicKeyRequest{
			Name: "kms:" + privateKeyPath,
		}}, signer.Public(), assert.NoError},
		{"fail empty name", softKMS, args{&apiv1.GetPublicKeyRequest{
			Name: "",
		}}, nil, assert.Error},
		{"fail SoftKMS missing", softKMS, args{&apiv1.GetPublicKeyRequest{
			Name: "kms:" + filepath.Join(dir, "notfound.key"),
		}}, nil, assert.Error},
		{"fail transform", softKMS, args{&apiv1.GetPublicKeyRequest{
			Name: "softkms:" + privateKeyPath,
		}}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldSkipNow(t, tt.kms)

			got, err := tt.kms.GetPublicKey(tt.args.req)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKMS_CreateKey(t *testing.T) {
	dir := t.TempDir()
	privateKeyPath := filepath.Join(dir, "private.key")
	softKMS := mustKMS(t, "kms:backend=softkms")

	suffix := mustSuffix(t)
	platformKMS := mustPlatformKMS(t)

	type args struct {
		req *apiv1.CreateKeyRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		equal     func(t *testing.T, got *apiv1.CreateKeyResponse)
		assertion assert.ErrorAssertionFunc
	}{
		// Platform KMS
		{"ok platform", platformKMS, args{&apiv1.CreateKeyRequest{
			Name: "kms:name=test1-" + suffix,
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			require.NotNil(t, got)

			t.Cleanup(func() {
				assert.NoError(t, platformKMS.DeleteKey(&apiv1.DeleteKeyRequest{
					Name: "kms:name=test1-" + suffix,
				}))
			})

			assert.Regexp(t, "^kms:.*name=test1-.*$", got.Name)
			assert.Equal(t, got.Name, got.CreateSignerRequest.SigningKey)

			if platformKMS.Type() == apiv1.TPMKMS && assert.IsType(t, &rsa.PublicKey{}, got.PublicKey) {
				assert.Equal(t, 256, got.PublicKey.(*rsa.PublicKey).Size())
			} else if assert.IsType(t, &ecdsa.PublicKey{}, got.PublicKey) {
				assert.Equal(t, elliptic.P256(), got.PublicKey.(*ecdsa.PublicKey).Curve)
			}
		}, assert.NoError},
		{"ok platform ECDSA", platformKMS, args{&apiv1.CreateKeyRequest{
			Name:               "kms:name=test2-" + suffix,
			SignatureAlgorithm: apiv1.ECDSAWithSHA384,
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			require.NotNil(t, got)

			t.Cleanup(func() {
				assert.NoError(t, platformKMS.DeleteKey(&apiv1.DeleteKeyRequest{
					Name: "kms:name=test2-" + suffix,
				}))
			})

			assert.Regexp(t, "^kms:.*name=test2-.*$", got.Name)
			assert.Equal(t, got.Name, got.CreateSignerRequest.SigningKey)

			if assert.IsType(t, &ecdsa.PublicKey{}, got.PublicKey) {
				assert.Equal(t, elliptic.P384(), got.PublicKey.(*ecdsa.PublicKey).Curve)
			}
		}, assert.NoError},
		{"ok platform RSA", platformKMS, args{&apiv1.CreateKeyRequest{
			Name:               "kms:name=test3-" + suffix,
			SignatureAlgorithm: apiv1.SHA256WithRSA,
			Bits:               2048,
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			require.NotNil(t, got)

			t.Cleanup(func() {
				assert.NoError(t, platformKMS.DeleteKey(&apiv1.DeleteKeyRequest{
					Name: "kms:name=test3-" + suffix,
				}))
			})

			assert.Regexp(t, "^kms:.*name=test3-.*$", got.Name)
			assert.Equal(t, got.Name, got.CreateSignerRequest.SigningKey)
			if assert.IsType(t, &rsa.PublicKey{}, got.PublicKey) {
				assert.Equal(t, 256, got.PublicKey.(*rsa.PublicKey).Size())
			}
		}, assert.NoError},
		{"fail platform algorithm", platformKMS, args{&apiv1.CreateKeyRequest{
			Name:               "kms:test4-" + suffix,
			SignatureAlgorithm: apiv1.SignatureAlgorithm(100),
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			assert.Nil(t, got)
		}, assert.Error},

		// SoftKMS
		{"ok softKMS", softKMS, args{&apiv1.CreateKeyRequest{
			Name: "kms:name=" + privateKeyPath,
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			signer := mustReadSigner(t, privateKeyPath)
			assert.IsType(t, &ecdsa.PrivateKey{}, signer)
			name := "kms:name=" + url.QueryEscape(privateKeyPath)
			assert.Equal(t, got, &apiv1.CreateKeyResponse{
				Name:       name,
				PublicKey:  signer.Public(),
				PrivateKey: signer,
				CreateSignerRequest: apiv1.CreateSignerRequest{
					Signer:     signer,
					SigningKey: name,
				},
			})
		}, assert.NoError},
		{"ok softKMS escape", softKMS, args{&apiv1.CreateKeyRequest{
			Name:               "kms:name=" + url.QueryEscape(privateKeyPath),
			SignatureAlgorithm: apiv1.SHA256WithRSA,
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			signer := mustReadSigner(t, privateKeyPath)
			if assert.IsType(t, &rsa.PrivateKey{}, signer) {
				assert.Equal(t, 3072/8, signer.(*rsa.PrivateKey).Size())
			}
			name := "kms:name=" + url.QueryEscape(privateKeyPath)
			assert.Equal(t, got, &apiv1.CreateKeyResponse{
				Name:       name,
				PublicKey:  signer.Public(),
				PrivateKey: signer,
				CreateSignerRequest: apiv1.CreateSignerRequest{
					Signer:     signer,
					SigningKey: name,
				},
			})
		}, assert.NoError},
		{"ok softKMS path", softKMS, args{&apiv1.CreateKeyRequest{
			Name:               "kms:" + privateKeyPath,
			SignatureAlgorithm: apiv1.SHA256WithRSA,
			Bits:               2048,
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			signer := mustReadSigner(t, privateKeyPath)
			name := "kms:name=" + url.QueryEscape(privateKeyPath)
			if assert.IsType(t, &rsa.PrivateKey{}, signer) {
				assert.Equal(t, 2048/8, signer.(*rsa.PrivateKey).Size())
			}
			assert.Equal(t, got, &apiv1.CreateKeyResponse{
				Name:       name,
				PublicKey:  signer.Public(),
				PrivateKey: signer,
				CreateSignerRequest: apiv1.CreateSignerRequest{
					Signer:     signer,
					SigningKey: name,
				},
			})
		}, assert.NoError},
		{"fail softKMS createKey", softKMS, args{&apiv1.CreateKeyRequest{
			Name:               "kms:" + privateKeyPath,
			SignatureAlgorithm: apiv1.SignatureAlgorithm(100),
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			assert.Nil(t, got)
		}, assert.Error},
		{"fail parseURI", softKMS, args{&apiv1.CreateKeyRequest{
			Name: "softkms:" + privateKeyPath,
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			assert.Nil(t, got)
		}, assert.Error},
		{"fail empty name", softKMS, args{&apiv1.CreateKeyRequest{
			Name: "",
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			assert.Nil(t, got)
		}, assert.Error},
		{"fail empty uri", softKMS, args{&apiv1.CreateKeyRequest{
			Name: "kms:",
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			assert.Nil(t, got)
		}, assert.Error},
		{"fail empty uri name", softKMS, args{&apiv1.CreateKeyRequest{
			Name: "kms:name=",
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			assert.Nil(t, got)
		}, assert.Error},
		{"fail empty uri path", softKMS, args{&apiv1.CreateKeyRequest{
			Name: "kms:path=",
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			assert.Nil(t, got)
		}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldSkipNow(t, tt.kms)

			got, err := tt.kms.CreateKey(tt.args.req)
			tt.assertion(t, err)
			tt.equal(t, got)
		})
	}
}

func TestKMS_CreateSigner(t *testing.T) {
	dir := t.TempDir()
	softKMS := mustKMS(t, "kms:backend=softkms")
	privateKeyPath := filepath.Join(dir, "private.key")
	resp, err := softKMS.CreateKey(&apiv1.CreateKeyRequest{
		Name: "kms:name=" + url.QueryEscape(privateKeyPath),
	})
	require.NoError(t, err)
	signer := mustReadSigner(t, privateKeyPath)

	platformKMS := mustPlatformKMS(t)
	platformKey := mustCreatePlatformKey(t, platformKMS)

	assertNil := func(t *testing.T, got crypto.Signer) {
		t.Helper()
		assert.Nil(t, got)
	}

	type args struct {
		req *apiv1.CreateSignerRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		equal     func(*testing.T, crypto.Signer)
		assertion assert.ErrorAssertionFunc
	}{
		// PlatformKMS
		{"ok platform", platformKMS, args{&apiv1.CreateSignerRequest{
			SigningKey: platformKeyName,
		}}, func(t *testing.T, s crypto.Signer) {
			require.NotNil(t, s)
			assert.Equal(t, platformKey.PublicKey, s.Public())
		}, assert.NoError},
		{"fail platform missing", platformKMS, args{&apiv1.CreateSignerRequest{
			SigningKey: platformMissingName,
		}}, assertNil, assert.Error},

		// SoftKMS
		{"ok softKMS", softKMS, args{&apiv1.CreateSignerRequest{
			SigningKey: "kms:name=" + url.QueryEscape(privateKeyPath),
		}}, func(t *testing.T, s crypto.Signer) {
			assert.Equal(t, signer, s)
		}, assert.NoError},
		{"ok softKMS with signer", softKMS, args{&apiv1.CreateSignerRequest{
			Signer:     resp.CreateSignerRequest.Signer,
			SigningKey: resp.CreateSignerRequest.SigningKey,
		}}, func(t *testing.T, s crypto.Signer) {
			assert.Equal(t, signer, s)
		}, assert.NoError},
		{"fail missing", softKMS, args{&apiv1.CreateSignerRequest{
			SigningKey: "kms:name=" + url.QueryEscape(filepath.Join(dir, "missing.key")),
		}}, assertNil, assert.Error},
		{"fail parseURI", softKMS, args{&apiv1.CreateSignerRequest{
			SigningKey: privateKeyPath,
		}}, assertNil, assert.Error},
		{"fail signingKey", softKMS, args{&apiv1.CreateSignerRequest{
			SigningKey: "",
		}}, assertNil, assert.Error},
		{"fail empty uri", softKMS, args{&apiv1.CreateSignerRequest{
			SigningKey: "kms:",
		}}, assertNil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldSkipNow(t, tt.kms)

			got, err := tt.kms.CreateSigner(tt.args.req)
			tt.assertion(t, err)
			tt.equal(t, got)
		})
	}
}

func TestKMS_DeleteKey(t *testing.T) {
	dir := t.TempDir()
	softKMS := mustKMS(t, "kms:backend=softkms")
	keyPath1 := filepath.Join(dir, "key1.key")
	_, err := softKMS.CreateKey(&apiv1.CreateKeyRequest{
		Name: "kms:name=" + url.QueryEscape(keyPath1),
	})
	require.NoError(t, err)

	keyPath2 := filepath.Join(dir, "key2.key")
	_, err = softKMS.CreateKey(&apiv1.CreateKeyRequest{
		Name: "kms:name=" + keyPath2,
	})
	require.NoError(t, err)

	platformKMS := mustPlatformKMS(t)
	platformKey := mustCreatePlatformKey(t, platformKMS, withNoCleanup())

	type args struct {
		req *apiv1.DeleteKeyRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		// Platform KMS
		{"ok platform", platformKMS, args{&apiv1.DeleteKeyRequest{
			Name: platformKey.Name,
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			_, getErr := platformKMS.GetPublicKey(&apiv1.GetPublicKeyRequest{
				Name: platformKey.Name,
			})
			return assert.NoError(t, err) && assert.Error(t, getErr)
		}},
		{"fail platform deleted", platformKMS, args{&apiv1.DeleteKeyRequest{
			Name: platformKey.Name,
		}}, assert.Error},
		{"fail platform missing", platformKMS, args{&apiv1.DeleteKeyRequest{
			Name: platformMissingName,
		}}, assert.Error},

		// SoftKMS
		{"ok softKMS", softKMS, args{&apiv1.DeleteKeyRequest{
			Name: "kms:name=" + url.QueryEscape(keyPath1),
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			return assert.NoError(t, err) &&
				assert.NoFileExists(t, keyPath1)
		}},
		{"fail missing", softKMS, args{&apiv1.DeleteKeyRequest{
			Name: "kms:name=" + url.QueryEscape(filepath.Join(dir, "missing.key")),
		}}, assert.Error},
		{"fail parseURI", softKMS, args{&apiv1.DeleteKeyRequest{
			Name: keyPath2,
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			return assert.Error(t, err) &&
				assert.FileExists(t, keyPath2)
		}},
		{"fail name", softKMS, args{&apiv1.DeleteKeyRequest{
			Name: "",
		}}, assert.Error},
		{"fail empty uri", softKMS, args{&apiv1.DeleteKeyRequest{
			Name: "kms:",
		}}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldSkipNow(t, tt.kms)

			tt.assertion(t, tt.kms.DeleteKey(tt.args.req))
		})
	}
}

func TestKMS_LoadCertificate(t *testing.T) {
	dir := t.TempDir()

	chainPath := filepath.Join(dir, "chain.crt")
	chain := mustCertificate(t, chainPath)

	certPath := filepath.Join(dir, "certificate.crt")
	softKMS := mustKMS(t, "kms:backend=softkms")
	require.NoError(t, softKMS.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name:        "kms:name=" + url.QueryEscape(certPath),
		Certificate: chain[0],
	}))

	platformKMS := mustPlatformKMS(t)
	platformChain := mustCreatePlatformCertificate(t, platformKMS)

	type args struct {
		req *apiv1.LoadCertificateRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		want      *x509.Certificate
		assertion assert.ErrorAssertionFunc
	}{
		// Platform KMS
		{"ok platform", platformKMS, args{&apiv1.LoadCertificateRequest{
			Name: platformCertName,
		}}, platformChain[0], assert.NoError},
		{"fail platform missing", platformKMS, args{&apiv1.LoadCertificateRequest{
			Name: platformMissingName,
		}}, nil, assert.Error},

		// SoftKMS
		{"ok softKMS", softKMS, args{&apiv1.LoadCertificateRequest{
			Name: "kms:" + certPath,
		}}, chain[0], assert.NoError},
		{"ok softKMS from chain", softKMS, args{&apiv1.LoadCertificateRequest{
			Name: "kms:name=" + url.QueryEscape(chainPath),
		}}, chain[0], assert.NoError},
		{"fail missing", softKMS, args{&apiv1.LoadCertificateRequest{
			Name: "kms:name=" + filepath.Join(dir, "missing.crt"),
		}}, nil, assert.Error},
		{"fail parseURI", softKMS, args{&apiv1.LoadCertificateRequest{
			Name: "foo:name=" + certPath,
		}}, nil, assert.Error},
		{"fail name", softKMS, args{&apiv1.LoadCertificateRequest{
			Name: "",
		}}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldSkipNow(t, tt.kms)

			got, err := tt.kms.LoadCertificate(tt.args.req)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKMS_StoreCertificate(t *testing.T) {
	dir := t.TempDir()
	chain := mustCertificate(t, "")
	softKMS := mustKMS(t, "kms:backend=softkms")

	platformKMS := mustPlatformKMS(t)
	platformKey := mustCreatePlatformKey(t, platformKMS)
	platformChain := mustCertificateWithKey(t, platformKey.PublicKey)

	type args struct {
		req *apiv1.StoreCertificateRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		// Platform KMS
		{"ok platform", platformKMS, args{&apiv1.StoreCertificateRequest{
			Name:        platformCertName,
			Certificate: platformChain[0],
		}}, assert.NoError},
		{"ok platform no key", platformKMS, args{&apiv1.StoreCertificateRequest{
			Name:        platformCertName + "-other",
			Certificate: chain[0],
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			// Storing a certificate with no key is not supported on TPMKMS.
			if platformKMS.Type() == apiv1.TPMKMS && runtime.GOOS != "windows" {
				return assert.Error(t, err)
			}

			t.Cleanup(func() {
				assert.NoError(t, platformKMS.DeleteCertificate(&apiv1.DeleteCertificateRequest{
					Name: platformCertName,
				}))
			})
			return assert.NoError(t, err)
		}},
		{"fail platform no certificate", platformKMS, args{&apiv1.StoreCertificateRequest{
			Name:        platformCertName,
			Certificate: nil,
		}}, assert.Error},

		// SoftKMS
		{"ok softKMS", softKMS, args{&apiv1.StoreCertificateRequest{
			Name:        "kms:name=" + filepath.Join(dir, "cert.crt"),
			Certificate: chain[0],
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			return assert.NoError(t, err) &&
				assert.FileExists(t, filepath.Join(dir, "cert.crt"))
		}},
		{"ok softKMS simple", softKMS, args{&apiv1.StoreCertificateRequest{
			Name:        "kms:" + filepath.Join(dir, "intermediate.crt"),
			Certificate: chain[1],
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			return assert.NoError(t, err) &&
				assert.FileExists(t, filepath.Join(dir, "intermediate.crt"))
		}},
		{"ok softKMS overwrite", softKMS, args{&apiv1.StoreCertificateRequest{
			Name:        "kms:" + filepath.Join(dir, "cert.crt"),
			Certificate: chain[0],
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			return assert.NoError(t, err) &&
				assert.FileExists(t, filepath.Join(dir, "cert.crt"))
		}},
		{"fail parseURI", softKMS, args{&apiv1.StoreCertificateRequest{
			Name:        "foo:" + filepath.Join(dir, "fail.crt"),
			Certificate: chain[0],
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			return assert.Error(t, err) &&
				assert.NoFileExists(t, filepath.Join(dir, "fail.crt"))
		}},
		{"fail name", softKMS, args{&apiv1.StoreCertificateRequest{
			Certificate: chain[0],
		}}, assert.Error},
		{"fail empty uri", softKMS, args{&apiv1.StoreCertificateRequest{
			Name:        "kms:",
			Certificate: chain[0],
		}}, assert.Error},
		{"fail certificate", softKMS, args{&apiv1.StoreCertificateRequest{
			Name: "kms:name=" + filepath.Join(dir, "cert.crt"),
		}}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldSkipNow(t, tt.kms)
			tt.assertion(t, tt.kms.StoreCertificate(tt.args.req))
		})
	}
}

func TestKMS_LoadCertificateChain(t *testing.T) {
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.crt")
	chain := mustCertificate(t, chainPath)
	softKMS := mustKMS(t, "kms:backend=softkms")

	platformKMS := mustPlatformKMS(t)
	platformChain := mustCreatePlatformCertificate(t, platformKMS)

	type args struct {
		req *apiv1.LoadCertificateChainRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		want      []*x509.Certificate
		assertion assert.ErrorAssertionFunc
	}{
		// Platform KMS
		{"ok platform", platformKMS, args{&apiv1.LoadCertificateChainRequest{
			Name: platformCertName,
		}}, platformChain, assert.NoError},
		{"fail platform missing", platformKMS, args{&apiv1.LoadCertificateChainRequest{
			Name: platformMissingName,
		}}, nil, assert.Error},

		// SoftKMS
		{"ok softKMS", softKMS, args{&apiv1.LoadCertificateChainRequest{
			Name: "kms:name=" + chainPath,
		}}, chain, assert.NoError},
		{"fail parseURI", softKMS, args{&apiv1.LoadCertificateChainRequest{
			Name: "foo:name=" + chainPath,
		}}, nil, assert.Error},
		{"fail missing", softKMS, args{&apiv1.LoadCertificateChainRequest{
			Name: "kms:name=" + filepath.Join(dir, "missing.crt"),
		}}, nil, assert.Error},
		{"fail parseuri", softKMS, args{&apiv1.LoadCertificateChainRequest{
			Name: "softkms:name=" + chainPath,
		}}, nil, assert.Error},
		{"fail name", softKMS, args{&apiv1.LoadCertificateChainRequest{
			Name: "",
		}}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldSkipNow(t, tt.kms)

			got, err := tt.kms.LoadCertificateChain(tt.args.req)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKMS_StoreCertificateChain(t *testing.T) {
	dir := t.TempDir()
	chain := mustCertificate(t, "")
	softKMS := mustKMS(t, "kms:backend=softkms")

	platformKMS := mustPlatformKMS(t)
	platformKey := mustCreatePlatformKey(t, platformKMS)
	platformChain := mustCertificateWithKey(t, platformKey.PublicKey)

	type args struct {
		req *apiv1.StoreCertificateChainRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		// Platform KMS
		{"ok platform", platformKMS, args{&apiv1.StoreCertificateChainRequest{
			Name:             platformCertName,
			CertificateChain: platformChain,
		}}, assert.NoError},
		{"ok platform no key", platformKMS, args{&apiv1.StoreCertificateChainRequest{
			Name:             platformCertName + "-other",
			CertificateChain: chain,
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			// Storing a certificate with no key is not supported on TPMKMS.
			if platformKMS.Type() == apiv1.TPMKMS && runtime.GOOS != "windows" {
				return assert.Error(t, err)
			}

			t.Cleanup(func() {
				assert.NoError(t, platformKMS.DeleteCertificate(&apiv1.DeleteCertificateRequest{
					Name: platformCertName,
				}))

				if typ := platformKMS.Type(); typ == apiv1.MacKMS || (typ == apiv1.TPMKMS && runtime.GOOS == "windows") {
					assert.NoError(t, platformKMS.DeleteCertificate(&apiv1.DeleteCertificateRequest{
						Name: uri.New(Scheme, url.Values{
							"issuer": []string{platformChain[1].Issuer.CommonName}, // for windows only
							"serial": []string{hex.EncodeToString(platformChain[1].SerialNumber.Bytes())},
						}).String(),
					}))
				}
			})
			return assert.NoError(t, err)
		}},
		{"fail platform bad chain", platformKMS, args{&apiv1.StoreCertificateChainRequest{
			Name:             platformCertName,
			CertificateChain: []*x509.Certificate{},
		}}, assert.Error},

		// SoftKMS
		{"ok softKMS", softKMS, args{&apiv1.StoreCertificateChainRequest{
			Name:             "kms:name=" + filepath.Join(dir, "chain.crt"),
			CertificateChain: chain,
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			return assert.NoError(t, err) && assert.FileExists(t, filepath.Join(dir, "chain.crt"))
		}},
		{"ok softKMS escape", softKMS, args{&apiv1.StoreCertificateChainRequest{
			Name:             "kms:name=" + url.QueryEscape(filepath.Join(dir, "leaf.crt")),
			CertificateChain: chain[:1],
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			return assert.NoError(t, err) && assert.FileExists(t, filepath.Join(dir, "leaf.crt"))
		}},
		{"fail parseURI", softKMS, args{&apiv1.StoreCertificateChainRequest{
			Name:             "foo:name=" + filepath.Join(dir, "other.crt"),
			CertificateChain: chain,
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			return assert.Error(t, err) && assert.NoFileExists(t, filepath.Join(dir, "other.crt"))
		}},
		{"fail name", softKMS, args{&apiv1.StoreCertificateChainRequest{
			Name:             "",
			CertificateChain: chain,
		}}, assert.Error},
		{"fail empty uri", softKMS, args{&apiv1.StoreCertificateChainRequest{
			Name:             "kms:",
			CertificateChain: chain,
		}}, assert.Error},
		{"fail certificateChain", softKMS, args{&apiv1.StoreCertificateChainRequest{
			Name: "kms:name=" + filepath.Join(dir, "other.crt"),
		}}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldSkipNow(t, tt.kms)
			tt.assertion(t, tt.kms.StoreCertificateChain(tt.args.req))
		})
	}
}

func TestKMS_DeleteCertificate(t *testing.T) {
	dir := t.TempDir()
	_ = mustCertificate(t, filepath.Join(dir, "chain.crt"))
	softKMS := mustKMS(t, "kms:backend=softkms")

	platformKMS := mustPlatformKMS(t)
	_ = mustCreatePlatformCertificate(t, platformKMS, withNoCleanupCertificate())

	type args struct {
		req *apiv1.DeleteCertificateRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		{"ok platform", platformKMS, args{&apiv1.DeleteCertificateRequest{
			Name: platformCertName,
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			_, loadErr := platformKMS.LoadCertificate(&apiv1.LoadCertificateRequest{
				Name: platformCertName,
			})
			return assert.NoError(t, err) && assert.Error(t, loadErr)
		}},
		{"fail platform missing", platformKMS, args{&apiv1.DeleteCertificateRequest{
			Name: platformMissingName,
		}}, assert.Error},

		// SoftKMS
		{"ok softKMS", softKMS, args{&apiv1.DeleteCertificateRequest{
			Name: "kms:name=" + url.QueryEscape(filepath.Join(dir, "chain.crt")),
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			return assert.NoError(t, err) &&
				assert.NoFileExists(t, filepath.Join(dir, "chain.crt"))
		}},
		{"fail missing", softKMS, args{&apiv1.DeleteCertificateRequest{
			Name: "kms:name=" + url.QueryEscape(filepath.Join(dir, "chain.crt")),
		}}, assert.Error},
		{"fail parseURI", softKMS, args{&apiv1.DeleteCertificateRequest{
			Name: "foo",
		}}, assert.Error},
		{"fail name", softKMS, args{&apiv1.DeleteCertificateRequest{
			Name: "",
		}}, assert.Error},
		{"fail empty uri", softKMS, args{&apiv1.DeleteCertificateRequest{
			Name: "kms:",
		}}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldSkipNow(t, tt.kms)

			tt.assertion(t, tt.kms.DeleteCertificate(tt.args.req))
		})
	}
}

func TestKMS_CreateAttestation(t *testing.T) {
	dir := t.TempDir()
	privateKeyPath := filepath.Join(dir, "private.key")
	signer := mustSigner(t, privateKeyPath)
	attester := mustSigner(t, filepath.Join(dir, "attester.key"))
	permanentIdentifier := mustPermanentIdentifier(t, attester.Public())

	ca, err := minica.New()
	require.NoError(t, err)
	cert, err := ca.Sign(&x509.Certificate{
		Subject: pkix.Name{
			CommonName: "attestation certificate",
		},
		URIs:      []*url.URL{permanentIdentifier},
		PublicKey: signer.Public(),
	})
	require.NoError(t, err)

	softKMS := mustKMS(t, "kms:backend=softkms")
	okClient := mustAttestationClient([]*x509.Certificate{cert, ca.Intermediate}, nil)
	failClient := mustAttestationClient(nil, errors.New("attestation failed"))

	type args struct {
		req *apiv1.CreateAttestationRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		want      *apiv1.CreateAttestationResponse
		assertion assert.ErrorAssertionFunc
	}{
		{"ok custom attestation", softKMS, args{&apiv1.CreateAttestationRequest{
			Name:              "kms:" + privateKeyPath,
			AttestationClient: okClient,
		}}, &apiv1.CreateAttestationResponse{
			Certificate:         cert,
			CertificateChain:    []*x509.Certificate{cert, ca.Intermediate},
			PublicKey:           signer.Public(),
			PermanentIdentifier: permanentIdentifier.String(),
		}, assert.NoError},
		{"fail missing key", softKMS, args{&apiv1.CreateAttestationRequest{
			Name:              "kms:" + platformMissingName,
			AttestationClient: okClient,
		}}, nil, assert.Error},
		{"fail custom attestation", softKMS, args{&apiv1.CreateAttestationRequest{
			Name:              "kms:" + privateKeyPath,
			AttestationClient: failClient,
		}}, nil, assert.Error},
		{"fail no client", softKMS, args{&apiv1.CreateAttestationRequest{
			Name: "kms:" + privateKeyPath,
		}}, nil, assert.Error},
		{"fail no name", softKMS, args{&apiv1.CreateAttestationRequest{}}, nil, assert.Error},
		{"fail parse", softKMS, args{&apiv1.CreateAttestationRequest{
			Name: "tpmkms:",
		}}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldSkipNow(t, tt.kms)

			got, err := tt.kms.CreateAttestation(tt.args.req)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKMS_SearchKeys(t *testing.T) {
	dir := t.TempDir()
	softKMS := mustKMS(t, "kms:backend=softkms")

	suffix := mustSuffix(t)
	platformKMS := mustPlatformKMS(t)

	platformKeys := make([]*apiv1.CreateKeyResponse, 4)
	for i := range platformKeys {
		name := fmt.Sprintf("kms:name=search-test-%d-%s", i, suffix)
		if runtime.GOOS == "darwin" {
			name += ";tag=com.smallstep.test." + suffix
		}
		platformKeys[i] = mustCreatePlatformKey(t, platformKMS, withName(name))
	}

	makeResult := func(r *apiv1.CreateKeyResponse) apiv1.SearchKeyResult {
		return apiv1.SearchKeyResult{
			Name:      r.Name,
			PublicKey: r.PublicKey,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: r.Name,
			},
		}
	}

	type args struct {
		req *apiv1.SearchKeysRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		want      *apiv1.SearchKeysResponse
		assertion assert.ErrorAssertionFunc
	}{
		// PlatformKMS
		{"ok platform", platformKMS, args{&apiv1.SearchKeysRequest{
			Query: "kms:tag=com.smallstep.test." + suffix,
		}}, &apiv1.SearchKeysResponse{
			Results: []apiv1.SearchKeyResult{
				makeResult(platformKeys[0]), makeResult(platformKeys[1]),
				makeResult(platformKeys[2]), makeResult(platformKeys[3]),
			},
		}, assert.NoError},
		{"ok platform with name", platformKMS, args{&apiv1.SearchKeysRequest{
			Query: fmt.Sprintf("kms:name=search-test-%d-%s;tag=com.smallstep.test.%s", 2, suffix, suffix),
		}}, &apiv1.SearchKeysResponse{
			Results: []apiv1.SearchKeyResult{
				makeResult(platformKeys[2]),
			},
		}, assert.NoError},
		{"fail parse", platformKMS, args{&apiv1.SearchKeysRequest{
			Query: "name=",
		}}, nil, assert.Error},

		// SoftKMS
		{"fail softKMS", softKMS, args{&apiv1.SearchKeysRequest{
			Query: "kms:name=" + url.QueryEscape(dir),
		}}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldSkipNow(t, tt.kms)

			got, err := tt.kms.SearchKeys(tt.args.req)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_getBackend(t *testing.T) {
	type args struct {
		opts apiv1.Options
	}
	tests := []struct {
		name      string
		args      args
		want      apiv1.Type
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", args{apiv1.Options{}}, apiv1.DefaultKMS, assert.NoError},
		{"ok from type", args{apiv1.Options{Type: apiv1.TPMKMS}}, apiv1.TPMKMS, assert.NoError},
		{"ok from uri", args{apiv1.Options{URI: "kms:backend=softkms"}}, apiv1.SoftKMS, assert.NoError},
		{"ok from both", args{apiv1.Options{Type: apiv1.CAPIKMS, URI: "kms:backend=capi"}}, apiv1.CAPIKMS, assert.NoError},
		{"fail uri", args{apiv1.Options{URI: "softkms:backend=softkms"}}, apiv1.DefaultKMS, assert.Error},
		{"fail mismatch", args{apiv1.Options{Type: apiv1.TPMKMS, URI: "kms:backend=softkms"}}, apiv1.DefaultKMS, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getBackend(tt.args.opts)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_parseURI(t *testing.T) {
	mustURI := func(scheme, opaque, rawquery string, values url.Values) *uri.URI {
		u := uri.New(scheme, values)
		u.Opaque = opaque
		u.RawQuery = rawquery
		return u
	}

	type args struct {
		rawuri string
	}
	tests := []struct {
		name      string
		args      args
		want      *kmsURI
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", args{"kms:"}, &kmsURI{
			uri:         uri.New(Scheme, url.Values{}),
			extraValues: url.Values{},
		}, assert.NoError},
		{"ok with name", args{"kms:name=foo"}, &kmsURI{
			uri:         mustURI(Scheme, "name=foo", "", url.Values{"name": []string{"foo"}}),
			name:        "foo",
			extraValues: url.Values{},
		}, assert.NoError},
		{"ok with hw", args{"kms:name=foo;hw=true"}, &kmsURI{
			uri: mustURI(Scheme, "name=foo;hw=true", "", url.Values{
				"name": []string{"foo"},
				"hw":   []string{"true"},
			}),
			name:        "foo",
			hw:          true,
			extraValues: url.Values{},
		}, assert.NoError},
		{"ok with hw on query", args{"kms:name=foo?hw=true"}, &kmsURI{
			uri:         mustURI(Scheme, "name=foo", "hw=true", url.Values{"name": []string{"foo"}}),
			name:        "foo",
			hw:          true,
			extraValues: url.Values{},
		}, assert.NoError},
		{"ok with extra values", args{"kms:name=foo;hw=true;foo=bar;backend=softkms?bar=zar&foo=qux"}, &kmsURI{
			uri: mustURI(Scheme, "name=foo;hw=true;foo=bar;backend=softkms", "bar=zar&foo=qux", url.Values{
				"name":    []string{"foo"},
				"hw":      []string{"true"},
				"foo":     []string{"bar"},
				"backend": []string{"softkms"},
			}),
			name: "foo",
			hw:   true,
			extraValues: url.Values{
				"foo": []string{"bar", "qux"},
				"bar": []string{"zar"},
			},
		}, assert.NoError},
		{"fail parse", args{"tpmkms:name=foo"}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseURI(tt.args.rawuri)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
