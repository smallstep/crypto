package platform

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
)

func mustKMS(t *testing.T, rawuri string) *KMS {
	t.Helper()

	km, err := New(t.Context(), apiv1.Options{
		URI: rawuri,
	})
	require.NoError(t, err)
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

	return []*x509.Certificate{
		cert, ca.Intermediate,
	}
}

func TestKMS_Type(t *testing.T) {
	softKMS := mustKMS(t, "kms:backend=softkms")
	assert.Equal(t, apiv1.SoftKMS, softKMS.Type())
}

func TestKMS_Close(t *testing.T) {
	softKMS := mustKMS(t, "kms:backend=softkms")
	assert.NoError(t, softKMS.Close())
}

func TestKMS_GetPublicKey(t *testing.T) {
	dir := t.TempDir()
	privateKeyPath := filepath.Join(dir, "private.key")
	signer := mustSigner(t, privateKeyPath)
	softKMS := mustKMS(t, "kms:backend=softkms")

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
		{"fail parseURI", softKMS, args{&apiv1.GetPublicKeyRequest{
			Name: "softkms:" + privateKeyPath,
		}}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		{"fail parseURI", softKMS, args{&apiv1.CreateKeyRequest{
			Name: "softkms:" + privateKeyPath,
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			assert.Nil(t, got)
		}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

	type args struct {
		req *apiv1.CreateSignerRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		want      crypto.Signer
		assertion assert.ErrorAssertionFunc
	}{
		{"ok softKMS", softKMS, args{&apiv1.CreateSignerRequest{
			SigningKey: "kms:name=" + url.QueryEscape(privateKeyPath),
		}}, signer, assert.NoError},
		{"ok softKMS with signer", softKMS, args{&apiv1.CreateSignerRequest{
			Signer:     resp.CreateSignerRequest.Signer,
			SigningKey: resp.CreateSignerRequest.SigningKey,
		}}, signer, assert.NoError},
		{"fail missing", softKMS, args{&apiv1.CreateSignerRequest{
			SigningKey: "kms:name=" + url.QueryEscape(filepath.Join(dir, "missing.key")),
		}}, nil, assert.Error},
		{"fail parseURI", softKMS, args{&apiv1.CreateSignerRequest{
			SigningKey: privateKeyPath,
		}}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.kms.CreateSigner(tt.args.req)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
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

	type args struct {
		req *apiv1.DeleteKeyRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		assertion assert.ErrorAssertionFunc
	}{
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		{"ok softKMS", softKMS, args{&apiv1.LoadCertificateRequest{
			Name: "kms:" + certPath,
		}}, chain[0], assert.NoError},
		{"ok softKMS from chain", softKMS, args{&apiv1.LoadCertificateRequest{
			Name: "kms:name=" + chainPath,
		}}, chain[0], assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.kms.LoadCertificate(tt.args.req)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
