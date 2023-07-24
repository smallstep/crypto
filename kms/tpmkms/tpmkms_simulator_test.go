//go:build tpmsimulator
// +build tpmsimulator

package tpmkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/go-attestation/attest"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/minica"
	tpmp "go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/simulator"
	"go.step.sm/crypto/tpm/storage"
)

type newSimulatedTPMOption func(t *testing.T, tpm *tpmp.TPM)

func withAK(name string) newSimulatedTPMOption {
	return func(t *testing.T, tpm *tpmp.TPM) {
		t.Helper()
		_, err := tpm.CreateAK(context.Background(), name)
		require.NoError(t, err)
	}
}

func withKey(name string) newSimulatedTPMOption {
	return func(t *testing.T, tpm *tpmp.TPM) {
		t.Helper()
		config := tpmp.CreateKeyConfig{
			Algorithm: "RSA",
			Size:      1024,
		}
		_, err := tpm.CreateKey(context.Background(), name, config)
		require.NoError(t, err)
	}
}

func newSimulatedTPM(t *testing.T, opts ...newSimulatedTPMOption) *tpmp.TPM {
	t.Helper()
	tmpDir := t.TempDir()
	tpm, err := tpmp.New(withSimulator(t), tpmp.WithStore(storage.NewDirstore(tmpDir)))
	require.NoError(t, err)
	for _, applyTo := range opts {
		applyTo(t, tpm)
	}
	return tpm
}

func withSimulator(t *testing.T) tpmp.NewTPMOption {
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
	return tpmp.WithSimulator(sim)
}

func TestTPMKMS_CreateKey(t *testing.T) {
	tpmWithAK := newSimulatedTPM(t, withAK("ak1"))
	type fields struct {
		tpm *tpmp.TPM
	}
	type args struct {
		req *apiv1.CreateKeyRequest
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		assertFunc assert.ValueAssertionFunc
		expErr     error
	}{
		{
			name: "ok/key",
			fields: fields{
				tpm: tpmWithAK,
			},
			args: args{
				req: &apiv1.CreateKeyRequest{
					Name:               "tpmkms:name=key1",
					SignatureAlgorithm: apiv1.SHA256WithRSA,
					Bits:               1024,
				},
			},
			assertFunc: func(tt assert.TestingT, i1 interface{}, i2 ...interface{}) bool {
				if assert.IsType(t, &apiv1.CreateKeyResponse{}, i1) {
					r, _ := i1.(*apiv1.CreateKeyResponse)
					if assert.NotNil(t, r) {
						assert.Equal(t, "tpmkms:name=key1", r.Name)
						assert.Equal(t, "tpmkms:name=key1", r.CreateSignerRequest.SigningKey)
						if assert.NotNil(t, r.CreateSignerRequest.Signer) {
							assert.Implements(t, (*crypto.Signer)(nil), r.CreateSignerRequest.Signer)
						}
						return true
					}
				}
				return false
			},
		},
		{
			name: "ok/attested-key",
			fields: fields{
				tpm: tpmWithAK,
			},
			args: args{
				req: &apiv1.CreateKeyRequest{
					Name:               "tpmkms:name=key2;attest-by=ak1",
					SignatureAlgorithm: apiv1.SHA256WithRSA,
					Bits:               1024,
				},
			},
			assertFunc: func(tt assert.TestingT, i1 interface{}, i2 ...interface{}) bool {
				if assert.IsType(t, &apiv1.CreateKeyResponse{}, i1) {
					r, _ := i1.(*apiv1.CreateKeyResponse)
					if assert.NotNil(t, r) {
						assert.Equal(t, "tpmkms:name=key2;attest-by=ak1", r.Name)
						assert.Equal(t, "tpmkms:name=key2;attest-by=ak1", r.CreateSignerRequest.SigningKey)
						if assert.NotNil(t, r.CreateSignerRequest.Signer) {
							assert.Implements(t, (*crypto.Signer)(nil), r.CreateSignerRequest.Signer)
						}
						return true
					}
				}
				return false
			},
		},
		{
			name: "ok/ak2",
			fields: fields{
				tpm: tpmWithAK,
			},
			args: args{
				req: &apiv1.CreateKeyRequest{
					Name:               "tpmkms:name=ak2;ak=true",
					SignatureAlgorithm: apiv1.SHA256WithRSA,
					Bits:               2048,
				},
			},
			assertFunc: func(tt assert.TestingT, i1 interface{}, i2 ...interface{}) bool {
				if assert.IsType(t, &apiv1.CreateKeyResponse{}, i1) {
					r, _ := i1.(*apiv1.CreateKeyResponse)
					if assert.NotNil(t, r) {
						assert.Equal(t, "tpmkms:name=ak2;ak=true", r.Name)
						assert.Equal(t, apiv1.CreateSignerRequest{}, r.CreateSignerRequest)
						return true
					}
				}
				return false
			},
		},
		{
			name: "ok/ecdsa-key",
			fields: fields{
				tpm: tpmWithAK,
			},
			args: args{
				req: &apiv1.CreateKeyRequest{
					Name:               "tpmkms:name=ecdsa-key",
					SignatureAlgorithm: apiv1.ECDSAWithSHA256,
				},
			},
			assertFunc: func(tt assert.TestingT, i1 interface{}, i2 ...interface{}) bool {
				if assert.IsType(t, &apiv1.CreateKeyResponse{}, i1) {
					r, _ := i1.(*apiv1.CreateKeyResponse)
					if assert.NotNil(t, r) {
						assert.Equal(t, "tpmkms:name=ecdsa-key", r.Name)
						assert.Equal(t, "tpmkms:name=ecdsa-key", r.CreateSignerRequest.SigningKey)
						if assert.NotNil(t, r.CreateSignerRequest.Signer) {
							assert.Implements(t, (*crypto.Signer)(nil), r.CreateSignerRequest.Signer)
						}
						return true
					}
				}
				return false
			},
		},
		{
			name: "fail/empty-name",
			fields: fields{
				tpm: tpmWithAK,
			},
			args: args{
				req: &apiv1.CreateKeyRequest{
					Name: "",
				},
			},
			assertFunc: func(tt assert.TestingT, i1 interface{}, i2 ...interface{}) bool {
				if assert.IsType(t, &apiv1.CreateKeyResponse{}, i1) {
					r, _ := i1.(*apiv1.CreateKeyResponse)
					return assert.Nil(t, r)
				}
				return false
			},
			expErr: errors.New("createKeyRequest 'name' cannot be empty"),
		},
		{
			name: "fail/negative-bits",
			fields: fields{
				tpm: tpmWithAK,
			},
			args: args{
				req: &apiv1.CreateKeyRequest{
					Name: "tpmkms:name=key1",
					Bits: -1,
				},
			},
			assertFunc: func(tt assert.TestingT, i1 interface{}, i2 ...interface{}) bool {
				if assert.IsType(t, &apiv1.CreateKeyResponse{}, i1) {
					r, _ := i1.(*apiv1.CreateKeyResponse)
					return assert.Nil(t, r)
				}
				return false
			},
			expErr: errors.New("createKeyRequest 'bits' cannot be negative"),
		},
		{
			name: "fail/ak-cannot-be-attested",
			fields: fields{
				tpm: tpmWithAK,
			},
			args: args{
				req: &apiv1.CreateKeyRequest{
					Name:               "tpmkms:name=akx;ak=true;attest-by=ak1",
					SignatureAlgorithm: apiv1.SHA256WithRSA,
					Bits:               2048,
				},
			},
			assertFunc: func(tt assert.TestingT, i1 interface{}, i2 ...interface{}) bool {
				if assert.IsType(t, &apiv1.CreateKeyResponse{}, i1) {
					r, _ := i1.(*apiv1.CreateKeyResponse)
					return assert.Nil(t, r)
				}
				return false
			},
			expErr: fmt.Errorf(`failed parsing "tpmkms:name=akx;ak=true;attest-by=ak1": "ak" and "attest-by" are mutually exclusive`),
		},
		{
			name: "fail/invalid-algorithm",
			fields: fields{
				tpm: tpmWithAK,
			},
			args: args{
				req: &apiv1.CreateKeyRequest{
					Name:               "tpmkms:name=key1",
					SignatureAlgorithm: apiv1.SignatureAlgorithm(-1),
					Bits:               1024,
				},
			},
			assertFunc: func(tt assert.TestingT, i1 interface{}, i2 ...interface{}) bool {
				if assert.IsType(t, &apiv1.CreateKeyResponse{}, i1) {
					r, _ := i1.(*apiv1.CreateKeyResponse)
					return assert.Nil(t, r)
				}
				return false
			},
			expErr: errors.New(`TPMKMS does not support signature algorithm "unknown(-1)"`),
		},
		{
			name: "fail/ecdsa-ak",
			fields: fields{
				tpm: tpmWithAK,
			},
			args: args{
				req: &apiv1.CreateKeyRequest{
					Name:               "tpmkms:name=invalidAK;ak=true",
					SignatureAlgorithm: apiv1.ECDSAWithSHA256,
				},
			},
			assertFunc: func(tt assert.TestingT, i1 interface{}, i2 ...interface{}) bool {
				if assert.IsType(t, &apiv1.CreateKeyResponse{}, i1) {
					r, _ := i1.(*apiv1.CreateKeyResponse)
					return assert.Nil(t, r)
				}
				return false
			},
			expErr: errors.New(`AKs must be RSA keys`),
		},
		{
			name: "fail/ak-3072-bits",
			fields: fields{
				tpm: tpmWithAK,
			},
			args: args{
				req: &apiv1.CreateKeyRequest{
					Name:               "tpmkms:name=invalidAK;ak=true",
					SignatureAlgorithm: apiv1.SHA256WithRSA,
					Bits:               3072,
				},
			},
			assertFunc: func(tt assert.TestingT, i1 interface{}, i2 ...interface{}) bool {
				if assert.IsType(t, &apiv1.CreateKeyResponse{}, i1) {
					r, _ := i1.(*apiv1.CreateKeyResponse)
					return assert.Nil(t, r)
				}
				return false
			},
			expErr: errors.New(`creating 3072 bit AKs is not supported; AKs must be RSA 2048 bits`),
		},
		{
			name: "fail/key-exists",
			fields: fields{
				tpm: tpmWithAK,
			},
			args: args{
				req: &apiv1.CreateKeyRequest{
					Name:               "tpmkms:name=key1",
					SignatureAlgorithm: apiv1.SHA256WithRSA,
					Bits:               1024,
				},
			},
			assertFunc: func(tt assert.TestingT, i1 interface{}, i2 ...interface{}) bool {
				if assert.IsType(t, &apiv1.CreateKeyResponse{}, i1) {
					r, _ := i1.(*apiv1.CreateKeyResponse)
					return assert.Nil(t, r)
				}
				return false
			},
			expErr: errors.New(`failed creating key "key1": already exists`),
		},
		{
			name: "fail/attested-key-exists",
			fields: fields{
				tpm: tpmWithAK,
			},
			args: args{
				req: &apiv1.CreateKeyRequest{
					Name:               "tpmkms:name=key2;attest-by=ak1",
					SignatureAlgorithm: apiv1.SHA256WithRSA,
					Bits:               1024,
				},
			},
			assertFunc: func(tt assert.TestingT, i1 interface{}, i2 ...interface{}) bool {
				if assert.IsType(t, &apiv1.CreateKeyResponse{}, i1) {
					r, _ := i1.(*apiv1.CreateKeyResponse)
					return assert.Nil(t, r)
				}
				return false
			},
			expErr: errors.New(`failed creating key "key2": already exists`),
		},
		{
			name: "fail/ak2-exists",
			fields: fields{
				tpm: tpmWithAK,
			},
			args: args{
				req: &apiv1.CreateKeyRequest{
					Name:               "tpmkms:name=ak2;ak=true",
					SignatureAlgorithm: apiv1.SHA256WithRSA,
					Bits:               2048,
				},
			},
			assertFunc: func(tt assert.TestingT, i1 interface{}, i2 ...interface{}) bool {
				if assert.IsType(t, &apiv1.CreateKeyResponse{}, i1) {
					r, _ := i1.(*apiv1.CreateKeyResponse)
					return assert.Nil(t, r)
				}
				return false
			},
			expErr: errors.New(`failed creating AK "ak2": already exists`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &TPMKMS{
				tpm: tt.fields.tpm,
			}
			got, err := k.CreateKey(tt.args.req)
			if tt.expErr != nil {
				assert.EqualError(t, err, tt.expErr.Error())
				return
			}

			assert.NoError(t, err)
			assert.True(t, tt.assertFunc(t, got))
		})
	}
}

func TestTPMKMS_CreateSigner(t *testing.T) {
	tpmWithKey := newSimulatedTPM(t, withKey("key1"))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	type fields struct {
		tpm *tpmp.TPM
	}
	type args struct {
		req *apiv1.CreateSignerRequest
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		expErr error
	}{
		{
			name: "ok/signer",
			fields: fields{
				tpm: tpmWithKey,
			},
			args: args{
				req: &apiv1.CreateSignerRequest{
					Signer: key,
				},
			},
		},
		{
			name: "ok/signing-key",
			fields: fields{
				tpm: tpmWithKey,
			},
			args: args{
				req: &apiv1.CreateSignerRequest{
					SigningKey: "tpmkms:name=key1",
				},
			},
		},
		{
			name: "fail/empty",
			fields: fields{
				tpm: tpmWithKey,
			},
			args: args{
				req: &apiv1.CreateSignerRequest{
					SigningKey: "",
				},
			},
			expErr: errors.New("createSignerRequest 'signingKey' cannot be empty"),
		},
		{
			name: "fail/ak",
			fields: fields{
				tpm: tpmWithKey,
			},
			args: args{
				req: &apiv1.CreateSignerRequest{
					SigningKey: "tpmkms:name=ak1;ak=true",
				},
			},
			expErr: errors.New("signing with an AK currently not supported"),
		},
		{
			name: "fail/unknown-key",
			fields: fields{
				tpm: tpmWithKey,
			},
			args: args{
				req: &apiv1.CreateSignerRequest{
					SigningKey: "tpmkms:name=unknown-key",
				},
			},
			expErr: fmt.Errorf(`failed getting key "unknown-key": not found`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &TPMKMS{
				tpm: tt.fields.tpm,
			}
			got, err := k.CreateSigner(tt.args.req)
			if tt.expErr != nil {
				assert.EqualError(t, err, tt.expErr.Error())
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, got)
		})
	}
}

func TestTPMKMS_GetPublicKey(t *testing.T) {
	tpmWithKey := newSimulatedTPM(t, withKey("key1"))
	_, err := tpmWithKey.CreateAK(context.Background(), "ak1")
	require.NoError(t, err)
	type fields struct {
		tpm *tpmp.TPM
	}
	type args struct {
		req *apiv1.GetPublicKeyRequest
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   crypto.PublicKey
		expErr error
	}{
		{
			name: "ok/key",
			fields: fields{
				tpm: tpmWithKey,
			},
			args: args{
				req: &apiv1.GetPublicKeyRequest{
					Name: "tpmkms:name=key1",
				},
			},
		},
		{
			name: "ok/ak",
			fields: fields{
				tpm: tpmWithKey,
			},
			args: args{
				req: &apiv1.GetPublicKeyRequest{
					Name: "tpmkms:name=ak1;ak=true",
				},
			},
		},
		{
			name: "fail/empty",
			fields: fields{
				tpm: tpmWithKey,
			},
			args: args{
				req: &apiv1.GetPublicKeyRequest{
					Name: "",
				},
			},
			expErr: errors.New("getPublicKeyRequest 'name' cannot be empty"),
		},
		{
			name: "fail/unknown-key",
			fields: fields{
				tpm: tpmWithKey,
			},
			args: args{
				req: &apiv1.GetPublicKeyRequest{
					Name: "tpmkms:name=unknown-key",
				},
			},
			expErr: fmt.Errorf(`failed getting key "unknown-key": not found`),
		},
		{
			name: "fail/unknown-ak",
			fields: fields{
				tpm: tpmWithKey,
			},
			args: args{
				req: &apiv1.GetPublicKeyRequest{
					Name: "tpmkms:name=unknown-ak;ak=true",
				},
			},
			expErr: fmt.Errorf(`failed getting AK "unknown-ak": not found`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &TPMKMS{
				tpm: tt.fields.tpm,
			}
			got, err := k.GetPublicKey(tt.args.req)
			if tt.expErr != nil {
				assert.EqualError(t, err, tt.expErr.Error())
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, got)
		})
	}
}

func TestTPMKMS_LoadCertificate(t *testing.T) {
	ctx := context.Background()
	tpm := newSimulatedTPM(t)
	config := tpmp.CreateKeyConfig{
		Algorithm: "RSA",
		Size:      1024,
	}
	key, err := tpm.CreateKey(ctx, "key1", config)
	require.NoError(t, err)
	ak, err := tpm.CreateAK(ctx, "ak1")
	require.NoError(t, err)
	_, err = tpm.CreateKey(ctx, "keyWithoutCertificate", config)
	require.NoError(t, err)
	_, err = tpm.CreateAK(ctx, "akWithoutCertificate")
	require.NoError(t, err)
	ca, err := minica.New(
		minica.WithGetSignerFunc(
			func() (crypto.Signer, error) {
				return keyutil.GenerateSigner("RSA", "", 2048)
			},
		),
	)
	require.NoError(t, err)
	signer, err := key.Signer(ctx)
	require.NoError(t, err)
	publicKey := signer.Public()
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "testkey",
		},
		PublicKey: publicKey,
	}
	cert, err := ca.Sign(template)
	require.NoError(t, err)
	require.NotNil(t, cert)
	err = key.SetCertificateChain(ctx, []*x509.Certificate{cert, ca.Intermediate})
	require.NoError(t, err)
	akPub := ak.Public()
	require.Implements(t, (*crypto.PublicKey)(nil), akPub)
	template = &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "testak",
		},
		PublicKey: akPub,
	}
	akCert, err := ca.Sign(template)
	err = ak.SetCertificateChain(ctx, []*x509.Certificate{akCert, ca.Intermediate})
	require.NoError(t, err)
	type fields struct {
		tpm *tpmp.TPM
	}
	type args struct {
		req *apiv1.LoadCertificateRequest
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *x509.Certificate
		expErr error
	}{
		{
			name: "ok/ak",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.LoadCertificateRequest{
					Name: "tpmkms:name=ak1;ak=true",
				},
			},
			want: akCert,
		},
		{
			name: "ok/key",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.LoadCertificateRequest{
					Name: "tpmkms:name=key1",
				},
			},
			want: cert,
		},
		{
			name: "fail/empty",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.LoadCertificateRequest{
					Name: "",
				},
			},
			expErr: errors.New("loadCertificateRequest 'name' cannot be empty"),
		},
		{
			name: "fail/unknown-ak",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.LoadCertificateRequest{
					Name: "tpmkms:name=unknown-ak;ak=true",
				},
			},
			expErr: fmt.Errorf(`failed getting AK "unknown-ak": not found`),
		},
		{
			name: "fail/unknown-key",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.LoadCertificateRequest{
					Name: "tpmkms:name=unknown-key",
				},
			},
			expErr: fmt.Errorf(`failed getting key "unknown-key": not found`),
		},
		{
			name: "fail/ak-without-certificate",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.LoadCertificateRequest{
					Name: "tpmkms:name=akWithoutCertificate;ak=true",
				},
			},
			expErr: fmt.Errorf(`failed getting certificate chain for "akWithoutCertificate": no certificate chain stored`),
		},
		{
			name: "fail/key-without-certificate",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.LoadCertificateRequest{
					Name: "tpmkms:name=keyWithoutCertificate",
				},
			},
			expErr: fmt.Errorf(`failed getting certificate chain for "keyWithoutCertificate": no certificate chain stored`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &TPMKMS{
				tpm: tt.fields.tpm,
			}
			got, err := k.LoadCertificate(tt.args.req)
			if tt.expErr != nil {
				assert.EqualError(t, err, tt.expErr.Error())
				return
			}

			assert.NoError(t, err)
			if assert.NotNil(t, got) {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestTPMKMS_LoadCertificateChain(t *testing.T) {
	ctx := context.Background()
	tpm := newSimulatedTPM(t)
	config := tpmp.CreateKeyConfig{
		Algorithm: "RSA",
		Size:      1024,
	}
	key, err := tpm.CreateKey(ctx, "key1", config)
	require.NoError(t, err)
	ak, err := tpm.CreateAK(ctx, "ak1")
	require.NoError(t, err)
	_, err = tpm.CreateKey(ctx, "keyWithoutCertificate", config)
	require.NoError(t, err)
	_, err = tpm.CreateAK(ctx, "akWithoutCertificate")
	require.NoError(t, err)
	ca, err := minica.New(
		minica.WithGetSignerFunc(
			func() (crypto.Signer, error) {
				return keyutil.GenerateSigner("RSA", "", 2048)
			},
		),
	)
	require.NoError(t, err)
	signer, err := key.Signer(ctx)
	require.NoError(t, err)
	publicKey := signer.Public()
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "testkey",
		},
		PublicKey: publicKey,
	}
	cert, err := ca.Sign(template)
	require.NoError(t, err)
	require.NotNil(t, cert)
	err = key.SetCertificateChain(ctx, []*x509.Certificate{cert, ca.Intermediate})
	require.NoError(t, err)
	akPub := ak.Public()
	require.Implements(t, (*crypto.PublicKey)(nil), akPub)
	template = &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "testak",
		},
		PublicKey: akPub,
	}
	akCert, err := ca.Sign(template)
	err = ak.SetCertificateChain(ctx, []*x509.Certificate{akCert, ca.Intermediate})
	require.NoError(t, err)
	type fields struct {
		tpm *tpmp.TPM
	}
	type args struct {
		req *apiv1.LoadCertificateChainRequest
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []*x509.Certificate
		expErr error
	}{
		{
			name: "ok/ak",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.LoadCertificateChainRequest{
					Name: "tpmkms:name=ak1;ak=true",
				},
			},
			want: []*x509.Certificate{
				akCert,
				ca.Intermediate,
			},
		},
		{
			name: "ok/key",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.LoadCertificateChainRequest{
					Name: "tpmkms:name=key1",
				},
			},
			want: []*x509.Certificate{
				cert,
				ca.Intermediate,
			},
		},
		{
			name: "fail/empty",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.LoadCertificateChainRequest{
					Name: "",
				},
			},
			expErr: errors.New("loadCertificateChainRequest 'name' cannot be empty"),
		},
		{
			name: "fail/unknown-ak",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.LoadCertificateChainRequest{
					Name: "tpmkms:name=unknown-ak;ak=true",
				},
			},
			expErr: fmt.Errorf(`failed getting AK "unknown-ak": not found`),
		},
		{
			name: "fail/unknown-key",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.LoadCertificateChainRequest{
					Name: "tpmkms:name=unknown-key",
				},
			},
			expErr: fmt.Errorf(`failed getting key "unknown-key": not found`),
		},
		{
			name: "fail/ak-without-certificate",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.LoadCertificateChainRequest{
					Name: "tpmkms:name=akWithoutCertificate;ak=true",
				},
			},
			expErr: fmt.Errorf(`failed getting certificate chain for "akWithoutCertificate": no certificate chain stored`),
		},
		{
			name: "fail/key-without-certificate",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.LoadCertificateChainRequest{
					Name: "tpmkms:name=keyWithoutCertificate",
				},
			},
			expErr: fmt.Errorf(`failed getting certificate chain for "keyWithoutCertificate": no certificate chain stored`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &TPMKMS{
				tpm: tt.fields.tpm,
			}
			got, err := k.LoadCertificateChain(tt.args.req)
			if tt.expErr != nil {
				assert.EqualError(t, err, tt.expErr.Error())
				return
			}

			assert.NoError(t, err)
			if assert.NotNil(t, got) {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestTPMKMS_StoreCertificate(t *testing.T) {
	ctx := context.Background()
	tpm := newSimulatedTPM(t)
	config := tpmp.CreateKeyConfig{
		Algorithm: "RSA",
		Size:      1024,
	}
	key, err := tpm.CreateKey(ctx, "key1", config)
	require.NoError(t, err)
	ak, err := tpm.CreateAK(ctx, "ak1")
	require.NoError(t, err)
	ca, err := minica.New(
		minica.WithGetSignerFunc(
			func() (crypto.Signer, error) {
				return keyutil.GenerateSigner("RSA", "", 2048)
			},
		),
	)
	require.NoError(t, err)
	signer, err := key.Signer(ctx)
	require.NoError(t, err)
	publicKey := signer.Public()
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "testkey",
		},
		PublicKey: publicKey,
	}
	cert, err := ca.Sign(template)
	require.NoError(t, err)
	require.NotNil(t, cert)
	anotherPublicKey, _, err := keyutil.GenerateDefaultKeyPair()
	require.NoError(t, err)
	template = &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "testanotherkey",
		},
		PublicKey: anotherPublicKey,
	}
	anotherCert, err := ca.Sign(template)
	require.NoError(t, err)
	require.NotNil(t, anotherCert)
	akPub := ak.Public()
	require.Implements(t, (*crypto.PublicKey)(nil), akPub)
	template = &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "testak",
		},
		PublicKey: akPub,
	}
	akCert, err := ca.Sign(template)
	require.NoError(t, err)
	require.NotNil(t, akCert)
	type fields struct {
		tpm *tpmp.TPM
	}
	type args struct {
		req *apiv1.StoreCertificateRequest
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		expErr error
	}{
		{
			name: "ok/ak",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.StoreCertificateRequest{
					Name:        "tpmkms:name=ak1;ak=true",
					Certificate: akCert,
				},
			},
		},
		{
			name: "ok/key",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.StoreCertificateRequest{
					Name:        "tpmkms:name=key1",
					Certificate: cert,
				},
			},
		},
		{
			name: "fail/empty",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.StoreCertificateRequest{
					Name: "",
				},
			},
			expErr: errors.New("storeCertificateRequest 'name' cannot be empty"),
		},
		{
			name: "fail/unknown-ak",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.StoreCertificateRequest{
					Name:        "tpmkms:name=unknown-ak;ak=true",
					Certificate: akCert,
				},
			},
			expErr: fmt.Errorf(`failed getting AK "unknown-ak": not found`),
		},
		{
			name: "fail/unknown-key",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.StoreCertificateRequest{
					Name:        "tpmkms:name=unknown-key",
					Certificate: cert,
				},
			},
			expErr: fmt.Errorf(`failed getting key "unknown-key": not found`),
		},
		{
			name: "fail/wrong-certificate-for-ak",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.StoreCertificateRequest{
					Name:        "tpmkms:name=ak1;ak=true",
					Certificate: anotherCert,
				},
			},
			expErr: errors.New(`failed storing certificate for AK "ak1": AK public key does not match the leaf certificate public key`),
		},
		{
			name: "fail/wrong-certificate-for-key",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.StoreCertificateRequest{
					Name:        "tpmkms:name=key1",
					Certificate: anotherCert,
				},
			},
			expErr: errors.New(`failed storing certificate for key "key1": public key does not match the leaf certificate public key`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &TPMKMS{
				tpm: tt.fields.tpm,
			}
			err := k.StoreCertificate(tt.args.req)
			if tt.expErr != nil {
				assert.EqualError(t, err, tt.expErr.Error())
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestTPMKMS_StoreCertificateChain(t *testing.T) {
	ctx := context.Background()
	tpm := newSimulatedTPM(t)
	config := tpmp.CreateKeyConfig{
		Algorithm: "RSA",
		Size:      1024,
	}
	key, err := tpm.CreateKey(ctx, "key1", config)
	require.NoError(t, err)
	ak, err := tpm.CreateAK(ctx, "ak1")
	require.NoError(t, err)
	ca, err := minica.New(
		minica.WithGetSignerFunc(
			func() (crypto.Signer, error) {
				return keyutil.GenerateSigner("RSA", "", 2048)
			},
		),
	)
	require.NoError(t, err)
	signer, err := key.Signer(ctx)
	require.NoError(t, err)
	publicKey := signer.Public()
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "testkey",
		},
		PublicKey: publicKey,
	}
	cert, err := ca.Sign(template)
	require.NoError(t, err)
	require.NotNil(t, cert)
	anotherPublicKey, _, err := keyutil.GenerateDefaultKeyPair()
	require.NoError(t, err)
	template = &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "testanotherkey",
		},
		PublicKey: anotherPublicKey,
	}
	anotherCert, err := ca.Sign(template)
	require.NoError(t, err)
	require.NotNil(t, anotherCert)
	akPub := ak.Public()
	require.Implements(t, (*crypto.PublicKey)(nil), akPub)
	template = &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "testak",
		},
		PublicKey: akPub,
	}
	akCert, err := ca.Sign(template)
	require.NoError(t, err)
	require.NotNil(t, akCert)
	type fields struct {
		tpm *tpmp.TPM
	}
	type args struct {
		req *apiv1.StoreCertificateChainRequest
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		expErr error
	}{
		{
			name: "ok/ak",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.StoreCertificateChainRequest{
					Name:             "tpmkms:name=ak1;ak=true",
					CertificateChain: []*x509.Certificate{akCert, ca.Intermediate},
				},
			},
		},
		{
			name: "ok/key",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.StoreCertificateChainRequest{
					Name:             "tpmkms:name=key1",
					CertificateChain: []*x509.Certificate{cert, ca.Intermediate},
				},
			},
		},
		{
			name: "fail/empty",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.StoreCertificateChainRequest{
					Name: "",
				},
			},
			expErr: errors.New("storeCertificateChainRequest 'name' cannot be empty"),
		},
		{
			name: "fail/empty-chain",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.StoreCertificateChainRequest{
					Name:             "tpmkms:name=key1",
					CertificateChain: []*x509.Certificate{},
				},
			},
			expErr: errors.New("storeCertificateChainRequest 'certificateChain' cannot be empty"),
		},
		{
			name: "fail/unknown-ak",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.StoreCertificateChainRequest{
					Name:             "tpmkms:name=unknown-ak;ak=true",
					CertificateChain: []*x509.Certificate{akCert, ca.Intermediate},
				},
			},
			expErr: fmt.Errorf(`failed getting AK "unknown-ak": not found`),
		},
		{
			name: "fail/unknown-key",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.StoreCertificateChainRequest{
					Name:             "tpmkms:name=unknown-key",
					CertificateChain: []*x509.Certificate{cert, ca.Intermediate},
				},
			},
			expErr: fmt.Errorf(`failed getting key "unknown-key": not found`),
		},
		{
			name: "fail/wrong-certificate-for-ak",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.StoreCertificateChainRequest{
					Name:             "tpmkms:name=ak1;ak=true",
					CertificateChain: []*x509.Certificate{anotherCert, ca.Intermediate},
				},
			},
			expErr: errors.New(`failed storing certificate for AK "ak1": AK public key does not match the leaf certificate public key`),
		},
		{
			name: "fail/wrong-certificate-for-key",
			fields: fields{
				tpm: tpm,
			},
			args: args{
				req: &apiv1.StoreCertificateChainRequest{
					Name:             "tpmkms:name=key1",
					CertificateChain: []*x509.Certificate{anotherCert, ca.Intermediate},
				},
			},
			expErr: errors.New(`failed storing certificate for key "key1": public key does not match the leaf certificate public key`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &TPMKMS{
				tpm: tt.fields.tpm,
			}
			err := k.StoreCertificateChain(tt.args.req)
			if tt.expErr != nil {
				assert.EqualError(t, err, tt.expErr.Error())
				return
			}

			assert.NoError(t, err)
		})
	}
}

// TODO(hs): dedupe these structs by creating some shared helper
// functions for running a fake attestation ca tpm.
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
	EK           []byte                `json:"ek,omitempty"`
	EKCerts      [][]byte              `json:"ekCerts,omitempty"`
	AKCert       []byte                `json:"akCert,omitempty"`
	AttestParams attestationParameters `json:"params,omitempty"`
}

type attestationResponse struct {
	Credential []byte `json:"credential"`
	Secret     []byte `json:"secret"` // encrypted secret
}

type secretRequest struct {
	Secret []byte `json:"secret"` // decrypted secret
}

type secretResponse struct {
	CertificateChain [][]byte `json:"chain"`
}

type customAttestationClient struct {
	chain []*x509.Certificate
}

func (c *customAttestationClient) Attest(context.Context) ([]*x509.Certificate, error) {
	return c.chain, nil
}

func TestTPMKMS_CreateAttestation(t *testing.T) {
	ctx := context.Background()
	tpm := newSimulatedTPM(t)
	eks, err := tpm.GetEKs(ctx)
	require.NoError(t, err)
	ek := getPreferredEK(eks)
	ekKeyID, err := generateKeyID(ek.Public())
	require.NoError(t, err)
	ekKeyURL := ekURL(ekKeyID)
	config := tpmp.AttestKeyConfig{
		Algorithm:      "RSA",
		Size:           1024,
		QualifyingData: []byte{1, 2, 3, 4},
	}
	ca, err := minica.New(
		minica.WithGetSignerFunc(
			func() (crypto.Signer, error) {
				return keyutil.GenerateSigner("RSA", "", 2048)
			},
		),
	)
	type fields struct {
		tpm                   *tpmp.TPM
		attestationCABaseURL  string
		attestationCARootFile string
		attestationCAInsecure bool
		permanentIdentifier   string
	}
	type args struct {
		req *apiv1.CreateAttestationRequest
	}
	type test struct {
		server *httptest.Server
		fields fields
		args   args
		want   *apiv1.CreateAttestationResponse
		expErr error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/empty-name": func(t *testing.T) test {
			return test{
				args: args{
					req: &apiv1.CreateAttestationRequest{
						Name: "",
					},
				},
				expErr: errors.New("createAttestationRequest 'name' cannot be empty"),
			}
		},
		"fail/ak-attestby-mutually-exclusive": func(t *testing.T) test {
			return test{
				args: args{
					req: &apiv1.CreateAttestationRequest{
						Name: "tpmkms:name=keyx;ak=true;attest-by=ak1",
					},
				},
				expErr: errors.New(`failed parsing "tpmkms:name=keyx;ak=true;attest-by=ak1": "ak" and "attest-by" are mutually exclusive`),
			}
		},
		"fail/non-matching-permanent-identifier": func(t *testing.T) test {
			_, err = tpm.CreateAK(ctx, "newAKWithoutCert")
			require.NoError(t, err)
			_, err = tpm.AttestKey(ctx, "newAKWithoutCert", "newkey", config)
			require.NoError(t, err)
			return test{
				fields: fields{
					tpm:                 tpm,
					permanentIdentifier: "wrong-provided-permanent-identifier",
				},
				args: args{
					req: &apiv1.CreateAttestationRequest{
						Name: "tpmkms:name=newkey", // newkey was attested by the newAKWithoutCert at creation time
					},
				},
				expErr: fmt.Errorf(`the provided permanent identifier "wrong-provided-permanent-identifier" does not match the EK URL %q`, ekKeyURL.String()),
			}
		},
		"fail/unknown-key": func(t *testing.T) test {
			return test{
				fields: fields{
					tpm: tpm,
				},
				args: args{
					req: &apiv1.CreateAttestationRequest{
						Name: "tpmkms:name=keyx",
					},
				},
				expErr: errors.New(`failed getting key "keyx": not found`),
			}
		},
		"fail/non-attested-key": func(t *testing.T) test {
			createConfig := tpmp.CreateKeyConfig{Algorithm: "RSA", Size: 1024}
			_, err = tpm.CreateKey(ctx, "nonAttestedKey", createConfig)
			return test{
				fields: fields{
					tpm: tpm,
				},
				args: args{
					req: &apiv1.CreateAttestationRequest{
						Name: "tpmkms:name=nonAttestedKey",
					},
				},
				expErr: errors.New(`key "nonAttestedKey" was not attested`),
			}
		},
		"fail/unknown-ak": func(t *testing.T) test {
			return test{
				fields: fields{
					tpm: tpm,
				},
				args: args{
					req: &apiv1.CreateAttestationRequest{
						Name: "tpmkms:name=unknownAK;ak=true",
					},
				},
				expErr: errors.New(`failed getting AK "unknownAK": not found`),
			}
		},
		"fail/create-attestor-client": func(t *testing.T) test {
			_, err = tpm.CreateAK(ctx, "ak2WithoutCert")
			require.NoError(t, err)
			_, err = tpm.AttestKey(ctx, "ak2WithoutCert", "key3", config)
			require.NoError(t, err)
			return test{
				fields: fields{
					tpm:                 tpm,
					permanentIdentifier: ekKeyURL.String(),
				},
				args: args{
					req: &apiv1.CreateAttestationRequest{
						Name: "tpmkms:name=key3", // key3 was attested by the ak2WithoutCert at creation time
					},
				},
				expErr: fmt.Errorf(`failed creating attestor client: failed creating attestation client: attestation CA base URL must not be empty`),
			}
		},
		"fail/attest": func(t *testing.T) test {
			_, err = tpm.CreateAK(ctx, "ak3WithoutCert")
			require.NoError(t, err)
			_, err = tpm.AttestKey(ctx, "ak3WithoutCert", "key4", config)
			require.NoError(t, err)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/attest":
					w.WriteHeader(http.StatusBadRequest)
				default:
					t.Errorf("unexpected %q request to %q", r.Method, r.URL)
				}
			})
			s := httptest.NewServer(handler)
			return test{
				server: s,
				fields: fields{
					tpm:                  tpm,
					attestationCABaseURL: s.URL,
					permanentIdentifier:  ekKeyURL.String(),
				},
				args: args{
					req: &apiv1.CreateAttestationRequest{
						Name: "tpmkms:name=key4", // key4 was attested by the ak3WithoutCert at creation time
					},
				},
				expErr: fmt.Errorf(`failed performing AK attestation: failed attesting AK: POST %q failed with HTTP status "400 Bad Request"`, fmt.Sprintf("%s/attest", s.URL)),
			}
		},
		"fail/set-ak-certificate-chain": func(t *testing.T) test {
			ak4WithoutCert, err := tpm.CreateAK(ctx, "ak4WithoutCert")
			require.NoError(t, err)
			_, err = tpm.AttestKey(ctx, "ak4WithoutCert", "key5", config)
			require.NoError(t, err)
			params, err := ak4WithoutCert.AttestationParameters(context.Background())
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
					parsedEK, err := x509.ParsePKIXPublicKey(ar.EK)
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
						CertificateChain: [][]byte{
							ca.Intermediate.Raw, // No leaf returned
						},
					})
				default:
					t.Errorf("unexpected %q request to %q", r.Method, r.URL)
				}
			})
			s := httptest.NewServer(handler)
			return test{
				server: s,
				fields: fields{
					tpm:                  tpm,
					attestationCABaseURL: s.URL,
					permanentIdentifier:  ekKeyURL.String(),
				},
				args: args{
					req: &apiv1.CreateAttestationRequest{
						Name: "tpmkms:name=key5", // key5 was attested by ak3WithoutCert at creation time
					},
				},
				want:   nil,
				expErr: fmt.Errorf(`failed storing AK certificate chain: AK public key does not match the leaf certificate public key`),
			}
		},
		"fail/ak-certificate-chain-has-invalid-identity": func(t *testing.T) test {
			ak5WithoutCert, err := tpm.CreateAK(ctx, "ak5WithoutCert")
			require.NoError(t, err)
			_, err = tpm.AttestKey(ctx, "ak5WithoutCert", "key6", config)
			require.NoError(t, err)
			ak5Pub := ak5WithoutCert.Public()
			require.Implements(t, (*crypto.PublicKey)(nil), ak5Pub)
			template := &x509.Certificate{ // NOTE: missing EK URI SAN
				Subject: pkix.Name{
					CommonName: "testinvalidak",
				},
				PublicKey: ak5Pub,
			}
			invalidAKIdentityCert, err := ca.Sign(template)
			require.NoError(t, err)
			require.NotNil(t, invalidAKIdentityCert)
			params, err := ak5WithoutCert.AttestationParameters(context.Background())
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
					parsedEK, err := x509.ParsePKIXPublicKey(ar.EK)
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
						CertificateChain: [][]byte{
							invalidAKIdentityCert.Raw, // AK certificate without EK URI SAN
							ca.Intermediate.Raw,
						},
					})
				default:
					t.Errorf("unexpected %q request to %q", r.Method, r.URL)
				}
			})
			s := httptest.NewServer(handler)
			return test{
				server: s,
				fields: fields{
					tpm:                  tpm,
					attestationCABaseURL: s.URL,
					permanentIdentifier:  ekKeyURL.String(),
				},
				args: args{
					req: &apiv1.CreateAttestationRequest{
						Name: "tpmkms:name=key6", // key6 was attested by ak5WithoutCert at creation time
					},
				},
				want:   nil,
				expErr: fmt.Errorf(`AK certificate (chain) not valid for EK %q: AK certificate does not contain valid identity`, ekKeyURL.String()),
			}
		},
		"ok": func(t *testing.T) test {
			akWithExistingCert, err := tpm.CreateAK(ctx, "akWithExistingCert")
			require.NoError(t, err)
			key, err := tpm.AttestKey(ctx, "akWithExistingCert", "key1", config)
			require.NoError(t, err)
			keyParams, err := key.CertificationParameters(ctx)
			require.NoError(t, err)
			signer, err := key.Signer(ctx)
			require.NoError(t, err)
			akPub := akWithExistingCert.Public()
			require.Implements(t, (*crypto.PublicKey)(nil), akPub)
			template := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "testak",
				},
				URIs:      []*url.URL{ekKeyURL},
				PublicKey: akPub,
			}
			validAKCert, err := ca.Sign(template)
			require.NoError(t, err)
			require.NotNil(t, validAKCert)
			err = akWithExistingCert.SetCertificateChain(ctx, []*x509.Certificate{validAKCert, ca.Intermediate})
			require.NoError(t, err)
			return test{
				fields: fields{
					tpm:                 tpm,
					permanentIdentifier: ekKeyURL.String(),
				},
				args: args{
					req: &apiv1.CreateAttestationRequest{
						Name: "tpmkms:name=key1", // key1 was attested by the akWithExistingCert at creation time
					},
				},
				want: &apiv1.CreateAttestationResponse{
					Certificate:      validAKCert,
					CertificateChain: []*x509.Certificate{validAKCert, ca.Intermediate},
					PublicKey:        signer.Public(),
					CertificationParameters: &apiv1.CertificationParameters{
						Public:            keyParams.Public,
						CreateData:        keyParams.CreateData,
						CreateAttestation: keyParams.CreateAttestation,
						CreateSignature:   keyParams.CreateSignature,
					},
					PermanentIdentifier: ekKeyURL.String(),
				},
				expErr: nil,
			}
		},
		"ok/new-chain": func(t *testing.T) test {
			akWithoutCert, err := tpm.CreateAK(ctx, "akWithoutCert")
			require.NoError(t, err)
			key, err := tpm.AttestKey(ctx, "akWithoutCert", "key2", config)
			require.NoError(t, err)
			keyParams, err := key.CertificationParameters(ctx)
			require.NoError(t, err)
			signer, err := key.Signer(ctx)
			require.NoError(t, err)
			akPubNew := akWithoutCert.Public()
			require.Implements(t, (*crypto.PublicKey)(nil), akPubNew)
			template := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "testnewak",
				},
				URIs:      []*url.URL{ekKeyURL},
				PublicKey: akPubNew,
			}
			newAKCert, err := ca.Sign(template)
			require.NoError(t, err)
			require.NotNil(t, newAKCert)
			params, err := akWithoutCert.AttestationParameters(context.Background())
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
				newAKCert.Raw,
				ca.Intermediate.Raw,
			}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/attest":
					var ar attestationRequest
					err := json.NewDecoder(r.Body).Decode(&ar)
					require.NoError(t, err)
					parsedEK, err := x509.ParsePKIXPublicKey(ar.EK)
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
					tpm:                  tpm,
					attestationCABaseURL: s.URL,
					permanentIdentifier:  ekKeyURL.String(),
				},
				args: args{
					req: &apiv1.CreateAttestationRequest{
						Name: "tpmkms:name=key2", // key2 was attested by akWithoutCert at creation time
					},
				},
				want: &apiv1.CreateAttestationResponse{
					Certificate:      newAKCert,
					CertificateChain: []*x509.Certificate{newAKCert, ca.Intermediate},
					PublicKey:        signer.Public(),
					CertificationParameters: &apiv1.CertificationParameters{
						Public:            keyParams.Public,
						CreateData:        keyParams.CreateData,
						CreateAttestation: keyParams.CreateAttestation,
						CreateSignature:   keyParams.CreateSignature,
					},
					PermanentIdentifier: ekKeyURL.String(),
				},
				expErr: nil,
			}
		},
		"ok/new-chain-with-custom-attestor-client": func(t *testing.T) test {
			ak6WithoutCert, err := tpm.CreateAK(ctx, "ak6WithoutCert")
			require.NoError(t, err)
			key, err := tpm.AttestKey(ctx, "ak6WithoutCert", "key7", config)
			require.NoError(t, err)
			keyParams, err := key.CertificationParameters(ctx)
			require.NoError(t, err)
			signer, err := key.Signer(ctx)
			require.NoError(t, err)
			ak6Pub := ak6WithoutCert.Public()
			require.Implements(t, (*crypto.PublicKey)(nil), ak6Pub)
			template := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "testak6",
				},
				URIs:      []*url.URL{ekKeyURL},
				PublicKey: ak6Pub,
			}
			ak6Cert, err := ca.Sign(template)
			require.NoError(t, err)
			require.NotNil(t, ak6Cert)
			return test{
				fields: fields{
					tpm:                 tpm,
					permanentIdentifier: ekKeyURL.String(),
				},
				args: args{
					req: &apiv1.CreateAttestationRequest{
						Name: "tpmkms:name=key7", // key7 was attested by ak6WithoutCert at creation time
						AttestationClient: &customAttestationClient{
							chain: []*x509.Certificate{ak6Cert, ca.Intermediate},
						},
					},
				},
				want: &apiv1.CreateAttestationResponse{
					Certificate:      ak6Cert,
					CertificateChain: []*x509.Certificate{ak6Cert, ca.Intermediate},
					PublicKey:        signer.Public(),
					CertificationParameters: &apiv1.CertificationParameters{
						Public:            keyParams.Public,
						CreateData:        keyParams.CreateData,
						CreateAttestation: keyParams.CreateAttestation,
						CreateSignature:   keyParams.CreateSignature,
					},
					PermanentIdentifier: ekKeyURL.String(),
				},
				expErr: nil,
			}
		},
		"ok/ak": func(t *testing.T) test {
			akWithCert, err := tpm.CreateAK(ctx, "akWithCert")
			require.NoError(t, err)
			akPub := akWithCert.Public()
			require.Implements(t, (*crypto.PublicKey)(nil), akPub)
			template := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "testak",
				},
				URIs:      []*url.URL{ekKeyURL},
				PublicKey: akPub,
			}
			validAKCert, err := ca.Sign(template)
			require.NoError(t, err)
			require.NotNil(t, validAKCert)
			err = akWithCert.SetCertificateChain(ctx, []*x509.Certificate{validAKCert, ca.Intermediate})
			require.NoError(t, err)
			return test{
				fields: fields{
					tpm:                 tpm,
					permanentIdentifier: ekKeyURL.String(),
				},
				args: args{
					req: &apiv1.CreateAttestationRequest{
						Name: "tpmkms:name=akWithCert;ak=true", // key1 was attested by the akWithExistingCert at creation time
					},
				},
				want: &apiv1.CreateAttestationResponse{
					Certificate:         validAKCert,
					CertificateChain:    []*x509.Certificate{validAKCert, ca.Intermediate},
					PublicKey:           akWithCert.Public(),
					PermanentIdentifier: ekKeyURL.String(),
				},
				expErr: nil,
			}
		},
	}
	for name, tt := range tests {
		tc := tt(t)
		t.Run(name, func(t *testing.T) {
			k := &TPMKMS{
				tpm:                   tc.fields.tpm,
				attestationCABaseURL:  tc.fields.attestationCABaseURL,
				attestationCARootFile: tc.fields.attestationCARootFile,
				attestationCAInsecure: tc.fields.attestationCAInsecure,
				permanentIdentifier:   tc.fields.permanentIdentifier,
			}
			if tc.server != nil {
				defer tc.server.Close()
			}
			got, err := k.CreateAttestation(tc.args.req)
			if tc.expErr != nil {
				assert.EqualError(t, err, tc.expErr.Error())
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func Test_hasValidIdentity(t *testing.T) {
	k := &TPMKMS{
		identityEarlyRenewalEnabled:     true,
		identityRenewalPeriodPercentage: 60,
	}
	ctx := context.Background()
	tpm := newSimulatedTPM(t)
	eks, err := tpm.GetEKs(ctx)
	require.NoError(t, err)
	ek := getPreferredEK(eks)
	ekKeyID, err := generateKeyID(ek.Public())
	require.NoError(t, err)
	ekKeyURL := ekURL(ekKeyID)
	ca, err := minica.New(
		minica.WithGetSignerFunc(
			func() (crypto.Signer, error) {
				return keyutil.GenerateSigner("RSA", "", 2048)
			},
		),
	)
	type args struct {
		k     *TPMKMS
		ak    *tpmp.AK
		ekURL *url.URL
	}
	type test struct {
		args   args
		expErr error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/no chain": func(t *testing.T) test {
			ak, err := tpm.CreateAK(ctx, "noChain")
			require.NoError(t, err)
			return test{
				args:   args{k, ak, ekKeyURL},
				expErr: errors.New("AK certificate not available"),
			}
		},
		"fail/not yet valid": func(t *testing.T) test {
			ak, err := tpm.CreateAK(ctx, "notYetValid")
			require.NoError(t, err)
			template := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "testak",
				},
				URIs:      []*url.URL{ekKeyURL},
				PublicKey: ak.Public(),
				NotBefore: time.Now().Add(1 * time.Hour),
			}
			notYetValidAKCert, err := ca.Sign(template)
			require.NoError(t, err)
			require.NotNil(t, notYetValidAKCert)
			err = ak.SetCertificateChain(ctx, []*x509.Certificate{notYetValidAKCert, ca.Intermediate})
			require.NoError(t, err)
			return test{
				args:   args{k, ak, ekKeyURL},
				expErr: errors.New("AK certificate not yet valid"),
			}
		},
		"fail/expired": func(t *testing.T) test {
			ak, err := tpm.CreateAK(ctx, "expiredAKCert")
			require.NoError(t, err)
			template := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "testak",
				},
				URIs:      []*url.URL{ekKeyURL},
				PublicKey: ak.Public(),
				NotAfter:  time.Now().Add(-1 * time.Hour),
			}
			expiredAKCert, err := ca.Sign(template)
			require.NoError(t, err)
			require.NotNil(t, expiredAKCert)
			err = ak.SetCertificateChain(ctx, []*x509.Certificate{expiredAKCert, ca.Intermediate})
			require.NoError(t, err)
			return test{
				args:   args{k, ak, ekKeyURL},
				expErr: errors.New("AK certificate has expired"),
			}
		},
		"fail/expiring": func(t *testing.T) test {
			ak, err := tpm.CreateAK(ctx, "expiringAKCert")
			require.NoError(t, err)
			template := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "testak",
				},
				URIs:      []*url.URL{ekKeyURL},
				PublicKey: ak.Public(),
				NotBefore: time.Now().Add(-5 * time.Hour),
				NotAfter:  time.Now().Add(1 * time.Hour), // less than half of the total time left
			}
			expiringAKCert, err := ca.Sign(template)
			require.NoError(t, err)
			require.NotNil(t, expiringAKCert)
			err = ak.SetCertificateChain(ctx, []*x509.Certificate{expiringAKCert, ca.Intermediate})
			require.NoError(t, err)
			return test{
				args:   args{k, ak, ekKeyURL},
				expErr: errors.New("AK certificate will expire soon"),
			}
		},
		"fail/no valid identity": func(t *testing.T) test {
			ak, err := tpm.CreateAK(ctx, "novalidIdentityAKCert")
			require.NoError(t, err)
			template := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "testak",
				},
				PublicKey: ak.Public(),
				NotBefore: time.Now().Add(-1 * time.Minute),
				NotAfter:  time.Now().Add(24 * time.Hour),
			}
			invalidIdentityAKCert, err := ca.Sign(template)
			require.NoError(t, err)
			require.NotNil(t, invalidIdentityAKCert)
			err = ak.SetCertificateChain(ctx, []*x509.Certificate{invalidIdentityAKCert, ca.Intermediate})
			require.NoError(t, err)
			return test{
				args:   args{k, ak, ekKeyURL},
				expErr: errors.New("AK certificate does not contain valid identity"),
			}
		},
		"ok": func(t *testing.T) test {
			ak, err := tpm.CreateAK(ctx, "validAKCert")
			require.NoError(t, err)
			template := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "testak",
				},
				URIs:      []*url.URL{ekKeyURL},
				PublicKey: ak.Public(),
				NotBefore: time.Now().Add(-1 * time.Minute),
				NotAfter:  time.Now().Add(24 * time.Hour),
			}
			validAKCert, err := ca.Sign(template)
			require.NoError(t, err)
			require.NotNil(t, validAKCert)
			err = ak.SetCertificateChain(ctx, []*x509.Certificate{validAKCert, ca.Intermediate})
			require.NoError(t, err)
			return test{
				args:   args{k, ak, ekKeyURL},
				expErr: nil,
			}
		},
	}

	for name, tt := range tests {
		tc := tt(t)
		t.Run(name, func(t *testing.T) {
			err := tc.args.k.hasValidIdentity(tc.args.ak, tc.args.ekURL)
			if tc.expErr != nil {
				assert.EqualError(t, err, tc.expErr.Error())
				return
			}

			assert.NoError(t, err)
		})
	}
}
