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
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/simulator"
	"go.step.sm/crypto/tpm/storage"
)

type newSimulatedTPMOption func(t *testing.T, tpm *tpm.TPM)

func withAK(name string) newSimulatedTPMOption {
	return func(t *testing.T, instance *tpm.TPM) {
		t.Helper()
		_, err := instance.CreateAK(context.Background(), name)
		require.NoError(t, err)
	}
}

func withKey(name string) newSimulatedTPMOption {
	return func(t *testing.T, instance *tpm.TPM) {
		t.Helper()
		config := tpm.CreateKeyConfig{
			Algorithm: "RSA",
			Size:      1024,
		}
		_, err := instance.CreateKey(context.Background(), name, config)
		require.NoError(t, err)
	}
}

func newSimulatedTPM(t *testing.T, opts ...newSimulatedTPMOption) *tpm.TPM {
	t.Helper()
	tmpDir := t.TempDir()
	tpm, err := tpm.New(withSimulator(t), tpm.WithStore(storage.NewDirstore(tmpDir)))
	require.NoError(t, err)
	for _, applyTo := range opts {
		applyTo(t, tpm)
	}
	return tpm
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
	sim = simulator.New()
	err := sim.Open()
	require.NoError(t, err)
	return tpm.WithSimulator(sim)
}

func TestTPMKMS_CreateKey(t *testing.T) {
	tpmWithAK := newSimulatedTPM(t, withAK("ak1"))
	type fields struct {
		tpm *tpm.TPM
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
						assert.Equal(t, apiv1.CreateSignerRequest{SigningKey: "tpmkms:name=key1"}, r.CreateSignerRequest)
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
						assert.Equal(t, apiv1.CreateSignerRequest{SigningKey: "tpmkms:name=key2;attest-by=ak1"}, r.CreateSignerRequest)
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
					Bits:               1024,
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
						assert.Equal(t, apiv1.CreateSignerRequest{SigningKey: "tpmkms:name=ecdsa-key"}, r.CreateSignerRequest)
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
			name: "fail/invalid-algorithm",
			fields: fields{
				tpm: tpmWithAK,
			},
			args: args{
				req: &apiv1.CreateKeyRequest{
					Name:               "tpmkms:name=akx;ak=true;attest-by=ak1",
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
			expErr: fmt.Errorf(`failed parsing "tpmkms:name=akx;ak=true;attest-by=ak1": "ak" and "attestBy" are mutually exclusive`),
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
		tpm *tpm.TPM
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
	type fields struct {
		tpm *tpm.TPM
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
			name: "ok",
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
			name: "fail/ak",
			fields: fields{
				tpm: tpmWithKey,
			},
			args: args{
				req: &apiv1.GetPublicKeyRequest{
					Name: "tpmkms:name=ak1;ak=true",
				},
			},
			expErr: errors.New("retrieving AK public key currently not supported"),
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
	instance := newSimulatedTPM(t)
	config := tpm.CreateKeyConfig{
		Algorithm: "RSA",
		Size:      1024,
	}
	key, err := instance.CreateKey(ctx, "key1", config)
	require.NoError(t, err)
	ak, err := instance.CreateAK(ctx, "ak1")
	require.NoError(t, err)
	_, err = instance.CreateKey(ctx, "keyWithoutCertificate", config)
	require.NoError(t, err)
	_, err = instance.CreateAK(ctx, "akWithoutCertificate")
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
	err = ak.SetCertificateChain(ctx, []*x509.Certificate{akCert})
	require.NoError(t, err)
	type fields struct {
		tpm *tpm.TPM
	}
	type args struct {
		req *apiv1.LoadCertificateRequest
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
				tpm: instance,
			},
			args: args{
				req: &apiv1.LoadCertificateRequest{
					Name: "tpmkms:name=ak1;ak=true",
				},
			},
		},
		{
			name: "ok/key",
			fields: fields{
				tpm: instance,
			},
			args: args{
				req: &apiv1.LoadCertificateRequest{
					Name: "tpmkms:name=key1",
				},
			},
		},
		{
			name: "fail/empty",
			fields: fields{
				tpm: instance,
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
				tpm: instance,
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
				tpm: instance,
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
				tpm: instance,
			},
			args: args{
				req: &apiv1.LoadCertificateRequest{
					Name: "tpmkms:name=akWithoutCertificate;ak=true",
				},
			},
			expErr: fmt.Errorf(`failed getting certificate for "akWithoutCertificate": no certificate stored`),
		},
		{
			name: "fail/key-without-certificate",
			fields: fields{
				tpm: instance,
			},
			args: args{
				req: &apiv1.LoadCertificateRequest{
					Name: "tpmkms:name=keyWithoutCertificate",
				},
			},
			expErr: fmt.Errorf(`failed getting certificate for "keyWithoutCertificate": no certificate stored`),
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
			assert.NotNil(t, got)
		})
	}
}

func TestTPMKMS_StoreCertificate(t *testing.T) {
	ctx := context.Background()
	instance := newSimulatedTPM(t)
	config := tpm.CreateKeyConfig{
		Algorithm: "RSA",
		Size:      1024,
	}
	key, err := instance.CreateKey(ctx, "key1", config)
	require.NoError(t, err)
	ak, err := instance.CreateAK(ctx, "ak1")
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
		tpm *tpm.TPM
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
				tpm: instance,
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
				tpm: instance,
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
				tpm: instance,
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
				tpm: instance,
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
				tpm: instance,
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
				tpm: instance,
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
				tpm: instance,
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
