//go:build tpmsimulator

package platform

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/simulator"
	"go.step.sm/crypto/tpm/storage"
)

func mustTPM(t *testing.T) *tpm.TPM {
	t.Helper()

	sim, err := simulator.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, sim.Close())
	})
	require.NoError(t, sim.Open())

	dir := t.TempDir()

	stpm, err := tpm.New(tpm.WithSimulator(sim), tpm.WithStore(storage.NewDirstore(dir)))
	require.NoError(t, err)

	return stpm
}

func mustTPMDevice(t *testing.T) (*tpm.TPM, string, string) {
	t.Helper()

	sim, err := simulator.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, sim.Close())
	})
	require.NoError(t, sim.Open())

	dir := t.TempDir()
	stpm, err := tpm.New(tpm.WithSimulator(sim), tpm.WithStore(storage.NewDirstore(dir)))
	require.NoError(t, err)

	listener := &net.ListenConfig{}
	socket := filepath.Join(dir, "tpm.sock")
	ln, err := listener.Listen(t.Context(), "unix", socket)
	require.NoError(t, err)

	go func() {
		for {
			conn, err := ln.Accept()
			require.NoError(t, err)

			go func(conn net.Conn) {
				defer conn.Close()

				readBuf := make([]byte, 4096)
				n, err := conn.Read(readBuf)
				require.NoError(t, err)

				_, err = sim.Write(readBuf[:n])
				require.NoError(t, err)

				writeBuf := make([]byte, 4096)
				nr, err := sim.Read(writeBuf)
				require.NoError(t, err)

				_, err = conn.Write(writeBuf[:nr])
				require.NoError(t, err)
			}(conn)
		}
	}()

	return stpm, socket, dir
}

func mustTPMKMS(t *testing.T) (*KMS, *tpm.TPM) {
	t.Helper()

	stpm, sock, dir := mustTPMDevice(t)
	km := mustKMS(t, uri.New(Scheme, url.Values{
		"backend":           []string{"tpmkms"},
		"device":            []string{sock},
		"storage-directory": []string{dir},
	}).String())

	return km, stpm
}

func TestKMS_Type_tpm(t *testing.T) {
	kms1, stpm := mustTPMKMS(t)
	assert.Equal(t, apiv1.TPMKMS, kms1.Type())

	kms2, err := NewWithTPM(t.Context(), stpm)
	require.NoError(t, err)
	assert.Equal(t, apiv1.TPMKMS, kms2.Type())

}

func TestKMS_Close_tpm(t *testing.T) {
	kms1, stpm := mustTPMKMS(t)
	assert.NoError(t, kms1.Close())

	kms2, err := NewWithTPM(t.Context(), stpm)
	require.NoError(t, err)
	assert.NoError(t, kms2.Close())
}

func TestKMS_GetPublicKey_tpm(t *testing.T) {
	ctx := t.Context()
	kms1, stpm := mustTPMKMS(t)
	kms2, err := NewWithTPM(ctx, stpm)
	require.NoError(t, err)

	key, err := stpm.CreateKey(ctx, "key-1", tpm.CreateKeyConfig{
		Algorithm: "RSA",
		Size:      2048,
	})
	require.NoError(t, err)

	keySigner, err := key.Signer(ctx)
	require.NoError(t, err)

	ak, err := stpm.CreateAK(ctx, "ak-1")
	require.NoError(t, err)

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
		{"ok key", kms1, args{&apiv1.GetPublicKeyRequest{
			Name: "kms:name=key-1",
		}}, keySigner.Public(), assert.NoError},
		{"ok ak", kms1, args{&apiv1.GetPublicKeyRequest{
			Name: "kms:name=ak-1;ak=true",
		}}, ak.Public(), assert.NoError},
		{"ok key with tpm", kms2, args{&apiv1.GetPublicKeyRequest{
			Name: "kms:name=key-1",
		}}, keySigner.Public(), assert.NoError},
		{"ok ak with tpm", kms2, args{&apiv1.GetPublicKeyRequest{
			Name: "kms:name=ak-1;ak=true",
		}}, ak.Public(), assert.NoError},
		{"fail missing key", kms1, args{&apiv1.GetPublicKeyRequest{
			Name: "kms:name=key-2",
		}}, nil, assert.Error},
		{"fail missing ak", kms2, args{&apiv1.GetPublicKeyRequest{
			Name: "kms:name=ak-2;ak=true",
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

func TestKMS_CreateKey_tpm(t *testing.T) {
	ctx := t.Context()
	kms1, stpm := mustTPMKMS(t)
	kms2, err := NewWithTPM(ctx, stpm)
	require.NoError(t, err)

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
		{"ok", kms1, args{&apiv1.CreateKeyRequest{
			Name: "kms:name=key-1",
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			key, err := stpm.GetKey(ctx, "key-1")
			require.NoError(t, err)
			signer, err := key.Signer(ctx)
			require.NoError(t, err)

			require.NotNil(t, got)
			require.NotNil(t, got.CreateSignerRequest.Signer)

			assert.Equal(t, signer.Public(), got.CreateSignerRequest.Signer.Public())
			got.CreateSignerRequest.Signer = signer

			assert.Equal(t, got, &apiv1.CreateKeyResponse{
				Name:      "kms:name=key-1",
				PublicKey: signer.Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					Signer:     signer,
					SigningKey: "kms:name=key-1",
				},
			})
		}, assert.NoError},
		{"ok ak", kms1, args{&apiv1.CreateKeyRequest{
			Name: "kms:name=ak-1;ak=true",
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			key, err := stpm.GetAK(ctx, "ak-1")
			require.NoError(t, err)

			assert.Equal(t, got, &apiv1.CreateKeyResponse{
				Name:      "kms:ak=true;name=ak-1",
				PublicKey: key.Public(),
			})
		}, assert.NoError},
		{"ok with tpm", kms2, args{&apiv1.CreateKeyRequest{
			Name: "kms:name=key-2",
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			key, err := stpm.GetKey(ctx, "key-2")
			require.NoError(t, err)
			signer, err := key.Signer(ctx)
			require.NoError(t, err)

			require.NotNil(t, got)
			require.NotNil(t, got.CreateSignerRequest.Signer)

			assert.Equal(t, signer.Public(), got.CreateSignerRequest.Signer.Public())
			got.CreateSignerRequest.Signer = signer

			assert.Equal(t, got, &apiv1.CreateKeyResponse{
				Name:      "kms:name=key-2",
				PublicKey: signer.Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					Signer:     signer,
					SigningKey: "kms:name=key-2",
				},
			})
		}, assert.NoError},
		{"ok ak with tpm", kms2, args{&apiv1.CreateKeyRequest{
			Name: "kms:name=ak-2;ak=true",
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			key, err := stpm.GetAK(ctx, "ak-2")
			require.NoError(t, err)

			assert.Equal(t, got, &apiv1.CreateKeyResponse{
				Name:      "kms:ak=true;name=ak-2",
				PublicKey: key.Public(),
			})
		}, assert.NoError},
		{"fail key already exists", kms1, args{&apiv1.CreateKeyRequest{
			Name: "kms:name=key-2",
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			assert.Nil(t, got)
		}, assert.Error},
		{"fail ak already exists", kms2, args{&apiv1.CreateKeyRequest{
			Name: "kms:name=ak-1;ak=true",
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

func TestKMS_CreateSigner_tpm(t *testing.T) {
	ctx := t.Context()
	stpm := mustTPM(t)
	km, err := NewWithTPM(ctx, stpm)
	require.NoError(t, err)

	key, err := stpm.CreateKey(ctx, "key-1", tpm.CreateKeyConfig{
		Algorithm: "RSA",
		Size:      2048,
	})
	require.NoError(t, err)

	signer, err := key.Signer(ctx)
	require.NoError(t, err)

	_, err = stpm.CreateAK(ctx, "ak-1")
	require.NoError(t, err)

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
		{"ok key", km, args{&apiv1.CreateSignerRequest{
			SigningKey: "kms:name=key-1",
		}}, func(t *testing.T, got crypto.Signer) {
			require.NotNil(t, got)
			assert.Equal(t, signer.Public(), got.Public())
		}, assert.NoError},
		{"ok key with signer", km, args{&apiv1.CreateSignerRequest{
			Signer:     signer,
			SigningKey: "kms:name=key1",
		}}, func(t *testing.T, got crypto.Signer) {
			assert.Equal(t, signer, got)
		}, assert.NoError},
		{"fail missing", km, args{&apiv1.CreateSignerRequest{
			SigningKey: "kms:name=key-2",
		}}, func(t *testing.T, got crypto.Signer) {
			assert.Nil(t, got)
		}, assert.Error},
		{"fail with ak", km, args{&apiv1.CreateSignerRequest{
			SigningKey: "kms:name=ak-1;ak=true",
		}}, func(t *testing.T, got crypto.Signer) {
			assert.Nil(t, got)
		}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.kms.CreateSigner(tt.args.req)
			tt.assertion(t, err)
			tt.equal(t, got)
		})
	}
}

func TestKMS_DeleteKey_tpm(t *testing.T) {
	ctx := t.Context()
	stpm := mustTPM(t)
	km, err := NewWithTPM(ctx, stpm)
	require.NoError(t, err)

	_, err = stpm.CreateKey(ctx, "key-1", tpm.CreateKeyConfig{
		Algorithm: "ECDSA",
		Size:      256,
	})
	require.NoError(t, err)

	_, err = stpm.CreateAK(ctx, "ak-1")
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
		{"ok key", km, args{&apiv1.DeleteKeyRequest{
			Name: "kms:name=key-1",
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			_, keyErr := stpm.GetKey(ctx, "key-1")
			return assert.NoError(t, err) && assert.Error(t, keyErr)
		}},
		{"ok ak", km, args{&apiv1.DeleteKeyRequest{
			Name: "kms:name=ak-1;ak=true",
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			_, akErr := stpm.GetAK(ctx, "ak-1")
			return assert.NoError(t, err) && assert.Error(t, akErr)
		}},
		{"fail missing key", km, args{&apiv1.DeleteKeyRequest{
			Name: "kms:name=key-2",
		}}, assert.Error},
		{"fail missing ak", km, args{&apiv1.DeleteKeyRequest{
			Name: "kms:name=ak-2;ak=true",
		}}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, tt.kms.DeleteKey(tt.args.req))
		})
	}
}

func TestKMS_LoadCertificate_tpm(t *testing.T) {
	ctx := t.Context()
	stpm := mustTPM(t)
	km, err := NewWithTPM(ctx, stpm)
	require.NoError(t, err)

	key, err := stpm.CreateKey(ctx, "key-1", tpm.CreateKeyConfig{
		Algorithm: "ECDSA",
		Size:      256,
	})
	require.NoError(t, err)

	ak, err := stpm.CreateAK(ctx, "ak-1")
	require.NoError(t, err)

	_, err = stpm.CreateKey(ctx, "key-2", tpm.CreateKeyConfig{
		Algorithm: "RSA",
		Size:      2048,
	})
	require.NoError(t, err)

	_, err = stpm.CreateAK(ctx, "ak-2")
	require.NoError(t, err)

	keyChain := mustCertificateWithKey(t, key.Public())
	require.NoError(t, key.SetCertificateChain(ctx, keyChain))

	akChain := mustCertificateWithKey(t, ak.Public())
	require.NoError(t, ak.SetCertificateChain(ctx, akChain))

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
		{"ok", km, args{&apiv1.LoadCertificateRequest{
			Name: "kms:name=key-1",
		}}, keyChain[0], assert.NoError},
		{"ok ak", km, args{&apiv1.LoadCertificateRequest{
			Name: "kms:name=ak-1;ak=true",
		}}, akChain[0], assert.NoError},
		{"fail no certificate", km, args{&apiv1.LoadCertificateRequest{
			Name: "kms:name=key-2",
		}}, nil, assert.Error},
		{"fail no ak certificate", km, args{&apiv1.LoadCertificateRequest{
			Name: "kms:name=ak-2;ak=true",
		}}, nil, assert.Error},
		{"fail missing", km, args{&apiv1.LoadCertificateRequest{
			Name: "kms:name=missing-key",
		}}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.kms.LoadCertificate(tt.args.req)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKMS_StoreCertificate_tpm(t *testing.T) {
	ctx := t.Context()
	stpm := mustTPM(t)
	km, err := NewWithTPM(ctx, stpm)
	require.NoError(t, err)

	key, err := stpm.CreateKey(ctx, "key-1", tpm.CreateKeyConfig{
		Algorithm: "ECDSA",
		Size:      256,
	})
	require.NoError(t, err)

	ak, err := stpm.CreateAK(ctx, "ak-1")
	require.NoError(t, err)

	keyChain1 := mustCertificateWithKey(t, key.Public())
	keyChain2 := mustCertificateWithKey(t, key.Public())
	akChain1 := mustCertificateWithKey(t, ak.Public())
	akChain2 := mustCertificateWithKey(t, ak.Public())

	type args struct {
		req *apiv1.StoreCertificateRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", km, args{&apiv1.StoreCertificateRequest{
			Name:        "kms:name=key-1",
			Certificate: keyChain1[0],
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			k, err := stpm.GetKey(ctx, "key-1")
			require.NoError(t, err)
			return assert.Equal(t, keyChain1[0], k.Certificate())
		}},
		{"ok overwrite", km, args{&apiv1.StoreCertificateRequest{
			Name:        "kms:name=key-1",
			Certificate: keyChain2[0],
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			k, err := stpm.GetKey(ctx, "key-1")
			require.NoError(t, err)
			return assert.Equal(t, keyChain2[0], k.Certificate())
		}},
		{"ok ak", km, args{&apiv1.StoreCertificateRequest{
			Name:        "kms:name=ak-1;ak=true",
			Certificate: akChain1[0],
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			k, err := stpm.GetAK(ctx, "ak-1")
			require.NoError(t, err)
			return assert.Equal(t, akChain1[0], k.Certificate())
		}},
		{"ok ak overwrite", km, args{&apiv1.StoreCertificateRequest{
			Name:        "kms:name=ak-1;ak=true",
			Certificate: akChain2[0],
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			k, err := stpm.GetAK(ctx, "ak-1")
			require.NoError(t, err)
			return assert.Equal(t, akChain2[0], k.Certificate())
		}},
		{"fail missing", km, args{&apiv1.StoreCertificateRequest{
			Name:        "kms:name=missing-key",
			Certificate: keyChain1[0],
		}}, assert.Error},
		{"fail key not match", km, args{&apiv1.StoreCertificateRequest{
			Name:        "kms:name=key-1",
			Certificate: akChain1[0],
		}}, assert.Error},
		{"fail ak key not match", km, args{&apiv1.StoreCertificateRequest{
			Name:        "kms:name=ak-1;ak=true",
			Certificate: keyChain1[0],
		}}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, tt.kms.StoreCertificate(tt.args.req))
		})
	}
}

func TestKMS_LoadCertificateChain_tpm(t *testing.T) {
	ctx := t.Context()
	stpm := mustTPM(t)
	km, err := NewWithTPM(ctx, stpm)
	require.NoError(t, err)

	key, err := stpm.CreateKey(ctx, "key-1", tpm.CreateKeyConfig{
		Algorithm: "ECDSA",
		Size:      256,
	})
	require.NoError(t, err)

	ak, err := stpm.CreateAK(ctx, "ak-1")
	require.NoError(t, err)

	_, err = stpm.CreateKey(ctx, "key-2", tpm.CreateKeyConfig{
		Algorithm: "RSA",
		Size:      2048,
	})
	require.NoError(t, err)

	_, err = stpm.CreateAK(ctx, "ak-2")
	require.NoError(t, err)

	keyChain := mustCertificateWithKey(t, key.Public())
	require.NoError(t, key.SetCertificateChain(ctx, keyChain))

	akChain := mustCertificateWithKey(t, ak.Public())
	require.NoError(t, ak.SetCertificateChain(ctx, akChain))

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
		{"ok", km, args{&apiv1.LoadCertificateChainRequest{
			Name: "kms:name=key-1",
		}}, keyChain, assert.NoError},
		{"ok ak", km, args{&apiv1.LoadCertificateChainRequest{
			Name: "kms:name=ak-1;ak=true",
		}}, akChain, assert.NoError},
		{"fail no chain", km, args{&apiv1.LoadCertificateChainRequest{
			Name: "kms:name=key-2",
		}}, nil, assert.Error},
		{"fail no ak chain", km, args{&apiv1.LoadCertificateChainRequest{
			Name: "kms:name=ak-2;ak=true",
		}}, nil, assert.Error},
		{"fail missing", km, args{&apiv1.LoadCertificateChainRequest{
			Name: "kms:name=missing-key",
		}}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.kms.LoadCertificateChain(tt.args.req)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKMS_StoreCertificateChain_tpm(t *testing.T) {
	ctx := t.Context()
	stpm := mustTPM(t)
	km, err := NewWithTPM(ctx, stpm)
	require.NoError(t, err)

	key, err := stpm.CreateKey(ctx, "key-1", tpm.CreateKeyConfig{
		Algorithm: "ECDSA",
		Size:      256,
	})
	require.NoError(t, err)

	ak, err := stpm.CreateAK(ctx, "ak-1")
	require.NoError(t, err)

	keyChain1 := mustCertificateWithKey(t, key.Public())
	keyChain2 := mustCertificateWithKey(t, key.Public())
	akChain1 := mustCertificateWithKey(t, ak.Public())
	akChain2 := mustCertificateWithKey(t, ak.Public())

	type args struct {
		req *apiv1.StoreCertificateChainRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", km, args{&apiv1.StoreCertificateChainRequest{
			Name:             "kms:name=key-1",
			CertificateChain: keyChain1,
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			k, err := stpm.GetKey(ctx, "key-1")
			require.NoError(t, err)
			return assert.Equal(t, keyChain1[0], k.Certificate()) &&
				assert.Equal(t, keyChain1, k.CertificateChain())
		}},
		{"ok overwrite", km, args{&apiv1.StoreCertificateChainRequest{
			Name:             "kms:name=key-1",
			CertificateChain: keyChain2,
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			k, err := stpm.GetKey(ctx, "key-1")
			require.NoError(t, err)
			return assert.Equal(t, keyChain2[0], k.Certificate()) &&
				assert.Equal(t, keyChain2, k.CertificateChain())
		}},
		{"ok ak", km, args{&apiv1.StoreCertificateChainRequest{
			Name:             "kms:name=ak-1;ak=true",
			CertificateChain: akChain1,
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			k, err := stpm.GetAK(ctx, "ak-1")
			require.NoError(t, err)
			return assert.Equal(t, akChain1[0], k.Certificate()) &&
				assert.Equal(t, akChain1, k.CertificateChain())
		}},
		{"ok ak overwrite", km, args{&apiv1.StoreCertificateChainRequest{
			Name:             "kms:name=ak-1;ak=true",
			CertificateChain: akChain2,
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			k, err := stpm.GetAK(ctx, "ak-1")
			require.NoError(t, err)
			return assert.Equal(t, akChain2[0], k.Certificate()) &&
				assert.Equal(t, akChain2, k.CertificateChain())
		}},
		{"fail missing", km, args{&apiv1.StoreCertificateChainRequest{
			Name:             "kms:name=missing-key",
			CertificateChain: keyChain1,
		}}, assert.Error},
		{"fail key not match", km, args{&apiv1.StoreCertificateChainRequest{
			Name:             "kms:name=key-1",
			CertificateChain: akChain1,
		}}, assert.Error},
		{"fail ak key not match", km, args{&apiv1.StoreCertificateChainRequest{
			Name:             "kms:name=ak-1;ak=true",
			CertificateChain: keyChain1,
		}}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, tt.kms.StoreCertificateChain(tt.args.req))
		})
	}
}

func TestKMS_DeleteCertificate_tpm(t *testing.T) {
	ctx := t.Context()
	stpm := mustTPM(t)
	km, err := NewWithTPM(ctx, stpm)
	require.NoError(t, err)

	key, err := stpm.CreateKey(ctx, "key-1", tpm.CreateKeyConfig{
		Algorithm: "ECDSA",
		Size:      256,
	})
	require.NoError(t, err)

	ak, err := stpm.CreateAK(ctx, "ak-1")
	require.NoError(t, err)

	keyChain := mustCertificateWithKey(t, key.Public())
	require.NoError(t, key.SetCertificateChain(ctx, keyChain))

	akChain := mustCertificateWithKey(t, ak.Public())
	require.NoError(t, ak.SetCertificateChain(ctx, akChain))

	type args struct {
		req *apiv1.DeleteCertificateRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", km, args{&apiv1.DeleteCertificateRequest{
			Name: "kms:name=key-1",
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			k, err := stpm.GetKey(ctx, "key-1")
			require.NoError(t, err)
			return assert.Nil(t, k.Certificate()) && assert.Nil(t, k.CertificateChain())
		}},
		{"ok ak", km, args{&apiv1.DeleteCertificateRequest{
			Name: "kms:name=ak-1;ak=true",
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			k, err := stpm.GetAK(ctx, "ak-1")
			require.NoError(t, err)
			return assert.Nil(t, k.Certificate()) && assert.Nil(t, k.CertificateChain())
		}},
		{"ok delete again", km, args{&apiv1.DeleteCertificateRequest{
			Name: "kms:name=key-1",
		}}, assert.NoError},
		{"ok delete again ak", km, args{&apiv1.DeleteCertificateRequest{
			Name: "kms:name=ak-1;ak=true",
		}}, assert.NoError},
		{"fail missing", km, args{&apiv1.DeleteCertificateRequest{
			Name: "kms:name=missing-ak;ak=true",
		}}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, tt.kms.DeleteCertificate(tt.args.req))
		})
	}
}

func TestKMS_CreateAttestation_tpm(t *testing.T) {
	ctx := t.Context()
	stpm := mustTPM(t)
	km, err := NewWithTPM(ctx, stpm)
	require.NoError(t, err)

	eks, err := stpm.GetEKs(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, eks)
	ekKeyURL := mustPermanentIdentifier(t, eks[0].Public())

	ak, err := stpm.CreateAK(ctx, "ak-1")
	require.NoError(t, err)

	key, err := stpm.AttestKey(ctx, "ak-1", "key-1", tpm.AttestKeyConfig{
		Algorithm:      "ECDSA",
		Size:           256,
		QualifyingData: []byte{1, 2, 3, 4},
	})
	require.NoError(t, err)
	keyParams, err := key.CertificationParameters(ctx)
	require.NoError(t, err)
	keySigner, err := key.Signer(ctx)
	require.NoError(t, err)

	_, err = stpm.CreateKey(ctx, "key-2", tpm.CreateKeyConfig{
		Algorithm: "ECDSA",
		Size:      256,
	})
	require.NoError(t, err)

	ca, err := minica.New()
	require.NoError(t, err)

	akCert, err := ca.Sign(&x509.Certificate{
		Subject: pkix.Name{
			CommonName: "ak-1",
		},
		URIs:      []*url.URL{ekKeyURL},
		PublicKey: ak.Public(),
	})
	require.NoError(t, err)
	require.NoError(t, ak.SetCertificateChain(ctx, []*x509.Certificate{
		akCert, ca.Intermediate,
	}))

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
		{"ok", km, args{&apiv1.CreateAttestationRequest{
			Name: "kms:name=key-1",
		}}, &apiv1.CreateAttestationResponse{
			Certificate:      akCert,
			CertificateChain: []*x509.Certificate{akCert, ca.Intermediate},
			PublicKey:        keySigner.Public(),
			CertificationParameters: &apiv1.CertificationParameters{
				Public:            keyParams.Public,
				CreateData:        keyParams.CreateData,
				CreateAttestation: keyParams.CreateAttestation,
				CreateSignature:   keyParams.CreateSignature,
			},
			PermanentIdentifier: ekKeyURL.String(),
		}, assert.NoError},
		{"fail not attested key", km, args{&apiv1.CreateAttestationRequest{
			Name: "kms:name=key-2",
		}}, nil, assert.Error},
		{"fail missing key", km, args{&apiv1.CreateAttestationRequest{
			Name: "kms:name=key-3",
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

func TestKMS_SearchKeys_tpm(t *testing.T) {
	ctx := t.Context()
	stpm := mustTPM(t)
	km, err := NewWithTPM(ctx, stpm)
	require.NoError(t, err)

	key1, err := stpm.CreateKey(ctx, "key-1", tpm.CreateKeyConfig{
		Algorithm: "ECDSA",
		Size:      256,
	})
	require.NoError(t, err)

	key2, err := stpm.CreateKey(ctx, "key-2", tpm.CreateKeyConfig{
		Algorithm: "ECDSA",
		Size:      256,
	})
	require.NoError(t, err)

	ak1, err := stpm.CreateAK(ctx, "ak-1")
	require.NoError(t, err)

	ak2, err := stpm.CreateAK(ctx, "ak-2")
	require.NoError(t, err)

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
		{"ok", km, args{&apiv1.SearchKeysRequest{
			Query: "kms:",
		}}, &apiv1.SearchKeysResponse{
			Results: []apiv1.SearchKeyResult{
				{Name: "kms:ak=true;name=ak-1", PublicKey: ak1.Public()},
				{Name: "kms:ak=true;name=ak-2", PublicKey: ak2.Public()},
				{Name: "kms:name=key-1", PublicKey: key1.Public(), CreateSignerRequest: apiv1.CreateSignerRequest{SigningKey: "kms:name=key-1"}},
				{Name: "kms:name=key-2", PublicKey: key2.Public(), CreateSignerRequest: apiv1.CreateSignerRequest{SigningKey: "kms:name=key-2"}},
			},
		}, assert.NoError},
		{"ok keys", km, args{&apiv1.SearchKeysRequest{
			Query: "kms:ak=false",
		}}, &apiv1.SearchKeysResponse{
			Results: []apiv1.SearchKeyResult{
				{Name: "kms:name=key-1", PublicKey: key1.Public(), CreateSignerRequest: apiv1.CreateSignerRequest{SigningKey: "kms:name=key-1"}},
				{Name: "kms:name=key-2", PublicKey: key2.Public(), CreateSignerRequest: apiv1.CreateSignerRequest{SigningKey: "kms:name=key-2"}},
			},
		}, assert.NoError},
		{"ok aks", km, args{&apiv1.SearchKeysRequest{
			Query: "kms:ak=true",
		}}, &apiv1.SearchKeysResponse{
			Results: []apiv1.SearchKeyResult{
				{Name: "kms:ak=true;name=ak-1", PublicKey: ak1.Public()},
				{Name: "kms:ak=true;name=ak-2", PublicKey: ak2.Public()},
			},
		}, assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.kms.SearchKeys(tt.args.req)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
