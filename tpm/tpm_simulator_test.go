//go:build tpmsimulator
// +build tpmsimulator

package tpm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/smallstep/go-attestation/attest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/tpm/simulator"
	"go.step.sm/crypto/tpm/storage"
	"go.step.sm/crypto/x509util"
)

func newSimulatedTPM(t *testing.T) *TPM {
	t.Helper()
	tmpDir := t.TempDir()
	tpm, err := New(withSimulator(t), WithStore(storage.NewDirstore(tmpDir))) // TODO: provide in-memory storage implementation instead
	require.NoError(t, err)
	return tpm
}

func withSimulator(t *testing.T) NewTPMOption {
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
	return WithSimulator(sim)
}

func TestTPM_Info(t *testing.T) {
	tpm := newSimulatedTPM(t)
	info, err := tpm.Info(context.Background())
	require.NoError(t, err)

	// expected TPM info for the Microsoft TPM simulator
	expected := &Info{
		Version:      Version(2),
		Interface:    Interface(3),
		Manufacturer: GetManufacturerByID(1297303124),
		VendorInfo:   "xCG fTPM",
		FirmwareVersion: FirmwareVersion{
			Major: 8215,
			Minor: 1561,
		},
	}

	require.Equal(t, expected, info)
}

func TestTPM_GenerateRandom(t *testing.T) {
	tpm := newSimulatedTPM(t)
	b, err := tpm.GenerateRandom(context.Background(), 16)
	require.NoError(t, err)
	require.Len(t, b, 16)

	b, err = tpm.GenerateRandom(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, b, 10)
}

func newErrorTPM(t *testing.T) *TPM {
	t.Helper()
	tmpDir := t.TempDir()
	tpm, err := New(withWriteErrorSimulator(t), WithStore(storage.NewDirstore(tmpDir))) // TODO: provide in-memory storage implementation instead
	require.NoError(t, err)
	return tpm
}

func withWriteErrorSimulator(t *testing.T) NewTPMOption {
	t.Helper()
	var sim simulator.Simulator
	t.Cleanup(func() {
		if sim == nil {
			return
		}
		err := sim.Close()
		require.NoError(t, err)
	})
	sim = &writeErrorSimulator{}
	err := sim.Open()
	require.NoError(t, err)
	return WithSimulator(sim)
}

type writeErrorSimulator struct {
}

func (s *writeErrorSimulator) Open() error {
	return nil
}

func (s *writeErrorSimulator) Close() error {
	return nil
}

func (s *writeErrorSimulator) Read([]byte) (int, error) {
	return -1, nil
}

func (s *writeErrorSimulator) Write([]byte) (int, error) {
	return 0, errors.New("forced write error") // writing command fails
}

func (s *writeErrorSimulator) MeasurementLog() ([]byte, error) {
	return nil, nil
}

var _ io.ReadWriteCloser = (*writeErrorSimulator)(nil)

func Test_generator_Read(t *testing.T) {
	tpm := newSimulatedTPM(t)
	errorTPM := newErrorTPM(t)
	type fields struct {
		t *TPM
	}
	type args struct {
		data []byte
	}
	short := make([]byte, 8)
	long := make([]byte, 32)
	tooLongForSimulator := make([]byte, 256) // I've observed the simulator to return 64 at most in one go; we loop through it, so we can get more than 64 random bytes
	maximumLength := make([]byte, math.MaxUint16)
	longerThanMax := make([]byte, math.MaxUint16+1)
	readError := make([]byte, 32)
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		expErr error
	}{
		{"ok/short", fields{tpm}, args{data: short}, 8, nil},
		{"ok/long", fields{tpm}, args{data: long}, 32, nil},
		{"ok/tooLongForSimulator", fields{tpm}, args{data: tooLongForSimulator}, 256, nil},
		{"ok/max", fields{tpm}, args{data: maximumLength}, math.MaxUint16, nil},
		{"ok/readError", fields{errorTPM}, args{data: readError}, 0, nil},
		{"fail/longerThanMax", fields{tpm}, args{data: longerThanMax}, 0, errors.New("number of random bytes to read cannot exceed 65535")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := tt.fields.t.RandomReader()
			require.NoError(t, err)

			got, err := g.Read(tt.args.data)
			if tt.expErr != nil {
				assert.EqualError(t, err, tt.expErr.Error())
				assert.Equal(t, 0, got)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)

			// for the test cases that use the errorTPM, check that trying
			// to read (again) from the same generator fails with the previous
			// error.
			if tt.fields.t == errorTPM {
				newShort := make([]byte, 8)
				n, err := g.Read(newShort)
				assert.Zero(t, n)
				assert.EqualError(t, err, "failed generating random bytes in previous call to Read: failed generating random data: forced write error: EOF")
				assert.ErrorIs(t, err, io.EOF)
			}
		})
	}
}

func TestTPM_GetEKs(t *testing.T) {
	tpm := newSimulatedTPM(t)
	eks, err := tpm.GetEKs(context.Background())
	require.NoError(t, err)
	require.Len(t, eks, 1)
	require.IsType(t, &rsa.PublicKey{}, eks[0].Public())
	require.Nil(t, eks[0].Certificate())
	require.Equal(t, "", eks[0].CertificateURL())

	fp, err := eks[0].Fingerprint()
	require.NoError(t, err)

	b, err := base64.StdEncoding.DecodeString(strings.Split(fp, ":")[1])
	require.NoError(t, err)
	require.Len(t, b, 32)
}

func TestTPM_CreateAK(t *testing.T) {
	tpm := newSimulatedTPM(t)
	ak, err := tpm.CreateAK(context.Background(), "first-ak")
	require.NoError(t, err)
	require.Equal(t, "first-ak", ak.Name())
	require.NotEqual(t, 0, len(ak.Data()))
	require.Same(t, tpm, ak.tpm)
}

func TestTPM_GetAK(t *testing.T) {
	tpm := newSimulatedTPM(t)
	ak, err := tpm.CreateAK(context.Background(), "")
	require.NoError(t, err)
	require.NotNil(t, ak)
	require.Same(t, tpm, ak.tpm)

	r, err := tpm.GetAK(context.Background(), ak.Name())
	require.NoError(t, err)
	require.Equal(t, ak.Name(), r.Name())
	require.Same(t, tpm, r.tpm)
	require.Equal(t, ak.CreatedAt(), r.CreatedAt())
	require.Equal(t, ak.Data(), r.Data())

	r, err = tpm.GetAK(context.Background(), "non-existing-key")
	require.EqualError(t, err, `failed getting AK "non-existing-key": not found`)
	require.Nil(t, r)
}

func TestTPM_ListAKs(t *testing.T) {
	tpm := newSimulatedTPM(t)
	ak1, err := tpm.CreateAK(context.Background(), "")
	require.NoError(t, err)
	require.NotNil(t, ak1)
	require.Same(t, tpm, ak1.tpm)

	ak2, err := tpm.CreateAK(context.Background(), "")
	require.NoError(t, err)
	require.NotNil(t, ak2)
	require.Same(t, tpm, ak2.tpm)

	ak3, err := tpm.CreateAK(context.Background(), "")
	require.NoError(t, err)
	require.NotNil(t, ak3)
	require.Same(t, tpm, ak3.tpm)

	aks, err := tpm.ListAKs(context.Background())
	require.NoError(t, err)
	require.Len(t, aks, 3)

	for _, ak := range aks {
		require.Same(t, tpm, ak.tpm)
	}
}

func TestTPM_DeleteAK(t *testing.T) {
	tpm := newSimulatedTPM(t)
	ak, err := tpm.CreateAK(context.Background(), "first-ak")
	require.NoError(t, err)
	require.NotNil(t, ak)
	require.Same(t, tpm, ak.tpm)

	err = tpm.DeleteAK(context.Background(), "first-ak")
	require.NoError(t, err)

	ak, err = tpm.CreateAK(context.Background(), "second-ak")
	require.NoError(t, err)
	require.NotNil(t, ak)

	config := AttestKeyConfig{
		Algorithm: "RSA",
		Size:      2048,
	}
	key, err := tpm.AttestKey(context.Background(), "second-ak", "first-key", config)
	require.NoError(t, err)
	require.NotNil(t, key)

	err = tpm.DeleteAK(context.Background(), "second-ak")
	require.EqualError(t, err, `failed deleting AK "second-ak" because 1 key(s) exist that were attested by it`)

	err = tpm.DeleteAK(context.Background(), "non-existing-ak")
	require.EqualError(t, err, `failed getting AK "non-existing-ak": not found`)
}

func TestAK_AttestationParameters(t *testing.T) {
	tpm := newSimulatedTPM(t)
	ak, err := tpm.CreateAK(context.Background(), "first-ak")
	require.NoError(t, err)
	require.NotNil(t, ak)
	require.Same(t, tpm, ak.tpm)

	params, err := ak.AttestationParameters(context.Background())
	require.NoError(t, err)
	require.NotNil(t, params)
}

func TestAK_ActivateCredential(t *testing.T) {
	tpm := newSimulatedTPM(t)
	ak, err := tpm.CreateAK(context.Background(), "first-ak")
	require.NoError(t, err)
	require.NotNil(t, ak)
	require.Same(t, tpm, ak.tpm)

	eks, err := tpm.GetEKs(context.Background())
	require.NoError(t, err)
	require.Len(t, eks, 1)

	params, err := ak.AttestationParameters(context.Background())
	require.NoError(t, err)
	require.NotNil(t, params)

	// prepare parameters for activation as performed by an attestor
	activation := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         eks[0].Public(),
		AK:         params,
	}

	// generate the encrypted challenge for the TPM
	expectedSecret, encryptedCredentials, err := activation.Generate()
	require.NoError(t, err)

	// activate the credential and verify secret is equal to attestor's value
	secret, err := ak.ActivateCredential(context.Background(), EncryptedCredential(*encryptedCredentials))
	require.NoError(t, err)
	require.Equal(t, expectedSecret, secret)
}

func TestAK_Blobs(t *testing.T) {
	tpm := newSimulatedTPM(t)
	ak, err := tpm.CreateAK(context.Background(), "first-ak")
	require.NoError(t, err)
	require.NotNil(t, ak)
	require.Same(t, tpm, ak.tpm)

	blobs, err := ak.Blobs(context.Background())
	require.NoError(t, err)
	require.NotNil(t, blobs)

	// check private bytes and its (encoded) length
	private, err := blobs.Private()
	require.NoError(t, err)
	require.NotEmpty(t, private)

	size := binary.BigEndian.Uint16(private[0:2])
	require.Len(t, private, int(size)+2)

	// check public bytes and its (encoded) length
	public, err := blobs.Public()
	require.NoError(t, err)
	require.NotEmpty(t, public)

	size = binary.BigEndian.Uint16(public[0:2])
	require.Len(t, public, int(size)+2)
}

func TestAK_Public(t *testing.T) {
	tpm := newSimulatedTPM(t)
	ak, err := tpm.CreateAK(context.Background(), "first-ak")
	require.NoError(t, err)
	require.NotNil(t, ak)
	require.Same(t, tpm, ak.tpm)

	akPub := ak.Public()
	require.NoError(t, err)
	require.NotNil(t, akPub)
	require.Implements(t, (*crypto.PublicKey)(nil), ak)
	_, ok := akPub.(crypto.Signer)
	require.False(t, ok)

	newAK := &AK{
		tpm:  tpm,
		name: "second-ak", // non-existent AK; results in error
	}
	newAKPub := newAK.Public()
	require.Nil(t, newAKPub)
}

func TestAK_CertificateOperations(t *testing.T) {

	tpm := newSimulatedTPM(t)
	ak, err := tpm.CreateAK(context.Background(), "first-ak")
	require.NoError(t, err)
	require.NotNil(t, ak)
	require.Same(t, tpm, ak.tpm)

	akPub := ak.Public()
	require.NoError(t, err)
	require.NotNil(t, akPub)

	ca, err := minica.New(
		minica.WithGetSignerFunc(
			func() (crypto.Signer, error) {
				return keyutil.GenerateSigner("RSA", "", 2048)
			},
		),
	)
	require.NoError(t, err)

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "testkey",
		},
		PublicKey: akPub,
	}
	cert, err := ca.Sign(template)
	require.NoError(t, err)
	require.NotNil(t, cert)

	akCert := ak.Certificate()
	require.Nil(t, akCert)

	akChain := ak.CertificateChain()
	require.Empty(t, akChain)

	chain := []*x509.Certificate{cert, ca.Intermediate}
	err = ak.SetCertificateChain(context.TODO(), chain)
	require.NoError(t, err)

	akCert = ak.Certificate()
	require.Equal(t, cert, akCert)

	akChain = ak.CertificateChain()
	require.Equal(t, chain, akChain)
}

func TestTPM_CreateKey(t *testing.T) {
	tpm := newSimulatedTPM(t)
	config := CreateKeyConfig{
		Algorithm: "RSA",
		Size:      2048,
	}
	key, err := tpm.CreateKey(context.Background(), "first-key", config)
	require.NoError(t, err)
	require.Equal(t, "first-key", key.Name())
	require.Equal(t, "", key.AttestedBy())
	require.NotEqual(t, 0, len(key.Data()))
	require.Same(t, tpm, key.tpm)
	require.False(t, key.WasAttested())

	config = CreateKeyConfig{
		Algorithm: "RSA",
		Size:      1024,
	}
	key, err = tpm.CreateKey(context.Background(), "1024", config)
	require.NoError(t, err)

	config = CreateKeyConfig{
		Algorithm: "RSA",
		Size:      3072,
	}
	key, err = tpm.CreateKey(context.Background(), "3072", config)
	assert.EqualError(t, err, "invalid key creation parameters: 3072 bits RSA keys are (currently) not supported in go.step.sm/crypto; maximum is 2048")
	assert.Nil(t, key)

	config = CreateKeyConfig{
		Algorithm: "RSA",
		Size:      4096,
	}
	key, err = tpm.CreateKey(context.Background(), "4096", config)
	assert.EqualError(t, err, "invalid key creation parameters: 4096 bits RSA keys are (currently) not supported in go.step.sm/crypto; maximum is 2048")
	assert.Nil(t, key)
}

func TestTPM_AttestKey(t *testing.T) {
	tpm := newSimulatedTPM(t)
	ak, err := tpm.CreateAK(context.Background(), "first-ak")
	require.NoError(t, err)
	require.NotNil(t, ak)
	require.Same(t, tpm, ak.tpm)

	config := AttestKeyConfig{
		Algorithm: "RSA",
		Size:      2048,
	}
	key, err := tpm.AttestKey(context.Background(), "first-ak", "first-key", config)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, "first-key", key.Name())
	require.NotEqual(t, 0, len(key.Data()))
	require.Equal(t, "first-ak", key.AttestedBy())
	require.Same(t, tpm, key.tpm)
	require.True(t, key.WasAttested())
	require.True(t, key.WasAttestedBy(ak))

	config = AttestKeyConfig{
		Algorithm: "RSA",
		Size:      3072,
	}
	key, err = tpm.AttestKey(context.Background(), "first-ak", "3072", config)
	assert.EqualError(t, err, "invalid key attestation parameters: 3072 bits RSA keys are (currently) not supported in go.step.sm/crypto; maximum is 2048")
	assert.Nil(t, key)
}

func TestTPM_GetKey(t *testing.T) {
	tpm := newSimulatedTPM(t)
	config := CreateKeyConfig{
		Algorithm: "RSA",
		Size:      2048,
	}
	key, err := tpm.CreateKey(context.Background(), "first-key", config)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, "", key.AttestedBy())
	require.Same(t, tpm, key.tpm)

	r, err := tpm.GetKey(context.Background(), key.Name())
	require.NoError(t, err)
	require.Equal(t, key.Name(), r.Name())
	require.Same(t, tpm, r.tpm)
	require.Equal(t, key.CreatedAt(), r.CreatedAt())
	require.Equal(t, key.Data(), r.Data())
	require.Equal(t, "", r.AttestedBy())

	r, err = tpm.GetKey(context.Background(), "non-existing-key")
	require.EqualError(t, err, `failed getting key "non-existing-key": not found`)
	require.Nil(t, r)
}

func TestTPM_GetKeys(t *testing.T) {
	tpm := newSimulatedTPM(t)
	config := CreateKeyConfig{
		Algorithm: "RSA",
		Size:      2048,
	}
	key1, err := tpm.CreateKey(context.Background(), "", config)
	require.NoError(t, err)
	require.NotNil(t, key1)
	require.Equal(t, "", key1.AttestedBy())
	require.Same(t, tpm, key1.tpm)

	key2, err := tpm.CreateKey(context.Background(), "", config)
	require.NoError(t, err)
	require.NotNil(t, key2)
	require.Equal(t, "", key2.AttestedBy())
	require.Same(t, tpm, key2.tpm)

	key3, err := tpm.CreateKey(context.Background(), "", config)
	require.NoError(t, err)
	require.NotNil(t, key3)
	require.Equal(t, "", key3.AttestedBy())
	require.Same(t, tpm, key3.tpm)

	keys, err := tpm.ListKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, keys, 3)

	for _, key := range keys {
		require.NotEqual(t, 0, len(key.Data()))
		require.Same(t, tpm, key.tpm)
	}
}

func TestTPM_DeleteKey(t *testing.T) {
	tpm := newSimulatedTPM(t)
	config := CreateKeyConfig{
		Algorithm: "RSA",
		Size:      2048,
	}
	key, err := tpm.CreateKey(context.Background(), "first-key", config)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, "", key.AttestedBy())
	require.Same(t, tpm, key.tpm)

	err = tpm.DeleteKey(context.Background(), "first-key")
	require.NoError(t, err)

	err = tpm.DeleteKey(context.Background(), "non-existing-key")
	require.EqualError(t, err, `failed getting key "non-existing-key": not found`)
}

func TestKey_CertificationParameters(t *testing.T) {
	tpm := newSimulatedTPM(t)
	ak, err := tpm.CreateAK(context.Background(), "first-ak")
	require.NoError(t, err)
	require.NotNil(t, ak)
	require.Same(t, tpm, ak.tpm)

	config := AttestKeyConfig{
		Algorithm: "RSA",
		Size:      2048,
	}
	key, err := tpm.AttestKey(context.Background(), "first-ak", "first-key", config)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, "first-key", key.Name())
	require.NotEqual(t, 0, len(key.Data()))
	require.Equal(t, "first-ak", key.AttestedBy())
	require.Same(t, tpm, key.tpm)
	require.True(t, key.WasAttested())
	require.True(t, key.WasAttestedBy(ak))

	params, err := key.CertificationParameters(context.Background())
	require.NoError(t, err)
	require.NotNil(t, params)
	require.NotEqual(t, 0, len(params.CreateAttestation))
	require.NotEqual(t, 0, len(params.CreateSignature))

	akParams, err := ak.AttestationParameters(context.Background())
	require.NoError(t, err)
	require.NotNil(t, akParams)

	akPublic, err := attest.ParseAKPublic(attest.TPMVersion20, akParams.Public)
	require.NoError(t, err)
	require.NotNil(t, akPublic)

	opts := attest.VerifyOpts{
		Public: akPublic.Public,
		Hash:   akPublic.Hash,
	}
	err = params.Verify(opts)
	require.NoError(t, err)
}

func TestKey_Blobs(t *testing.T) {
	tpm := newSimulatedTPM(t)
	config := CreateKeyConfig{
		Algorithm: "RSA",
		Size:      2048,
	}
	key, err := tpm.CreateKey(context.Background(), "first-key", config)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, "", key.AttestedBy())
	require.Same(t, tpm, key.tpm)

	blobs, err := key.Blobs(context.Background())
	require.NoError(t, err)
	require.NotNil(t, blobs)

	// check private bytes and its (encoded) length
	private, err := blobs.Private()
	require.NoError(t, err)
	require.NotEmpty(t, private)

	size := binary.BigEndian.Uint16(private[0:2])
	require.Len(t, private, int(size)+2)

	// check public bytes and its (encoded) length
	public, err := blobs.Public()
	require.NoError(t, err)
	require.NotEmpty(t, public)

	size = binary.BigEndian.Uint16(public[0:2])
	require.Len(t, public, int(size)+2)
}

func TestKey_SetCertificateChain(t *testing.T) {
	tpm := newSimulatedTPM(t)
	config := CreateKeyConfig{
		Algorithm: "RSA",
		Size:      2048,
	}
	key, err := tpm.CreateKey(context.Background(), "first-key", config)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, "", key.AttestedBy())
	require.Same(t, tpm, key.tpm)

	ca, err := minica.New(
		minica.WithGetSignerFunc(
			func() (crypto.Signer, error) {
				return keyutil.GenerateSigner("RSA", "", 2048)
			},
		),
	)
	require.NoError(t, err)

	signer, err := key.Signer(context.Background())
	require.NoError(t, err)

	cr, err := x509util.NewCertificateRequest(signer)
	require.NoError(t, err)
	cr.Subject.CommonName = "testkey"

	csr, err := cr.GetCertificateRequest()
	require.NoError(t, err)

	cert, err := ca.SignCSR(csr)
	require.NoError(t, err)

	keyCert := key.Certificate()
	require.Nil(t, keyCert)

	keyChain := key.CertificateChain()
	require.Empty(t, keyChain)

	chain := []*x509.Certificate{cert, ca.Intermediate}
	err = key.SetCertificateChain(context.TODO(), chain)
	require.NoError(t, err)

	keyCert = key.Certificate()
	require.Equal(t, cert, keyCert)

	keyChain = key.CertificateChain()
	require.Equal(t, chain, keyChain)
}

func TestTPM_GetSigner(t *testing.T) {
	tpm := newSimulatedTPM(t)
	signer, err := tpm.GetSigner(context.Background(), "non-existing-key")
	require.EqualError(t, err, `failed getting signer for key "non-existing-key": not found`)
	require.Nil(t, signer)
}

func TestKey_Signer(t *testing.T) {
	tpm := newSimulatedTPM(t)
	config := CreateKeyConfig{
		Algorithm: "RSA",
		Size:      2048,
	}
	key, err := tpm.CreateKey(context.Background(), "first-key", config)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, "", key.AttestedBy())
	require.Same(t, tpm, key.tpm)

	signer, err := key.Signer(context.Background())
	require.NoError(t, err)
	require.NotNil(t, signer)
}

func Test_signer_Sign(t *testing.T) {
	tpm := newSimulatedTPM(t)
	config := CreateKeyConfig{
		Algorithm: "RSA",
		Size:      2048,
	}
	key, err := tpm.CreateKey(context.Background(), "first-key", config)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, "", key.AttestedBy())
	require.Same(t, tpm, key.tpm)

	signer, err := key.Signer(context.Background())
	require.NoError(t, err)
	require.NotNil(t, signer)

	random := make([]byte, 32)
	n, err := rand.Read(random)
	require.NoError(t, err)
	require.Equal(t, 32, n)

	signature, err := signer.Sign(rand.Reader, random, crypto.SHA256)
	require.NoError(t, err)
	require.NotNil(t, signature)
}
