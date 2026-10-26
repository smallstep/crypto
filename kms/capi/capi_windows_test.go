//go:build windows && !nocapi

package capi

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"go.step.sm/crypto/fingerprint"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/x509util"
)

// mustStoreSelfSignedCertificate generates a self-signed certificate, stores it
// in the current-user "My" store using the given URI, and registers its removal
// with t.Cleanup. storeName carries the attributes under test; the certificate
// is always deleted by SHA-1 fingerprint.
func mustStoreSelfSignedCertificate(t *testing.T, k *CAPIKMS, storeName string) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "go.step.sm/crypto capi SearchCertificates test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	// Computed up front (it depends only on cert.Raw) so the cleanup below
	// can be registered right after the certificate is stored, rather than
	// after a later require that could fail and skip it.
	fp, err := fingerprint.New(cert.Raw, crypto.SHA1, fingerprint.HexFingerprint)
	require.NoError(t, err)
	deleteName := "capi:store-location=user;store=My;sha1=" + fp

	require.NoError(t, k.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name:        storeName,
		Certificate: cert,
	}))
	t.Cleanup(func() {
		assert.NoError(t, k.DeleteCertificate(&apiv1.DeleteCertificateRequest{Name: deleteName}))
	})

	return cert
}

// findSearchResult returns the SearchCertificates result matching cert, or nil.
func findSearchResult(resp *apiv1.SearchCertificatesResponse, cert *x509.Certificate) *apiv1.SearchCertificateResult {
	for i := range resp.Results {
		if resp.Results[i].Certificate.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return &resp.Results[i]
		}
	}
	return nil
}

// TestCAPIKMS_SearchCertificates_user runs only on a developer Windows
// machine: crypto's CI has no Windows runner, so this test is not executed
// there. It exercises the current-user "My" store, which does not require
// administrative rights.
func TestCAPIKMS_SearchCertificates_user(t *testing.T) {
	k := &CAPIKMS{}

	// skip-find-certificate-key=true stores the certificate with no
	// associated private key, matching the case being asserted below.
	cert := mustStoreSelfSignedCertificate(t, k,
		"capi:store-location=user;store=My;skip-find-certificate-key=true")

	resp, err := k.SearchCertificates(&apiv1.SearchCertificatesRequest{
		Name: "capi:store-location=user;store=My",
	})
	require.NoError(t, err)

	found := findSearchResult(resp, cert)
	require.NotNil(t, found, "stored certificate not returned by SearchCertificates")
	assert.Equal(t, cert.Raw, found.Certificate.Raw)
	assert.Empty(t, found.KeyName)
	assert.NoError(t, found.Err)
}

// TestCAPIKMS_SearchCertificates_keyContainerName asserts the container name
// recorded on a certificate is read back verbatim. It is the counterpart to
// TestCAPIKMS_SearchCertificates_user, which asserts the no-association case
// and so cannot distinguish a working reader from one that returns "" for
// everything.
//
// No key is created: StoreCertificate's "key" branch records the association
// with setCertificateKeyProvInfo without verifying the container exists, which
// produces exactly the state this API exists to detect — a certificate naming a
// key container that is not there. That also means this test needs no TPM and
// no administrative rights, only Windows.
func TestCAPIKMS_SearchCertificates_keyContainerName(t *testing.T) {
	k := &CAPIKMS{}

	suffix := make([]byte, 8)
	_, err := rand.Read(suffix)
	require.NoError(t, err)
	containerName := "go-step-crypto-test-" + hex.EncodeToString(suffix)

	cert := mustStoreSelfSignedCertificate(t, k,
		"capi:store-location=user;store=My;key="+containerName+";skip-find-certificate-key=true")

	resp, err := k.SearchCertificates(&apiv1.SearchCertificatesRequest{
		Name: "capi:store-location=user;store=My",
	})
	require.NoError(t, err)

	found := findSearchResult(resp, cert)
	require.NotNil(t, found, "stored certificate not returned by SearchCertificates")
	assert.Equal(t, cert.Raw, found.Certificate.Raw)
	assert.NoError(t, found.Err)
	assert.Equal(t, containerName, found.KeyName)
}

// TestCAPIKMS_machineKeyset runs only on a developer Windows machine with
// administrative rights, which creating a machine-keyset key requires. It pins
// that a key created in the machine keyset stays addressable as one: through
// the URI CreateKey returns, and through the container name when the
// certificate stored for it is looked up or deleted. Each fails with
// NTE_BAD_KEYSET if the key is opened in the user keyset instead.
func TestCAPIKMS_machineKeyset(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("creating a machine-keyset key requires administrative rights")
	}

	k, err := New(context.Background(), apiv1.Options{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Close() })

	suffix := make([]byte, 8)
	_, err = rand.Read(suffix)
	require.NoError(t, err)
	container := "go-step-crypto-test-" + hex.EncodeToString(suffix)
	keyName := "capi:key=" + container + ";store-location=machine"

	resp, err := k.CreateKey(&apiv1.CreateKeyRequest{
		Name:               keyName,
		SignatureAlgorithm: apiv1.ECDSAWithSHA256,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, k.DeleteKey(&apiv1.DeleteKeyRequest{Name: keyName}))
	})

	signer, err := k.CreateSigner(&resp.CreateSignerRequest)
	require.NoError(t, err, "the URI CreateKey returned must open the key it created")
	assert.Equal(t, resp.PublicKey, signer.Public())

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	// A certificate is found from its key by subject key identifier, which Go
	// sets on its own only for CA certificates.
	skid, err := x509util.GenerateSubjectKeyID(signer.Public())
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		SubjectKeyId: skid,
		Subject:      pkix.Name{CommonName: "go.step.sm/crypto capi machine keyset test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	certName := "capi:store-location=machine;store=My;key=" + container
	require.NoError(t, k.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name:        certName,
		Certificate: cert,
	}))
	fp, err := fingerprint.New(cert.Raw, crypto.SHA1, fingerprint.HexFingerprint)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, k.DeleteCertificate(&apiv1.DeleteCertificateRequest{
			Name: "capi:store-location=machine;store=My;sha1=" + fp,
		}))
	})

	loaded, err := k.LoadCertificate(&apiv1.LoadCertificateRequest{Name: certName})
	require.NoError(t, err, "the certificate must be found through its machine-keyset key")
	assert.Equal(t, cert.Raw, loaded.Raw)

	require.NoError(t, k.DeleteCertificate(&apiv1.DeleteCertificateRequest{Name: certName}))
	_, err = k.LoadCertificate(&apiv1.LoadCertificateRequest{
		Name: "capi:store-location=machine;store=My;sha1=" + fp,
	})
	assert.ErrorIs(t, err, apiv1.NotFoundError{}, "the certificate must be deleted through its machine-keyset key")
}

// TestCAPIKMS_containerKeyset runs only on a developer Windows machine with
// administrative rights, which a certificate in the machine store requires. It
// pins how a certificate in the machine store is found through a key in the
// user's keyset: with no "key-scope" the user's keyset is searched once the
// machine keyset has no such key, while an explicit "key-scope" is followed
// alone, so "machine" does not find it and "user" does.
func TestCAPIKMS_containerKeyset(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("storing a certificate in the machine store requires administrative rights")
	}

	k, err := New(context.Background(), apiv1.Options{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Close() })

	suffix := make([]byte, 8)
	_, err = rand.Read(suffix)
	require.NoError(t, err)
	container := "go-step-crypto-test-" + hex.EncodeToString(suffix)
	keyName := "capi:key=" + container

	resp, err := k.CreateKey(&apiv1.CreateKeyRequest{
		Name:               keyName,
		SignatureAlgorithm: apiv1.ECDSAWithSHA256,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, k.DeleteKey(&apiv1.DeleteKeyRequest{Name: keyName}))
	})
	signer, err := k.CreateSigner(&resp.CreateSignerRequest)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	skid, err := x509util.GenerateSubjectKeyID(signer.Public())
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		SubjectKeyId: skid,
		Subject:      pkix.Name{CommonName: "go.step.sm/crypto capi container keyset test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	require.NoError(t, k.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name:        "capi:store-location=machine;store=My;key-scope=user;key=" + container,
		Certificate: cert,
	}))
	fp, err := fingerprint.New(cert.Raw, crypto.SHA1, fingerprint.HexFingerprint)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, k.DeleteCertificate(&apiv1.DeleteCertificateRequest{
			Name: "capi:store-location=machine;store=My;sha1=" + fp,
		}))
	})

	loaded, err := k.LoadCertificate(&apiv1.LoadCertificateRequest{
		Name: "capi:store-location=machine;store=My;key=" + container,
	})
	require.NoError(t, err, "without key-scope the user's keyset must be searched")
	assert.Equal(t, cert.Raw, loaded.Raw)

	loaded, err = k.LoadCertificate(&apiv1.LoadCertificateRequest{
		Name: "capi:store-location=machine;store=My;key-scope=user;key=" + container,
	})
	require.NoError(t, err, "key-scope=user must find the key in the user's keyset")
	assert.Equal(t, cert.Raw, loaded.Raw)

	_, err = k.LoadCertificate(&apiv1.LoadCertificateRequest{
		Name: "capi:store-location=machine;store=My;key-scope=machine;key=" + container,
	})
	assert.True(t, isBadKeyset(err), "key-scope=machine must not fall back to the user's keyset: %v", err)
}

// TestCAPIKMS_ImportKey runs only on a developer Windows machine. It pins that
// an imported key is the key that was imported -- the provider signs with it
// and reports its public key -- and that the provider holds it as a
// non-exportable key in the keyset the URI named. The machine keyset needs
// administrative rights and is skipped without them.
func TestCAPIKMS_ImportKey(t *testing.T) {
	k, err := New(context.Background(), apiv1.Options{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Close() })

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecP384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	ecP521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsa3072Key, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)
	rsa4096Key, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	tests := []struct {
		name          string
		key           crypto.Signer
		storeLocation string
	}{
		{"ecdsa user", ecKey, "user"},
		{"ecdsa p384 user", ecP384Key, "user"},
		{"ecdsa p521 user", ecP521Key, "user"},
		{"rsa user", rsaKey, "user"},
		{"rsa 3072 user", rsa3072Key, "user"},
		{"rsa 4096 user", rsa4096Key, "user"},
		{"ecdsa machine", ecKey, "machine"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.storeLocation == "machine" && !windows.GetCurrentProcessToken().IsElevated() {
				t.Skip("importing into the machine keyset requires administrative rights")
			}

			suffix := make([]byte, 8)
			_, err := rand.Read(suffix)
			require.NoError(t, err)
			container := "go-step-crypto-test-" + hex.EncodeToString(suffix)
			keyName := "capi:key=" + container + ";store-location=" + tt.storeLocation

			resp, err := k.ImportKey(&ImportKeyRequest{Name: keyName, PrivateKey: tt.key})
			require.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, k.DeleteKey(&apiv1.DeleteKeyRequest{Name: keyName}))
			})
			assert.Equal(t, tt.key.Public(), resp.PublicKey)

			// Both the returned URI and the container name open it.
			for _, name := range []string{resp.CreateSignerRequest.SigningKey, keyName} {
				signer, err := k.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: name})
				require.NoError(t, err, name)

				digest := sha256.Sum256([]byte("imported"))
				sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
				require.NoError(t, err)
				switch pub := tt.key.Public().(type) {
				case *ecdsa.PublicKey:
					assert.True(t, ecdsa.VerifyASN1(pub, digest[:], sig), "signature must verify against the imported key")
				case *rsa.PublicKey:
					assert.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig))
				}
			}

			u, err := parseURI(keyName)
			require.NoError(t, err)
			flags, err := k.getKeyFlags(u)
			require.NoError(t, err)
			kh, err := nCryptOpenKey(k.providerHandle, container, 0, flags)
			require.NoError(t, err)
			defer nCryptFreeObject(kh)

			// The export policy is a DWORD, so it is decoded from exactly four
			// bytes rather than through nCryptGetPropertyInt, which reads a
			// whole int.
			policy, err := getProperty(kh, wide(NCRYPT_EXPORT_POLICY_PROPERTY))
			require.NoError(t, err)
			require.Len(t, policy, 4)
			assert.Zero(t, binary.LittleEndian.Uint32(policy), "the imported key must not be exportable")
			_, err = nCryptExportKey(kh, NCRYPT_PKCS8_PRIVATE_KEY_BLOB)
			assert.Error(t, err, "exporting the private key must fail")

			_, err = k.ImportKey(&ImportKeyRequest{Name: keyName, PrivateKey: tt.key})
			assert.ErrorIs(t, err, apiv1.AlreadyExistsError{}, "an existing container must not be replaced")
		})
	}
}

func TestCAPIKMS_ImportKey_refusals(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	k, err := New(context.Background(), apiv1.Options{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Close() })

	_, err = k.ImportKey(&ImportKeyRequest{Name: "capi:key=x", PrivateKey: nil})
	assert.Error(t, err)
	_, err = k.ImportKey(&ImportKeyRequest{Name: "capi:store-location=user", PrivateKey: ecKey})
	assert.ErrorContains(t, err, "key not specified")
	_, err = k.ImportKey(&ImportKeyRequest{Name: "capi:key=x", PrivateKey: ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize))})
	assert.ErrorContains(t, err, "unsupported private key type")
	_, err = k.ImportKey(&ImportKeyRequest{Name: "capi:key=x", PrivateKey: (*ecdsa.PrivateKey)(nil)})
	assert.ErrorContains(t, err, "incomplete ECDSA private key")
	_, err = k.ImportKey(&ImportKeyRequest{Name: "capi:key=x", PrivateKey: &ecdsa.PrivateKey{}})
	assert.ErrorContains(t, err, "incomplete ECDSA private key")
	_, err = k.ImportKey(&ImportKeyRequest{Name: "capi:key=x", PrivateKey: (*rsa.PrivateKey)(nil)})
	assert.ErrorContains(t, err, "incomplete RSA private key")
	_, err = k.ImportKey(&ImportKeyRequest{Name: "capi:key=x;key-spec=AT_SIGNATURE", PrivateKey: ecKey})
	assert.ErrorContains(t, err, "key-spec cannot be set")

	pcp := &CAPIKMS{providerName: ProviderMSPCP}
	_, err = pcp.ImportKey(&ImportKeyRequest{Name: "capi:key=x", PrivateKey: ecKey})
	assert.ErrorContains(t, err, "cannot import keys into")
}

func TestCAPIKMS_containerKeysets(t *testing.T) {
	machineStore := &uriAttributes{storeLocation: MachineStoreLocation}
	tests := map[string]struct {
		provider string
		u        *uriAttributes
		want     []bool
	}{
		"a user store uses the user keyset":                         {ProviderMSKSP, &uriAttributes{storeLocation: UserStoreLocation}, []bool{false}},
		"a machine store tries the machine keyset, then the user's": {ProviderMSKSP, machineStore, []bool{true, false}},
		"an explicit machine scope is followed alone":               {ProviderMSKSP, &uriAttributes{storeLocation: UserStoreLocation, keyScope: MachineStoreLocation}, []bool{true}},
		"an explicit user scope is followed alone":                  {ProviderMSKSP, &uriAttributes{storeLocation: MachineStoreLocation, keyScope: UserStoreLocation}, []bool{false}},
		"platform crypto provider keys are machine-wide":            {ProviderMSPCP, machineStore, []bool{true}},
		"smart card keys are opened without the machine flag":       {ProviderMSSC, machineStore, []bool{false}},
		"smart card keys ignore an explicit machine scope":          {ProviderMSSC, &uriAttributes{storeLocation: MachineStoreLocation, keyScope: MachineStoreLocation}, []bool{false}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			k := &CAPIKMS{providerName: tt.provider}
			assert.Equal(t, tt.want, k.containerKeysets(tt.u))
		})
	}
}
