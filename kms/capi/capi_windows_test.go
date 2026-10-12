//go:build windows && !nocapi

package capi

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
