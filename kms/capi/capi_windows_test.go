//go:build windows && !nocapi

package capi

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/fingerprint"
	"go.step.sm/crypto/internal/utils/cryptoutil"
	"go.step.sm/crypto/kms/apiv1"
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

// capiProviders are the key storage providers used in the signer tests, with
// the store location each requires. The TPM provider only supports machine
// keys.
var capiProviders = map[string]string{
	ProviderMSKSP: UserStoreLocation,
	ProviderMSPCP: MachineStoreLocation,
}

// mustCreateSigner creates a key with the given provider and returns its
// signer. It registers the removal of the key with t.Cleanup.
func mustCreateSigner(t *testing.T, provider, location string, sa apiv1.SignatureAlgorithm, bits int) crypto.Signer {
	t.Helper()

	k, err := New(context.Background(), apiv1.Options{
		URI: "capi:provider=" + provider,
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, k.Close()) })

	resp, err := k.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "capi:store-location=" + location,
		SignatureAlgorithm: sa,
		Bits:               bits,
	})
	require.NoError(t, err)
	// The URI returned by CreateKey doesn't include the store location.
	name := resp.Name + ";store-location=" + location
	t.Cleanup(func() {
		assert.NoError(t, k.DeleteKey(&apiv1.DeleteKeyRequest{Name: name}))
	})

	signer, err := k.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: name})
	require.NoError(t, err)
	return signer
}

// TestCAPISigner_Sign_nilOpts checks that, for every digest length from 1 to
// 80 bytes, a signature with nil opts verifies against the original digest, as
// it would if ecdsa.PrivateKey.Sign had signed it. An empty digest, with or
// without opts, and, for P-521, a digest longer than 64 bytes must fail. It
// runs only on a developer Windows machine, using the software and the TPM key
// storage providers.
func TestCAPISigner_Sign_nilOpts(t *testing.T) {
	for provider, location := range capiProviders {
		t.Run(provider, func(t *testing.T) {
			for _, sa := range []apiv1.SignatureAlgorithm{apiv1.ECDSAWithSHA256, apiv1.ECDSAWithSHA384, apiv1.ECDSAWithSHA512} {
				t.Run(sa.String(), func(t *testing.T) {
					signer := mustCreateSigner(t, provider, location, sa, 0)
					pub, ok := signer.Public().(*ecdsa.PublicKey)
					require.True(t, ok)

					for n := 0; n <= 80; n++ {
						t.Run(fmt.Sprint(n), func(t *testing.T) {
							if n == 0 {
								_, err := signer.Sign(rand.Reader, nil, nil)
								assert.EqualError(t, err, "digest cannot be empty")
								// CNG rejects an empty digest.
								_, err = signer.Sign(rand.Reader, nil, crypto.SHA256)
								assert.Error(t, err)
								return
							}

							digest := make([]byte, n)
							_, err := rand.Read(digest)
							require.NoError(t, err)
							// Make the leftmost byte non-zero, so truncating or
							// padding the wrong end of the digest changes the
							// signed value.
							digest[0] |= 0x80

							sig, err := signer.Sign(rand.Reader, digest, nil)
							if pub.Curve == elliptic.P521() && n > 64 {
								assert.Error(t, err)
								return
							}
							require.NoError(t, err)
							assert.True(t, ecdsa.VerifyASN1(pub, digest, sig))
						})
					}
				})
			}
		})
	}
}

// TestCAPISigner_Sign_rsaNilOpts checks that RSA keys fail with nil opts, as
// the signature depends on the hash. It runs only on a developer Windows
// machine, using the software and the TPM key storage providers.
func TestCAPISigner_Sign_rsaNilOpts(t *testing.T) {
	for provider, location := range capiProviders {
		t.Run(provider, func(t *testing.T) {
			signer := mustCreateSigner(t, provider, location, apiv1.SHA256WithRSA, 2048)
			pub, ok := signer.Public().(*rsa.PublicKey)
			require.True(t, ok)

			digest := sha256.Sum256([]byte("message"))
			_, err := signer.Sign(rand.Reader, digest[:], nil)
			assert.ErrorIs(t, err, cryptoutil.ErrSignerOptsRequired)

			// CNG rejects an empty digest.
			_, err = signer.Sign(rand.Reader, nil, crypto.SHA256)
			assert.Error(t, err)

			sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			require.NoError(t, err)
			assert.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig))
		})
	}
}
