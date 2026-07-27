//go:build windows && !nocapi

package capi

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/fingerprint"
	"go.step.sm/crypto/kms/apiv1"
)

// TestCAPIKMS_SearchCertificates_user runs only on a developer Windows
// machine: crypto's CI has no Windows runner, so this test is not executed
// there. It exercises the current-user "My" store, which does not require
// administrative rights.
func TestCAPIKMS_SearchCertificates_user(t *testing.T) {
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

	k := &CAPIKMS{}

	// skip-find-certificate-key=true stores the certificate with no
	// associated private key, matching the case being asserted below.
	storeName := "capi:store-location=user;store=My;skip-find-certificate-key=true"
	require.NoError(t, k.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name:        storeName,
		Certificate: cert,
	}))

	fp, err := fingerprint.New(cert.Raw, crypto.SHA1, fingerprint.HexFingerprint)
	require.NoError(t, err)
	deleteName := "capi:store-location=user;store=My;sha1=" + fp
	defer func() {
		assert.NoError(t, k.DeleteCertificate(&apiv1.DeleteCertificateRequest{Name: deleteName}))
	}()

	resp, err := k.SearchCertificates(&apiv1.SearchCertificatesRequest{
		Name: "capi:store-location=user;store=My",
	})
	require.NoError(t, err)

	var found *apiv1.SearchCertificatesResult
	for i := range resp.Results {
		if resp.Results[i].Certificate.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			found = &resp.Results[i]
			break
		}
	}
	require.NotNil(t, found, "stored certificate not returned by SearchCertificates")
	assert.Equal(t, cert.Raw, found.Certificate.Raw)
	assert.Empty(t, found.KeyContainerName)
}
