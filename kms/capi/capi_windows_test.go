//go:build windows && !nocapi

package capi

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/randutil"
	"go.step.sm/crypto/x509util"
)

// makeSoftwareKSPKeyAndCert creates a Software-KSP-backed RSA key in
// CurrentUser scope, signs a short-lived self-signed cert with it, stores
// the cert in CurrentUser\My, and binds the cert to the key via
// CryptFindCertificateKeyProvInfo. Returns the container name and the
// stored cert's SHA-1 thumbprint (hex-encoded). Registers cleanup that
// deletes both.
//
// We need a cert that's actually bound to a CNG container, not just a raw
// cert in the store — that's what every test below exercises.
func makeSoftwareKSPKeyAndCert(t *testing.T, subject string) (containerName string) {
	t.Helper()
	ctx := t.Context()

	suffix, err := randutil.Hex(8)
	require.NoError(t, err)
	containerName = "step-capi-test-" + suffix

	km, err := New(ctx, apiv1.Options{
		Type: apiv1.CAPIKMS,
		URI:  uri.New(Scheme, url.Values{ProviderNameArg: []string{ProviderMSKSP}}).String(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close() })

	created, err := km.CreateKey(&apiv1.CreateKeyRequest{
		Name:               uri.New(Scheme, url.Values{ProviderNameArg: []string{ProviderMSKSP}, ContainerNameArg: []string{containerName}}).String(),
		SignatureAlgorithm: apiv1.SHA256WithRSA,
		Bits:               2048,
	})
	require.NoError(t, err)

	signer, err := km.CreateSigner(&created.CreateSignerRequest)
	require.NoError(t, err)

	// x509.CreateCertificate doesn't auto-populate SubjectKeyId on leaf
	// certs, so we have to set it explicitly. Without it the cert lacks a
	// subjectKeyIdentifier extension and the SKI-indexed lookup branch
	// can't find it — which is the very branch the indexedPath test is
	// supposed to exercise.
	ski, err := x509util.GenerateSubjectKeyID(signer.Public())
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: subject},
		Issuer:       pkix.Name{CommonName: subject},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SubjectKeyId: ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	require.NoError(t, km.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name: uri.New(Scheme, url.Values{
			StoreLocationArg: []string{UserStoreLocation},
			StoreNameArg:     []string{MyStore},
		}).String(),
		Certificate: cert,
	}))

	t.Cleanup(func() {
		// Best-effort cleanup. If a test already deleted the cert, the
		// second delete returns NotFound — that's fine.
		_ = km.DeleteCertificate(&apiv1.DeleteCertificateRequest{
			Name: uri.New(Scheme, url.Values{
				HashArg:          []string{hexString(cert.SubjectKeyId)},
				StoreLocationArg: []string{UserStoreLocation},
				StoreNameArg:     []string{MyStore},
			}).String(),
		})
		_ = km.DeleteKey(&apiv1.DeleteKeyRequest{
			Name: uri.New(Scheme, url.Values{
				ProviderNameArg:  []string{ProviderMSKSP},
				ContainerNameArg: []string{containerName},
			}).String(),
		})
	})

	return containerName
}

func hexString(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexChars[v>>4]
		out[i*2+1] = hexChars[v&0x0f]
	}
	return string(out)
}

// TestCryptFindCertificateKeyContainerName verifies that the rewritten
// container-name reader actually returns the bound container, where the
// pre-fix implementation always returned "". Without this round-trip the
// fallback paths can't tell certs apart.
func TestCryptFindCertificateKeyContainerName(t *testing.T) {
	container := makeSoftwareKSPKeyAndCert(t, "container-name-readback")

	// Open user\My and find the cert by SKI so we get its CertContext.
	st, err := windows.CertOpenStore(
		certStoreProvSystem, 0, 0, certStoreCurrentUser,
		uintptr(unsafe.Pointer(wide(MyStore))),
	)
	require.NoError(t, err)
	defer windows.CertCloseStore(st, 0)

	got, err := findCertificateByKeyContainerName(st, container)
	require.NoError(t, err)
	require.NotNil(t, got)
	defer windows.CertFreeCertificateContext(got)

	readback, err := cryptFindCertificateKeyContainerName(got)
	require.NoError(t, err)
	assert.Equal(t, container, readback)
}

// TestLoadCertificate_containerName_fallback exercises the path that the
// agent's renewal cleanup hits: the CAPIKMS instance is bound to the
// Microsoft Platform Crypto Provider (which is how tpmkms constructs its
// windowsCertificateManager), but the cert lives in the Software KSP. The
// indexed GetPublicKey lookup against PCP fails; the fallback enumerates
// the store by CERT_KEY_PROV_INFO container name and finds the cert.
func TestLoadCertificate_containerName_fallback(t *testing.T) {
	container := makeSoftwareKSPKeyAndCert(t, "fallback-load")

	// PCP-bound CAPIKMS — same shape as tpmkms's windowsCertificateManager.
	pcp, err := New(t.Context(), apiv1.Options{
		Type: apiv1.CAPIKMS,
		URI:  uri.New(Scheme, url.Values{ProviderNameArg: []string{ProviderMSPCP}}).String(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pcp.Close() })

	cert, err := pcp.LoadCertificate(&apiv1.LoadCertificateRequest{
		Name: uri.New(Scheme, url.Values{
			ContainerNameArg: []string{container},
			StoreLocationArg: []string{UserStoreLocation},
			StoreNameArg:     []string{MyStore},
		}).String(),
	})
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, "fallback-load", cert.Subject.CommonName)
}

// TestLoadCertificate_containerName_notFound asserts the fallback path
// returns NotFoundError (not a wrapped Windows error) when nothing matches.
// The agent's cleanup wrapper specifically tests errors.Is(err, NotFound),
// so the shape matters.
func TestLoadCertificate_containerName_notFound(t *testing.T) {
	suffix, err := randutil.Hex(8)
	require.NoError(t, err)
	missing := "step-capi-test-missing-" + suffix

	pcp, err := New(t.Context(), apiv1.Options{
		Type: apiv1.CAPIKMS,
		URI:  uri.New(Scheme, url.Values{ProviderNameArg: []string{ProviderMSPCP}}).String(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pcp.Close() })

	_, err = pcp.LoadCertificate(&apiv1.LoadCertificateRequest{
		Name: uri.New(Scheme, url.Values{
			ContainerNameArg: []string{missing},
			StoreLocationArg: []string{UserStoreLocation},
			StoreNameArg:     []string{MyStore},
		}).String(),
	})
	assert.ErrorIs(t, err, apiv1.NotFoundError{})
}

// TestDeleteCertificate_containerName_fallback is the load test's twin for
// the delete path the agent's cleanup actually uses. After delete, a second
// lookup must return NotFound; otherwise duplicates keep accumulating.
func TestDeleteCertificate_containerName_fallback(t *testing.T) {
	container := makeSoftwareKSPKeyAndCert(t, "fallback-delete")

	pcp, err := New(t.Context(), apiv1.Options{
		Type: apiv1.CAPIKMS,
		URI:  uri.New(Scheme, url.Values{ProviderNameArg: []string{ProviderMSPCP}}).String(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pcp.Close() })

	require.NoError(t, pcp.DeleteCertificate(&apiv1.DeleteCertificateRequest{
		Name: uri.New(Scheme, url.Values{
			ContainerNameArg: []string{container},
			StoreLocationArg: []string{UserStoreLocation},
			StoreNameArg:     []string{MyStore},
		}).String(),
	}))

	_, err = pcp.LoadCertificate(&apiv1.LoadCertificateRequest{
		Name: uri.New(Scheme, url.Values{
			ContainerNameArg: []string{container},
			StoreLocationArg: []string{UserStoreLocation},
			StoreNameArg:     []string{MyStore},
		}).String(),
	})
	assert.ErrorIs(t, err, apiv1.NotFoundError{})
}

// TestLoadCertificate_containerName_indexedPath confirms the preferred
// SKI-indexed branch still works when the bound provider *can* open the
// container. The fallback must not regress the TPM-resident case.
func TestLoadCertificate_containerName_indexedPath(t *testing.T) {
	container := makeSoftwareKSPKeyAndCert(t, "indexed-path")

	// Same provider that owns the key — GetPublicKey will succeed and the
	// preferred SKI-indexed branch fires.
	msksp, err := New(t.Context(), apiv1.Options{
		Type: apiv1.CAPIKMS,
		URI:  uri.New(Scheme, url.Values{ProviderNameArg: []string{ProviderMSKSP}}).String(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = msksp.Close() })

	cert, err := msksp.LoadCertificate(&apiv1.LoadCertificateRequest{
		Name: uri.New(Scheme, url.Values{
			ContainerNameArg: []string{container},
			StoreLocationArg: []string{UserStoreLocation},
			StoreNameArg:     []string{MyStore},
		}).String(),
	})
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, "indexed-path", cert.Subject.CommonName)
}

