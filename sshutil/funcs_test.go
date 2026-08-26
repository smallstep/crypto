package sshutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/x509util"
)

func TestRegisterTemplateFunc(t *testing.T) {
	cr := CertificateRequest{Key: mustGeneratePublicKey(t), Type: UserCert.String()}
	data := CreateTemplateData(UserCert, "jane@example.com", []string{"jane"})

	require.NoError(t, RegisterTemplateFunc("testPrincipals", func(data any) (any, error) {
		m, _ := data.(TemplateData)
		return m[PrincipalsKey], nil
	}))
	t.Cleanup(func() { UnregisterTemplateFunc("testPrincipals") })

	var o Options
	require.NoError(t, WithTemplate(`{{ testPrincipals $ | toJson }}`, data)(cr, &o))
	assert.Equal(t, `["jane"]`, o.CertBuffer.String())
}

func TestRegisterTemplateFuncErrors(t *testing.T) {
	require.Error(t, RegisterTemplateFunc("", func() string { return "" }))
	require.Error(t, RegisterTemplateFunc("notfn", "a string"))

	err := RegisterTemplateFunc("toJson", func() string { return "" })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "built in and cannot be replaced")
}

// TestRegistriesAreSeparate is the reason there are two entry points rather
// than one: registering a function for SSH templates must not silently make it
// available to X.509 ones, and the other way round.
func TestRegistriesAreSeparate(t *testing.T) {
	require.NoError(t, RegisterTemplateFunc("testSSHOnly", func() string { return "ssh" }))
	t.Cleanup(func() { UnregisterTemplateFunc("testSSHOnly") })

	cr := CertificateRequest{Key: mustGeneratePublicKey(t), Type: UserCert.String()}
	data := CreateTemplateData(UserCert, "jane@example.com", []string{"jane"})

	var o Options
	require.NoError(t, WithTemplate(`{{ testSSHOnly }}`, data)(cr, &o))
	assert.Equal(t, "ssh", o.CertBuffer.String())

	// The same name is undefined for X.509 templates.
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	xcr, err := x509util.CreateCertificateRequest("foo", []string{"foo.com"}, signer)
	require.NoError(t, err)
	var xo x509util.Options
	err = x509util.WithTemplate(`{{ testSSHOnly }}`, x509util.TemplateData{})(xcr, &xo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `function "testSSHOnly" not defined`)

	// And an application wanting it in both registers with both.
	require.NoError(t, x509util.RegisterTemplateFunc("testSSHOnly", func() string { return "x509" }))
	t.Cleanup(func() { x509util.UnregisterTemplateFunc("testSSHOnly") })

	var xo2 x509util.Options
	require.NoError(t, x509util.WithTemplate(`{{ testSSHOnly }}`, x509util.TemplateData{})(xcr, &xo2))
	assert.Equal(t, "x509", xo2.CertBuffer.String())
}
