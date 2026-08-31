package x509util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReplaceTemplateFunc checks that a built-in can be replaced deliberately,
// but not by [RegisterTemplateFunc].
func TestReplaceTemplateFunc(t *testing.T) {
	cr, _ := createCertificateRequest(t, "foo", []string{"foo.com"})

	require.Error(t, RegisterTemplateFunc("toJson", func(any) string { return "replaced" }))

	require.NoError(t, ReplaceTemplateFunc("toJson", func(any) string { return "replaced" }))
	t.Cleanup(func() { UnregisterTemplateFunc("toJson") })

	var o Options
	require.NoError(t, WithTemplate(`{{ toJson .Subject }}`, TemplateData{})(cr, &o))
	assert.Equal(t, "replaced", o.CertBuffer.String())

	// Removing it restores the built-in.
	UnregisterTemplateFunc("toJson")
	var o2 Options
	require.NoError(t, WithTemplate(`{{ toJson "x" }}`, TemplateData{})(cr, &o2))
	assert.Equal(t, `"x"`, o2.CertBuffer.String())
}

func TestReplaceTemplateFuncOverridesARegistration(t *testing.T) {
	require.NoError(t, RegisterTemplateFunc("testReplaceMe", func() string { return "first" }))
	t.Cleanup(func() { UnregisterTemplateFunc("testReplaceMe") })

	require.NoError(t, ReplaceTemplateFunc("testReplaceMe", func() string { return "second" }))

	cr, _ := createCertificateRequest(t, "foo", []string{"foo.com"})
	var o Options
	require.NoError(t, WithTemplate(`{{ testReplaceMe }}`, TemplateData{})(cr, &o))
	assert.Equal(t, "second", o.CertBuffer.String())
}

func TestReplaceTemplateFuncStillValidates(t *testing.T) {
	require.Error(t, ReplaceTemplateFunc("", func() string { return "" }))
	require.Error(t, ReplaceTemplateFunc("bad-name", func() string { return "" }))
	require.Error(t, ReplaceTemplateFunc("notfn", "a string"))
	require.Error(t, ReplaceTemplateFunc("nilfn", nil))
}
