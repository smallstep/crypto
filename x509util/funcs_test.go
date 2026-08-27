package x509util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterTemplateFunc(t *testing.T) {
	cr, _ := createCertificateRequest(t, "foo", []string{"foo.com"})

	require.NoError(t, RegisterTemplateFunc("testShout", func(s string) string {
		return s + "!"
	}))
	t.Cleanup(func() { UnregisterTemplateFunc("testShout") })

	var o Options
	require.NoError(t, WithTemplate(`{{ testShout "hello" }}`, TemplateData{})(cr, &o))
	assert.Equal(t, "hello!", o.CertBuffer.String())
}

// A function receives only its own arguments, so a template that needs the
// template data passes it with $.
func TestRegisterTemplateFuncReachesTheData(t *testing.T) {
	cr, _ := createCertificateRequest(t, "foo", []string{"foo.com"})

	require.NoError(t, RegisterTemplateFunc("testPick", func(key string, data any) (any, error) {
		m, _ := data.(TemplateData)
		return m[key], nil
	}))
	t.Cleanup(func() { UnregisterTemplateFunc("testPick") })

	data := TemplateData{
		SubjectKey: Subject{CommonName: "example"},
		"custom":   []string{"a", "b"},
	}

	t.Run("at the top level", func(t *testing.T) {
		var o Options
		require.NoError(t, WithTemplate(`{{ testPick "custom" $ | toJson }}`, data)(cr, &o))
		assert.Equal(t, `["a","b"]`, o.CertBuffer.String())
	})

	// $ is the value the template was executed with wherever it appears; the
	// dot is not.
	t.Run("inside a range block", func(t *testing.T) {
		var o Options
		text := `{{ range $i, $v := (testPick "custom" $) }}{{ testPick "custom" $ | toJson }}{{ end }}`
		require.NoError(t, WithTemplate(text, data)(cr, &o))
		assert.Equal(t, `["a","b"]["a","b"]`, o.CertBuffer.String())
	})
}

func TestRegisterTemplateFuncErrors(t *testing.T) {
	tests := []struct {
		name    string
		fnName  string
		fn      any
		wantErr string
	}{
		{"empty name", "", func() string { return "" }, "name is required"},
		{"nil function", "nilfn", nil, "is nil"},
		{"not a function", "notfn", "a string", "not a function"},
		{"invalid identifier", "not-an-identifier", func() string { return "" }, "not a valid identifier"},
		{"leading digit", "1abc", func() string { return "" }, "not a valid identifier"},
		{"shadows sprig", "toJson", func() string { return "" }, "built in and cannot be replaced"},
		{"shadows fail", "fail", func() string { return "" }, "built in and cannot be replaced"},
		{"shadows asn1", "asn1Enc", func() string { return "" }, "built in and cannot be replaced"},
		{"shadows time helper", "toTime", func() string { return "" }, "built in and cannot be replaced"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RegisterTemplateFunc(tt.fnName, tt.fn)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestRegisterTemplateFuncRejectsDuplicates(t *testing.T) {
	require.NoError(t, RegisterTemplateFunc("dup", func() string { return "first" }))
	t.Cleanup(func() { UnregisterTemplateFunc("dup") })

	err := RegisterTemplateFunc("dup", func() string { return "second" })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestUnregisterTemplateFunc(t *testing.T) {
	assert.False(t, UnregisterTemplateFunc("never-registered"))

	require.NoError(t, RegisterTemplateFunc("temp", func() string { return "" }))
	assert.True(t, UnregisterTemplateFunc("temp"))

	// A template calling a function that is not registered fails to parse.
	cr, _ := createCertificateRequest(t, "foo", []string{"foo.com"})
	var o Options
	err := WithTemplate(`{{ temp }}`, TemplateData{})(cr, &o)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `function "temp" not defined`)
}

// TestBuiltinsAreUnaffected checks that registering leaves the built-in
// functions in place.
func TestBuiltinsAreUnaffected(t *testing.T) {
	require.NoError(t, RegisterTemplateFunc("extra", func() string { return "x" }))
	t.Cleanup(func() { UnregisterTemplateFunc("extra") })

	cr, _ := createCertificateRequest(t, "foo", []string{"foo.com"})
	var o Options
	text := `{{ toJson .Subject.CommonName }}{{ "a" | upper }}{{ extra }}`
	require.NoError(t, WithTemplate(text, TemplateData{
		SubjectKey: Subject{CommonName: "example"},
	})(cr, &o))
	assert.Equal(t, `"example"Ax`, o.CertBuffer.String())
}
