package x509util

import (
	"reflect"
	"testing"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/celutil"
)

// TestCELPipesToJSON is the reason the cel function returns a value rather than
// pre-formatted text. A template placing an expression in a JSON position pipes
// it through toJson, and that has to be correct for every result type — a bare
// string is not valid JSON where a value is expected, and a list formatted to a
// string would become a quoted string where the certificate needs an array.
func TestCELPipesToJSON(t *testing.T) {
	cr, _ := createCertificateRequest(t, "foo", []string{"foo.com", "foo@foo.com", "https://foo.com"})

	data := TemplateData{
		SubjectKey: Subject{CommonName: "example", Country: []string{"ES"}},
		SANsKey:    CreateSANs([]string{"foo.com", "bar.com"}),
	}

	tests := []struct {
		name string
		text string
		want string
	}{
		{"string", `{{ cel "Subject.CommonName" | toJson }}`, `"example"`},
		{"string function", `{{ cel "Subject.CommonName.upperAscii()" | toJson }}`, `"EXAMPLE"`},
		{"list of strings", `{{ cel "SANs.map(s, s.Value)" | toJson }}`, `["foo.com","bar.com"]`},
		{"list from a field", `{{ cel "Subject.Country" | toJson }}`, `["ES"]`},
		{"filtered list", `{{ cel "SANs.filter(s, s.Value.startsWith(\"foo\")).map(s, s.Value)" | toJson }}`, `["foo.com"]`},
		{"number", `{{ cel "size(SANs)" | toJson }}`, `2`},
		{"boolean", `{{ cel "Subject.CommonName == \"example\"" | toJson }}`, `true`},
		// A literal is the commonest configuration of all, and it must not be
		// metered as though it were unbounded work.
		{"constant string", `{{ cel "\"wifi\"" | toJson }}`, `"wifi"`},
		{"constant list", `{{ cel "[\"a\", \"b\"]" | toJson }}`, `["a","b"]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var o Options
			require.NoError(t, WithTemplate(tt.text, data)(cr, &o))
			assert.Equal(t, tt.want, o.CertBuffer.String())
		})
	}
}

// TestCELEnvironmentIsReused checks that the environment is not rebuilt for
// every certificate. Constructing one registers native types by reflection and
// initialises seven extension libraries; doing that per signature is pure waste.
func TestCELEnvironmentIsReused(t *testing.T) {
	first, err := celEnv.Env()
	require.NoError(t, err)
	second, err := celEnv.Env()
	require.NoError(t, err)
	assert.Same(t, first, second)
}

func TestCELProgramIsReused(t *testing.T) {
	const expr = `Subject.CommonName + "-reused"`
	data := TemplateData{SubjectKey: Subject{CommonName: "example"}}

	first, err := celEnv.Program(expr)
	require.NoError(t, err)
	second, err := celEnv.Program(expr)
	require.NoError(t, err)
	assert.Same(t, first, second)

	got, err := celEnv.Eval(expr, data)
	require.NoError(t, err)
	assert.Equal(t, "example-reused", got)
}

// device is a caller-supplied schema, standing in for the kind of typed data a
// CA knows about and this package cannot.
type device struct {
	Serial      string   `cel:"serial"`
	Hostname    string   `cel:"hostname"`
	IPAddresses []string `cel:"ipAddresses"`
}

// TestCELExtension covers the whole point of the registry: a caller declares
// typed variables, supplies their values from the template data, and templates
// read them with the type visible to the checker.
func TestCELExtension(t *testing.T) {
	require.NoError(t, celutil.Register(celutil.Extension{
		Name: "test-device",
		EnvOptions: []cel.EnvOption{
			ext.NativeTypes(reflect.TypeFor[device](), ext.ParseStructTag("cel")),
			cel.Variable("device", cel.ObjectType(celTypeName[device]())),
		},
		Activation: func(data map[string]any) map[string]any {
			// Stands in for reading a webhook response and projecting it onto
			// a schema the caller controls.
			wh, _ := data[WebhooksKey].(map[string]any)
			agent, _ := wh["Agent"].(map[string]any)
			d := device{IPAddresses: []string{}}
			if agent != nil {
				d.Serial, _ = agent["Serial"].(string)
				d.Hostname, _ = agent["Hostname"].(string)
			}
			return map[string]any{"device": d}
		},
	}))
	t.Cleanup(func() { celutil.Unregister("test-device") })

	cr, _ := createCertificateRequest(t, "foo", []string{"foo.com"})
	data := TemplateData{
		SubjectKey: Subject{CommonName: "example"},
		WebhooksKey: map[string]any{
			"Agent": map[string]any{"Serial": "C02XK1JMJGH5", "Hostname": "d1.example.com"},
		},
	}

	t.Run("typed read", func(t *testing.T) {
		var o Options
		text := `{{ cel "\"arn:aws:iam::123:role/\" + device.serial.lowerAscii()" | toJson }}`
		require.NoError(t, WithTemplate(text, data)(cr, &o))
		assert.Equal(t, `"arn:aws:iam::123:role/c02xk1jmjgh5"`, o.CertBuffer.String())
	})

	t.Run("absent value reads as empty, not an error", func(t *testing.T) {
		var o Options
		text := `{{ cel "[device.serial, \"unknown\"].filter(v, v != \"\")[0]" | toJson }}`
		require.NoError(t, WithTemplate(text, TemplateData{})(cr, &o))
		assert.Equal(t, `"unknown"`, o.CertBuffer.String())
	})

	t.Run("misspelled field fails to compile", func(t *testing.T) {
		var o Options
		err := WithTemplate(`{{ cel "device.serail" }}`, data)(cr, &o)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "undefined field 'serail'")
	})

	t.Run("still reachable untyped", func(t *testing.T) {
		var o Options
		text := `{{ cel "Webhooks.Agent.Serial" | toJson }}`
		require.NoError(t, WithTemplate(text, data)(cr, &o))
		assert.Equal(t, `"C02XK1JMJGH5"`, o.CertBuffer.String())
	})
}

// TestCELExtensionRebuildsEnvironment checks that registering after an
// environment has already been built takes effect, rather than being silently
// ignored by a cache that was populated first.
func TestCELExtensionRebuildsEnvironment(t *testing.T) {
	cr, _ := createCertificateRequest(t, "foo", []string{"foo.com"})

	var o Options
	require.NoError(t, WithTemplate(`{{ cel "1 + 1" | toJson }}`, TemplateData{})(cr, &o))

	require.NoError(t, celutil.Register(celutil.Extension{
		Name:       "late",
		EnvOptions: []cel.EnvOption{cel.Variable("late", cel.StringType)},
		Activation: func(map[string]any) map[string]any {
			return map[string]any{"late": "bound"}
		},
	}))
	t.Cleanup(func() { celutil.Unregister("late") })

	var o2 Options
	require.NoError(t, WithTemplate(`{{ cel "late" | toJson }}`, TemplateData{})(cr, &o2))
	assert.Equal(t, `"bound"`, o2.CertBuffer.String())

	// And it is gone again once unregistered.
	celutil.Unregister("late")
	var o3 Options
	err := WithTemplate(`{{ cel "late" }}`, TemplateData{})(cr, &o3)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "undeclared reference")
}

func TestCELEnvOptionsIsExported(t *testing.T) {
	// A caller validating expressions ahead of time builds the same
	// environment the renderer uses.
	env, err := cel.NewEnv(CELEnvOptions()...)
	require.NoError(t, err)

	ast, iss := env.Compile(`Subject.CommonName.lowerAscii()`)
	require.NoError(t, iss.Err())
	assert.Equal(t, "string", ast.OutputType().String())

	_, iss = env.Compile(`Subject.CommonNam`)
	require.Error(t, iss.Err())
}

func TestCELCostLimit(t *testing.T) {
	cr, _ := createCertificateRequest(t, "foo", []string{"foo.com"})
	var o Options
	err := WithTemplate(`{{ cel "lists.range(1000)" }}`, TemplateData{})(cr, &o)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cost limit exceeded")
}
