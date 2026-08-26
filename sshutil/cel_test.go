package sshutil

import (
	"reflect"
	"testing"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/celutil"
)

func TestCELTemplate(t *testing.T) {
	cr := CertificateRequest{
		Key:        mustGeneratePublicKey(t),
		Type:       UserCert.String(),
		KeyID:      "jane@example.com",
		Principals: []string{"Jane", "jane"},
	}
	data := CreateTemplateData(UserCert, "jane@example.com", []string{"Jane", "jane"})
	data.SetToken(map[string]any{"sub": "jane@example.com"})

	tests := []struct {
		name string
		text string
		want string
	}{
		{"key id", `{{ cel "KeyID" | toJson }}`, `"jane@example.com"`},
		{"principals", `{{ cel "Principals" | toJson }}`, `["Jane","jane"]`},
		{"lowered principals", `{{ cel "Principals.map(p, p.lowerAscii())" | toJson }}`, `["jane","jane"]`},
		{"deduplicated", `{{ cel "Principals.map(p, p.lowerAscii()).distinct()" | toJson }}`, `["jane"]`},
		{"local part", `{{ cel "KeyID.split(\"@\")[0]" | toJson }}`, `"jane"`},
		{"cert type", `{{ cel "Type" | toJson }}`, `"user"`},
		{"token", `{{ cel "Token.sub" | toJson }}`, `"jane@example.com"`},
		{"has extension", `{{ cel "\"permit-pty\" in Extensions" | toJson }}`, `true`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var o Options
			require.NoError(t, WithTemplate(tt.text, data)(cr, &o))
			assert.Equal(t, tt.want, o.CertBuffer.String())
		})
	}
}

func TestCELTemplateErrors(t *testing.T) {
	cr := CertificateRequest{Key: mustGeneratePublicKey(t), Type: UserCert.String()}
	data := CreateTemplateData(UserCert, "jane@example.com", []string{"jane"})

	t.Run("undeclared variable", func(t *testing.T) {
		var o Options
		err := WithTemplate(`{{ cel "Nope" }}`, data)(cr, &o)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "undeclared reference")
	})

	t.Run("cost limit", func(t *testing.T) {
		var o Options
		err := WithTemplate(`{{ cel "lists.range(1000)" }}`, data)(cr, &o)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cost limit exceeded")
	})
}

type sshDevice struct {
	Serial string `cel:"serial"`
}

// TestCELExtensionAppliesToSSH checks that one registration covers both
// certificate kinds. A CA registers its schema once at start-up and it is
// available to X.509 and SSH templates alike.
func TestCELExtensionAppliesToSSH(t *testing.T) {
	require.NoError(t, celutil.Register(celutil.Extension{
		Name: "test-ssh-device",
		EnvOptions: []cel.EnvOption{
			ext.NativeTypes(reflect.TypeFor[sshDevice](), ext.ParseStructTag("cel")),
			cel.Variable("device", cel.ObjectType(reflect.TypeFor[sshDevice]().String())),
		},
		Activation: func(map[string]any) map[string]any {
			return map[string]any{"device": sshDevice{Serial: "C02XK1JMJGH5"}}
		},
	}))
	t.Cleanup(func() { celutil.Unregister("test-ssh-device") })

	cr := CertificateRequest{Key: mustGeneratePublicKey(t), Type: UserCert.String()}
	data := CreateTemplateData(UserCert, "jane@example.com", []string{"jane"})

	var o Options
	text := `{{ cel "Principals + [device.serial.lowerAscii()]" | toJson }}`
	require.NoError(t, WithTemplate(text, data)(cr, &o))
	assert.Equal(t, `["jane","c02xk1jmjgh5"]`, o.CertBuffer.String())
}

func TestSSHCELEnvOptionsIsExported(t *testing.T) {
	env, err := cel.NewEnv(CELEnvOptions()...)
	require.NoError(t, err)

	ast, iss := env.Compile(`Principals.map(p, p.lowerAscii())`)
	require.NoError(t, iss.Err())
	assert.Equal(t, "list(string)", ast.OutputType().String())
}
