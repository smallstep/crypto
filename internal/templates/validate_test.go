package templates

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateTemplate(t *testing.T) {
	tests := []struct {
		name string
		text string
		err  error
	}{
		{
			name: "ok",
			text: `{
				"subject": {{ toJson .Subject }},
				"sans": {{ toJson .SANs }},
			{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
				"keyUsage": ["keyEncipherment", "digitalSignature"],
			{{- else }}
				"keyUsage": ["digitalSignature"],
			{{- end }}
				"extKeyUsage": ["serverAuth", "clientAuth"]
			}`,
			err: nil,
		},
		{
			name: "fail/template-parsing-trailing-brace",
			text: `
				{
					"subject": {{ toJson .Subject }}},
					"issuer": {{ toJson .Subject }}
				}
			`,
			err: errors.New("invalid JSON: early decoder termination suspected"),
		},
		{
			name: "fail/template-parsing-unknown-function",
			text: `{
				"subject": {{ unknownFunction .Subject }}
			}`,
			err: errors.New("error parsing template: template: template:2: function \"unknownFunction\" not defined"),
		},
		{
			name: "fail/template-parsing-missing-closing-braces",
			text: `{
				"subject": {{ toJson .Subject }},
				"sans": {{ toJson .SANs }
			}`,
			err: errors.New("error parsing template: template: template:3: unexpected \"}\" in operand"),
		},
		{
			name: "fail/json-missing-trailing-comma",
			text: `{
				"subject": {{ toJson .Subject }}
				"sans": {{ toJson .SANs }}
			}`,
			err: errors.New("invalid JSON: invalid character '\"' after object key:value pair"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplate(tt.text)
			if tt.err != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, tt.err.Error())
				return
			}

			assert.Nil(t, err)

		})
	}
}

func TestValidateTemplateData(t *testing.T) {
	tests := []struct {
		name string
		text string
		err  error
	}{
		{
			name: "ok",
			text: `{
				"x": 1,
				"y": 2
			}`,
			err: nil,
		},
		{
			name: "fail/missing-comma-trailing-comma",
			text: `{
				"x": 1
				"y": 2
			}`,
			err: errors.New("invalid JSON: invalid character '\"' after object key:value pair"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplateData(tt.text)
			if tt.err != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, tt.err.Error())
				return
			}

			assert.Nil(t, err)
		})
	}
}
