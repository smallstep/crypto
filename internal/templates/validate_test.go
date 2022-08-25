package templates

import (
	"errors"
	"fmt"
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
			name: "ok/default-leaf-template",
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
			name: "ok/default-x509-iid-template",
			text: `{
				"subject": {"commonName": {{ toJson .Insecure.CR.Subject.CommonName }}},
			{{- if .SANs }}
				"sans": {{ toJson .SANs }},
			{{- else }}
				"dnsNames": {{ toJson .Insecure.CR.DNSNames }},
				"emailAddresses": {{ toJson .Insecure.CR.EmailAddresses }},
				"ipAddresses": {{ toJson .Insecure.CR.IPAddresses }},
				"uris": {{ toJson .Insecure.CR.URIs }},
			{{- end }}
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
			name: "ok/default-x509-adobe",
			text: `{
				"test:": "default-x509-adobe",
				"subject": {{ toJson .Token.email }},
				"sans": {{ toJson .SANs }},
			{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
				"keyUsage": ["dataEncipherment", "digitalSignature", "keyAgreement"],
			{{- else }}
				{{ fail "Key type must be RSA. Try again with --kty=RSA" }}
			{{- end }}
				"extensions": [{"id": "1.2.840.113583.1.1.10", "value": "BQA="}]
			}`,
			err: nil,
		},
		{
			name: "ok/range-subdomains-regex",
			text: `{
				{{ range .SANs }}
					{{ if not (and (regexMatch ".*\\.smallstep\\.com" .Value) (eq .Type "dns")) }}
						{{ fail "Not a *.smallstep.com host" }}
					{{ end }}
				{{ end }}
				"subject": {{ toJson .Subject }},
				"sans": {{ toJson .SANs }},
				"keyUsage": ["digitalSignature", "keyEncipherment", "keyAgreement"],
				"extKeyUsage": ["serverAuth"]
			}`,
			err: nil,
		},
		{
			name: "ok/default-ssh-iid-template",
			text: `{
				"type": {{ toJson .Type }},
				"keyId": {{ toJson .KeyID }},
			{{- if .Insecure.CR.Principals }}
				"principals": {{ toJson .Insecure.CR.Principals }},
			{{- else }}
				"principals": {{ toJson .Principals }},
			{{- end }}
				"extensions": {{ toJson .Extensions }}
			}`,
			err: nil,
		},
		{
			name: "ok/ssh-cr-template",
			text: `{
				"type": {{ toJson .Insecure.CR.Type }},
				"keyId": {{ toJson .Insecure.CR.KeyID }},
				"principals": {{ toJson .Insecure.CR.Principals }}
			{{- if eq .Insecure.CR.Type "user" }}
				, "extensions": {
					"permit-X11-forwarding":   "",
					"permit-agent-forwarding": "",
					"permit-port-forwarding":  "",
					"permit-pty":              "",
					"permit-user-rc":          ""
				}
			{{- end }}
			}`,
			err: nil,
		},
		{
			name: "ok/ssh-github-token",
			text: `{
				"type": {{ toJson .Type }},
				"keyId": {{ toJson .KeyID }},
				"principals": {{ toJson .Principals }},
				"criticalOptions": {{ toJson .CriticalOptions }},
			{{ if .Token.ghu }}
				"extensions": {
				  "login@github.com": {{ toJson .Token.ghu }}
				}
			{{ else }}
				"extensions": {{ toJson .Extensions }}
			{{ end }}
			}`,
			err: nil,
		},
		{
			name: "ok/empty-template",
			text: "",
			err:  nil,
		},
		{
			name: "ok/template-with-nested-property",
			text: `
			{{ if not .Token.ghu.foo }}
				{{ toJson "token has no GitHub username" }}
			{{ end }}
		  `,
			err: nil,
		},
		{
			name: "fail/template-parsing-unterminated-quoted-string",
			text: `
			{{ if not .Token.ghu }} 
				{{ fail "token has no GitHub username }}
			{{ end }}
			`,
			err: errors.New("error parsing template: template: template:3: unterminated quoted string"),
		},
		{
			name: "fail/template-parsing-unknown-function",
			text: `{
				"subject": {{ unknownFunction .Subject }}
			}`,
			err: errors.New("error parsing template: template: template:2: function \"unknownFunction\" not defined"),
		},
		{
			name: "fail/template-parsing-missing-closing-brace",
			text: `{
				"subject": {{ toJson .Subject }},
				"sans": {{ toJson .SANs }
			}`,
			err: errors.New("error parsing template: template: template:3: unexpected \"}\" in operand"),
		},
		{
			name: "ok/json-extraneous-trailing-brace",
			text: `
				{
					"subject": {{ toJson .Subject }}},
					"issuer": {{ toJson .Subject }}
				}
			`,
			err: nil, // NOTE: ideally we would like to catch this, but without validating the JSON, this seems hard
		},
		{
			name: "ok/json-missing-trailing-comma",
			text: `{
				"subject": {{ toJson .Subject }}
				"sans": {{ toJson .SANs }}
			}`,
			err: nil, // NOTE: ideally we would like to catch this, but without validating the JSON, this seems hard
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println(tt.name)
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
