package sshutil

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"reflect"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetFuncMap(t *testing.T) {
	ok := []string{"fail", "contains", "split"}
	fail := []string{"env", "expandenv"}

	funcMap := GetFuncMap()
	for _, name := range ok {
		if _, ok := funcMap[name]; !ok {
			t.Errorf("GetFuncMap() does not contain the function %s", name)
		}
	}
	for _, name := range fail {
		if _, ok := funcMap[name]; ok {
			t.Errorf("GetFuncMap() contains the function %s", name)
		}
	}
}

// TestGetFuncMap_cel pins that a func map obtained with GetFuncMap, which is
// not bound to any template data, evaluates a CEL expression against the data
// the template passes as "$".
func TestGetFuncMap_cel(t *testing.T) {
	tmpl, err := template.New("template").Funcs(GetFuncMap()).Parse(`{{ cel "Token.sub" $ }}`)
	require.NoError(t, err)

	data := TemplateData{
		TokenKey: map[string]any{"sub": "8ff6a183"},
	}
	buf := new(bytes.Buffer)
	require.NoError(t, tmpl.Execute(buf, data))
	assert.Equal(t, "8ff6a183", buf.String())
}

func TestWithTemplate(t *testing.T) {
	key := mustGeneratePublicKey(t)
	cr := CertificateRequest{
		Key: key,
	}

	type args struct {
		text string
		data TemplateData
		cr   CertificateRequest
	}
	tests := []struct {
		name    string
		args    args
		want    Options
		wantErr bool
	}{
		{"user", args{DefaultTemplate, TemplateData{
			TypeKey:       "user",
			KeyIDKey:      "jane@doe.com",
			PrincipalsKey: []string{"jane", "jane@doe.com"},
			ExtensionsKey: DefaultExtensions(UserCert),
		}, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"type": "user",
	"keyId": "jane@doe.com",
	"principals": ["jane","jane@doe.com"],
	"extensions": {"permit-X11-forwarding":"","permit-agent-forwarding":"","permit-port-forwarding":"","permit-pty":"","permit-user-rc":""},
	"criticalOptions": null
}`)}, false},
		{"host", args{DefaultTemplate, TemplateData{
			TypeKey:            "host",
			KeyIDKey:           "foo",
			PrincipalsKey:      []string{"foo.internal"},
			CriticalOptionsKey: map[string]string{"foo": "bar"},
		}, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"type": "host",
	"keyId": "foo",
	"principals": ["foo.internal"],
	"extensions": null,
	"criticalOptions": {"foo":"bar"}
}`)}, false},
		{"fail", args{`{{ fail "a message" }}`, TemplateData{}, cr}, Options{}, true},
		{"failTemplate", args{`{{ fail "fatal error }}`, TemplateData{}, cr}, Options{}, true},
		{"error", args{`{{ mustHas 3 .Data }}`, TemplateData{
			"Data": 3,
		}, cr}, Options{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Options
			fn := WithTemplate(tt.args.text, tt.args.data)
			if err := fn(tt.args.cr, &got); (err != nil) != tt.wantErr {
				t.Errorf("WithTemplate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithTemplate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithTemplate_cel(t *testing.T) {
	key := mustGeneratePublicKey(t)
	cr := CertificateRequest{
		Key:        key,
		Principals: []string{"joe", "joe@example.com"},
	}

	buf := func(s string) Options {
		return Options{
			CertBuffer: bytes.NewBufferString(s),
		}
	}

	type args struct {
		text string
		data TemplateData
		cr   CertificateRequest
	}
	tests := []struct {
		name      string
		args      args
		want      Options
		assertion assert.ErrorAssertionFunc
	}{
		{"type", args{`{{cel "Type == 'user' ? 'admin@example.com' : 'admin.example.com'"}}`, TemplateData{
			TypeKey: UserCert.String(),
		}, cr}, buf("admin@example.com"), assert.NoError},
		{"keyID", args{`{{cel "json.encode({'type':'host', 'keyId': KeyID, 'principals': [KeyID, 'internal.' + KeyID]})"}}`, TemplateData{
			KeyIDKey: "example.com",
		}, cr}, buf(`{"keyId":"example.com","principals":["example.com","internal.example.com"],"type":"host"}`), assert.NoError},
		{"principals", args{`{{cel "Principals.map(s, s == 'admin' ? 'root' : s)"}}`, TemplateData{
			PrincipalsKey: []string{"joe", "admin", "joe@example.com"},
		}, cr}, buf(`[joe root joe@example.com]`), assert.NoError},
		{"extensions", args{`{{cel "json.encode(Extensions.transformMapEntry(k, v, k == 'github' ? {'login@github.com':v} : {k:v}))"}}`, TemplateData{
			ExtensionsKey: map[string]any{
				"github":                 "joe@example.com",
				"permit-port-forwarding": "",
				"permit-pty":             "",
				"permit-user-rc":         "",
			},
		}, cr}, buf(`{"login@github.com":"joe@example.com","permit-port-forwarding":"","permit-pty":"","permit-user-rc":""}`), assert.NoError},
		{"criticalOptions", args{`{{cel "json.encode(CriticalOptions.transformMap(k, v, k == 'force-command', 'bash -c \"' + v + '\"'))"}}`, TemplateData{
			CriticalOptionsKey: map[string]any{
				"force-command":  "whoami",
				"source-address": "127.0.0.1",
			},
		}, cr}, buf(`{"force-command":"bash -c \"whoami\""}`), assert.NoError},
		{"token with $", args{`{{cel "Token.sub" $}}`, TemplateData{
			TokenKey: map[string]any{"sub": "sub"},
		}, cr}, buf("sub"), assert.NoError},
		{"token", args{`{{cel "json.encode({'principals':[Token.sub], 'extensions':{'iss': Token.iss}})"}}`, TemplateData{
			TokenKey: map[string]any{
				"iss": "https://iss",
				"sub": "sub",
				"nbf": time.Now().Unix(),
			},
		}, cr}, buf(`{"extensions":{"iss":"https://iss"},"principals":["sub"]}`), assert.NoError},
		{"webhoks", args{`{{cel "strings.quote(Webhooks.Device.?Serial.or(Webhooks.Device.?Hostname).orValue('Unknown'))"}}`, TemplateData{
			WebhooksKey: map[string]any{
				"Device": map[string]any{
					"OS":       "Linux",
					"Hostname": "d1.example.com",
				},
			},
		}, cr}, buf(`"d1.example.com"`), assert.NoError},
		{"webhoks with get", args{`{{cel "'hostname:' + Webhooks.Device.get('Hostname') + ', serial:' + Webhooks.Device.get('Serial')"}}`, TemplateData{
			WebhooksKey: map[string]any{
				"Device": map[string]any{
					"OS":       "Linux",
					"Hostname": "d1.example.com",
				},
			},
		}, cr}, buf("hostname:d1.example.com, serial:"), assert.NoError},
		{"insecure", args{`{{cel "Insecure.CR.Principals.filter(s, s == Insecure.User.Email).first().value()"}}`, TemplateData{
			InsecureKey: TemplateData{
				UserKey: map[string]any{
					"Email": "joe@example.com",
				},
			},
		}, cr}, buf("joe@example.com"), assert.NoError},
		{"authorizationCrt", args{`{{cel "\"arn:aws:iam:1234567890:role/\" + AuthorizationCrt.Subject.OrganizationalUnit[0].lowerAscii()"}}`, TemplateData{
			AuthorizationCrtKey: &x509.Certificate{
				Subject: pkix.Name{OrganizationalUnit: []string{"Eng"}},
			},
		}, cr}, buf("arn:aws:iam:1234567890:role/eng"), assert.NoError},
		{"authorizationChain", args{`{{cel "\"arn:aws:iam:1234567890:role/\" + AuthorizationChain.map(x, x.Subject.OrganizationalUnit[0]).reverse().join('.').lowerAscii()"}}`, TemplateData{
			AuthorizationChainKey: []*x509.Certificate{
				{Subject: pkix.Name{OrganizationalUnit: []string{"Eng"}}},
				{Subject: pkix.Name{OrganizationalUnit: []string{"OpSec"}}},
			},
		}, cr}, buf("arn:aws:iam:1234567890:role/opsec.eng"), assert.NoError},
		{"fail compile", args{`{{cel "MyKey.CommonName"}}`, TemplateData{
			"MyKey": "admin@example.com",
		}, cr}, Options{}, assert.Error},
		{"fail eval", args{`{{cel "Webhooks.Device.Serial"}}`, TemplateData{
			WebhooksKey: map[string]any{
				"Device": map[string]any{
					"Hostname": "example.com",
				},
			},
		}, cr}, Options{}, assert.Error},
		{"fail costlimit", args{`{{cel "lists.range(1000)"}}`, TemplateData{
			PrincipalsKey: []string{"joe", "joe@example.com"},
		}, cr}, Options{}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Options
			fn := WithTemplate(tt.args.text, tt.args.data)
			tt.assertion(t, fn(tt.args.cr, &got))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWithTemplateBase64(t *testing.T) {
	key := mustGeneratePublicKey(t)
	cr := CertificateRequest{
		Key: key,
	}

	type args struct {
		s    string
		data TemplateData
		cr   CertificateRequest
	}
	tests := []struct {
		name    string
		args    args
		want    Options
		wantErr bool
	}{
		{"host", args{base64.StdEncoding.EncodeToString([]byte(DefaultTemplate)), TemplateData{
			TypeKey:            "host",
			KeyIDKey:           "foo.internal",
			PrincipalsKey:      []string{"foo.internal", "bar.internal"},
			ExtensionsKey:      map[string]interface{}{"foo": "bar"},
			CriticalOptionsKey: map[string]interface{}{"bar": "foo"},
		}, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"type": "host",
	"keyId": "foo.internal",
	"principals": ["foo.internal","bar.internal"],
	"extensions": {"foo":"bar"},
	"criticalOptions": {"bar":"foo"}
}`)}, false},
		{"badBase64", args{"foobar", TemplateData{}, cr}, Options{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Options
			fn := WithTemplateBase64(tt.args.s, tt.args.data)
			if err := fn(tt.args.cr, &got); (err != nil) != tt.wantErr {
				t.Errorf("WithTemplateBase64() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithTemplateBase64() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithTemplateFile(t *testing.T) {
	key := mustGeneratePublicKey(t)
	cr := CertificateRequest{
		Key: key,
	}

	data := TemplateData{
		TypeKey:       "user",
		KeyIDKey:      "jane@doe.com",
		PrincipalsKey: []string{"jane", "jane@doe.com"},
		ExtensionsKey: DefaultExtensions(UserCert),
		InsecureKey: TemplateData{
			UserKey: map[string]interface{}{
				"username": "jane",
			},
		},
	}

	type args struct {
		path string
		data TemplateData
		cr   CertificateRequest
	}
	tests := []struct {
		name    string
		args    args
		want    Options
		wantErr bool
	}{
		{"github.com", args{"./testdata/github.tpl", data, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"type": "user",
	"keyId": "jane@doe.com",
	"principals": ["jane","jane@doe.com"],
	"extensions": {"login@github.com":"jane","permit-X11-forwarding":"","permit-agent-forwarding":"","permit-port-forwarding":"","permit-pty":"","permit-user-rc":""}
}`),
		}, false},
		{"missing", args{"./testdata/missing.tpl", data, cr}, Options{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Options
			fn := WithTemplateFile(tt.args.path, tt.args.data)
			if err := fn(tt.args.cr, &got); (err != nil) != tt.wantErr {
				t.Errorf("WithTemplateFile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithTemplateFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
