package x509util

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func createRSACertificateRequest(t *testing.T, bits int, commonName string, sans []string) (*x509.CertificateRequest, crypto.Signer) {
	dnsNames, ips, emails, uris := SplitSANs(sans)
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	asn1Data, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: commonName},
		DNSNames:           dnsNames,
		IPAddresses:        ips,
		EmailAddresses:     emails,
		URIs:               uris,
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := x509.ParseCertificateRequest(asn1Data)
	if err != nil {
		t.Fatal(err)
	}
	return cr, priv
}

func TestGetFuncMap(t *testing.T) {
	ok := []string{
		"fail", "contains", "split", // generic sprig functions
		"asn1Enc", "asn1Marshal", "asn1Seq", "asn1Set", // custom functions
	}
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

func TestWithTemplate(t *testing.T) {
	cr, _ := createCertificateRequest(t, "foo", []string{"foo.com", "foo@foo.com", "::1", "https://foo.com"})
	crRSA, _ := createRSACertificateRequest(t, 2048, "foo", []string{"foo.com", "foo@foo.com", "::1", "https://foo.com"})
	crQuotes, _ := createCertificateRequest(t, `foo"}`, []string{"foo.com", "foo@foo.com", "::1", "https://foo.com"})

	templateWithExtensions := `{
	"subject": {{ toJson .Subject }},
	"sans": {{ toJson .SANs }},
{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
	"keyUsage": ["keyEncipherment", "digitalSignature"],
{{- else }}
	"keyUsage": ["digitalSignature"],
{{- end }}
	"extKeyUsage": ["serverAuth", "clientAuth"],
	"extensions": [
		{"id": "1.2.3.4", "value": {{ asn1Enc (first .Insecure.CR.DNSNames) | toJson }}},
		{"id": "1.2.3.5", "value": {{ asn1Marshal (first .Insecure.CR.DNSNames) | toJson }}},
		{"id": "1.2.3.6", "value": {{ asn1Seq (asn1Enc (first .Insecure.CR.DNSNames)) (asn1Enc "int:123456") | toJson }}},
		{"id": "1.2.3.7", "value": {{ asn1Set (asn1Marshal (first .Insecure.CR.DNSNames) "utf8") (asn1Enc "bool:true") | toJson }}}
	]
}`

	type args struct {
		text string
		data TemplateData
		cr   *x509.CertificateRequest
	}
	tests := []struct {
		name    string
		args    args
		want    Options
		wantErr bool
	}{
		{"leaf", args{DefaultLeafTemplate, TemplateData{
			SubjectKey: Subject{CommonName: "foo"},
			SANsKey:    []SubjectAlternativeName{{Type: "dns", Value: "foo.com"}},
		}, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foo"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`),
		}, false},
		{"leafRSA", args{DefaultLeafTemplate, TemplateData{
			SubjectKey: Subject{CommonName: "foo"},
			SANsKey:    []SubjectAlternativeName{{Type: "dns", Value: "foo.com"}},
		}, crRSA}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foo"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["keyEncipherment", "digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`),
		}, false},
		{"iid", args{DefaultIIDLeafTemplate, TemplateData{}, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName": "foo"},
	"dnsNames": ["foo.com"],
	"emailAddresses": ["foo@foo.com"],
	"ipAddresses": ["::1"],
	"uris": ["https://foo.com"],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`),
		}, false},
		{"iidRSAAndEnforced", args{DefaultIIDLeafTemplate, TemplateData{
			SANsKey: []SubjectAlternativeName{{Type: "dns", Value: "foo.com"}},
		}, crRSA}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName": "foo"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["keyEncipherment", "digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`),
		}, false},
		{"iidEscape", args{DefaultIIDLeafTemplate, TemplateData{}, crQuotes}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName": "foo\"}"},
	"dnsNames": ["foo.com"],
	"emailAddresses": ["foo@foo.com"],
	"ipAddresses": ["::1"],
	"uris": ["https://foo.com"],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`),
		}, false},
		{"admin", args{DefaultAdminLeafTemplate, TemplateData{}, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foo"},
	"dnsNames": ["foo.com"],
	"emailAddresses": ["foo@foo.com"],
	"ipAddresses": ["::1"],
	"uris": ["https://foo.com"],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`)}, false},
		{"adminRSA", args{DefaultAdminLeafTemplate, TemplateData{}, crRSA}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foo"},
	"dnsNames": ["foo.com"],
	"emailAddresses": ["foo@foo.com"],
	"ipAddresses": ["::1"],
	"uris": ["https://foo.com"],
	"keyUsage": ["keyEncipherment", "digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`)}, false},
		{"extensions", args{templateWithExtensions, TemplateData{
			SubjectKey: Subject{CommonName: "foo"},
			SANsKey:    []SubjectAlternativeName{{Type: "dns", Value: "foo.com"}},
		}, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foo"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"],
	"extensions": [
		{"id": "1.2.3.4", "value": "Ewdmb28uY29t"},
		{"id": "1.2.3.5", "value": "Ewdmb28uY29t"},
		{"id": "1.2.3.6", "value": "MA4TB2Zvby5jb20CAwHiQA=="},
		{"id": "1.2.3.7", "value": "MQwMB2Zvby5jb20BAf8="}
	]
}`),
		}, false},
		{"fail", args{`{{ fail "a message" }}`, TemplateData{}, cr}, Options{}, true},
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

func TestWithTemplateBase64(t *testing.T) {
	cr, _ := createCertificateRequest(t, "foo", []string{"foo.com", "foo@foo.com", "::1", "https://foo.com"})
	type args struct {
		s    string
		data TemplateData
		cr   *x509.CertificateRequest
	}
	tests := []struct {
		name    string
		args    args
		want    Options
		wantErr bool
	}{
		{"leaf", args{base64.StdEncoding.EncodeToString([]byte(DefaultLeafTemplate)), TemplateData{
			SubjectKey: Subject{CommonName: "foo"},
			SANsKey:    []SubjectAlternativeName{{Type: "dns", Value: "foo.com"}},
		}, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foo"},
	"sans": [{"type":"dns","value":"foo.com"}],
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`),
		}, false},
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
	cr, _ := createCertificateRequest(t, "foo", []string{"foo.com", "foo@foo.com", "::1", "https://foo.com"})
	rsa2048, _ := createRSACertificateRequest(t, 2048, "foo", []string{"foo.com", "foo@foo.com", "::1", "https://foo.com"})
	rsa3072, _ := createRSACertificateRequest(t, 3072, "foo", []string{"foo.com", "foo@foo.com", "::1", "https://foo.com"})

	data := TemplateData{
		SANsKey: []SubjectAlternativeName{
			{Type: "dns", Value: "foo.com"},
			{Type: "email", Value: "root@foo.com"},
			{Type: "ip", Value: "127.0.0.1"},
			{Type: "uri", Value: "uri:foo:bar"},
		},
		TokenKey: map[string]interface{}{
			"iss": "https://iss",
			"sub": "sub",
		},
	}
	type args struct {
		path string
		data TemplateData
		cr   *x509.CertificateRequest
	}
	tests := []struct {
		name    string
		args    args
		want    Options
		wantErr bool
	}{
		{"example", args{"./testdata/example.tpl", data, cr}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foo"},
	"sans": [{"type":"dns","value":"foo.com"},{"type":"email","value":"root@foo.com"},{"type":"ip","value":"127.0.0.1"},{"type":"uri","value":"uri:foo:bar"}],
	"emailAddresses": ["foo@foo.com"],
	"uris": "https://iss#sub",
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`),
		}, false},
		{"exampleRSA3072", args{"./testdata/example.tpl", data, rsa3072}, Options{
			CertBuffer: bytes.NewBufferString(`{
	"subject": {"commonName":"foo"},
	"sans": [{"type":"dns","value":"foo.com"},{"type":"email","value":"root@foo.com"},{"type":"ip","value":"127.0.0.1"},{"type":"uri","value":"uri:foo:bar"}],
	"emailAddresses": ["foo@foo.com"],
	"uris": "https://iss#sub",
	"keyUsage": ["keyEncipherment", "digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`),
		}, false},
		{"exampleRSA2048", args{"./testdata/example.tpl", data, rsa2048}, Options{}, true},
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

func mustMarshal(t *testing.T, value interface{}, params string) string {
	t.Helper()
	b, err := asn1.MarshalWithParams(value, params)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func Test_asn1Encode(t *testing.T) {
	now := time.Now().UTC()

	type args struct {
		str string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"ok", args{"string"}, mustMarshal(t, "string", "printable"), false},
		{"ok explicit", args{"explicit:string"}, mustMarshal(t, "string", "printable,explicit"), false},
		{"ok printable", args{"printable:string"}, mustMarshal(t, "string", "printable"), false},
		{"ok printable explicit", args{"printable,explicit:string"}, mustMarshal(t, "string", "printable,explicit"), false},
		{"ok ia5", args{"ia5:string"}, mustMarshal(t, "string", "ia5"), false},
		{"ok utf8", args{"utf8:string"}, mustMarshal(t, "string", "utf8"), false},
		{"ok utc", args{"utc:" + now.String()}, mustMarshal(t, now, "utc"), false},
		{"ok generalized", args{"generalized:" + now.Format(time.RFC3339)}, mustMarshal(t, now, "generalized"), false},
		{"ok int", args{"int:1234"}, mustMarshal(t, 1234, ""), false},
		{"ok numeric", args{"numeric:1234"}, mustMarshal(t, "1234", "numeric"), false},
		{"ok bool", args{"bool:true"}, mustMarshal(t, true, ""), false},
		{"ok raw", args{"raw:" + mustMarshal(t, 1234, "")}, mustMarshal(t, 1234, ""), false},
		{"fail numeric", args{"numeric:not-a-number"}, "", true},
		{"fail time", args{"utc:not-a-time"}, "", true},
		{"fail bool", args{"bool:untrue"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := asn1Encode(tt.args.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("asn1Encode() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("asn1Encode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_asn1Marshal(t *testing.T) {
	now := time.Now()
	type args struct {
		v      interface{}
		params []string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"ok printable", args{"string", nil}, mustMarshal(t, "string", "printable"), false},
		{"ok utf8", args{"string", []string{"utf8"}}, mustMarshal(t, "string", "utf8"), false},
		{"ok int", args{1234, nil}, mustMarshal(t, 1234, ""), false},
		{"ok time", args{now, nil}, mustMarshal(t, now, "utc"), false},
		{"ok seq", args{[]any{"string", 1234}, nil}, mustMarshal(t, []any{"string", 1234}, ""), false},
		{"ok set", args{[]any{"string", 1234}, []string{"set"}}, mustMarshal(t, []any{"string", 1234}, "set"), false},
		{"ok bool", args{false, nil}, mustMarshal(t, false, ""), false},
		{"fail numeric", args{"string", []string{"numeric"}}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := asn1Marshal(tt.args.v, tt.args.params...)
			if (err != nil) != tt.wantErr {
				t.Errorf("asn1Marshal() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("asn1Marshal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_asn1Sequence(t *testing.T) {
	now := time.Now().UTC()
	type set struct {
		Int  int
		Time time.Time `asn1:"utc"`
	}
	type complexWithSet struct {
		String string
		Set    set `asn1:"set"`
	}

	b64String, err := asn1Encode("string")
	require.NoError(t, err)

	b64Int, err := asn1Encode("int:1234")
	require.NoError(t, err)

	b64Time, err := asn1Encode("utc:" + now.String())
	require.NoError(t, err)

	b64Set, err := asn1Set(b64Int, b64Time)
	require.NoError(t, err)

	type args struct {
		b64enc []string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"ok", args{[]string{b64String, b64Int}}, mustMarshal(t, []any{"string", 1234}, "sequence"), false},
		{"ok complex", args{[]string{b64String, b64Set}}, mustMarshal(t, complexWithSet{"string", set{1234, now}}, ""), false},
		{"fail", args{[]string{b64String, "bad-base-64"}}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := asn1Sequence(tt.args.b64enc...)
			if (err != nil) != tt.wantErr {
				t.Errorf("asn1Sequence() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("asn1Sequence() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_asn1Set(t *testing.T) {
	now := time.Now().UTC()

	type complexWithSequence struct {
		String   string
		Sequence []any
	}

	b64String, err := asn1Encode("string")
	require.NoError(t, err)

	b64Int, err := asn1Encode("int:1234")
	require.NoError(t, err)

	b64Time, err := asn1Encode("utc:" + now.String())
	require.NoError(t, err)

	b64Sequence, err := asn1Sequence(b64Int, b64Time)
	require.NoError(t, err)

	type args struct {
		b64enc []string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"ok", args{[]string{b64Int, b64String}}, mustMarshal(t, []any{1234, "string"}, "set"), false},
		{"ok complex", args{[]string{b64String, b64Sequence}}, mustMarshal(t, complexWithSequence{"string", []any{1234, now}}, "set"), false},
		{"fail", args{[]string{b64String, "bad-base-64"}}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := asn1Set(tt.args.b64enc...)
			if (err != nil) != tt.wantErr {
				t.Errorf("asn1Set() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("asn1Set() = %v, want %v", got, tt.want)
			}
		})
	}
}
