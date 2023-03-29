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
	"fmt"
	"reflect"
	"strconv"
	"testing"
	"time"
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
		{"type": "1.2.3.4", "value": {{ asn1Encode (first .Insecure.CR.DNSNames) | toJson }},
		{"type": "1.2.3.5", "value": {{ asn1Sequence (asn1Encode (first .Insecure.CR.DNSNames)) (asn1Encode "int:123456") | toJson }},
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
		{"type": "1.2.3.4", "value": "Ewdmb28uY29t",
		{"type": "1.2.3.5", "value": "MA4TB2Zvby5jb20CAwHiQA==",
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

	_, timeErr := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", "not-a-time")
	timeErr = fmt.Errorf("invalid utc value: %w", timeErr)

	type args struct {
		str string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"ok", args{"string"}, mustMarshal(t, "string", "printable")},
		{"ok explicit", args{"explicit:string"}, mustMarshal(t, "string", "printable,explicit")},
		{"ok printable", args{"printable:string"}, mustMarshal(t, "string", "printable")},
		{"ok printable explicit", args{"printable,explicit:string"}, mustMarshal(t, "string", "printable,explicit")},
		{"ok ia5", args{"ia5:string"}, mustMarshal(t, "string", "ia5")},
		{"ok utf8", args{"utf8:string"}, mustMarshal(t, "string", "utf8")},
		{"ok utc", args{"utc:" + now.String()}, mustMarshal(t, now, "utc")},
		{"ok generalized", args{"generalized:" + now.Format(time.RFC3339)}, mustMarshal(t, now, "generalized")},
		{"ok int", args{"int:1234"}, mustMarshal(t, 1234, "")},
		{"ok numeric", args{"numeric:1234"}, mustMarshal(t, "1234", "numeric")},
		{"ok raw", args{"raw:" + mustMarshal(t, 1234, "")}, mustMarshal(t, 1234, "")},
		{"fail numeric", args{"numeric:not-a-number"}, "invalid numeric value"},
		{"fail time", args{"utc:not-a-time"}, timeErr.Error()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := asn1Encode(tt.args.str); got != tt.want {
				t.Errorf("asn1Encode() = %v, want %v", got, tt.want)
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

	_, err := strconv.Atoi("string")
	err = fmt.Errorf("invalid int value: %w", err)
	_, err = base64.StdEncoding.DecodeString(err.Error())

	type args struct {
		b64enc []string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"ok", args{[]string{asn1Encode("string"), asn1Encode("int:1234")}}, mustMarshal(t, []any{"string", 1234}, "sequence")},
		{"ok complex", args{[]string{asn1Encode("string"), asn1Set(asn1Encode("int:1234"), asn1Encode("utc:"+now.String()))}}, mustMarshal(t, complexWithSet{"string", set{1234, now}}, "")},
		{"fail", args{[]string{asn1Encode("string"), asn1Encode("int:string")}}, err.Error()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := asn1Sequence(tt.args.b64enc...); got != tt.want {
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

	_, err := strconv.Atoi("string")
	err = fmt.Errorf("invalid int value: %w", err)
	_, err = base64.StdEncoding.DecodeString(err.Error())

	type args struct {
		b64enc []string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"ok", args{[]string{asn1Encode("int:1234"), asn1Encode("string")}}, mustMarshal(t, []any{1234, "string"}, "set")},
		{"ok complex", args{[]string{asn1Encode("string"), asn1Sequence(asn1Encode("int:1234"), asn1Encode("utc:"+now.String()))}}, mustMarshal(t, complexWithSequence{"string", []any{1234, now}}, "set")},
		{"fail", args{[]string{asn1Encode("string"), asn1Encode("int:string")}}, err.Error()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := asn1Set(tt.args.b64enc...); got != tt.want {
				t.Errorf("asn1Set() = %v, want %v", got, tt.want)
			}
		})
	}
}
