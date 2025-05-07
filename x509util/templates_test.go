package x509util

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTemplateError_Error(t *testing.T) {
	type fields struct {
		Message string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"ok", fields{"an error"}, "an error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &TemplateError{
				Message: tt.fields.Message,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("TemplateError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewTemplateData(t *testing.T) {
	tests := []struct {
		name string
		want TemplateData
	}{
		{"ok", TemplateData{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewTemplateData(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTemplateData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateTemplateData(t *testing.T) {
	type args struct {
		commonName string
		sans       []string
	}
	tests := []struct {
		name string
		args args
		want TemplateData
	}{
		{"ok", args{"jane.doe.com", []string{"jane.doe.com", "jane@doe.com", "1.1.1.1", "mailto:jane@doe.com"}}, TemplateData{
			SubjectKey: Subject{CommonName: "jane.doe.com"},
			SANsKey: []SubjectAlternativeName{
				{Type: DNSType, Value: "jane.doe.com"},
				{Type: IPType, Value: "1.1.1.1"},
				{Type: EmailType, Value: "jane@doe.com"},
				{Type: URIType, Value: "mailto:jane@doe.com"},
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CreateTemplateData(tt.args.commonName, tt.args.sans); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateTemplateData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTemplateData_SetInsecure(t *testing.T) {
	type args struct {
		key string
		v   interface{}
	}
	tests := []struct {
		name string
		td   TemplateData
		args args
		want TemplateData
	}{
		{"empty", TemplateData{}, args{"foo", "bar"}, TemplateData{InsecureKey: TemplateData{"foo": "bar"}}},
		{"overwrite", TemplateData{InsecureKey: TemplateData{"foo": "bar"}}, args{"foo", "zar"}, TemplateData{InsecureKey: TemplateData{"foo": "zar"}}},
		{"existing", TemplateData{InsecureKey: TemplateData{"foo": "bar"}}, args{"bar", "foo"}, TemplateData{InsecureKey: TemplateData{"foo": "bar", "bar": "foo"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.td.SetInsecure(tt.args.key, tt.args.v)
			if !reflect.DeepEqual(tt.td, tt.want) {
				t.Errorf("TemplateData.SetInsecure() = %v, want %v", tt.td, tt.want)
			}
		})
	}
}

func TestTemplateData_SetSubject(t *testing.T) {
	type args struct {
		v Subject
	}
	tests := []struct {
		name string
		td   TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{Subject{CommonName: "foo"}}, TemplateData{SubjectKey: Subject{CommonName: "foo"}}},
		{"overwrite", TemplateData{SubjectKey: Subject{CommonName: "foo"}}, args{Subject{Province: []string{"CA"}}}, TemplateData{SubjectKey: Subject{Province: []string{"CA"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.td.SetSubject(tt.args.v)
			if !reflect.DeepEqual(tt.td, tt.want) {
				t.Errorf("TemplateData.SetSubject() = %v, want %v", tt.td, tt.want)
			}
		})
	}
}

func TestTemplateData_SetCommonName(t *testing.T) {
	type args struct {
		cn string
	}
	tests := []struct {
		name string
		td   TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{"commonName"}, TemplateData{SubjectKey: Subject{CommonName: "commonName"}}},
		{"overwrite", TemplateData{SubjectKey: Subject{CommonName: "foo", Province: []string{"CA"}}}, args{"commonName"}, TemplateData{SubjectKey: Subject{CommonName: "commonName", Province: []string{"CA"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.td.SetCommonName(tt.args.cn)
			if !reflect.DeepEqual(tt.td, tt.want) {
				t.Errorf("TemplateData.SetCommonName() = %v, want %v", tt.td, tt.want)
			}
		})
	}
}

func TestTemplateData_SetSANs(t *testing.T) {
	type args struct {
		sans []string
	}
	tests := []struct {
		name string
		td   TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{[]string{"jane.doe.com", "jane@doe.com", "1.1.1.1", "mailto:jane@doe.com"}}, TemplateData{
			SANsKey: []SubjectAlternativeName{
				{Type: DNSType, Value: "jane.doe.com"},
				{Type: IPType, Value: "1.1.1.1"},
				{Type: EmailType, Value: "jane@doe.com"},
				{Type: URIType, Value: "mailto:jane@doe.com"},
			}},
		},
		{"overwrite", TemplateData{
			SubjectKey: Subject{CommonName: "foo", Province: []string{"CA"}},
			SANsKey:    []SubjectAlternativeName{{Type: DNSType, Value: "john.doe.com"}},
		}, args{[]string{"jane.doe.com"}}, TemplateData{
			SubjectKey: Subject{CommonName: "foo", Province: []string{"CA"}},
			SANsKey: []SubjectAlternativeName{
				{Type: DNSType, Value: "jane.doe.com"},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.td.SetSANs(tt.args.sans)
			if !reflect.DeepEqual(tt.td, tt.want) {
				t.Errorf("TemplateData.SetSANs() = %v, want %v", tt.td, tt.want)
			}
		})
	}
}

func TestTemplateData_SetSubjectAlternativeNames(t *testing.T) {
	type args struct {
		sans []SubjectAlternativeName
	}
	tests := []struct {
		name string
		td   TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{[]SubjectAlternativeName{
			{Type: "dns", Value: "jane.doe.com"},
			{Type: "permanentIdentifier", Value: "123456789"},
		}}, TemplateData{
			SANsKey: []SubjectAlternativeName{
				{Type: DNSType, Value: "jane.doe.com"},
				{Type: "permanentIdentifier", Value: "123456789"},
			}},
		},
		{"overwrite", TemplateData{
			SubjectKey: Subject{CommonName: "foo", Province: []string{"CA"}},
			SANsKey: []SubjectAlternativeName{
				{Type: DNSType, Value: "jane.doe.com"},
				{Type: "permanentIdentifier", Value: "123456789"},
			},
		}, args{[]SubjectAlternativeName{
			{Type: "email", Value: "jane@doe.com"},
		}}, TemplateData{
			SubjectKey: Subject{CommonName: "foo", Province: []string{"CA"}},
			SANsKey: []SubjectAlternativeName{
				{Type: "email", Value: "jane@doe.com"},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.td.SetSubjectAlternativeNames(tt.args.sans...)
			if !reflect.DeepEqual(tt.td, tt.want) {
				t.Errorf("TemplateData.SetSubjectAlternativeNames() = %v, want %v", tt.td, tt.want)
			}
		})
	}
}

func TestTemplateData_SetToken(t *testing.T) {
	type args struct {
		v interface{}
	}
	tests := []struct {
		name string
		td   TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{"token"}, TemplateData{TokenKey: "token"}},
		{"overwrite", TemplateData{TokenKey: "foo"}, args{"token"}, TemplateData{TokenKey: "token"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.td.SetToken(tt.args.v)
			if !reflect.DeepEqual(tt.td, tt.want) {
				t.Errorf("TemplateData.SetToken() = %v, want %v", tt.td, tt.want)
			}
		})
	}
}

func TestTemplateData_SetUserData(t *testing.T) {
	type args struct {
		v interface{}
	}
	tests := []struct {
		name string
		td   TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{"userData"}, TemplateData{InsecureKey: TemplateData{UserKey: "userData"}}},
		{"overwrite", TemplateData{InsecureKey: TemplateData{UserKey: "foo"}}, args{"userData"}, TemplateData{InsecureKey: TemplateData{UserKey: "userData"}}},
		{"existing", TemplateData{InsecureKey: TemplateData{"foo": "bar"}}, args{"userData"}, TemplateData{InsecureKey: TemplateData{"foo": "bar", UserKey: "userData"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.td.SetUserData(tt.args.v)
			if !reflect.DeepEqual(tt.td, tt.want) {
				t.Errorf("TemplateData.SetUserData() = %v, want %v", tt.td, tt.want)
			}
		})
	}
}

func TestTemplateData_SetAuthorizationCertificate(t *testing.T) {
	crt1 := Certificate{DNSNames: []string{"crt1"}}
	crt2 := Certificate{DNSNames: []string{"crt2"}}
	type args struct {
		crt Certificate
	}
	tests := []struct {
		name string
		t    TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{crt1}, TemplateData{
			AuthorizationCrtKey: crt1,
		}},
		{"overwrite", TemplateData{
			AuthorizationCrtKey: crt1,
			InsecureKey: TemplateData{
				UserKey: "data",
			},
		}, args{crt2}, TemplateData{
			AuthorizationCrtKey: crt2,
			InsecureKey: TemplateData{
				UserKey: "data",
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.t.SetAuthorizationCertificate(tt.args.crt)
			if !reflect.DeepEqual(tt.t, tt.want) {
				t.Errorf("TemplateData.SetCertificate() = %v, want %v", tt.t, tt.want)
			}
		})
	}
}

func TestTemplateData_SetAuthorizationCertificateChain(t *testing.T) {
	crt1 := Certificate{DNSNames: []string{"crt1"}}
	crt2 := Certificate{DNSNames: []string{"crt2"}}
	type args struct {
		crt []interface{}
	}
	tests := []struct {
		name string
		t    TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{[]interface{}{crt1, crt2}}, TemplateData{
			AuthorizationChainKey: []interface{}{crt1, crt2},
		}},
		{"overwrite", TemplateData{
			AuthorizationChainKey: []interface{}{crt1, crt2},
			InsecureKey: TemplateData{
				UserKey: "data",
			},
		}, args{[]interface{}{crt1}}, TemplateData{
			AuthorizationChainKey: []interface{}{crt1},
			InsecureKey: TemplateData{
				UserKey: "data",
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.t.SetAuthorizationCertificateChain(tt.args.crt)
			if !reflect.DeepEqual(tt.t, tt.want) {
				t.Errorf("TemplateData.SetCertificate() = %v, want %v", tt.t, tt.want)
			}
		})
	}
}

func TestTemplateData_SetCertificateRequest(t *testing.T) {
	ku, err := KeyUsage(x509.KeyUsageDigitalSignature).Extension()
	require.NoError(t, err)
	eku, err := ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning}.Extension(nil)
	require.NoError(t, err)

	cr := &x509.CertificateRequest{
		DNSNames: []string{"foo", "bar"},
		Extensions: []pkix.Extension{{
			Id:       asn1.ObjectIdentifier(eku.ID),
			Critical: eku.Critical,
			Value:    eku.Value,
		}, {
			Id:       asn1.ObjectIdentifier(ku.ID),
			Critical: ku.Critical,
			Value:    ku.Value,
		}},
	}
	cr1 := &CertificateRequest{
		DNSNames:    []string{"foo", "bar"},
		KeyUsage:    KeyUsage(x509.KeyUsageDigitalSignature),
		ExtKeyUsage: ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning},
		Extensions:  []Extension{eku, ku},
	}
	cr2 := &CertificateRequest{
		EmailAddresses: []string{"foo@bar.com"},
	}
	type args struct {
		cr *x509.CertificateRequest
	}
	tests := []struct {
		name string
		td   TemplateData
		args args
		want TemplateData
	}{
		{"ok", TemplateData{}, args{cr}, TemplateData{InsecureKey: TemplateData{CertificateRequestKey: cr1}}},
		{"overwrite", TemplateData{InsecureKey: TemplateData{CertificateRequestKey: cr2}}, args{cr}, TemplateData{InsecureKey: TemplateData{CertificateRequestKey: cr1}}},
		{"existing", TemplateData{InsecureKey: TemplateData{"foo": "bar"}}, args{cr}, TemplateData{InsecureKey: TemplateData{"foo": "bar", CertificateRequestKey: cr1}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.td.SetCertificateRequest(tt.args.cr)
			if !reflect.DeepEqual(tt.td, tt.want) {
				t.Errorf("TemplateData.SetCertificateRequest() = %v, want %v", tt.td, tt.want)
			}
		})
	}
}

func TestTemplateData_SetWebhook(t *testing.T) {
	type args struct {
		name string
		v    interface{}
	}
	tests := []struct {
		name string
		td   TemplateData
		args args
		want TemplateData
	}{
		{"empty", TemplateData{}, args{"foo", "bar"}, TemplateData{WebhooksKey: map[string]interface{}{"foo": "bar"}}},
		{"overwrite", TemplateData{WebhooksKey: map[string]interface{}{"foo": "bar"}}, args{"foo", "zar"}, TemplateData{WebhooksKey: map[string]interface{}{"foo": "zar"}}},
		{"existing", TemplateData{WebhooksKey: map[string]interface{}{"foo": "bar"}}, args{"bar", "foo"}, TemplateData{WebhooksKey: map[string]interface{}{"foo": "bar", "bar": "foo"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.td.SetWebhook(tt.args.name, tt.args.v)
			if !reflect.DeepEqual(tt.td, tt.want) {
				t.Errorf("TemplateData.SetWebhook() = %v, want %v", tt.td, tt.want)
			}
		})
	}
}

func TestValidateTemplate(t *testing.T) {
	tests := []struct {
		name    string
		text    []byte
		wantErr bool
	}{
		{
			name:    "ok",
			text:    []byte(DefaultLeafTemplate),
			wantErr: false,
		},
		{
			name:    "ok/invalid-json",
			text:    []byte("{!?}"),
			wantErr: false,
		},
		{
			name:    "fail/unknown-function",
			text:    []byte("{{ unknownFunction }}"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateTemplate(tt.text); (err != nil) != tt.wantErr {
				t.Errorf("ValidateTemplate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTemplateData(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "ok",
			data:    []byte("{}"),
			wantErr: false,
		},
		{
			name:    "fail",
			data:    []byte("{!?}"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateTemplateData(tt.data); (err != nil) != tt.wantErr {
				t.Errorf("ValidateTemplateData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
