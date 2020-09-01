package x509util

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"net/url"
	"reflect"
	"testing"
)

func TestNewCertificateRequest(t *testing.T) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		signer crypto.Signer
		opts   []Option
	}
	tests := []struct {
		name    string
		args    args
		want    *CertificateRequest
		wantErr bool
	}{
		{"ok simple", args{signer, []Option{}}, &CertificateRequest{
			PublicKey: signer.Public(),
			Signer:    signer,
		}, false},
		{"ok default", args{signer, []Option{
			WithTemplate(DefaultCertificateRequestTemplate, CreateTemplateData("commonName", []string{"foo.com", "3.14.15.92", "root@foo.com", "mailto:root@foo.com"})),
		}}, &CertificateRequest{
			Subject: Subject{CommonName: "commonName"},
			SANs: []SubjectAlternativeName{
				{Type: "dns", Value: "foo.com"},
				{Type: "ip", Value: "3.14.15.92"},
				{Type: "email", Value: "root@foo.com"},
				{Type: "uri", Value: "mailto:root@foo.com"},
			},
			PublicKey: signer.Public(),
			Signer:    signer,
		}, false},
		{"fail apply", args{signer, []Option{WithTemplateFile("testdata/missing.tpl", NewTemplateData())}}, nil, true},
		{"fail unmarshal", args{signer, []Option{WithTemplate("{badjson", NewTemplateData())}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCertificateRequest(tt.args.signer, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCertificateRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCertificateRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newCertificateRequest(t *testing.T) {
	type args struct {
		cr *x509.CertificateRequest
	}
	tests := []struct {
		name string
		args args
		want *CertificateRequest
	}{
		{"ok", args{&x509.CertificateRequest{}}, &CertificateRequest{}},
		{"complex", args{&x509.CertificateRequest{
			Extensions:         []pkix.Extension{{Id: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}}},
			Subject:            pkix.Name{Province: []string{"CA"}, CommonName: "commonName"},
			DNSNames:           []string{"foo"},
			PublicKey:          []byte("publicKey"),
			SignatureAlgorithm: x509.PureEd25519,
		}}, &CertificateRequest{
			Extensions:         []Extension{{ID: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}}},
			Subject:            Subject{Province: []string{"CA"}, CommonName: "commonName"},
			DNSNames:           []string{"foo"},
			PublicKey:          []byte("publicKey"),
			SignatureAlgorithm: SignatureAlgorithm(x509.UnknownSignatureAlgorithm),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newCertificateRequest(tt.args.cr); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newCertificateRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCertificateRequest_GetCertificateRequest(t *testing.T) {
	signer := ed25519.PrivateKey{
		0x18, 0x92, 0xea, 0xa9, 0x63, 0xfc, 0x79, 0x6a,
		0xaf, 0x04, 0xd8, 0x2a, 0x6e, 0xff, 0xc0, 0x7e,
		0x67, 0x2d, 0x25, 0x48, 0xb0, 0x32, 0xe7, 0x53,
		0xb1, 0xe8, 0x32, 0x01, 0x68, 0xab, 0xde, 0x08,
		0x79, 0x0c, 0x43, 0x95, 0xdc, 0x3a, 0x1f, 0x99,
		0xed, 0xd6, 0x85, 0xe2, 0x13, 0xf3, 0x4b, 0xf9,
		0x71, 0xdb, 0x2b, 0x96, 0x8c, 0x4c, 0x7e, 0x68,
		0xeb, 0x39, 0x80, 0xcf, 0xab, 0xc7, 0x55, 0x12,
	}
	badSigner := createBadSigner(t)

	expected := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "commonName",
			Names:      []pkix.AttributeTypeAndValue{{Type: []int{2, 5, 4, 3}, Value: "commonName"}},
		},
		DNSNames:       []string{"foo.com", "bar.com"},
		EmailAddresses: []string{"root@foo.com"},
		IPAddresses:    []net.IP{net.ParseIP("::1")},
		URIs:           []*url.URL{{Scheme: "mailto", Opaque: "root@foo.com"}},
		Extensions: []pkix.Extension{
			{Id: []int{2, 5, 29, 17}, Critical: false, Value: []byte{0x30, 0x47, 0x82, 0x7, 0x66, 0x6f, 0x6f, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x7, 0x62, 0x61, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x81, 0xc, 0x72, 0x6f, 0x6f, 0x74, 0x40, 0x66, 0x6f, 0x6f, 0x2e, 0x63, 0x6f, 0x6d, 0x87, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x86, 0x13, 0x6d, 0x61, 0x69, 0x6c, 0x74, 0x6f, 0x3a, 0x72, 0x6f, 0x6f, 0x74, 0x40, 0x66, 0x6f, 0x6f, 0x2e, 0x63, 0x6f, 0x6d}},
			{Id: []int{1, 2, 3, 4}, Critical: true, Value: []byte{0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72}},
		},
		SignatureAlgorithm: x509.PureEd25519,
		PublicKey:          signer.Public(),
		PublicKeyAlgorithm: x509.Ed25519,
		Signature: []byte{
			0x2d, 0xa9, 0x79, 0x56, 0xb5, 0xf1, 0xbf, 0x1d,
			0xe8, 0xf9, 0xb0, 0x62, 0x8c, 0xf2, 0x36, 0x2f,
			0x6f, 0x2a, 0xba, 0xd3, 0xa5, 0xd4, 0xa8, 0x6b,
			0x61, 0x5a, 0xea, 0xb1, 0xea, 0xdc, 0xe4, 0x50,
			0xbf, 0x2, 0x1, 0xce, 0x50, 0x89, 0xcd, 0xe3,
			0xfd, 0x7b, 0x94, 0x95, 0xbd, 0xb9, 0x5a, 0xe0,
			0xe, 0x58, 0x76, 0x19, 0xee, 0xa4, 0x5, 0x24,
			0x41, 0x5a, 0xc2, 0x22, 0x4b, 0xc1, 0x3a, 0x1,
		},
	}
	type fields struct {
		Subject            Subject
		DNSNames           MultiString
		EmailAddresses     MultiString
		IPAddresses        MultiIP
		URIs               MultiURL
		SANs               []SubjectAlternativeName
		Extensions         []Extension
		SignatureAlgorithm SignatureAlgorithm
		Signer             crypto.Signer
	}
	tests := []struct {
		name    string
		fields  fields
		want    *x509.CertificateRequest
		wantErr bool
	}{
		{"ok", fields{
			Subject:            Subject{CommonName: "commonName"},
			DNSNames:           []string{"foo.com"},
			EmailAddresses:     []string{"root@foo.com"},
			IPAddresses:        []net.IP{net.ParseIP("::1")},
			URIs:               []*url.URL{{Scheme: "mailto", Opaque: "root@foo.com"}},
			SANs:               []SubjectAlternativeName{{Type: "dns", Value: "bar.com"}},
			Extensions:         []Extension{{ID: []int{1, 2, 3, 4}, Critical: true, Value: []byte("foobar")}},
			SignatureAlgorithm: SignatureAlgorithm(x509.PureEd25519),
			Signer:             signer,
		}, expected, false},
		{"fail", fields{
			Subject:            Subject{CommonName: "commonName"},
			DNSNames:           []string{"foo.com"},
			EmailAddresses:     []string{"root@foo.com"},
			IPAddresses:        []net.IP{net.ParseIP("::1")},
			URIs:               []*url.URL{{Scheme: "mailto", Opaque: "root@foo.com"}},
			SANs:               []SubjectAlternativeName{{Type: "dns", Value: "bar.com"}},
			Extensions:         []Extension{{ID: []int{1, 2, 3, 4}, Critical: true, Value: []byte("foobar")}},
			SignatureAlgorithm: SignatureAlgorithm(x509.PureEd25519),
			Signer:             badSigner,
		}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CertificateRequest{
				Subject:            tt.fields.Subject,
				DNSNames:           tt.fields.DNSNames,
				EmailAddresses:     tt.fields.EmailAddresses,
				IPAddresses:        tt.fields.IPAddresses,
				URIs:               tt.fields.URIs,
				SANs:               tt.fields.SANs,
				Extensions:         tt.fields.Extensions,
				SignatureAlgorithm: tt.fields.SignatureAlgorithm,
				Signer:             tt.fields.Signer,
			}
			got, err := c.GetCertificateRequest()
			if (err != nil) != tt.wantErr {
				t.Errorf("CertificateRequest.GetCertificateRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Remove raw data
			if got != nil {
				got.Raw = nil
				got.RawSubject = nil
				got.RawSubjectPublicKeyInfo = nil
				got.RawTBSCertificateRequest = nil
				got.Attributes = nil //nolint:deprecated
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CertificateRequest.GetCertificateRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCertificateRequest_GetCertificate(t *testing.T) {
	type fields struct {
		Version            int
		Subject            Subject
		DNSNames           MultiString
		EmailAddresses     MultiString
		IPAddresses        MultiIP
		URIs               MultiURL
		Extensions         []Extension
		PublicKey          interface{}
		PublicKeyAlgorithm x509.PublicKeyAlgorithm
		Signature          []byte
		SignatureAlgorithm SignatureAlgorithm
	}
	tests := []struct {
		name   string
		fields fields
		want   *Certificate
	}{
		{"ok",
			fields{
				Version:            2,
				Subject:            Subject{CommonName: "foo"},
				DNSNames:           []string{"foo"},
				EmailAddresses:     []string{"foo@bar.com"},
				IPAddresses:        []net.IP{net.ParseIP("::1")},
				URIs:               []*url.URL{{Scheme: "https", Host: "foo.bar"}},
				Extensions:         []Extension{{ID: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}}},
				PublicKey:          []byte("publicKey"),
				PublicKeyAlgorithm: x509.Ed25519,
				Signature:          []byte("signature"),
				SignatureAlgorithm: SignatureAlgorithm(x509.PureEd25519),
			},
			&Certificate{
				Subject:            Subject{CommonName: "foo"},
				DNSNames:           []string{"foo"},
				EmailAddresses:     []string{"foo@bar.com"},
				IPAddresses:        []net.IP{net.ParseIP("::1")},
				URIs:               []*url.URL{{Scheme: "https", Host: "foo.bar"}},
				Extensions:         []Extension{{ID: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}}},
				PublicKey:          []byte("publicKey"),
				PublicKeyAlgorithm: x509.Ed25519,
				SignatureAlgorithm: SignatureAlgorithm(x509.PureEd25519),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CertificateRequest{
				Version:            tt.fields.Version,
				Subject:            tt.fields.Subject,
				DNSNames:           tt.fields.DNSNames,
				EmailAddresses:     tt.fields.EmailAddresses,
				IPAddresses:        tt.fields.IPAddresses,
				URIs:               tt.fields.URIs,
				Extensions:         tt.fields.Extensions,
				PublicKey:          tt.fields.PublicKey,
				PublicKeyAlgorithm: tt.fields.PublicKeyAlgorithm,
				Signature:          tt.fields.Signature,
				SignatureAlgorithm: tt.fields.SignatureAlgorithm,
			}
			if got := c.GetCertificate(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CertificateRequest.GetCertificate() = \n%#v, want \n%#v", got, tt.want)
			}
		})
	}
}

func TestCertificateRequest_GetLeafCertificate(t *testing.T) {
	type fields struct {
		Version            int
		Subject            Subject
		DNSNames           MultiString
		EmailAddresses     MultiString
		IPAddresses        MultiIP
		URIs               MultiURL
		Extensions         []Extension
		PublicKey          interface{}
		PublicKeyAlgorithm x509.PublicKeyAlgorithm
		Signature          []byte
		SignatureAlgorithm SignatureAlgorithm
	}
	tests := []struct {
		name   string
		fields fields
		want   *Certificate
	}{
		{"ok",
			fields{
				Version:            2,
				Subject:            Subject{CommonName: "foo"},
				DNSNames:           []string{"foo"},
				EmailAddresses:     []string{"foo@bar.com"},
				IPAddresses:        []net.IP{net.ParseIP("::1")},
				URIs:               []*url.URL{{Scheme: "https", Host: "foo.bar"}},
				Extensions:         []Extension{{ID: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}}},
				PublicKey:          []byte("publicKey"),
				PublicKeyAlgorithm: x509.Ed25519,
				Signature:          []byte("signature"),
				SignatureAlgorithm: SignatureAlgorithm(x509.PureEd25519),
			},
			&Certificate{
				Subject:        Subject{CommonName: "foo"},
				DNSNames:       []string{"foo"},
				EmailAddresses: []string{"foo@bar.com"},
				IPAddresses:    []net.IP{net.ParseIP("::1")},
				URIs:           []*url.URL{{Scheme: "https", Host: "foo.bar"}},
				Extensions:     []Extension{{ID: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}}},
				KeyUsage:       KeyUsage(x509.KeyUsageDigitalSignature),
				ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
					x509.ExtKeyUsageServerAuth,
					x509.ExtKeyUsageClientAuth,
				}),
				PublicKey:          []byte("publicKey"),
				PublicKeyAlgorithm: x509.Ed25519,
				SignatureAlgorithm: SignatureAlgorithm(x509.PureEd25519),
			},
		},
		{"rsa",
			fields{
				Version:            2,
				Subject:            Subject{CommonName: "foo"},
				DNSNames:           []string{"foo"},
				EmailAddresses:     []string{"foo@bar.com"},
				IPAddresses:        []net.IP{net.ParseIP("::1")},
				URIs:               []*url.URL{{Scheme: "https", Host: "foo.bar"}},
				Extensions:         []Extension{{ID: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}}},
				PublicKey:          &rsa.PublicKey{},
				PublicKeyAlgorithm: x509.RSA,
				Signature:          []byte("signature"),
				SignatureAlgorithm: SignatureAlgorithm(x509.SHA256WithRSA),
			},
			&Certificate{
				Subject:        Subject{CommonName: "foo"},
				DNSNames:       []string{"foo"},
				EmailAddresses: []string{"foo@bar.com"},
				IPAddresses:    []net.IP{net.ParseIP("::1")},
				URIs:           []*url.URL{{Scheme: "https", Host: "foo.bar"}},
				Extensions:     []Extension{{ID: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}}},
				KeyUsage:       KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment),
				ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
					x509.ExtKeyUsageServerAuth,
					x509.ExtKeyUsageClientAuth,
				}),
				PublicKey:          &rsa.PublicKey{},
				PublicKeyAlgorithm: x509.RSA,
				SignatureAlgorithm: SignatureAlgorithm(x509.SHA256WithRSA),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CertificateRequest{
				Version:            tt.fields.Version,
				Subject:            tt.fields.Subject,
				DNSNames:           tt.fields.DNSNames,
				EmailAddresses:     tt.fields.EmailAddresses,
				IPAddresses:        tt.fields.IPAddresses,
				URIs:               tt.fields.URIs,
				Extensions:         tt.fields.Extensions,
				PublicKey:          tt.fields.PublicKey,
				PublicKeyAlgorithm: tt.fields.PublicKeyAlgorithm,
				Signature:          tt.fields.Signature,
				SignatureAlgorithm: tt.fields.SignatureAlgorithm,
			}
			if got := c.GetLeafCertificate(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CertificateRequest.GetLeafCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateCertificateRequest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	badSigner := createBadSigner(t)

	type args struct {
		commonName string
		sans       []string
		signer     crypto.Signer
	}
	tests := []struct {
		name    string
		args    args
		want    *x509.CertificateRequest
		wantErr bool
	}{
		{"ok", args{"foo.bar", []string{"foo.bar", "john@doe.com", "uri:uuid:48da8308-b399-4748-861f-cb418362f820", "1.2.3.4"}, priv}, &x509.CertificateRequest{
			Version: 0,
			Subject: pkix.Name{
				CommonName: "foo.bar",
				Names:      []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "foo.bar"}},
			},
			DNSNames:           []string{"foo.bar"},
			EmailAddresses:     []string{"john@doe.com"},
			IPAddresses:        []net.IP{{1, 2, 3, 4}},
			URIs:               []*url.URL{{Scheme: "uri", Opaque: "uuid:48da8308-b399-4748-861f-cb418362f820"}},
			PublicKey:          pub,
			SignatureAlgorithm: x509.PureEd25519,
			PublicKeyAlgorithm: x509.Ed25519,
		}, false},
		{"fail ", args{"foo.bar", []string{"foo.bar"}, badSigner}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateCertificateRequest(tt.args.commonName, tt.args.sans, tt.args.signer)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateCertificateRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if err := got.CheckSignature(); err != nil {
					t.Errorf("CheckSignature() error = %v", err)
					return
				}
				tt.want.Raw = got.Raw
				tt.want.RawSubject = got.RawSubject
				tt.want.RawSubjectPublicKeyInfo = got.RawSubjectPublicKeyInfo
				tt.want.RawTBSCertificateRequest = got.RawTBSCertificateRequest
				tt.want.Attributes = got.Attributes //nolint:deprecated
				tt.want.Extensions = got.Extensions
				tt.want.Signature = got.Signature
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateCertificateRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
