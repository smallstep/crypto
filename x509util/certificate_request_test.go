package x509util

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestNewCertificateRequest(t *testing.T) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// ok extended sans
	sans := []SubjectAlternativeName{
		{Type: DNSType, Value: "foo.com"},
		{Type: EmailType, Value: "root@foo.com"},
		{Type: IPType, Value: "3.14.15.92"},
		{Type: URIType, Value: "mailto:root@foo.com"},
		{Type: PermanentIdentifierType, Value: "123456789"},
	}
	extendedSANs := CreateTemplateData("123456789", nil)
	extendedSANs.SetSubjectAlternativeNames(sans...)
	extendedSANsExtension, err := createSubjectAltNameExtension(nil, nil, nil, nil, sans, false)
	require.NoError(t, err)

	// ok extended sans and extension
	extendedSANsAndExtensionsTemplate := fmt.Sprintf(`{
		"subject": {{ toJson .Subject }},
		"sans": {{ toJson .SANs }},
		"extensions": [
			{"id":"2.5.29.17", "value":"%s"}
		]
	}`, base64.StdEncoding.EncodeToString(extendedSANsExtension.Value))

	// ok permanent identifier template
	permanentIdentifierTemplate := `{ 
		"subject": {{ toJson .Subject }},
		"sans": [{
			"type": "permanentIdentifier", 
			"value": {{ toJson .Subject.CommonName }}
		}]
	}`
	permanentIdentifierTemplateExtension, err := createSubjectAltNameExtension(nil, nil, nil, nil, []SubjectAlternativeName{
		{Type: PermanentIdentifierType, Value: "123456789"},
	}, false)
	require.NoError(t, err)

	// ok with key usage and basic constraints
	caTemplate := `{ 
		"subject": {{ toJson .Subject }},
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 0
		}
	}`

	// ok with key usage and extended key usage
	leafTemplate := `{ 
		"subject": {{ toJson .Subject }},
		"sans": {{ toJson .SANs }},
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["serverAuth", "clientAuth"]
	}`

	caKeyUsageExtension, err := KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign).Extension()
	require.NoError(t, err)
	leafKeyUsageExtension, err := KeyUsage(x509.KeyUsageDigitalSignature).Extension()
	require.NoError(t, err)
	basicConstraintsExtension, err := BasicConstraints{IsCA: true, MaxPathLen: 0}.Extension()
	require.NoError(t, err)
	extKeyUsageExtension, err := ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}.Extension(nil)
	require.NoError(t, err)

	// fail extended sans
	failExtendedSANs := CreateTemplateData("123456789", nil)
	failExtendedSANs.SetSubjectAlternativeNames(SubjectAlternativeName{Type: "badType", Value: "foo.com"})

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
		{"ok extended sans", args{signer, []Option{
			WithTemplate(DefaultCertificateRequestTemplate, extendedSANs),
		}}, &CertificateRequest{
			Subject: Subject{CommonName: "123456789"},
			SANs: []SubjectAlternativeName{
				{Type: "dns", Value: "foo.com"},
				{Type: "email", Value: "root@foo.com"},
				{Type: "ip", Value: "3.14.15.92"},
				{Type: "uri", Value: "mailto:root@foo.com"},
				{Type: "permanentIdentifier", Value: "123456789"},
			},
			Extensions: []Extension{extendedSANsExtension},
			PublicKey:  signer.Public(),
			Signer:     signer,
		}, false},
		{"ok extended sans and extension", args{signer, []Option{
			WithTemplate(extendedSANsAndExtensionsTemplate, extendedSANs),
		}}, &CertificateRequest{
			Subject: Subject{CommonName: "123456789"},
			SANs: []SubjectAlternativeName{
				{Type: "dns", Value: "foo.com"},
				{Type: "email", Value: "root@foo.com"},
				{Type: "ip", Value: "3.14.15.92"},
				{Type: "uri", Value: "mailto:root@foo.com"},
				{Type: "permanentIdentifier", Value: "123456789"},
			},
			Extensions: []Extension{extendedSANsExtension},
			PublicKey:  signer.Public(),
			Signer:     signer,
		}, false},
		{"ok permanent identifier template", args{signer, []Option{
			WithTemplate(permanentIdentifierTemplate, CreateTemplateData("123456789", []string{})),
		}}, &CertificateRequest{
			Subject: Subject{CommonName: "123456789"},
			SANs: []SubjectAlternativeName{
				{Type: "permanentIdentifier", Value: "123456789"},
			},
			Extensions: []Extension{permanentIdentifierTemplateExtension},
			PublicKey:  signer.Public(),
			Signer:     signer,
		}, false},
		{"ok with key usage and basic constraints", args{signer, []Option{
			WithTemplate(caTemplate, extendedSANs),
		}}, &CertificateRequest{
			Subject:          Subject{CommonName: "123456789"},
			KeyUsage:         KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
			BasicConstraints: &BasicConstraints{IsCA: true, MaxPathLen: 0},
			Extensions: []Extension{
				basicConstraintsExtension,
				caKeyUsageExtension,
			},
			PublicKey: signer.Public(),
			Signer:    signer,
		}, false},
		{"ok with key usage and extended key usage", args{signer, []Option{
			WithTemplate(leafTemplate, extendedSANs),
		}}, &CertificateRequest{
			Subject: Subject{CommonName: "123456789"},
			SANs: []SubjectAlternativeName{
				{Type: "dns", Value: "foo.com"},
				{Type: "email", Value: "root@foo.com"},
				{Type: "ip", Value: "3.14.15.92"},
				{Type: "uri", Value: "mailto:root@foo.com"},
				{Type: "permanentIdentifier", Value: "123456789"},
			},
			KeyUsage:    KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			Extensions: []Extension{
				extKeyUsageExtension,
				leafKeyUsageExtension,
				extendedSANsExtension,
			},
			PublicKey: signer.Public(),
			Signer:    signer,
		}, false},
		{"fail apply", args{signer, []Option{WithTemplateFile("testdata/missing.tpl", NewTemplateData())}}, nil, true},
		{"fail unmarshal", args{signer, []Option{WithTemplate("{badjson", NewTemplateData())}}, nil, true},
		{"fail extended sans", args{signer, []Option{WithTemplate(DefaultCertificateRequestTemplate, failExtendedSANs)}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCertificateRequest(tt.args.signer, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCertificateRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCertificateRequest() = %+v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newCertificateRequest(t *testing.T) {
	ku, err := KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign).Extension()
	require.NoError(t, err)
	eku, err := ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning}.Extension(
		UnknownExtKeyUsage{{1, 2, 4, 8}, {1, 3, 5, 9}},
	)
	require.NoError(t, err)
	bc, err := BasicConstraints{IsCA: true, MaxPathLen: 0}.Extension()
	require.NoError(t, err)

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
		{"with known extensions", args{&x509.CertificateRequest{
			Extensions: []pkix.Extension{
				{Id: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}},
				{Id: asn1.ObjectIdentifier(ku.ID), Critical: ku.Critical, Value: ku.Value},
				{Id: asn1.ObjectIdentifier(eku.ID), Critical: eku.Critical, Value: eku.Value},
				{Id: asn1.ObjectIdentifier(bc.ID), Critical: bc.Critical, Value: bc.Value},
			},
			Subject:            pkix.Name{Province: []string{"CA"}, CommonName: "commonName"},
			DNSNames:           []string{"foo"},
			PublicKey:          []byte("publicKey"),
			SignatureAlgorithm: x509.PureEd25519,
		}}, &CertificateRequest{
			Extensions: []Extension{
				{ID: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}},
				ku, eku, bc,
			},
			Subject:            Subject{Province: []string{"CA"}, CommonName: "commonName"},
			DNSNames:           []string{"foo"},
			KeyUsage:           KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
			ExtKeyUsage:        ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning},
			UnknownExtKeyUsage: UnknownExtKeyUsage{{1, 2, 4, 8}, {1, 3, 5, 9}},
			BasicConstraints:   &BasicConstraints{IsCA: true, MaxPathLen: 0},
			PublicKey:          []byte("publicKey"),
			SignatureAlgorithm: SignatureAlgorithm(x509.UnknownSignatureAlgorithm),
		}},
		{"with ignored errors", args{&x509.CertificateRequest{
			Extensions: []pkix.Extension{
				{Id: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}},
				{Id: asn1.ObjectIdentifier(ku.ID), Critical: ku.Critical, Value: []byte("garbage")},
				{Id: asn1.ObjectIdentifier(eku.ID), Critical: eku.Critical, Value: []byte("garbage")},
				{Id: asn1.ObjectIdentifier(bc.ID), Critical: bc.Critical, Value: []byte("garbage")},
			},
			Subject:            pkix.Name{Province: []string{"CA"}, CommonName: "commonName"},
			DNSNames:           []string{"foo"},
			PublicKey:          []byte("publicKey"),
			SignatureAlgorithm: x509.PureEd25519,
		}}, &CertificateRequest{
			Extensions: []Extension{
				{ID: []int{1, 2, 3}, Critical: true, Value: []byte{3, 2, 1}},
				{ID: ku.ID, Critical: ku.Critical, Value: []byte("garbage")},
				{ID: eku.ID, Critical: eku.Critical, Value: []byte("garbage")},
				{ID: bc.ID, Critical: bc.Critical, Value: []byte("garbage")},
			},
			Subject:            Subject{Province: []string{"CA"}, CommonName: "commonName"},
			DNSNames:           []string{"foo"},
			PublicKey:          []byte("publicKey"),
			SignatureAlgorithm: SignatureAlgorithm(x509.UnknownSignatureAlgorithm),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewCertificateRequestFromX509(tt.args.cr); !reflect.DeepEqual(got, tt.want) {
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
				got.Attributes = nil //nolint:staticcheck // testing legacy behavior
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CertificateRequest.GetCertificateRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCertificateRequest_GetCertificateRequest_challengePassword(t *testing.T) {
	rsaPEM, err := os.ReadFile("testdata/rsa.key")
	require.NoError(t, err)

	block, _ := pem.Decode(rsaPEM)
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	expectedPrintableString, err := os.ReadFile("testdata/challengePassword.csr")
	require.NoError(t, err)
	expectedUTF8String, err := os.ReadFile("testdata/challengePasswordUTF8.csr")
	require.NoError(t, err)

	tests := []struct {
		name      string
		cr        *CertificateRequest
		want      []byte
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", &CertificateRequest{
			Subject:            Subject{CommonName: "commonName"},
			DNSNames:           []string{"foo.com"},
			EmailAddresses:     []string{"root@foo.com"},
			IPAddresses:        []net.IP{net.ParseIP("::1")},
			URIs:               []*url.URL{{Scheme: "mailto", Opaque: "root@foo.com"}},
			SANs:               []SubjectAlternativeName{{Type: "dns", Value: "bar.com"}},
			ChallengePassword:  "challengePassword",
			Extensions:         []Extension{{ID: []int{1, 2, 3, 4}, Critical: true, Value: []byte("foobar")}},
			SignatureAlgorithm: SignatureAlgorithm(x509.SHA256WithRSA),
			Signer:             rsaKey,
		}, expectedPrintableString, assert.NoError},
		{"ok UTF8String", &CertificateRequest{
			Subject:            Subject{CommonName: "commonName"},
			DNSNames:           []string{"foo.com"},
			EmailAddresses:     []string{"root@foo.com"},
			IPAddresses:        []net.IP{net.ParseIP("::1")},
			URIs:               []*url.URL{{Scheme: "mailto", Opaque: "root@foo.com"}},
			SANs:               []SubjectAlternativeName{{Type: "dns", Value: "bar.com"}},
			ChallengePassword:  "🔐",
			Extensions:         []Extension{{ID: []int{1, 2, 3, 4}, Critical: true, Value: []byte("foobar")}},
			SignatureAlgorithm: SignatureAlgorithm(x509.SHA256WithRSA),
			Signer:             rsaKey,
		}, expectedUTF8String, assert.NoError},
		{"fail challengePassword", &CertificateRequest{
			Subject:            Subject{CommonName: "commonName"},
			DNSNames:           []string{"foo.com"},
			EmailAddresses:     []string{"root@foo.com"},
			IPAddresses:        []net.IP{net.ParseIP("::1")},
			URIs:               []*url.URL{{Scheme: "mailto", Opaque: "root@foo.com"}},
			SANs:               []SubjectAlternativeName{{Type: "dns", Value: "bar.com"}},
			ChallengePassword:  "\x91\x80\x80\x80",
			Extensions:         []Extension{{ID: []int{1, 2, 3, 4}, Critical: true, Value: []byte("foobar")}},
			SignatureAlgorithm: SignatureAlgorithm(x509.SHA256WithRSA),
			Signer:             rsaKey,
		}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csr, err := tt.cr.GetCertificateRequest()
			tt.assertion(t, err)
			if tt.want == nil {
				assert.Nil(t, csr)
			} else {
				assert.Equal(t, tt.want, pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE REQUEST",
					Bytes: csr.Raw,
				}))
			}
		})
	}
}

func TestCertificateRequest_addChallengePassword(t *testing.T) {
	rsaPEM, err := os.ReadFile("testdata/rsa.key")
	require.NoError(t, err)

	block, _ := pem.Decode(rsaPEM)
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	base := &CertificateRequest{
		Subject:            Subject{CommonName: "commonName"},
		DNSNames:           []string{"foo.com"},
		EmailAddresses:     []string{"root@foo.com"},
		IPAddresses:        []net.IP{net.ParseIP("::1")},
		URIs:               []*url.URL{{Scheme: "mailto", Opaque: "root@foo.com"}},
		SANs:               []SubjectAlternativeName{{Type: "dns", Value: "bar.com"}},
		Extensions:         []Extension{{ID: []int{1, 2, 3, 4}, Critical: true, Value: []byte("foobar")}},
		SignatureAlgorithm: SignatureAlgorithm(x509.SHA256WithRSA),
		Signer:             rsaKey,
	}
	csr, err := base.GetCertificateRequest()
	require.NoError(t, err)

	var cr certificateRequest
	_, err = asn1.Unmarshal(csr.Raw, &cr)
	require.NoError(t, err)
	cr.Raw = nil
	cr.TBSCSR.Raw = nil
	cr.SignatureAlgorithm = pkix.AlgorithmIdentifier{
		Algorithm: []int{1, 2, 3, 4},
	}
	failSignatureAlgorithm, err := asn1.Marshal(cr)
	require.NoError(t, err)

	b, err := os.ReadFile("testdata/challengePassword.csr")
	require.NoError(t, err)
	block, _ = pem.Decode(b)
	expectedPrintableString := block.Bytes

	b, err = os.ReadFile("testdata/challengePasswordUTF8.csr")
	require.NoError(t, err)
	block, _ = pem.Decode(b)
	expectedUTF8String := block.Bytes

	type args struct {
		asn1Data []byte
	}
	tests := []struct {
		name      string
		cr        *CertificateRequest
		args      args
		want      []byte
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", &CertificateRequest{
			Subject:            base.Subject,
			DNSNames:           base.DNSNames,
			EmailAddresses:     base.EmailAddresses,
			IPAddresses:        base.IPAddresses,
			URIs:               base.URIs,
			SANs:               base.SANs,
			ChallengePassword:  "challengePassword",
			Extensions:         base.Extensions,
			SignatureAlgorithm: base.SignatureAlgorithm,
			Signer:             base.Signer,
		}, args{csr.Raw}, expectedPrintableString, assert.NoError},
		{"ok UTF8String", &CertificateRequest{
			Subject:            base.Subject,
			DNSNames:           base.DNSNames,
			EmailAddresses:     base.EmailAddresses,
			IPAddresses:        base.IPAddresses,
			URIs:               base.URIs,
			SANs:               base.SANs,
			ChallengePassword:  "🔐",
			Extensions:         base.Extensions,
			SignatureAlgorithm: base.SignatureAlgorithm,
			Signer:             base.Signer,
		}, args{csr.Raw}, expectedUTF8String, assert.NoError},
		{"fail challengePassword", &CertificateRequest{
			Subject:            base.Subject,
			DNSNames:           base.DNSNames,
			EmailAddresses:     base.EmailAddresses,
			IPAddresses:        base.IPAddresses,
			URIs:               base.URIs,
			SANs:               base.SANs,
			ChallengePassword:  "\x91\x80\x80\x80",
			Extensions:         base.Extensions,
			SignatureAlgorithm: base.SignatureAlgorithm,
			Signer:             base.Signer,
		}, args{csr.Raw}, nil, assert.Error},
		{"fail unmarshal", &CertificateRequest{
			Subject:            base.Subject,
			DNSNames:           base.DNSNames,
			EmailAddresses:     base.EmailAddresses,
			IPAddresses:        base.IPAddresses,
			URIs:               base.URIs,
			SANs:               base.SANs,
			ChallengePassword:  "challengePassword",
			Extensions:         base.Extensions,
			SignatureAlgorithm: base.SignatureAlgorithm,
			Signer:             base.Signer,
		}, args{[]byte("not ans1")}, nil, assert.Error},
		{"fail unmarshal rest", &CertificateRequest{
			Subject:            base.Subject,
			DNSNames:           base.DNSNames,
			EmailAddresses:     base.EmailAddresses,
			IPAddresses:        base.IPAddresses,
			URIs:               base.URIs,
			SANs:               base.SANs,
			ChallengePassword:  "challengePassword",
			Extensions:         base.Extensions,
			SignatureAlgorithm: base.SignatureAlgorithm,
			Signer:             base.Signer,
		}, args{append(csr.Raw, []byte("some extra data")...)}, nil, assert.Error},
		{"fail signatureAlgorithm", &CertificateRequest{
			Subject:            base.Subject,
			DNSNames:           base.DNSNames,
			EmailAddresses:     base.EmailAddresses,
			IPAddresses:        base.IPAddresses,
			URIs:               base.URIs,
			SANs:               base.SANs,
			ChallengePassword:  "challengePassword",
			Extensions:         base.Extensions,
			SignatureAlgorithm: base.SignatureAlgorithm,
			Signer:             base.Signer,
		}, args{failSignatureAlgorithm}, nil, assert.Error},
		{"fail sign", &CertificateRequest{
			Subject:            base.Subject,
			DNSNames:           base.DNSNames,
			EmailAddresses:     base.EmailAddresses,
			IPAddresses:        base.IPAddresses,
			URIs:               base.URIs,
			SANs:               base.SANs,
			ChallengePassword:  "challengePassword",
			Extensions:         base.Extensions,
			SignatureAlgorithm: base.SignatureAlgorithm,
			Signer:             &badSigner{},
		}, args{csr.Raw}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cr.addChallengePassword(tt.args.asn1Data)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
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
				SignatureAlgorithm: SignatureAlgorithm(x509.UnknownSignatureAlgorithm),
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
				SignatureAlgorithm: SignatureAlgorithm(x509.UnknownSignatureAlgorithm),
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
				SignatureAlgorithm: SignatureAlgorithm(x509.UnknownSignatureAlgorithm),
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
				tt.want.Attributes = got.Attributes //nolint:staticcheck // testing legacy behavior
				tt.want.Extensions = got.Extensions
				tt.want.Signature = got.Signature
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateCertificateRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignCertificateRequestTemplates(t *testing.T) {
	iss, issPriv := createIssuerCertificate(t, "issuer")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("sign ca certificate maxPathLen 1", func(t *testing.T) {
		template := `{ 
			"subject": {{ toJson .Subject }},
			"keyUsage": ["certSign", "crlSign"],
			"basicConstraints": {
				"isCA": true,
				"maxPathLen": 1
			}
		}`
		csr, err := NewCertificateRequest(priv, WithTemplate(template, TemplateData{SubjectKey: Subject{
			CommonName: "CA Intermediate MaxPathLen 1",
		}}))
		require.NoError(t, err)

		crt, err := CreateCertificate(csr.GetCertificate().GetCertificate(), iss, pub, issPriv)
		require.NoError(t, err)
		assert.Equal(t, "CA Intermediate MaxPathLen 1", crt.Subject.CommonName)
		assert.Equal(t, "issuer", crt.Issuer.CommonName)
		assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, crt.KeyUsage)
		assert.True(t, crt.BasicConstraintsValid)
		assert.True(t, crt.IsCA)
		assert.False(t, false, crt.MaxPathLenZero)
		assert.Equal(t, 1, crt.MaxPathLen)
	})

	t.Run("sign ca certificate maxPathLen 0", func(t *testing.T) {
		template := `{ 
			"subject": {{ toJson .Subject }},
			"keyUsage": ["certSign", "crlSign"],
			"basicConstraints": {
				"isCA": true,
				"maxPathLen": 0
			}
		}`
		csr, err := NewCertificateRequest(priv, WithTemplate(template, TemplateData{SubjectKey: Subject{
			CommonName: "CA Intermediate MaxPathLen 0",
		}}))
		require.NoError(t, err)

		crt, err := CreateCertificate(csr.GetCertificate().GetCertificate(), iss, pub, issPriv)
		require.NoError(t, err)
		assert.Equal(t, "CA Intermediate MaxPathLen 0", crt.Subject.CommonName)
		assert.Equal(t, "issuer", crt.Issuer.CommonName)
		assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, crt.KeyUsage)
		assert.True(t, crt.BasicConstraintsValid)
		assert.True(t, crt.IsCA)
		assert.True(t, crt.MaxPathLenZero)
		assert.Equal(t, 0, crt.MaxPathLen)
	})

	t.Run("sign leaf certificate", func(t *testing.T) {
		template := `{ 
			"subject": {{ toJson .Subject }},
			"sans": {{ toJson .SANs }},
			{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
			"keyUsage": ["keyEncipherment", "digitalSignature"],
			{{- else }}
			"keyUsage": ["digitalSignature"],
			{{- end }}
			"extKeyUsage": ["serverAuth", "clientAuth"]
		}`

		csr, err := NewCertificateRequest(priv, WithTemplate(template, CreateTemplateData("leaf", []string{"leaf.example.com"})))
		require.NoError(t, err)

		crt, err := CreateCertificate(csr.GetCertificate().GetCertificate(), iss, pub, issPriv)
		require.NoError(t, err)
		assert.Equal(t, "leaf", crt.Subject.CommonName)
		assert.Equal(t, "issuer", crt.Issuer.CommonName)
		assert.Equal(t, []string{"leaf.example.com"}, crt.DNSNames)
		assert.Equal(t, x509.KeyUsageDigitalSignature, crt.KeyUsage)
		assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, crt.ExtKeyUsage)
	})

}

func Test_parseKeyUsageExtension(t *testing.T) {
	mustValue := func(ku KeyUsage) cryptobyte.String {
		ext, err := ku.Extension()
		require.NoError(t, err)
		return ext.Value
	}

	type args struct {
		der cryptobyte.String
	}
	tests := []struct {
		name      string
		args      args
		want      KeyUsage
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", args{mustValue(KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign))}, KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign), assert.NoError},
		{"ok", args{mustValue(KeyUsage(x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature))}, KeyUsage(x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature), assert.NoError},
		{"fail", args{cryptobyte.String("garbage")}, KeyUsage(0), assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseKeyUsageExtension(tt.args.der)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_parseExtKeyUsageExtension(t *testing.T) {
	mustValue := func(eku ExtKeyUsage, ueku UnknownExtKeyUsage) cryptobyte.String {
		ext, err := eku.Extension(ueku)
		require.NoError(t, err)
		return ext.Value
	}

	b64OID, err := asn1Encode("oid:1.2.3.4")
	require.NoError(t, err)

	b64Int, err := asn1Encode("int:10")
	require.NoError(t, err)

	b64Seq, err := asn1Sequence(b64OID, b64Int)
	require.NoError(t, err)

	badParse, err := base64.StdEncoding.DecodeString(b64Seq)
	require.NoError(t, err)

	type args struct {
		der cryptobyte.String
	}
	tests := []struct {
		name      string
		args      args
		want      ExtKeyUsage
		want1     UnknownExtKeyUsage
		assertion assert.ErrorAssertionFunc
	}{
		{"fail parse", args{cryptobyte.String(badParse)}, nil, nil, assert.Error},
		{"ok", args{mustValue(ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, nil)},
			ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, nil, assert.NoError},
		{"ok unhandled", args{mustValue(ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, UnknownExtKeyUsage{{1, 2, 3, 4}, {1, 4, 6, 8}})},
			ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, UnknownExtKeyUsage{{1, 2, 3, 4}, {1, 4, 6, 8}}, assert.NoError},
		{"ok unhandled only", args{mustValue(ExtKeyUsage{}, UnknownExtKeyUsage{{1, 2, 3, 4}, {1, 4, 6, 8}})},
			nil, UnknownExtKeyUsage{{1, 2, 3, 4}, {1, 4, 6, 8}}, assert.NoError},
		{"fail", args{cryptobyte.String("garbage")}, nil, nil, assert.Error},
		{"fail parse", args{cryptobyte.String(badParse)}, nil, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := parseExtKeyUsageExtension(tt.args.der)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.want1, got1)
		})
	}
}

func Test_parseBasicConstraintsExtension(t *testing.T) {
	mustValue := func(bc BasicConstraints) cryptobyte.String {
		ext, err := bc.Extension()
		require.NoError(t, err)
		return ext.Value
	}

	var b1 cryptobyte.Builder
	b1.AddASN1(cbasn1.SEQUENCE, func(child *cryptobyte.Builder) {
		// Tag 1 boolean and garbage
		child.AddBytes([]byte{1, 2, 3})
	})
	failParseBool, err := b1.Bytes()
	require.NoError(t, err)

	var b2 cryptobyte.Builder
	b2.AddASN1(cbasn1.SEQUENCE, func(child *cryptobyte.Builder) {
		child.AddASN1Boolean(true)
		// Tag 2 integer and nothing
		child.AddBytes([]byte{2})
	})
	failParseInt, err := b2.Bytes()
	require.NoError(t, err)

	type args struct {
		der cryptobyte.String
	}
	tests := []struct {
		name      string
		args      args
		want      *BasicConstraints
		assertion assert.ErrorAssertionFunc
	}{
		{"ok 0", args{mustValue(BasicConstraints{IsCA: true, MaxPathLen: 0})}, &BasicConstraints{IsCA: true, MaxPathLen: 0}, assert.NoError},
		{"ok 1", args{mustValue(BasicConstraints{IsCA: true, MaxPathLen: 1})}, &BasicConstraints{IsCA: true, MaxPathLen: 1}, assert.NoError},
		{"ok -1", args{mustValue(BasicConstraints{IsCA: true, MaxPathLen: -1})}, &BasicConstraints{IsCA: true, MaxPathLen: -1}, assert.NoError},
		{"ok no ca", args{mustValue(BasicConstraints{IsCA: false, MaxPathLen: 0})}, &BasicConstraints{IsCA: false, MaxPathLen: -1}, assert.NoError},
		{"fail", args{cryptobyte.String("garbage")}, nil, assert.Error},
		{"fail parse bool", args{failParseBool}, nil, assert.Error},
		{"fail parse int", args{failParseInt}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseBasicConstraintsExtension(tt.args.der)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
