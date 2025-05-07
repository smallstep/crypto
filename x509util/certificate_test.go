package x509util

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/pemutil"
)

func mustOID(t *testing.T, s string) x509.OID {
	t.Helper()

	oid, err := x509.ParseOID(s)
	require.NoError(t, err)
	return oid
}

func createCertificateRequest(t *testing.T, commonName string, sans []string) (*x509.CertificateRequest, crypto.Signer) {
	dnsNames, ips, emails, uris := SplitSANs(sans)
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	asn1Data, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: commonName},
		DNSNames:           dnsNames,
		IPAddresses:        ips,
		EmailAddresses:     emails,
		URIs:               uris,
		SignatureAlgorithm: x509.PureEd25519,
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

func readCertificateRequest(t *testing.T, filename, keyFilename string) (*x509.CertificateRequest, crypto.Signer) {
	t.Helper()

	cr, err := pemutil.ReadCertificateRequest(filename)
	require.NoError(t, err)

	key, err := pemutil.Read(keyFilename)
	require.NoError(t, err)

	signer, ok := key.(crypto.Signer)
	require.True(t, ok)

	return cr, signer
}

func createIssuerCertificate(t *testing.T, commonName string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	now := time.Now()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subjectKeyID, err := generateSubjectKeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	sn, err := generateSerialNumber()
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            -1,
		MaxPathLenZero:        false,
		Issuer:                pkix.Name{CommonName: "issuer"},
		Subject:               pkix.Name{CommonName: "issuer"},
		SerialNumber:          sn,
		SubjectKeyId:          subjectKeyID,
	}
	asn1Data, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	crt, err := x509.ParseCertificate(asn1Data)
	if err != nil {
		t.Fatal(err)
	}
	return crt, priv
}

type badSigner struct {
	pub crypto.PublicKey
}

func createBadSigner(t *testing.T) *badSigner {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &badSigner{
		pub: pub,
	}
}

func (b *badSigner) Public() crypto.PublicKey {
	return b.pub
}

func (b *badSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("💥")
}

func TestNewCertificate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cr, priv := createCertificateRequest(t, "commonName", []string{"foo.com", "root@foo.com"})
	crBadSignateure, _ := createCertificateRequest(t, "fail", []string{"foo.com"})
	crBadSignateure.PublicKey = priv.Public()

	customSANsData := CreateTemplateData("commonName", nil)
	customSANsData.Set(SANsKey, []SubjectAlternativeName{
		{Type: PermanentIdentifierType, Value: "123456"},
		{Type: "1.2.3.4", Value: "utf8:otherName"},
	})
	badCustomSANsData := CreateTemplateData("commonName", nil)
	badCustomSANsData.Set(SANsKey, []SubjectAlternativeName{
		{Type: "1.2.3.4", Value: "int:not-an-int"},
	})

	ipNet := func(s string) *net.IPNet {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		return ipNet
	}

	rawSubjectCR, rawSubjectKey := readCertificateRequest(t, "testdata/rawSubject.csr", "testdata/rawSubject.key")

	type args struct {
		cr   *x509.CertificateRequest
		opts []Option
	}
	tests := []struct {
		name    string
		args    args
		want    *Certificate
		wantErr bool
	}{
		{"okSimple", args{cr, nil}, &Certificate{
			Subject:        Subject{CommonName: "commonName"},
			DNSNames:       []string{"foo.com"},
			EmailAddresses: []string{"root@foo.com"},
			KeyUsage:       KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			Extensions:         newExtensions(cr.Extensions),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.Ed25519,
			SignatureAlgorithm: SignatureAlgorithm(x509.UnknownSignatureAlgorithm),
		}, false},
		{"okDefaultTemplate", args{cr, []Option{WithTemplate(DefaultLeafTemplate, CreateTemplateData("commonName", []string{"foo.com"}))}}, &Certificate{
			Subject:  Subject{CommonName: "commonName"},
			SANs:     []SubjectAlternativeName{{Type: DNSType, Value: "foo.com"}},
			KeyUsage: KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.Ed25519,
		}, false},
		{"okCustomSANs", args{cr, []Option{WithTemplate(DefaultLeafTemplate, customSANsData)}}, &Certificate{
			Subject: Subject{CommonName: "commonName"},
			SANs: []SubjectAlternativeName{
				{Type: PermanentIdentifierType, Value: "123456"},
				{Type: "1.2.3.4", Value: "utf8:otherName"},
			},
			Extensions: []Extension{{
				ID:       ObjectIdentifier{2, 5, 29, 17},
				Critical: false,
				Value:    []byte{48, 44, 160, 22, 6, 8, 43, 6, 1, 5, 5, 7, 8, 3, 160, 10, 48, 8, 12, 6, 49, 50, 51, 52, 53, 54, 160, 18, 6, 3, 42, 3, 4, 160, 11, 12, 9, 111, 116, 104, 101, 114, 78, 97, 109, 101},
			}},
			KeyUsage: KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.Ed25519,
		}, false},
		{"okExample", args{cr, []Option{WithTemplateFile("./testdata/example.tpl", TemplateData{
			SANsKey: []SubjectAlternativeName{
				{Type: "dns", Value: "foo.com"},
			},
			TokenKey: map[string]interface{}{
				"iss": "https://iss",
				"sub": "sub",
				"nbf": now.Unix(),
			},
			WebhooksKey: map[string]interface{}{
				"Test": map[string]interface{}{
					"notAfter": now.Add(10 * time.Hour).Format(time.RFC3339),
				},
			},
		})}}, &Certificate{
			Subject:        Subject{CommonName: "commonName"},
			SANs:           []SubjectAlternativeName{{Type: DNSType, Value: "foo.com"}},
			EmailAddresses: []string{"root@foo.com"},
			URIs:           []*url.URL{{Scheme: "https", Host: "iss", Fragment: "sub"}},
			NotBefore:      now,
			NotAfter:       now.Add(10 * time.Hour),
			KeyUsage:       KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.Ed25519,
		}, false},
		{"okFullSimple", args{cr, []Option{WithTemplateFile("./testdata/fullsimple.tpl", TemplateData{})}}, &Certificate{
			Version:               3,
			Subject:               Subject{CommonName: "subjectCommonName"},
			SerialNumber:          SerialNumber{big.NewInt(78187493520)},
			Issuer:                Issuer{CommonName: "issuerCommonName"},
			DNSNames:              []string{"doe.com"},
			IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
			EmailAddresses:        []string{"jane@doe.com"},
			URIs:                  []*url.URL{{Scheme: "https", Host: "doe.com"}},
			SANs:                  []SubjectAlternativeName{{Type: DNSType, Value: "www.doe.com"}},
			NotBefore:             time.Unix(1234567890, 0).UTC(),
			NotAfter:              time.Unix(1234654290, 0).UTC(),
			Extensions:            []Extension{{ID: []int{1, 2, 3, 4}, Critical: true, Value: []byte("extension")}},
			KeyUsage:              KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage:           ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}),
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{[]int{1, 3, 6, 1, 4, 1, 44924, 1, 6}, []int{1, 3, 6, 1, 4, 1, 44924, 1, 7}},
			SubjectKeyID:          []byte("subjectKeyId"),
			AuthorityKeyID:        []byte("authorityKeyId"),
			OCSPServer:            []string{"https://ocsp.server"},
			IssuingCertificateURL: []string{"https://ca.com"},
			CRLDistributionPoints: []string{"https://ca.com/ca.crl"},
			PolicyIdentifiers:     PolicyIdentifiers{mustOID(t, "1.2.3.4.5.6")},
			BasicConstraints: &BasicConstraints{
				IsCA:       false,
				MaxPathLen: 0,
			},
			NameConstraints: &NameConstraints{
				Critical:                true,
				PermittedDNSDomains:     []string{"jane.doe.com"},
				ExcludedDNSDomains:      []string{"john.doe.com"},
				PermittedIPRanges:       []*net.IPNet{ipNet("127.0.0.1/32")},
				ExcludedIPRanges:        []*net.IPNet{ipNet("0.0.0.0/0")},
				PermittedEmailAddresses: []string{"jane@doe.com"},
				ExcludedEmailAddresses:  []string{"john@doe.com"},
				PermittedURIDomains:     []string{"https://jane.doe.com"},
				ExcludedURIDomains:      []string{"https://john.doe.com"},
			},
			SignatureAlgorithm: SignatureAlgorithm(x509.PureEd25519),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.Ed25519,
		},
			false},
		{"okOPCUA", args{cr, []Option{WithTemplateFile("./testdata/opcua.tpl", TemplateData{
			SANsKey: []SubjectAlternativeName{
				{Type: "dns", Value: "foo.com"},
			},
			TokenKey: map[string]interface{}{
				"iss": "https://iss",
				"sub": "sub",
			},
		})}}, &Certificate{
			Subject:  Subject{CommonName: ""},
			SANs:     []SubjectAlternativeName{{Type: DNSType, Value: "foo.com"}},
			KeyUsage: KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign),
			BasicConstraints: &BasicConstraints{
				IsCA:       false,
				MaxPathLen: 0,
			},
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.Ed25519,
		}, false},
		{"okRawSubject", args{rawSubjectCR, []Option{WithTemplateFile("./testdata/rawSubject.tpl", TemplateData{
			SANsKey: []SubjectAlternativeName{
				{Type: "dns", Value: "foo.com"},
			},
			CertificateRequestKey: NewCertificateRequestFromX509(rawSubjectCR),
		})}}, &Certificate{
			Subject: Subject{},
			RawSubject: []byte{
				0x30, 0x68, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
				0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
				0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
				0x0c, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f,
				0x72, 0x6e, 0x69, 0x61, 0x31, 0x16, 0x30, 0x14,
				0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x0d, 0x53,
				0x61, 0x6e, 0x20, 0x46, 0x72, 0x61, 0x6e, 0x63,
				0x69, 0x73, 0x63, 0x6f, 0x31, 0x1d, 0x30, 0x1b,
				0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x14, 0x53,
				0x6d, 0x61, 0x6c, 0x6c, 0x73, 0x74, 0x65, 0x70,
				0x20, 0x4c, 0x61, 0x62, 0x73, 0x2c, 0x20, 0x49,
				0x6e, 0x63, 0x2e, 0x31, 0x0d, 0x30, 0x0b, 0x06,
				0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, 0x54, 0x65,
				0x73, 0x74,
			},
			SANs:     []SubjectAlternativeName{{Type: DNSType, Value: "foo.com"}},
			KeyUsage: KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			PublicKey:          rawSubjectKey.Public(),
			PublicKeyAlgorithm: x509.ECDSA,
		}, false},
		{"badSignature", args{crBadSignateure, nil}, nil, true},
		{"failTemplate", args{cr, []Option{WithTemplate(`{{ fail "fatal error }}`, CreateTemplateData("commonName", []string{"foo.com"}))}}, nil, true},
		{"missingTemplate", args{cr, []Option{WithTemplateFile("./testdata/missing.tpl", CreateTemplateData("commonName", []string{"foo.com"}))}}, nil, true},
		{"badJson", args{cr, []Option{WithTemplate(`"this is not a json object"`, CreateTemplateData("commonName", []string{"foo.com"}))}}, nil, true},
		{"failCustomSANs", args{cr, []Option{WithTemplate(DefaultLeafTemplate, badCustomSANsData)}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCertificate(tt.args.cr, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewCertificateTemplate(t *testing.T) {
	marshal := func(t *testing.T, value interface{}, params string) []byte {
		t.Helper()
		b, err := asn1.MarshalWithParams(value, params)
		assert.NoError(t, err)
		return b
	}

	tpl := `{
	"subject": {{ set (toJson .Subject | fromJson) "extraNames" (list (dict "type" "1.2.840.113556.1.4.656" "value" .Token.upn )) | toJson }},
	"sans": {{ concat .SANs (list
		(dict "type" "dn" "value" ` + "`" + `{"country":"US","organization":"ACME","commonName":"rocket"}` + "`" + `)
		(dict "type" "permanentIdentifier" "value" .Token.pi)
		(dict "type" "hardwareModuleName" "value" .Insecure.User.hmn)
		(dict "type" "userPrincipalName" "value" .Token.upn)
		(dict "type" "1.2.3.4" "value" (printf "int:%s" .Insecure.User.id))
	) | toJson }},
	"notBefore": "{{ .Token.nbf | formatTime }}",
	"notAfter": {{ now | dateModify "24h" | toJson }},
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
		{"id": "1.2.3.7", "value": {{ asn1Set (asn1Marshal (first .Insecure.CR.DNSNames) "utf8") (asn1Enc "int:123456") | toJson }}}
	]
}`

	// Regular sans
	sans := []string{"foo.com", "www.foo.com", "root@foo.com"}
	// Template data
	data := CreateTemplateData("commonName", sans)
	data.SetUserData(map[string]any{
		"id":  "123456",
		"hmn": `{"type":"1.2.3.1", "serialNumber": "MTIzNDU2"}`,
	})
	data.SetToken(map[string]any{
		"upn": "foo@upn.com",
		"pi":  "0123456789",
		"nbf": time.Now().Unix(),
	})

	iss, issPriv := createIssuerCertificate(t, "issuer")
	cr, priv := createCertificateRequest(t, "commonName", sans)

	now := time.Now().Truncate(time.Second)
	cert, err := NewCertificate(cr, WithTemplate(tpl, data))
	require.NoError(t, err)

	crt, err := CreateCertificate(cert.GetCertificate(), iss, priv.Public(), issPriv)
	require.NoError(t, err)

	// Create expected subject
	assert.Equal(t, pkix.Name{
		CommonName: "commonName",
		Names: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "commonName"},
			{Type: asn1.ObjectIdentifier{1, 2, 840, 113556, 1, 4, 656}, Value: "foo@upn.com"},
		},
	}, crt.Subject)

	assert.WithinDuration(t, now, crt.NotBefore, 2*time.Second)
	assert.WithinDuration(t, now.Add(24*time.Hour), crt.NotAfter, 2*time.Second)

	// Create expected SAN extension
	var rawValues []asn1.RawValue
	for _, san := range []SubjectAlternativeName{
		{Type: DNSType, Value: "foo.com"},
		{Type: DNSType, Value: "www.foo.com"},
		{Type: EmailType, Value: "root@foo.com"},
		{Type: DirectoryNameType, ASN1Value: []byte(`{"country":"US","organization":"ACME","commonName":"rocket"}`)},
		{Type: PermanentIdentifierType, Value: "0123456789"},
		{Type: HardwareModuleNameType, ASN1Value: []byte(`{"type":"1.2.3.1", "serialNumber": "MTIzNDU2"}`)},
		{Type: UserPrincipalNameType, Value: "foo@upn.com"},
		{Type: "1.2.3.4", Value: "int:123456"},
	} {
		rawValue, err := san.RawValue()
		require.NoError(t, err)
		rawValues = append(rawValues, rawValue)
	}
	rawBytes, err := asn1.Marshal(rawValues)
	require.NoError(t, err)

	var found int
	for _, ext := range crt.Extensions {
		switch {
		case ext.Id.Equal(oidExtensionSubjectAltName):
			assert.Equal(t, pkix.Extension{
				Id:    oidExtensionSubjectAltName,
				Value: rawBytes,
			}, ext)
		case ext.Id.Equal([]int{1, 2, 3, 4}):
			assert.Equal(t, pkix.Extension{
				Id:    ext.Id,
				Value: marshal(t, "foo.com", "printable"),
			}, ext)
		case ext.Id.Equal([]int{1, 2, 3, 5}):
			assert.Equal(t, pkix.Extension{
				Id:    ext.Id,
				Value: marshal(t, "foo.com", ""),
			}, ext)
		case ext.Id.Equal([]int{1, 2, 3, 6}):
			assert.Equal(t, pkix.Extension{
				Id:    ext.Id,
				Value: marshal(t, []any{"foo.com", 123456}, ""),
			}, ext)
		case ext.Id.Equal([]int{1, 2, 3, 7}):
			assert.Equal(t, pkix.Extension{
				Id: ext.Id,
				Value: marshal(t, struct {
					String string `asn1:"utf8"`
					Int    int
				}{"foo.com", 123456}, "set"),
			}, ext)
		default:
			continue
		}
		found++
	}

	assert.Equal(t, 5, found, "some of the expected extension where not found")

}

func TestNewCertificateFromX509(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{ // similar template as the certificate request for TestNewCertificate
		PublicKey:          priv.Public(),
		PublicKeyAlgorithm: x509.ECDSA,
		Subject:            pkix.Name{CommonName: "commonName"},
		DNSNames:           []string{"foo.com"},
		EmailAddresses:     []string{"root@foo.com"},
	}
	customSANsData := CreateTemplateData("commonName", nil)
	customSANsData.Set(SANsKey, []SubjectAlternativeName{
		{Type: PermanentIdentifierType, Value: "123456"},
		{Type: "1.2.3.4", Value: "utf8:otherName"},
	})
	badCustomSANsData := CreateTemplateData("commonName", nil)
	badCustomSANsData.Set(SANsKey, []SubjectAlternativeName{
		{Type: "1.2.3.4", Value: "int:not-an-int"},
	})
	ipNet := func(s string) *net.IPNet {
		_, ipNet, err := net.ParseCIDR(s)
		require.NoError(t, err)
		return ipNet
	}
	type args struct {
		template *x509.Certificate
		opts     []Option
	}
	tests := []struct {
		name    string
		args    args
		want    *Certificate
		wantErr bool
	}{
		{"okSimple", args{template, nil}, &Certificate{
			Subject:        Subject{CommonName: "commonName"},
			DNSNames:       []string{"foo.com"},
			EmailAddresses: []string{"root@foo.com"},
			KeyUsage:       KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			Extensions:         newExtensions(template.Extensions),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.ECDSA,
			SignatureAlgorithm: SignatureAlgorithm(x509.UnknownSignatureAlgorithm),
		}, false},
		{"okDefaultTemplate", args{template, []Option{WithTemplate(DefaultLeafTemplate, CreateTemplateData("commonName", []string{"foo.com"}))}}, &Certificate{
			Subject:  Subject{CommonName: "commonName"},
			SANs:     []SubjectAlternativeName{{Type: DNSType, Value: "foo.com"}},
			KeyUsage: KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.ECDSA,
		}, false},
		{"okCustomSANs", args{template, []Option{WithTemplate(DefaultLeafTemplate, customSANsData)}}, &Certificate{
			Subject: Subject{CommonName: "commonName"},
			SANs: []SubjectAlternativeName{
				{Type: PermanentIdentifierType, Value: "123456"},
				{Type: "1.2.3.4", Value: "utf8:otherName"},
			},
			Extensions: []Extension{{
				ID:       ObjectIdentifier{2, 5, 29, 17},
				Critical: false,
				Value:    []byte{48, 44, 160, 22, 6, 8, 43, 6, 1, 5, 5, 7, 8, 3, 160, 10, 48, 8, 12, 6, 49, 50, 51, 52, 53, 54, 160, 18, 6, 3, 42, 3, 4, 160, 11, 12, 9, 111, 116, 104, 101, 114, 78, 97, 109, 101},
			}},
			KeyUsage: KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.ECDSA,
		}, false},
		{"okExample", args{template, []Option{WithTemplateFile("./testdata/example.tpl", TemplateData{
			SANsKey: []SubjectAlternativeName{
				{Type: "dns", Value: "foo.com"},
			},
			TokenKey: map[string]interface{}{
				"iss": "https://iss",
				"sub": "sub",
				"nbf": now.Unix(),
			},
			WebhooksKey: map[string]interface{}{
				"Test": map[string]interface{}{
					"notAfter": now.Add(10 * time.Hour).Format(time.RFC3339),
				},
			},
		})}}, &Certificate{
			Subject:        Subject{CommonName: "commonName"},
			SANs:           []SubjectAlternativeName{{Type: DNSType, Value: "foo.com"}},
			EmailAddresses: []string{"root@foo.com"},
			URIs:           []*url.URL{{Scheme: "https", Host: "iss", Fragment: "sub"}},
			NotBefore:      now,
			NotAfter:       now.Add(10 * time.Hour),
			KeyUsage:       KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.ECDSA,
		}, false},
		{"okFullSimple", args{template, []Option{WithTemplateFile("./testdata/fullsimple.tpl", TemplateData{})}}, &Certificate{
			Version:               3,
			Subject:               Subject{CommonName: "subjectCommonName"},
			SerialNumber:          SerialNumber{big.NewInt(78187493520)},
			Issuer:                Issuer{CommonName: "issuerCommonName"},
			DNSNames:              []string{"doe.com"},
			IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
			EmailAddresses:        []string{"jane@doe.com"},
			URIs:                  []*url.URL{{Scheme: "https", Host: "doe.com"}},
			SANs:                  []SubjectAlternativeName{{Type: DNSType, Value: "www.doe.com"}},
			NotBefore:             time.Unix(1234567890, 0).UTC(),
			NotAfter:              time.Unix(1234654290, 0).UTC(),
			Extensions:            []Extension{{ID: []int{1, 2, 3, 4}, Critical: true, Value: []byte("extension")}},
			KeyUsage:              KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage:           ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}),
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{[]int{1, 3, 6, 1, 4, 1, 44924, 1, 6}, []int{1, 3, 6, 1, 4, 1, 44924, 1, 7}},
			SubjectKeyID:          []byte("subjectKeyId"),
			AuthorityKeyID:        []byte("authorityKeyId"),
			OCSPServer:            []string{"https://ocsp.server"},
			IssuingCertificateURL: []string{"https://ca.com"},
			CRLDistributionPoints: []string{"https://ca.com/ca.crl"},
			PolicyIdentifiers:     PolicyIdentifiers{mustOID(t, "1.2.3.4.5.6")},
			BasicConstraints: &BasicConstraints{
				IsCA:       false,
				MaxPathLen: 0,
			},
			NameConstraints: &NameConstraints{
				Critical:                true,
				PermittedDNSDomains:     []string{"jane.doe.com"},
				ExcludedDNSDomains:      []string{"john.doe.com"},
				PermittedIPRanges:       []*net.IPNet{ipNet("127.0.0.1/32")},
				ExcludedIPRanges:        []*net.IPNet{ipNet("0.0.0.0/0")},
				PermittedEmailAddresses: []string{"jane@doe.com"},
				ExcludedEmailAddresses:  []string{"john@doe.com"},
				PermittedURIDomains:     []string{"https://jane.doe.com"},
				ExcludedURIDomains:      []string{"https://john.doe.com"},
			},
			SignatureAlgorithm: SignatureAlgorithm(x509.PureEd25519),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.ECDSA,
		}, false},
		{"failTemplate", args{template, []Option{WithTemplate(`{{ fail "fatal error }}`, CreateTemplateData("commonName", []string{"foo.com"}))}}, nil, true},
		{"missingTemplate", args{template, []Option{WithTemplateFile("./testdata/missing.tpl", CreateTemplateData("commonName", []string{"foo.com"}))}}, nil, true},
		{"badJson", args{template, []Option{WithTemplate(`"this is not a json object"`, CreateTemplateData("commonName", []string{"foo.com"}))}}, nil, true},
		{"failCustomSANs", args{template, []Option{WithTemplate(DefaultLeafTemplate, badCustomSANsData)}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCertificateFromX509(tt.args.template, tt.args.opts...)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCertificate_GetCertificate(t *testing.T) {
	now := time.Now()
	type fields struct {
		Version               int
		Subject               Subject
		Issuer                Issuer
		SerialNumber          SerialNumber
		DNSNames              MultiString
		EmailAddresses        MultiString
		IPAddresses           MultiIP
		URIs                  MultiURL
		SANs                  []SubjectAlternativeName
		NotBefore             time.Time
		NotAfter              time.Time
		Extensions            []Extension
		KeyUsage              KeyUsage
		ExtKeyUsage           ExtKeyUsage
		UnknownExtKeyUsage    UnknownExtKeyUsage
		SubjectKeyID          SubjectKeyID
		AuthorityKeyID        AuthorityKeyID
		OCSPServer            OCSPServer
		IssuingCertificateURL IssuingCertificateURL
		CRLDistributionPoints CRLDistributionPoints
		PolicyIdentifiers     PolicyIdentifiers
		BasicConstraints      *BasicConstraints
		NameConstraints       *NameConstraints
		SignatureAlgorithm    SignatureAlgorithm
		PublicKeyAlgorithm    x509.PublicKeyAlgorithm
		PublicKey             interface{}
	}
	tests := []struct {
		name   string
		fields fields
		want   *x509.Certificate
	}{
		{"ok", fields{
			Version:        3,
			Subject:        Subject{CommonName: "commonName", Organization: []string{"smallstep"}},
			Issuer:         Issuer{CommonName: "issuer", Organization: []string{"smallstep"}},
			SerialNumber:   SerialNumber{big.NewInt(123)},
			DNSNames:       []string{"foo.bar"},
			EmailAddresses: []string{"root@foo.com"},
			IPAddresses:    []net.IP{net.ParseIP("::1")},
			URIs:           []*url.URL{{Scheme: "mailto", Opaque: "root@foo.com"}},
			SANs: []SubjectAlternativeName{
				{Type: DNSType, Value: "www.foo.bar"},
				{Type: IPType, Value: "127.0.0.1"},
				{Type: EmailType, Value: "admin@foo.com"},
				{Type: URIType, Value: "mailto:admin@foo.com"},
			},
			NotBefore:  now,
			NotAfter:   time.Time{},
			Extensions: []Extension{{ID: []int{1, 2, 3, 4}, Critical: true, Value: []byte("custom extension")}},
			KeyUsage:   KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{[]int{1, 3, 6, 1, 4, 1, 44924, 1, 6}, []int{1, 3, 6, 1, 4, 1, 44924, 1, 7}},
			SubjectKeyID:          []byte("subject-key-id"),
			AuthorityKeyID:        []byte("authority-key-id"),
			OCSPServer:            []string{"https://oscp.server"},
			IssuingCertificateURL: []string{"https://ca.com"},
			CRLDistributionPoints: []string{"https://ca.com/crl"},
			PolicyIdentifiers:     PolicyIdentifiers{mustOID(t, "1.2.3.4")},
			BasicConstraints:      &BasicConstraints{IsCA: true, MaxPathLen: 0},
			NameConstraints:       &NameConstraints{PermittedDNSDomains: []string{"foo.bar"}},
			SignatureAlgorithm:    SignatureAlgorithm(x509.PureEd25519),
			PublicKeyAlgorithm:    x509.Ed25519,
			PublicKey:             ed25519.PublicKey("public key"),
		}, &x509.Certificate{
			Version:         0,
			Subject:         pkix.Name{CommonName: "commonName", Organization: []string{"smallstep"}},
			Issuer:          pkix.Name{},
			SerialNumber:    big.NewInt(123),
			NotBefore:       now,
			NotAfter:        time.Time{},
			DNSNames:        []string{"foo.bar", "www.foo.bar"},
			EmailAddresses:  []string{"root@foo.com", "admin@foo.com"},
			IPAddresses:     []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")},
			URIs:            []*url.URL{{Scheme: "mailto", Opaque: "root@foo.com"}, {Scheme: "mailto", Opaque: "admin@foo.com"}},
			ExtraExtensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}, Critical: true, Value: []byte("custom extension")}},
			KeyUsage:        x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			},
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{[]int{1, 3, 6, 1, 4, 1, 44924, 1, 6}, []int{1, 3, 6, 1, 4, 1, 44924, 1, 7}},
			SubjectKeyId:          []byte("subject-key-id"),
			AuthorityKeyId:        []byte("authority-key-id"),
			OCSPServer:            []string{"https://oscp.server"},
			IssuingCertificateURL: []string{"https://ca.com"},
			CRLDistributionPoints: []string{"https://ca.com/crl"},
			PolicyIdentifiers:     []asn1.ObjectIdentifier{{1, 2, 3, 4}},
			Policies:              []x509.OID{mustOID(t, "1.2.3.4")},
			IsCA:                  true,
			MaxPathLen:            0,
			MaxPathLenZero:        true,
			BasicConstraintsValid: true,
			PermittedDNSDomains:   []string{"foo.bar"},
			SignatureAlgorithm:    x509.PureEd25519,
			PublicKeyAlgorithm:    x509.Ed25519,
			PublicKey:             ed25519.PublicKey("public key"),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Certificate{
				Version:               tt.fields.Version,
				Subject:               tt.fields.Subject,
				Issuer:                tt.fields.Issuer,
				SerialNumber:          tt.fields.SerialNumber,
				DNSNames:              tt.fields.DNSNames,
				EmailAddresses:        tt.fields.EmailAddresses,
				IPAddresses:           tt.fields.IPAddresses,
				URIs:                  tt.fields.URIs,
				SANs:                  tt.fields.SANs,
				NotBefore:             tt.fields.NotBefore,
				NotAfter:              tt.fields.NotAfter,
				Extensions:            tt.fields.Extensions,
				KeyUsage:              tt.fields.KeyUsage,
				ExtKeyUsage:           tt.fields.ExtKeyUsage,
				UnknownExtKeyUsage:    tt.fields.UnknownExtKeyUsage,
				SubjectKeyID:          tt.fields.SubjectKeyID,
				AuthorityKeyID:        tt.fields.AuthorityKeyID,
				OCSPServer:            tt.fields.OCSPServer,
				IssuingCertificateURL: tt.fields.IssuingCertificateURL,
				CRLDistributionPoints: tt.fields.CRLDistributionPoints,
				PolicyIdentifiers:     tt.fields.PolicyIdentifiers,
				BasicConstraints:      tt.fields.BasicConstraints,
				NameConstraints:       tt.fields.NameConstraints,
				SignatureAlgorithm:    tt.fields.SignatureAlgorithm,
				PublicKeyAlgorithm:    tt.fields.PublicKeyAlgorithm,
				PublicKey:             tt.fields.PublicKey,
			}
			assert.Equal(t, tt.want, c.GetCertificate())
		})
	}
}

func TestCreateCertificate(t *testing.T) {
	iss, issPriv := createIssuerCertificate(t, "issuer")

	mustSerialNumber := func() *big.Int {
		sn, err := generateSerialNumber()
		if err != nil {
			t.Fatal(err)
		}
		return sn
	}
	mustSubjectKeyID := func(pub crypto.PublicKey) []byte {
		b, err := generateSubjectKeyID(pub)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	cr1, priv1 := createCertificateRequest(t, "commonName", []string{"foo.com"})
	crt1 := NewCertificateRequestFromX509(cr1).GetLeafCertificate().GetCertificate()
	crt1.SerialNumber = mustSerialNumber()
	crt1.SubjectKeyId = mustSubjectKeyID(priv1.Public())

	cr2, priv2 := createCertificateRequest(t, "commonName", []string{"foo.com"})
	crt2 := NewCertificateRequestFromX509(cr2).GetLeafCertificate().GetCertificate()
	crt2.SerialNumber = mustSerialNumber()

	cr3, priv3 := createCertificateRequest(t, "commonName", []string{"foo.com"})
	crt3 := NewCertificateRequestFromX509(cr3).GetLeafCertificate().GetCertificate()
	crt3.SubjectKeyId = mustSubjectKeyID(priv1.Public())

	cr4, priv4 := createCertificateRequest(t, "commonName", []string{"foo.com"})
	crt4 := NewCertificateRequestFromX509(cr4).GetLeafCertificate().GetCertificate()

	cr5, _ := createCertificateRequest(t, "commonName", []string{"foo.com"})
	crt5 := NewCertificateRequestFromX509(cr5).GetLeafCertificate().GetCertificate()

	badSigner := createBadSigner(t)

	type args struct {
		template *x509.Certificate
		parent   *x509.Certificate
		pub      crypto.PublicKey
		signer   crypto.Signer
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{crt1, iss, priv1.Public(), issPriv}, false},
		{"okNoSubjectKeyID", args{crt2, iss, priv2.Public(), issPriv}, false},
		{"okNoSerialNumber", args{crt3, iss, priv3.Public(), issPriv}, false},
		{"okNothing", args{crt4, iss, priv4.Public(), issPriv}, false},
		{"failSubjectKeyID", args{crt5, iss, []byte("foo"), issPriv}, true},
		{"failSign", args{crt1, iss, priv1.Public(), badSigner}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateCertificate(tt.args.template, tt.args.parent, tt.args.pub, tt.args.signer)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if err := got.CheckSignatureFrom(iss); err != nil {
					t.Errorf("Certificate.CheckSignatureFrom() error = %v", err)
				}
			}
		})
	}
}

func TestCreateCertificate_criticalSANs(t *testing.T) {
	cr, _ := createCertificateRequest(t, "", []string{"foo.com"})
	iss, issPriv := createIssuerCertificate(t, "issuer")

	type args struct {
		cr   *x509.CertificateRequest
		opts []Option
	}
	tests := []struct {
		name string
		args args
	}{
		{"okNoOptions", args{cr, nil}},
		{"okDefaultLeafTemplate", args{cr, []Option{WithTemplate(DefaultLeafTemplate, CreateTemplateData("", []string{"foo.com"}))}}},
		{"okCertificateRequestTemplate", args{cr, []Option{WithTemplate(CertificateRequestTemplate, CreateTemplateData("", []string{"foo.com"}))}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := NewCertificate(cr, tt.args.opts...)
			if err != nil {
				t.Fatalf("NewCertificate() error = %v", err)
			}

			template := cert.GetCertificate()
			got, err := CreateCertificate(template, iss, template.PublicKey, issPriv)
			if err != nil {
				t.Fatalf("Certificate.CheckSignatureFrom() error = %v", err)
			}

			if err := got.CheckSignatureFrom(iss); err != nil {
				t.Fatalf("Certificate.CheckSignatureFrom() error = %v", err)
			}

			asn1Subject, err := asn1.Marshal(got.Subject.ToRDNSequence())
			if err != nil {
				t.Fatalf("asn1.Marshal() error = %v", err)
			}

			if bytes.Equal(asn1Subject, emptyASN1Subject) {
				for _, ext := range got.Extensions {
					if ext.Id.Equal(oidExtensionSubjectAltName) && !ext.Critical {
						t.Errorf("Extension %s is not critical: %v", ext.Id, ext)
					}

				}
			}
		})
	}
}

func TestCreateCertificateTemplate(t *testing.T) {
	cr1, _ := createCertificateRequest(t, "commonName", []string{"doe.com", "jane@doe.com", "1.2.3.4", "urn:uuid:2bbe86fc-a35e-4c68-a5cb-cb1060f57629"})
	cr2, _ := createCertificateRequest(t, "", []string{"doe.com"})
	cr3, _ := createCertificateRequest(t, "commonName", []string{})

	fail, _ := createCertificateRequest(t, "commonName", []string{"doe.com"})
	fail.Signature = []byte{1, 2, 3, 4}

	type args struct {
		cr *x509.CertificateRequest
	}
	tests := []struct {
		name    string
		args    args
		want    *x509.Certificate
		wantErr bool
	}{
		{"ok", args{cr1}, &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "commonName",
				Names:      []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "commonName"}},
			},
			PublicKey:          cr1.PublicKey,
			PublicKeyAlgorithm: cr1.PublicKeyAlgorithm,
			ExtraExtensions: []pkix.Extension{
				{Id: oidExtensionSubjectAltName, Critical: false, Value: cr1.Extensions[0].Value},
			},
			DNSNames:       []string{"doe.com"},
			EmailAddresses: []string{"jane@doe.com"},
			IPAddresses:    []net.IP{net.ParseIP("1.2.3.4").To4()},
			URIs:           []*url.URL{{Scheme: "urn", Opaque: "uuid:2bbe86fc-a35e-4c68-a5cb-cb1060f57629"}},
		}, false},
		{"ok critical", args{cr2}, &x509.Certificate{
			Subject:            pkix.Name{},
			PublicKey:          cr2.PublicKey,
			PublicKeyAlgorithm: cr3.PublicKeyAlgorithm,
			ExtraExtensions: []pkix.Extension{
				{Id: oidExtensionSubjectAltName, Critical: true, Value: cr2.Extensions[0].Value},
			},
			DNSNames: []string{"doe.com"},
		}, false},
		{"ok no extensions", args{cr3}, &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "commonName",
				Names:      []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "commonName"}},
			},
			PublicKey:          cr3.PublicKey,
			PublicKeyAlgorithm: cr3.PublicKeyAlgorithm,
		}, false},
		{"fail", args{fail}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateCertificateTemplate(tt.args.cr)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateCertificateTemplate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateCertificateTemplate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateCertificate_debug(t *testing.T) {
	csr, _ := createCertificateRequest(t, "rocket", nil)
	iss, issPriv := createIssuerCertificate(t, "issuer")

	data := CreateTemplateData("rocket", nil)
	data.Set(SANsKey, []SubjectAlternativeName{
		{Type: DirectoryNameType, ASN1Value: []byte(`{"country":"US","organization":"ACME","commonName":"rocket"}`)},
	})

	tests := []struct {
		name string
		sans []SubjectAlternativeName
	}{
		{"directoryName", []SubjectAlternativeName{
			{Type: DirectoryNameType, ASN1Value: []byte(`{"country":"US","organization":"ACME","commonName":"rocket"}`)},
		}},
		{"hardwareModuleName", []SubjectAlternativeName{
			{Type: HardwareModuleNameType, ASN1Value: []byte(`{"type":"1.2.3.4","serialNumber":"MDEyMzQ1Njc4OQ=="}`)},
		}},
		{"permanentIdentifier", []SubjectAlternativeName{
			{Type: PermanentIdentifierType, ASN1Value: []byte(`{"identifier":"0123456789","assigner":"1.2.3.4"}`)},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := CreateTemplateData("rocket", nil)
			data.Set(SANsKey, tt.sans)

			c, err := NewCertificate(csr, WithTemplate(DefaultLeafTemplate, data))
			if err != nil {
				t.Fatal(err)
			}

			template := c.GetCertificate()
			cert, err := CreateCertificate(template, iss, csr.PublicKey, issPriv)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("\n%s", pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE", Bytes: cert.Raw,
			}))
		})
	}
}
