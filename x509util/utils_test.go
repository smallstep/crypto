package x509util

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/url"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.step.sm/crypto/fipsutil"
)

func decodeCertificateFile(t *testing.T, filename string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("error decoding pem")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return crt
}

func TestSplitSANs(t *testing.T) {
	type args struct {
		sans []string
	}
	tests := []struct {
		name         string
		args         args
		wantDNSNames []string
		wantIps      []net.IP
		wantEmails   []string
		wantUris     []*url.URL
	}{
		{"nil", args{nil}, []string{}, []net.IP{}, []string{}, []*url.URL{}},
		{"empty", args{[]string{}}, []string{}, []net.IP{}, []string{}, []*url.URL{}},
		{"dns", args{[]string{"doe.com"}}, []string{"doe.com"}, []net.IP{}, []string{}, []*url.URL{}},
		{"ip", args{[]string{"127.0.0.1", "1.2.3.4"}}, []string{}, []net.IP{
			net.ParseIP("127.0.0.1"), net.ParseIP("1.2.3.4"),
		}, []string{}, []*url.URL{}},
		{"ipv6", args{[]string{"::1", "2001:0db8:0000:0000:0000:8a2e:0370:7334", "2001:db8::8a2e:370:7334"}}, []string{}, []net.IP{
			net.ParseIP("::1"), net.ParseIP("2001:0db8:0000:0000:0000:8a2e:0370:7334"), net.ParseIP("2001:db8::8a2e:370:7334"),
		}, []string{}, []*url.URL{}},
		{"emails", args{[]string{"john@doe.com", "jane@doe.com"}}, []string{}, []net.IP{}, []string{
			"john@doe.com", "jane@doe.com",
		}, []*url.URL{}},
		{"uris", args{[]string{"https://smallstep.com/step/", "mailto:john@doe.com", "urn:uuid:ddfe62ba-7e99-4bc1-83b3-8f57fe3e9959"}}, []string{}, []net.IP{}, []string{}, []*url.URL{
			{Scheme: "https", Host: "smallstep.com", Path: "/step/"},
			{Scheme: "mailto", Opaque: "john@doe.com"},
			{Scheme: "urn", Opaque: "uuid:ddfe62ba-7e99-4bc1-83b3-8f57fe3e9959"},
		}},
		{"mixed", args{[]string{
			"foo.internal", "https://ca.smallstep.com", "max@smallstep.com",
			"urn:uuid:ddfe62ba-7e99-4bc1-83b3-8f57fe3e9959", "mariano@smallstep.com",
			"1.1.1.1", "bar.internal", "https://google.com/index.html",
			"mailto:john@doe.com", "2102:446:c001:d65e:ab1a:bf20:4b26:31f7"}},
			[]string{"foo.internal", "bar.internal"},
			[]net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2102:446:c001:d65e:ab1a:bf20:4b26:31f7")},
			[]string{"max@smallstep.com", "mariano@smallstep.com"},
			[]*url.URL{
				{Scheme: "https", Host: "ca.smallstep.com"},
				{Scheme: "urn", Opaque: "uuid:ddfe62ba-7e99-4bc1-83b3-8f57fe3e9959"},
				{Scheme: "https", Host: "google.com", Path: "/index.html"},
				{Scheme: "mailto", Opaque: "john@doe.com"},
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDNSNames, gotIps, gotEmails, gotUris := SplitSANs(tt.args.sans)
			if !reflect.DeepEqual(gotDNSNames, tt.wantDNSNames) {
				t.Errorf("SplitSANs() gotDNSNames = %v, want %v", gotDNSNames, tt.wantDNSNames)
			}
			if !reflect.DeepEqual(gotIps, tt.wantIps) {
				t.Errorf("SplitSANs() gotIps = %v, want %v", gotIps, tt.wantIps)
			}
			if !reflect.DeepEqual(gotEmails, tt.wantEmails) {
				t.Errorf("SplitSANs() gotEmails = %v, want %v", gotEmails, tt.wantEmails)
			}
			if !reflect.DeepEqual(gotUris, tt.wantUris) {
				t.Errorf("SplitSANs() gotUris = %v, want %v", gotUris, tt.wantUris)
			}
		})
	}
}

func TestCreateSANs(t *testing.T) {
	type args struct {
		sans []string
	}
	tests := []struct {
		name string
		args args
		want []SubjectAlternativeName
	}{
		{"nil", args{nil}, []SubjectAlternativeName{}},
		{"empty", args{[]string{}}, []SubjectAlternativeName{}},
		{"dns", args{[]string{"doe.com"}}, []SubjectAlternativeName{{Type: "dns", Value: "doe.com"}}},
		{"ip", args{[]string{"127.0.0.1", "2001:0db8:0000:0000:0000:8a2e:0370:7334"}}, []SubjectAlternativeName{
			{Type: "ip", Value: "127.0.0.1"},
			{Type: "ip", Value: "2001:db8::8a2e:370:7334"},
		}},
		{"emails", args{[]string{"john@doe.com", "jane@doe.com"}}, []SubjectAlternativeName{
			{Type: "email", Value: "john@doe.com"},
			{Type: "email", Value: "jane@doe.com"},
		}},
		{"uris", args{[]string{"https://smallstep.com/step/", "mailto:john@doe.com", "urn:uuid:ddfe62ba-7e99-4bc1-83b3-8f57fe3e9959"}}, []SubjectAlternativeName{
			{Type: "uri", Value: "https://smallstep.com/step/"},
			{Type: "uri", Value: "mailto:john@doe.com"},
			{Type: "uri", Value: "urn:uuid:ddfe62ba-7e99-4bc1-83b3-8f57fe3e9959"},
		}},
		{"mixed", args{[]string{
			"foo.internal", "https://ca.smallstep.com", "max@smallstep.com",
			"urn:uuid:ddfe62ba-7e99-4bc1-83b3-8f57fe3e9959", "mariano@smallstep.com",
			"1.1.1.1", "bar.internal", "https://google.com/index.html",
			"mailto:john@doe.com", "2102:446:c001:d65e:ab1a:bf20:4b26:31f7"}},
			[]SubjectAlternativeName{
				{Type: "dns", Value: "foo.internal"},
				{Type: "dns", Value: "bar.internal"},
				{Type: "ip", Value: "1.1.1.1"},
				{Type: "ip", Value: "2102:446:c001:d65e:ab1a:bf20:4b26:31f7"},
				{Type: "email", Value: "max@smallstep.com"},
				{Type: "email", Value: "mariano@smallstep.com"},
				{Type: "uri", Value: "https://ca.smallstep.com"},
				{Type: "uri", Value: "urn:uuid:ddfe62ba-7e99-4bc1-83b3-8f57fe3e9959"},
				{Type: "uri", Value: "https://google.com/index.html"},
				{Type: "uri", Value: "mailto:john@doe.com"},
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CreateSANs(tt.args.sans); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateSANs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_generateSubjectKeyID(t *testing.T) {
	if fipsutil.Enabled() {
		t.Skip("FIPS 140-3 mode is enabled")
	}

	ecdsaCrt := decodeCertificateFile(t, "testdata/google.crt")
	rsaCrt := decodeCertificateFile(t, "testdata/smallstep.crt")
	ed25519Crt := decodeCertificateFile(t, "testdata/ed25519.crt")

	type args struct {
		pub crypto.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"ecdsa", args{ecdsaCrt.PublicKey}, ecdsaCrt.SubjectKeyId, false},
		{"rsa", args{rsaCrt.PublicKey}, rsaCrt.SubjectKeyId, false},
		{"ed25519", args{ed25519Crt.PublicKey}, ed25519Crt.SubjectKeyId, false},
		{"fail", args{[]byte("fail")}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateSubjectKeyID(tt.args.pub)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateSubjectKeyID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("generateSubjectKeyID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_generateSubjectKeyID_fips(t *testing.T) {
	if !fipsutil.Enabled() {
		t.Skip("FIPS 140-3 mode is not enabled")
	}

	sha256Cert := decodeCertificateFile(t, "testdata/letsencrypt.crt")
	type args struct {
		pub crypto.PublicKey
	}
	tests := []struct {
		name      string
		args      args
		want      []byte
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", args{sha256Cert.PublicKey}, sha256Cert.SubjectKeyId, assert.NoError},
		{"fail", args{[]byte("fail")}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateSubjectKeyID(tt.args.pub)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSanitizeName(t *testing.T) {
	type args struct {
		domain string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"ok", args{"smallstep.com"}, "smallstep.com", false},
		{"ok ascii", args{"bücher.example.com"}, "xn--bcher-kva.example.com", false},
		{"fail", args{"xn--bücher.example.com"}, "", true},
		{"fail with port", args{"smallstep.com:8080"}, "", true},
		{"fail empty", args{""}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizeName(tt.args.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("SanitizeName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SanitizeName() = %v, want %v", got, tt.want)
			}
		})
	}
}
