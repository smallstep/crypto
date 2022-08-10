package sshutil

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"
)

type badSigner struct {
	signer ssh.Signer
}

func (b *badSigner) PublicKey() ssh.PublicKey {
	return b.signer.PublicKey()
}

func (b *badSigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	return nil, fmt.Errorf("an error")
}

func (b *badSigner) SignWithAlgorithm(r io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	return nil, fmt.Errorf("an error")
}

func mustGenerateKey(t *testing.T) (ssh.PublicKey, ssh.Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return key, signer
}

func mustGenerateRSAKey(t *testing.T) (ssh.PublicKey, ssh.Signer) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return key, signer
}

func mustGeneratePublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	key, _ := mustGenerateKey(t)
	return key
}

func TestNewCertificate(t *testing.T) {
	key := mustGeneratePublicKey(t)
	cr := CertificateRequest{
		Key: key,
	}

	crEscape := CertificateRequest{
		Type:       "host",
		KeyID:      `foobar", "criticalOptions": {"foo": "bar"},"foo":"`,
		Principals: []string{"foo.internal", "bar.internal"},
		Key:        key,
	}

	type args struct {
		cr   CertificateRequest
		opts []Option
	}
	tests := []struct {
		name    string
		args    args
		want    *Certificate
		wantErr bool
	}{
		{"user", args{cr, []Option{WithTemplate(DefaultTemplate, CreateTemplateData(UserCert, "jane@doe.com", []string{"jane"}))}}, &Certificate{
			Nonce:           nil,
			Key:             key,
			Serial:          0,
			Type:            UserCert,
			KeyID:           "jane@doe.com",
			Principals:      []string{"jane"},
			ValidAfter:      0,
			ValidBefore:     0,
			CriticalOptions: nil,
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
			Reserved:     nil,
			SignatureKey: nil,
			Signature:    nil,
		}, false},
		{"host", args{cr, []Option{WithTemplate(DefaultTemplate, CreateTemplateData(HostCert, "foobar", []string{"foo.internal", "bar.internal"}))}}, &Certificate{
			Nonce:           nil,
			Key:             key,
			Serial:          0,
			Type:            HostCert,
			KeyID:           "foobar",
			Principals:      []string{"foo.internal", "bar.internal"},
			ValidAfter:      0,
			ValidBefore:     0,
			CriticalOptions: nil,
			Extensions:      nil,
			Reserved:        nil,
			SignatureKey:    nil,
			Signature:       nil,
		}, false},
		{"host escape", args{crEscape, []Option{WithTemplate(CertificateRequestTemplate, CreateTemplateData(HostCert, "foobar", []string{"foo.internal", "bar.internal"}))}}, &Certificate{
			Nonce:           nil,
			Key:             key,
			Serial:          0,
			Type:            HostCert,
			KeyID:           `foobar", "criticalOptions": {"foo": "bar"},"foo":"`,
			Principals:      []string{"foo.internal", "bar.internal"},
			ValidAfter:      0,
			ValidBefore:     0,
			CriticalOptions: nil,
			Extensions:      nil,
			Reserved:        nil,
			SignatureKey:    nil,
			Signature:       nil,
		}, false},
		{"file", args{cr, []Option{WithTemplateFile("./testdata/github.tpl", TemplateData{
			TypeKey:       UserCert,
			KeyIDKey:      "john@doe.com",
			PrincipalsKey: []string{"john", "john@doe.com"},
			ExtensionsKey: DefaultExtensions(UserCert),
			InsecureKey: TemplateData{
				"User": map[string]interface{}{"username": "john"},
			},
		})}}, &Certificate{
			Nonce:           nil,
			Key:             key,
			Serial:          0,
			Type:            UserCert,
			KeyID:           "john@doe.com",
			Principals:      []string{"john", "john@doe.com"},
			ValidAfter:      0,
			ValidBefore:     0,
			CriticalOptions: nil,
			Extensions: map[string]string{
				"login@github.com":        "john",
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
			Reserved:     nil,
			SignatureKey: nil,
			Signature:    nil,
		}, false},
		{"base64", args{cr, []Option{WithTemplateBase64(base64.StdEncoding.EncodeToString([]byte(DefaultTemplate)), CreateTemplateData(HostCert, "foo.internal", nil))}}, &Certificate{
			Nonce:           nil,
			Key:             key,
			Serial:          0,
			Type:            HostCert,
			KeyID:           "foo.internal",
			Principals:      nil,
			ValidAfter:      0,
			ValidBefore:     0,
			CriticalOptions: nil,
			Extensions:      nil,
			Reserved:        nil,
			SignatureKey:    nil,
			Signature:       nil,
		}, false},
		{"failNilOptions", args{cr, nil}, nil, true},
		{"failEmptyOptions", args{cr, nil}, nil, true},
		{"badBase64Template", args{cr, []Option{WithTemplateBase64("foobar", TemplateData{})}}, nil, true},
		{"badFileTemplate", args{cr, []Option{WithTemplateFile("./testdata/missing.tpl", TemplateData{})}}, nil, true},
		{"badJsonTemplate", args{cr, []Option{WithTemplate(`{"type":{{ .Type }}}`, TemplateData{})}}, nil, true},
		{"failTemplate", args{cr, []Option{WithTemplate(`{{ fail "an error" }}`, TemplateData{})}}, nil, true},
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

func TestCertificate_GetCertificate(t *testing.T) {
	key := mustGeneratePublicKey(t)

	type fields struct {
		Nonce           []byte
		Key             ssh.PublicKey
		Serial          uint64
		Type            CertType
		KeyID           string
		Principals      []string
		ValidAfter      uint64
		ValidBefore     uint64
		CriticalOptions map[string]string
		Extensions      map[string]string
		Reserved        []byte
		SignatureKey    ssh.PublicKey
		Signature       *ssh.Signature
	}
	tests := []struct {
		name   string
		fields fields
		want   *ssh.Certificate
	}{
		{"user", fields{
			Nonce:           []byte("0123456789"),
			Key:             key,
			Serial:          123,
			Type:            UserCert,
			KeyID:           "key-id",
			Principals:      []string{"john"},
			ValidAfter:      1111,
			ValidBefore:     2222,
			CriticalOptions: map[string]string{"foo": "bar"},
			Extensions:      map[string]string{"login@github.com": "john"},
			Reserved:        []byte("reserved"),
			SignatureKey:    key,
			Signature:       &ssh.Signature{Format: "foo", Blob: []byte("bar")},
		}, &ssh.Certificate{
			Nonce:           []byte("0123456789"),
			Key:             key,
			Serial:          123,
			CertType:        ssh.UserCert,
			KeyId:           "key-id",
			ValidPrincipals: []string{"john"},
			ValidAfter:      1111,
			ValidBefore:     2222,
			Permissions: ssh.Permissions{
				CriticalOptions: map[string]string{"foo": "bar"},
				Extensions:      map[string]string{"login@github.com": "john"},
			},
			Reserved: []byte("reserved"),
		}},
		{"host", fields{
			Nonce:           []byte("0123456789"),
			Key:             key,
			Serial:          123,
			Type:            HostCert,
			KeyID:           "key-id",
			Principals:      []string{"foo.internal", "bar.internal"},
			ValidAfter:      1111,
			ValidBefore:     2222,
			CriticalOptions: map[string]string{"foo": "bar"},
			Extensions:      nil,
			Reserved:        []byte("reserved"),
			SignatureKey:    key,
			Signature:       &ssh.Signature{Format: "foo", Blob: []byte("bar")},
		}, &ssh.Certificate{
			Nonce:           []byte("0123456789"),
			Key:             key,
			Serial:          123,
			CertType:        ssh.HostCert,
			KeyId:           "key-id",
			ValidPrincipals: []string{"foo.internal", "bar.internal"},
			ValidAfter:      1111,
			ValidBefore:     2222,
			Permissions: ssh.Permissions{
				CriticalOptions: map[string]string{"foo": "bar"},
				Extensions:      nil,
			},
			Reserved: []byte("reserved"),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Certificate{
				Nonce:           tt.fields.Nonce,
				Key:             tt.fields.Key,
				Serial:          tt.fields.Serial,
				Type:            tt.fields.Type,
				KeyID:           tt.fields.KeyID,
				Principals:      tt.fields.Principals,
				ValidAfter:      tt.fields.ValidAfter,
				ValidBefore:     tt.fields.ValidBefore,
				CriticalOptions: tt.fields.CriticalOptions,
				Extensions:      tt.fields.Extensions,
				Reserved:        tt.fields.Reserved,
				SignatureKey:    tt.fields.SignatureKey,
				Signature:       tt.fields.Signature,
			}
			if got := c.GetCertificate(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Certificate.GetCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateCertificate(t *testing.T) {
	key, signer := mustGenerateKey(t)
	rsaKey, rsaSigner := mustGenerateRSAKey(t)

	type args struct {
		cert   *ssh.Certificate
		signer ssh.Signer
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{&ssh.Certificate{
			Nonce:           []byte("0123456789"),
			Key:             key,
			Serial:          123,
			CertType:        ssh.HostCert,
			KeyId:           "foo",
			ValidPrincipals: []string{"foo.internal"},
			ValidAfter:      1111,
			ValidBefore:     2222,
			Permissions:     ssh.Permissions{},
			Reserved:        []byte("reserved"),
		}, signer}, false},
		{"ok rsa", args{&ssh.Certificate{
			Nonce:           []byte("0123456789"),
			Key:             rsaKey,
			Serial:          123,
			CertType:        ssh.UserCert,
			KeyId:           "foo",
			ValidPrincipals: []string{"foo.internal"},
			ValidAfter:      1111,
			ValidBefore:     2222,
			Permissions:     ssh.Permissions{},
			Reserved:        []byte("reserved"),
		}, rsaSigner}, false},
		{"emptyNonce", args{&ssh.Certificate{
			Key:             key,
			Serial:          123,
			CertType:        ssh.UserCert,
			KeyId:           "jane@doe.com",
			ValidPrincipals: []string{"jane"},
			ValidAfter:      1111,
			ValidBefore:     2222,
			Permissions:     ssh.Permissions{},
			Reserved:        []byte("reserved"),
		}, signer}, false},
		{"emptySerial", args{&ssh.Certificate{
			Nonce:           []byte("0123456789"),
			Key:             key,
			CertType:        ssh.UserCert,
			KeyId:           "jane@doe.com",
			ValidPrincipals: []string{"jane"},
			ValidAfter:      1111,
			ValidBefore:     2222,
			Permissions:     ssh.Permissions{},
			Reserved:        []byte("reserved"),
		}, signer}, false},
		{"fail signer.Sign", args{&ssh.Certificate{
			Nonce:           []byte("0123456789"),
			Key:             key,
			Serial:          123,
			CertType:        ssh.HostCert,
			KeyId:           "foo",
			ValidPrincipals: []string{"foo.internal"},
			ValidAfter:      1111,
			ValidBefore:     2222,
			Permissions:     ssh.Permissions{},
			Reserved:        []byte("reserved"),
		}, &badSigner{signer}}, true},
		{"fail signer.SignWithAlgorithm", args{&ssh.Certificate{
			Nonce:           []byte("0123456789"),
			Key:             rsaKey,
			Serial:          123,
			CertType:        ssh.UserCert,
			KeyId:           "foo",
			ValidPrincipals: []string{"foo.internal"},
			ValidAfter:      1111,
			ValidBefore:     2222,
			Permissions:     ssh.Permissions{},
			Reserved:        []byte("reserved"),
		}, &badSigner{rsaSigner}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateCertificate(tt.args.cert, tt.args.signer)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil {
				switch {
				case len(got.Nonce) == 0:
					t.Errorf("CreateCertificate() nonce should not be empty")
				case got.Serial == 0:
					t.Errorf("CreateCertificate() serial should not be 0")
				case got.Signature == nil:
					t.Errorf("CreateCertificate() signature should not be nil")
				case !bytes.Equal(got.SignatureKey.Marshal(), tt.args.signer.PublicKey().Marshal()):
					t.Errorf("CreateCertificate() signature key is not the expected one")
				}

				signature := got.Signature
				got.Signature = nil

				data := got.Marshal()
				data = data[:len(data)-4]

				var sig *ssh.Signature
				if got.SignatureKey.Type() == "rsa-ssh" {
					algSigner, ok := tt.args.signer.(ssh.AlgorithmSigner)
					if !ok {
						t.Fatalf("signer %T is not an ssh.AlgorithmSigner", tt.args.signer)
					}
					if sig, err = algSigner.SignWithAlgorithm(rand.Reader, data, "rsa-sha2-256"); err != nil {
						t.Errorf("algSigner.SignWithAlgorithm() error = %v", err)
					}
				} else {
					if sig, err = tt.args.signer.Sign(rand.Reader, data); err != nil {
						t.Errorf("signer.Sign() error = %v", err)
					}
				}

				// Verify signature
				got.Signature = signature
				if err := tt.args.signer.PublicKey().Verify(data, got.Signature); err != nil {
					t.Errorf("CreateCertificate() signature verify error = %v", err)
				}
				// Verify data with public key in cert
				if err := got.Verify(data, sig); err != nil {
					t.Errorf("CreateCertificate() certificate verify error = %v", err)
				}

			}
		})
	}
}
