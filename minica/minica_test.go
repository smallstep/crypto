package minica

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/x509util"
	"golang.org/x/crypto/ssh"
)

type badSigner struct{}

func (p badSigner) Public() crypto.PublicKey {
	return []byte("foo")
}

func (p badSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return nil, errors.New("foo")
}

type mockConnMetadata string

func (c mockConnMetadata) User() string {
	return string(c)
}
func (c mockConnMetadata) SessionID() []byte {
	return []byte{1, 2, 3}
}
func (c mockConnMetadata) ClientVersion() []byte {
	return []byte{1, 2, 3}
}
func (c mockConnMetadata) ServerVersion() []byte {
	return []byte{1, 2, 3}
}
func (c mockConnMetadata) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: net.IP{1, 2, 3, 4}}
}
func (c mockConnMetadata) LocalAddr() net.Addr {
	return &net.IPAddr{IP: net.IP{1, 2, 3, 4}}
}

func mustCA(t *testing.T, opts ...Option) *CA {
	t.Helper()
	ca, err := New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestNew(t *testing.T) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	failGetSigner := func(n int) func() (crypto.Signer, error) {
		var callNumber int
		return func() (crypto.Signer, error) {
			callNumber++
			if callNumber == n {
				return nil, errors.New("an error")
			}
			return signer, nil
		}
	}
	failSigner := func(n int) func() (crypto.Signer, error) {
		var callNumber int
		return func() (crypto.Signer, error) {
			callNumber++
			if callNumber == n {
				return badSigner{}, nil
			}
			return signer, nil
		}
	}

	type args struct {
		opts []Option
	}
	tests := []struct {
		name     string
		args     args
		wantName string
		wantErr  bool
	}{
		{"ok", args{}, "MiniCA", false},
		{"ok with options", args{[]Option{WithName("Test"), WithGetSignerFunc(func() (crypto.Signer, error) {
			_, s, err := ed25519.GenerateKey(rand.Reader)
			return s, err
		})}}, "Test", false},
		{"fail root signer", args{[]Option{WithGetSignerFunc(failGetSigner(1))}}, "", true},
		{"fail intermediate signer", args{[]Option{WithGetSignerFunc(failGetSigner(2))}}, "", true},
		{"fail host signer", args{[]Option{WithGetSignerFunc(failGetSigner(3))}}, "", true},
		{"fail user signer", args{[]Option{WithGetSignerFunc(failGetSigner(4))}}, "", true},
		{"fail root template", args{[]Option{WithRootTemplate(`fail "foo"`)}}, "", true},
		{"fail intermediate template", args{[]Option{WithIntermediateTemplate(`fail "foo"`)}}, "", true},
		{"fail root csr", args{[]Option{WithGetSignerFunc(failSigner(1))}}, "", true},
		{"fail intermediate csr", args{[]Option{WithGetSignerFunc(failSigner(2))}}, "", true},
		{"fail host ssh signer", args{[]Option{WithGetSignerFunc(failSigner(3))}}, "", true},
		{"fail user ssh signer", args{[]Option{WithGetSignerFunc(failSigner(4))}}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if got != nil {
					t.Errorf("New() = %v, want nil", got)
				}
			} else {
				if got.Root == nil {
					t.Error("CA.Root should not be nil")
				}
				if got.Intermediate == nil {
					t.Error("CA.Intermediate should not be nil")
				}
				if got.Signer == nil {
					t.Error("CA.Signer should not be nil")
				}
				if got.SSHHostSigner == nil {
					t.Error("CA.SSHHostSigner should not be nil")
				}
				if got.SSHUserSigner == nil {
					t.Error("CA.SSHUserSigner should not be nil")
				}

				// Check common names
				if cn := got.Root.Subject.CommonName; cn != tt.wantName+" Root CA" {
					t.Errorf("CA.Root.Subject.CommonName = %s, want %s Root CA", cn, tt.wantName)
				}
				if cn := got.Root.Issuer.CommonName; cn != tt.wantName+" Root CA" {
					t.Errorf("CA.Root.Issuer.CommonName = %s, want %s Root CA", cn, tt.wantName)
				}
				if cn := got.Intermediate.Subject.CommonName; cn != tt.wantName+" Intermediate CA" {
					t.Errorf("CA.Intermediate.Subject.CommonName = %s, want %s Intermediate CA", cn, tt.wantName)
				}
				if cn := got.Intermediate.Issuer.CommonName; cn != tt.wantName+" Root CA" {
					t.Errorf("CA.Root.Intermediate.Issuer.CommonName = %s, want %s Root CA", cn, tt.wantName)
				}

				// Verify intermediate
				pool := x509.NewCertPool()
				pool.AddCert(got.Root)
				if _, err := got.Intermediate.Verify(x509.VerifyOptions{
					Roots: pool,
				}); err != nil {
					t.Errorf("CA.Intermediate.Verify() error = %v", err)
				}
			}
		})
	}
}

func TestCA_Sign(t *testing.T) {
	signer, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		template *x509.Certificate
	}
	tests := []struct {
		name    string
		ca      *CA
		args    args
		wantErr bool
	}{
		{"ok", mustCA(t), args{&x509.Certificate{
			DNSNames:  []string{"leaf.test.com"},
			PublicKey: signer.Public(),
		}}, false},
		{"ok with lifetime", mustCA(t), args{&x509.Certificate{
			DNSNames:  []string{"leaf.test.com"},
			PublicKey: signer.Public(),
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(1 * time.Hour),
		}}, false},
		{"fail", mustCA(t), args{&x509.Certificate{
			DNSNames:  []string{"leaf.test.com"},
			PublicKey: []byte("not a key"),
		}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ca.Sign(tt.args.template)
			if (err != nil) != tt.wantErr {
				t.Errorf("CA.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if got != nil {
					t.Errorf("CA.Sign() = %v, want nil", got)
				}
			} else {
				roots := x509.NewCertPool()
				roots.AddCert(tt.ca.Root)
				ints := x509.NewCertPool()
				ints.AddCert(tt.ca.Intermediate)

				if _, err := got.Verify(x509.VerifyOptions{
					Roots:         roots,
					Intermediates: ints,
					DNSName:       "leaf.test.com",
					KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
				}); err != nil {
					t.Errorf("Certificate.Verify() error = %v", err)
				}
			}
		})
	}
}

func TestCA_Sign_mutation(t *testing.T) {
	signer, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatal(err)
	}

	ca := mustCA(t)
	template := &x509.Certificate{
		DNSNames:  []string{"leaf.test.com"},
		PublicKey: signer.Public(),
	}
	got, err := ca.Sign(template)
	if err != nil {
		t.Fatal(err)
	}

	// Verify certificate
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	ints := x509.NewCertPool()
	ints.AddCert(ca.Intermediate)
	if _, err := got.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: ints,
		DNSName:       "leaf.test.com",
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("Certificate.Verify() error = %v", err)
	}

	// Check mutation
	if !template.NotBefore.IsZero() {
		t.Error("CA.Sign() mutated template.NotBefore")
	}
	if !template.NotAfter.IsZero() {
		t.Error("CA.Sign() mutated template.NotAfter")
	}
	if template.SerialNumber != nil {
		t.Error("CA.Sign() mutated template.SerialNumber")
	}
	if template.SubjectKeyId != nil {
		t.Error("CA.Sign() mutated template.SubjectKeyId")
	}

	if got.NotBefore.IsZero() {
		t.Error("CA.Sign() got.NotBefore should not be 0")
	}
	if got.NotAfter.IsZero() {
		t.Error("CA.Sign() got.NotAfter should not be 0")
	}
	if got.SerialNumber == nil {
		t.Error("CA.Sign() got.SerialNumber should not be nil")
	}
	if got.SubjectKeyId == nil {
		t.Error("CA.Sign() got.SubjectKeyId should not be nil")
	}
}

func TestCA_SignCSR(t *testing.T) {
	signer, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509util.CreateCertificateRequest("", []string{"leaf.test.com", "127.0.0.1", "test@test.com", "uuid:64757c7c-33b0-4125-9a73-be41e17f9f98"}, signer)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		csr  *x509.CertificateRequest
		opts []SignOption
	}
	tests := []struct {
		name          string
		ca            *CA
		args          args
		wantDNSName   string
		wantKeyUsages []x509.ExtKeyUsage
		wantErr       bool
	}{
		{"ok", mustCA(t), args{csr, nil}, "leaf.test.com", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, false},
		{"ok with modify", mustCA(t), args{csr, []SignOption{WithModifyFunc(func(cert *x509.Certificate) error {
			cert.DNSNames = []string{"foo.test.com"}
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
			return nil
		})}}, "foo.test.com", []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, false},
		{"fail new certificate", mustCA(t), args{&x509.CertificateRequest{}, nil}, "", nil, true},
		{"fail modify", mustCA(t), args{csr, []SignOption{WithModifyFunc(func(cert *x509.Certificate) error {
			return errors.New("an error")
		})}}, "", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ca.SignCSR(tt.args.csr, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("CA.SignCSR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if got != nil {
					t.Errorf("CA.Sign() = %v, want nil", got)
				}
			} else {
				roots := x509.NewCertPool()
				roots.AddCert(tt.ca.Root)
				ints := x509.NewCertPool()
				ints.AddCert(tt.ca.Intermediate)

				if _, err := got.Verify(x509.VerifyOptions{
					Roots:         roots,
					Intermediates: ints,
					DNSName:       tt.wantDNSName,
					KeyUsages:     tt.wantKeyUsages,
				}); err != nil {
					t.Errorf("Certificate.Verify() error = %v", err)
				}
			}
		})
	}
}

func TestCA_SignSSH(t *testing.T) {
	signer, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		cert *ssh.Certificate
	}
	tests := []struct {
		name          string
		ca            *CA
		args          args
		wantCertType  uint32
		wantPrincipal string
		wantErr       bool
	}{
		{"ok host", mustCA(t), args{&ssh.Certificate{
			Key:             publicKey,
			Serial:          1234,
			CertType:        ssh.HostCert,
			KeyId:           "ssh.test.com",
			ValidPrincipals: []string{"ssh.test.com"},
		}}, ssh.HostCert, "ssh.test.com", false},
		{"ok user", mustCA(t), args{&ssh.Certificate{
			Key:             publicKey,
			Serial:          1234,
			CertType:        ssh.UserCert,
			KeyId:           "jane@test.com",
			ValidPrincipals: []string{"jane"},
			ValidAfter:      uint64(time.Now().Unix()),
			ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		}}, ssh.UserCert, "jane", false},
		{"ok infinity", mustCA(t), args{&ssh.Certificate{
			Key:             publicKey,
			Serial:          1234,
			CertType:        ssh.UserCert,
			KeyId:           "jane@test.com",
			ValidPrincipals: []string{"jane"},
			ValidBefore:     ssh.CertTimeInfinity,
		}}, ssh.UserCert, "jane", false},
		{"fail type", mustCA(t), args{&ssh.Certificate{
			Key:             publicKey,
			Serial:          1234,
			CertType:        100,
			KeyId:           "jane@test.com",
			ValidPrincipals: []string{"jane"},
		}}, 0, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ca.SignSSH(tt.args.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("CA.SignSSH() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if got != nil {
					t.Errorf("CA.SignSSH() = %v, want nil", got)
				}
			} else {
				checker := ssh.CertChecker{
					IsUserAuthority: func(auth ssh.PublicKey) bool {
						return reflect.DeepEqual(auth, tt.ca.SSHUserSigner.PublicKey())
					},
					IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
						return reflect.DeepEqual(auth, tt.ca.SSHHostSigner.PublicKey())
					},
				}
				switch tt.wantCertType {
				case ssh.HostCert:
					if err := checker.CheckHostKey(tt.wantPrincipal+":22", &net.IPAddr{IP: net.IP{1, 2, 3, 4}}, got); err != nil {
						t.Errorf("CertChecker.CheckHostKey() error = %v", err)
					}
				case ssh.UserCert:
					if _, err := checker.Authenticate(mockConnMetadata(tt.wantPrincipal), got); err != nil {
						t.Errorf("CertChecker.Authenticate() error = %v", err)
					}
				default:
					t.Fatalf("unknown cert type %v", tt.wantCertType)
				}
			}
		})
	}
}

func TestCA_SignSSH_mutation(t *testing.T) {
	signer, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}

	template := &ssh.Certificate{
		Key:             publicKey,
		CertType:        ssh.HostCert,
		KeyId:           "ssh.test.com",
		ValidPrincipals: []string{"ssh.test.com"},
	}

	ca := mustCA(t)
	got, err := ca.SignSSH(template)
	if err != nil {
		t.Fatal(err)
	}

	// Validate certificate
	checker := ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
			return reflect.DeepEqual(auth, ca.SSHHostSigner.PublicKey())
		},
	}
	if err := checker.CheckHostKey("ssh.test.com:22", &net.IPAddr{IP: net.IP{1, 2, 3, 4}}, got); err != nil {
		t.Errorf("CertChecker.CheckHostKey() error = %v", err)
	}

	// Validate mutation
	if template.ValidAfter != 0 {
		t.Error("CA.SignSSH() mutated template.ValidAfter")
	}
	if template.ValidBefore != 0 {
		t.Error("CA.SignSSH() mutated template.ValidBefore")
	}
	if template.Nonce != nil {
		t.Error("CA.SignSSH() mutated template.Nonce")
	}
	if template.Serial != 0 {
		t.Error("CA.SignSSH() mutated template.Serial")
	}

	if got.ValidAfter == 0 {
		t.Error("CA.SignSSH() got.ValidAfter should not be 0")
	}
	if got.ValidBefore == 0 {
		t.Error("CA.SignSSH() got.ValidBefore should not be 0")
	}
	if len(got.Nonce) == 0 {
		t.Error("CA.SignSSH() got.Nonce should not be empty")
	}
	if got.Serial == 0 {
		t.Error("CA.SignSSH() got.Serial should not be 0")
	}
}

func TestCA_SignSSH_infinity(t *testing.T) {
	signer, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}

	template := &ssh.Certificate{
		Key:             publicKey,
		Serial:          1234,
		CertType:        ssh.UserCert,
		KeyId:           "jane@test.com",
		ValidPrincipals: []string{"jane"},
		ValidBefore:     ssh.CertTimeInfinity,
	}

	ca := mustCA(t)
	got, err := ca.SignSSH(template)
	if err != nil {
		t.Fatal(err)
	}

	// Validate certificate
	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return reflect.DeepEqual(auth, ca.SSHUserSigner.PublicKey())
		},
	}
	if _, err := checker.Authenticate(mockConnMetadata("jane"), got); err != nil {
		t.Errorf("CertChecker.Authenticate() error = %v", err)
	}

	if got.ValidAfter != 0 {
		t.Error("CA.SignSSH() got.ValidAfter should be 0")
	}
	if got.ValidBefore != ssh.CertTimeInfinity {
		t.Error("CA.SignSSH() got.ValidBefore should not be ssh.CertTimInfinity")
	}
}
