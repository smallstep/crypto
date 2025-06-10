package sshutil

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // support for DSA fingerprints
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/internal/emoji"
	"golang.org/x/crypto/ssh"
)

func generateCertificate(t *testing.T) ssh.PublicKey {
	t.Helper()
	key, signer := mustGenerateKey(t)

	cert, err := CreateCertificate(&ssh.Certificate{
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
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestFingerprint(t *testing.T) {
	ecKey, sshECKey := generateKey(t, "EC", "P-256", 0)
	edKey, sshEDKey := generateKey(t, "OKP", "Ed25519", 0)
	_, sshRSAKey := generateKey(t, "RSA", "", 2048)

	skECKey := generateFakeSKKey(t, ecKey)
	skEDKey := generateFakeSKKey(t, edKey)
	sshCert := generateCertificate(t)

	type args struct {
		pub ssh.PublicKey
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"ok ECDSA", args{sshECKey}, ssh.FingerprintSHA256(sshECKey)},
		{"ok ED25519", args{sshEDKey}, ssh.FingerprintSHA256(sshEDKey)},
		{"ok RSA", args{sshRSAKey}, ssh.FingerprintSHA256(sshRSAKey)},
		{"ok SK-ECDSA", args{skECKey}, ssh.FingerprintSHA256(skECKey)},
		{"ok SK-ED25519", args{skEDKey}, ssh.FingerprintSHA256(skEDKey)},
		{"ok CERT", args{sshCert}, ssh.FingerprintSHA256(sshCert)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Fingerprint(tt.args.pub); got != tt.want {
				t.Errorf("Fingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncodedFingerprint(t *testing.T) {
	_, sshECKey := generateKey(t, "EC", "P-256", 0)

	expected := ssh.FingerprintSHA256(sshECKey)
	b, err := base64.RawStdEncoding.DecodeString(expected[7:])
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		pub      ssh.PublicKey
		encoding FingerprintEncoding
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"default", args{sshECKey, 0}, ssh.FingerprintSHA256(sshECKey)},
		{"Base64RawFingerprint", args{sshECKey, Base64RawFingerprint}, expected},
		{"Base64RawURLFingerprint", args{sshECKey, Base64RawURLFingerprint}, "SHA256:" + base64.RawURLEncoding.EncodeToString(b)},
		{"Base64Fingerprint", args{sshECKey, Base64Fingerprint}, "SHA256:" + base64.StdEncoding.EncodeToString(b)},
		{"Base64URLFingerprint", args{sshECKey, Base64URLFingerprint}, "SHA256:" + base64.URLEncoding.EncodeToString(b)},
		{"HexFingerprint", args{sshECKey, HexFingerprint}, "SHA256:" + hex.EncodeToString(b)},
		{"EmojiFingerprint", args{sshECKey, EmojiFingerprint}, "SHA256:" + emoji.Emoji(b)},
		{"fail", args{sshECKey, 100}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EncodedFingerprint(tt.args.pub, tt.args.encoding); got != tt.want {
				t.Errorf("EncodedFingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func marshal(t *testing.T, pub ssh.PublicKey, comment string) []byte {
	t.Helper()
	b := &bytes.Buffer{}
	_, err := b.WriteString(pub.Type())
	require.NoError(t, err)
	err = b.WriteByte(' ')
	require.NoError(t, err)
	e := base64.NewEncoder(base64.StdEncoding, b)
	_, err = e.Write(pub.Marshal())
	require.NoError(t, err)
	err = e.Close()
	require.NoError(t, err)
	if comment != "" {
		_, err = b.WriteString(" " + comment)
		require.NoError(t, err)
	}
	err = b.WriteByte('\n')
	require.NoError(t, err)
	return b.Bytes()
}

const (
	fixtureECDSACertificate = `ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgLnkvSk4odlo3b1R+RDw+LmorL3RkN354IilCIVFVen4AAAAIbmlzdHAyNTYAAABBBHjKHss8WM2ffMYlavisoLXR0I6UEIU+cidV1ogEH1U6+/SYaFPrlzQo0tGLM5CNkMbhInbyasQsrHzn8F1Rt7nHg5/tcSf9qwAAAAEAAAAGaGVybWFuAAAACgAAAAZoZXJtYW4AAAAAY8kvJwAAAABjyhBjAAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAEEE/ayqpPrZZF5uA1UlDt4FreTf15agztQIzpxnWq/XoxAHzagRSkFGkdgFpjgsfiRpP8URHH3BZScqc0ZDCTxhoQAAAGQAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAEkAAAAhAJuP1wCVwoyrKrEtHGfFXrVbRHySDjvXtS1tVTdHyqymAAAAIBa/CSSzfZb4D2NLP+eEmOOMJwSjYOiNM8fiOoAaqglI herman`
)

func TestFormatFingerprint(t *testing.T) {
	ecKey, sshECKey := generateKey(t, "EC", "P-256", 0)
	_, sshEC384Key := generateKey(t, "EC", "P-384", 0)
	_, sshEC521Key := generateKey(t, "EC", "P-521", 0)
	edKey, sshEDKey := generateKey(t, "OKP", "Ed25519", 0)
	_, sshRSAKey := generateKey(t, "RSA", "", 2048)

	skECKey := generateFakeSKKey(t, ecKey)
	skEDKey := generateFakeSKKey(t, edKey)
	sshCert := generateCertificate(t)
	sshCertPublicKey := sshCert.(*ssh.Certificate).Key

	dsaKey := new(dsa.PrivateKey)
	if err := dsa.GenerateParameters(&dsaKey.Parameters, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	if err := dsa.GenerateKey(dsaKey, rand.Reader); err != nil {
		t.Fatal(err)
	}
	dsaSigner, err := ssh.NewSignerFromKey(dsaKey)
	if err != nil {
		t.Fatal(err)
	}
	sshDSAKey := dsaSigner.PublicKey()

	ec256Bytes, err := base64.RawStdEncoding.DecodeString(ssh.FingerprintSHA256(sshECKey)[7:])
	if err != nil {
		t.Fatal(err)
	}
	type args struct {
		in       []byte
		encoding FingerprintEncoding
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"P256", args{marshal(t, sshECKey, "jane@example.com"), 0}, "256 " + ssh.FingerprintSHA256(sshECKey) + " jane@example.com (ECDSA)", false},
		{"P384", args{marshal(t, sshEC384Key, "jane@example.com"), 0}, "384 " + ssh.FingerprintSHA256(sshEC384Key) + " jane@example.com (ECDSA)", false},
		{"P521", args{marshal(t, sshEC521Key, "jane@example.com"), 0}, "521 " + ssh.FingerprintSHA256(sshEC521Key) + " jane@example.com (ECDSA)", false},
		{"Ed25519", args{marshal(t, sshEDKey, "jane@example.com"), 0}, "256 " + ssh.FingerprintSHA256(sshEDKey) + " jane@example.com (ED25519)", false},
		{"RSA", args{marshal(t, sshRSAKey, "jane@example.com"), 0}, "2048 " + ssh.FingerprintSHA256(sshRSAKey) + " jane@example.com (RSA)", false},
		{"SK-ECDSA", args{marshal(t, skECKey, "jane@example.com"), 0}, "256 " + ssh.FingerprintSHA256(skECKey) + " jane@example.com (SK-ECDSA)", false},
		{"SK-ED25519", args{marshal(t, skEDKey, "jane@example.com"), 0}, "256 " + ssh.FingerprintSHA256(skEDKey) + " jane@example.com (SK-ED25519)", false},
		{"ED25519-CERT", args{marshal(t, sshCert, "jane@example.com"), 0}, "256 " + ssh.FingerprintSHA256(sshCertPublicKey) + " jane@example.com (ED25519-CERT)", false},
		{"ECDSA-CERT (fixture)", args{[]byte(fixtureECDSACertificate), DefaultFingerprint}, "256 SHA256:RvkDPGwl/G9d7LUFm1kmWhvOD9I/moPq4yxcb0STwr0 herman (ECDSA-CERT)", false},
		{"DSA", args{marshal(t, sshDSAKey, "jane@example.com"), 0}, "1024 " + ssh.FingerprintSHA256(sshDSAKey) + " jane@example.com (DSA)", false},
		{"Base64RawFingerprint", args{marshal(t, sshECKey, ""), Base64RawFingerprint}, "256 " + ssh.FingerprintSHA256(sshECKey) + " no comment (ECDSA)", false},
		{"Base64RawURLFingerprint", args{marshal(t, sshECKey, ""), Base64RawURLFingerprint}, "256 SHA256:" + base64.RawURLEncoding.EncodeToString(ec256Bytes) + " no comment (ECDSA)", false},
		{"Base64Fingerprint", args{marshal(t, sshECKey, ""), Base64Fingerprint}, "256 SHA256:" + base64.StdEncoding.EncodeToString(ec256Bytes) + " no comment (ECDSA)", false},
		{"Base64UrlFingerprint", args{marshal(t, sshECKey, ""), Base64URLFingerprint}, "256 SHA256:" + base64.URLEncoding.EncodeToString(ec256Bytes) + " no comment (ECDSA)", false},
		{"HexFingerprint", args{marshal(t, sshECKey, ""), HexFingerprint}, "256 SHA256:" + hex.EncodeToString(ec256Bytes) + " no comment (ECDSA)", false},
		{"EmojiFingerprint", args{marshal(t, sshECKey, ""), EmojiFingerprint}, "256 SHA256:" + emoji.Emoji(ec256Bytes) + " no comment (ECDSA)", false},
		{"fail input", args{marshal(t, sshECKey, "")[:50], EmojiFingerprint}, "", true},
		{"fail encoding", args{marshal(t, sshECKey, ""), 100}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FormatFingerprint(tt.args.in, tt.args.encoding)
			if (err != nil) != tt.wantErr {
				t.Errorf("FormatFingerprint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("FormatFingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatCertificateFingerprint(t *testing.T) {
	ecKey, sshECKey := generateKey(t, "EC", "P-256", 0)
	_ = ecKey
	type args struct {
		in       []byte
		encoding FingerprintEncoding
	}
	tests := []struct {
		name   string
		args   args
		want   string
		expErr error
	}{
		{"P256", args{marshal(t, sshECKey, "jane@example.com"), 0}, "256 " + ssh.FingerprintSHA256(sshECKey) + " jane@example.com (ECDSA)", errors.New("cannot fingerprint SSH key as SSH certificate")},
		{"ECDSA-CERT (fixture)", args{[]byte(fixtureECDSACertificate), DefaultFingerprint}, "256 SHA256:YuV7pyvW7Jp4iEwddOsMw+EdugrhKGqOKh6o+PP0xeg herman (ECDSA-CERT)", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FormatCertificateFingerprint(tt.args.in, tt.args.encoding)
			if tt.expErr != nil {
				assert.EqualError(t, err, tt.expErr.Error())
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

type fakeKey struct {
	typ   string
	bytes []byte
}

func (s *fakeKey) Type() string                                 { return s.typ }
func (s *fakeKey) Marshal() []byte                              { return s.bytes }
func (s *fakeKey) Verify(data []byte, sig *ssh.Signature) error { return nil }

type fakeCryptoPublicKey struct {
	typ   string
	key   crypto.PublicKey
	bytes []byte
}

func (s *fakeCryptoPublicKey) Type() string                                 { return s.typ }
func (s *fakeCryptoPublicKey) Marshal() []byte                              { return s.bytes }
func (s *fakeCryptoPublicKey) Verify(data []byte, sig *ssh.Signature) error { return nil }
func (s *fakeCryptoPublicKey) CryptoPublicKey() crypto.PublicKey            { return s.key }

func Test_publicKeyTypeAndSize_errors(t *testing.T) {
	ecKey, _ := generateKey(t, "EC", "P-256", 0)

	type args struct {
		key ssh.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   int
		wantErr bool
	}{
		{"fail RSA", args{&fakeKey{ssh.KeyAlgoRSA, nil}}, "", 0, true},
		{"fail DSA", args{&fakeKey{ssh.InsecureKeyAlgoDSA, nil}}, "", 0, true}, //nolint:staticcheck // just using the constant; no dependent logic
		{"fail RSA cast", args{&fakeCryptoPublicKey{ssh.KeyAlgoRSA, ecKey, nil}}, "", 0, true},
		{"fail DSA cast", args{&fakeCryptoPublicKey{ssh.InsecureKeyAlgoDSA, ecKey, nil}}, "", 0, true}, //nolint:staticcheck // just using the constant; no dependent logic
		{"fail type", args{&fakeKey{"unknown-type", nil}}, "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := publicKeyTypeAndSize(tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("publicKeyTypeAndSize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("publicKeyTypeAndSize() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("publicKeyTypeAndSize() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
