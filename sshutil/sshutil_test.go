package sshutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"reflect"
	"testing"

	"go.step.sm/crypto/keyutil"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type skKey struct {
	typ   string
	bytes []byte
}

func (s *skKey) Type() string                                 { return s.typ }
func (s *skKey) Marshal() []byte                              { return s.bytes }
func (s *skKey) Verify(data []byte, sig *ssh.Signature) error { return nil }

func generateKey(t *testing.T, kty, crv string, size int) (crypto.PublicKey, ssh.PublicKey) {
	t.Helper()
	signer, err := keyutil.GenerateSigner(kty, crv, size)
	if err != nil {
		t.Fatal(err)
	}
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	return signer.Public(), sshSigner.PublicKey()
}

func generateFakeSKKey(t *testing.T, pub crypto.PublicKey) ssh.PublicKey {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		w := struct {
			Name        string
			ID          string
			Key         []byte
			Application string
		}{"name", "id", elliptic.Marshal(k.Curve, k.X, k.Y), "ssh"}
		return &skKey{
			typ:   "sk-ecdsa-sha2-nistp256@openssh.com",
			bytes: ssh.Marshal(w),
		}
	case ed25519.PublicKey:
		w := struct {
			Name        string
			KeyBytes    []byte
			Application string
		}{"name", []byte(k), "ssh"}
		return &skKey{
			typ:   "sk-ssh-ed25519@openssh.com",
			bytes: ssh.Marshal(w),
		}
	default:
		t.Fatalf("unsupported public key type %T", k)
		return nil
	}
}

func TestCryptoPublicKey(t *testing.T) {
	ecKey, sshECKey := generateKey(t, "EC", "P-256", 0)
	edKey, sshEDKey := generateKey(t, "OKP", "Ed25519", 0)
	rsaKey, sshRSAKey := generateKey(t, "RSA", "", 2048)

	skECKey := generateFakeSKKey(t, ecKey)
	skEDKey := generateFakeSKKey(t, edKey)

	type args struct {
		pub interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{"ok ec", args{ecKey}, ecKey, false},
		{"ok Ed25519", args{edKey}, edKey, false},
		{"ok rsa", args{rsaKey}, rsaKey, false},
		{"ok ssh ec", args{sshECKey}, ecKey, false},
		{"ok ssh Ed25519", args{sshEDKey}, edKey, false},
		{"ok ssh rsa", args{sshRSAKey}, rsaKey, false},
		{"ok agent", args{&agent.Key{Blob: sshECKey.Marshal()}}, ecKey, false},
		{"ok sk ec", args{skECKey}, ecKey, false},
		{"ok sk Ed25519", args{skEDKey}, edKey, false},
		{"fail agent", args{&agent.Key{Blob: []byte("foobar")}}, nil, true},
		{"fail type", args{"not a key"}, nil, true},
		{"fail sk", args{&skKey{typ: "foo"}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CryptoPublicKey(tt.args.pub)
			if (err != nil) != tt.wantErr {
				t.Errorf("CryptoPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CryptoPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
