package keyutil

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func readPublicKey(t *testing.T, filename string) crypto.PublicKey {
	t.Helper()
	b, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("error decoding pem")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestFingerprint(t *testing.T) {
	ecdsaKey := readPublicKey(t, "testdata/p256.pub")
	rsaKey := readPublicKey(t, "testdata/rsa.pub")
	ed25519Key := readPublicKey(t, "testdata/ed25519.pub")

	type args struct {
		pub crypto.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"ecdsa", args{ecdsaKey}, "SHA256:BlA/0e0DGQ8Gcpv+EPNDp3aa8O4TZ6VDLKMIXi40qlE=", false},
		{"rsa", args{rsaKey}, "SHA256:Su5MWuU91vpyPy2YlX7lqTXomZ1AoGqKbvbZbf0Ff6M=", false},
		{"ed25519", args{ed25519Key}, "SHA256:r/tA+Uv4M2ff1ZrAz8l+5mu0aJ1yOGwnWV5jDotBySI=", false},
		{"fail", args{[]byte("not a key")}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Fingerprint(tt.args.pub)
			if (err != nil) != tt.wantErr {
				t.Errorf("Fingerprint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Fingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncodedFingerprint(t *testing.T) {
	ecdsaKey := readPublicKey(t, "testdata/p256.pub")
	rsaKey := readPublicKey(t, "testdata/rsa.pub")
	ed25519Key := readPublicKey(t, "testdata/ed25519.pub")

	type args struct {
		pub      crypto.PublicKey
		encoding FingerprintEncoding
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"ecdsa", args{ecdsaKey, DefaultFingerprint}, "SHA256:BlA/0e0DGQ8Gcpv+EPNDp3aa8O4TZ6VDLKMIXi40qlE=", false},
		{"rsa", args{rsaKey, HexFingerprint}, "SHA256:4aee4c5ae53dd6fa723f2d98957ee5a935e8999d40a06a8a6ef6d96dfd057fa3", false},
		{"ed25519", args{ed25519Key, Base64RawURLFingerprint}, "SHA256:r_tA-Uv4M2ff1ZrAz8l-5mu0aJ1yOGwnWV5jDotBySI", false},
		{"fail", args{[]byte("not a key"), DefaultFingerprint}, "", true},
		{"fail bad encoding", args{ed25519Key, 100}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodedFingerprint(tt.args.pub, tt.args.encoding)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodedFingerprint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("EncodedFingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}
