package pemutil

import (
	"crypto"
	"encoding/pem"
	"os"
	"reflect"
	"testing"
)

func mustRead(t *testing.T, filename string) crypto.PublicKey {
	t.Helper()

	key, err := Read(filename)
	if err != nil {
		t.Fatalf("error parsing %s: %v", filename, err)
	}
	return key
}

func mustDecode(t *testing.T, filename string) []byte {
	t.Helper()

	b, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("error decoding %s: failed to parse pem", filename)
	}
	return block.Bytes
}

func TestMarshalPKIXPublicKey(t *testing.T) {
	type args struct {
		pub crypto.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"p256", args{mustRead(t, "testdata/openssl.p256.pub.pem")}, mustDecode(t, "testdata/openssl.p256.pub.pem"), false},
		{"rsa2048", args{mustRead(t, "testdata/openssl.rsa2048.pub.pem")}, mustDecode(t, "testdata/openssl.rsa2048.pub.pem"), false},
		{"ed25519", args{mustRead(t, "testdata/pkcs8/openssl.ed25519.pub.pem")}, mustDecode(t, "testdata/pkcs8/openssl.ed25519.pub.pem"), false},
		{"fail", args{"not a key"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MarshalPKIXPublicKey(tt.args.pub)
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalPKIXPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MarshalPKIXPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMarshalPKCS8PrivateKey(t *testing.T) {
	type args struct {
		key crypto.PrivateKey
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"p256", args{mustRead(t, "testdata/pkcs8/openssl.p256.pem")}, mustDecode(t, "testdata/pkcs8/openssl.p256.pem"), false},
		{"rsa2048", args{mustRead(t, "testdata/pkcs8/openssl.rsa2048.pem")}, mustDecode(t, "testdata/pkcs8/openssl.rsa2048.pem"), false},
		{"ed25519", args{mustRead(t, "testdata/pkcs8/openssl.ed25519.pem")}, mustDecode(t, "testdata/pkcs8/openssl.ed25519.pem"), false},
		{"fail", args{"not a key"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MarshalPKCS8PrivateKey(tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalPKCS8PrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MarshalPKCS8PrivateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
