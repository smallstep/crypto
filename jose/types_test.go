package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
	"time"

	"github.com/pkg/errors"
	"go.step.sm/crypto/x25519"
)

func TestNumericDate(t *testing.T) {
	now := time.Now()

	// NewNumericDate
	wantNumericDate := NumericDate(now.Unix())
	if got := NewNumericDate(now); !reflect.DeepEqual(got, &wantNumericDate) {
		t.Errorf("NewNumericDate() = %v, want %v", got, &wantNumericDate)
	}
	if got := NewNumericDate(time.Time{}); !reflect.DeepEqual(got, (*NumericDate)(nil)) {
		t.Errorf("NewNumericDate() = %v, want %v", got, nil)
	}

	// UnixNumericDate
	if got := UnixNumericDate(now.Unix()); !reflect.DeepEqual(got, &wantNumericDate) {
		t.Errorf("UnixNumericDate() = %v, want %v", got, &wantNumericDate)
	}
	if got := UnixNumericDate(0); !reflect.DeepEqual(got, (*NumericDate)(nil)) {
		t.Errorf("UnixNumericDate() = %v, want %v", got, nil)
	}
}

func TestIsSymmetric(t *testing.T) {
	type args struct {
		k *JSONWebKey
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"EC", args{mustGenerateJWK(t, "EC", "P-256", "ES256", "enc", "", 0)}, false},
		{"RSA", args{mustGenerateJWK(t, "RSA", "", "RS256", "sig", "", 2048)}, false},
		{"RSA", args{mustGenerateJWK(t, "RSA", "", "PS256", "enc", "", 2048)}, false},
		{"OKP", args{mustGenerateJWK(t, "OKP", "Ed25519", "EdDSA", "sig", "", 0)}, false},
		{"oct", args{mustGenerateJWK(t, "oct", "", "HS256", "sig", "", 64)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSymmetric(tt.args.k); got != tt.want {
				t.Errorf("IsSymmetric() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsAsymmetric(t *testing.T) {
	type args struct {
		k *JSONWebKey
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"EC", args{mustGenerateJWK(t, "EC", "P-256", "ES256", "enc", "", 0)}, true},
		{"RSA", args{mustGenerateJWK(t, "RSA", "", "RS256", "sig", "", 2048)}, true},
		{"RSA", args{mustGenerateJWK(t, "RSA", "", "PS256", "enc", "", 2048)}, true},
		{"OKP", args{mustGenerateJWK(t, "OKP", "Ed25519", "EdDSA", "sig", "", 0)}, true},
		{"oct", args{mustGenerateJWK(t, "oct", "", "HS256", "sig", "", 64)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAsymmetric(tt.args.k); got != tt.want {
				t.Errorf("IsAsymmetric() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrimPrefix(t *testing.T) {
	type args struct {
		err error
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{"nil", args{nil}, nil},
		{"trim", args{errors.New("go-jose/go-jose: an error")}, errors.New("an error")},
		{"no trim", args{errors.New("json: an error")}, errors.New("json: an error")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := TrimPrefix(tt.args.err); !reflect.DeepEqual(err, tt.wantErr) && err.Error() != tt.wantErr.Error() { //nolint:govet // variable names match crypto formulae docs
				t.Errorf("TrimPrefix() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignVerify(t *testing.T) {
	must := func(args ...interface{}) crypto.Signer {
		last := len(args) - 1
		if err := args[last]; err != nil {
			t.Fatal(err)
		}
		return args[last-1].(crypto.Signer)
	}

	p224 := must(ecdsa.GenerateKey(elliptic.P224(), rand.Reader))
	p256 := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	p384 := must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	p521 := must(ecdsa.GenerateKey(elliptic.P521(), rand.Reader))
	rsa2048 := must(rsa.GenerateKey(rand.Reader, 2048))
	edKey := must(ed25519.GenerateKey(rand.Reader))
	xKey := must(x25519.GenerateKey(rand.Reader))

	type args struct {
		sig  SigningKey
		opts *SignerOptions
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"byte", args{SigningKey{Key: []byte("the-key")}, nil}, false},
		{"P256", args{SigningKey{Key: p256}, nil}, false},
		{"P384", args{SigningKey{Key: p384}, nil}, false},
		{"P521", args{SigningKey{Key: p521}, nil}, false},
		{"rsa2048", args{SigningKey{Key: rsa2048}, nil}, false},
		{"ed", args{SigningKey{Key: edKey}, nil}, false},
		{"x25519", args{SigningKey{Key: xKey}, nil}, false},
		{"signer", args{SigningKey{Key: wrapSigner{edKey}}, nil}, false},
		{"opaque", args{SigningKey{Key: NewOpaqueSigner(edKey)}, nil}, false},
		{"fail P224", args{SigningKey{Key: p224}, nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSigner(tt.args.sig, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				payload := []byte(`{"sub": "sub"}`)
				jws, err := got.Sign(payload)
				if err != nil {
					t.Errorf("Signer.Sign() error = %v", err)
					return
				}
				jwt, err := ParseSigned(jws.FullSerialize())
				if err != nil {
					t.Errorf("ParseSigned() error = %v", err)
					return
				}

				var claims Claims
				switch k := tt.args.sig.Key.(type) {
				case crypto.Signer:
					err = Verify(jwt, k.Public(), &claims)
				case OpaqueSigner:
					err = Verify(jwt, k.Public(), &claims)
				default:
					err = Verify(jwt, k, &claims)
				}
				if err != nil {
					t.Errorf("JSONWebSignature.Verify() error = %v", err)
					return
				}
				want := Claims{Subject: "sub"}
				if !reflect.DeepEqual(claims, want) {
					t.Errorf("JSONWebSignature.Verify() claims = %v, want %v", claims, want)
				}
			}
		})
	}
}
