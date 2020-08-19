// Code generated (comment to force golint to ignore this file). DO NOT EDIT.

package jose

import (
	"reflect"
	"testing"
	"time"

	"github.com/pkg/errors"
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
		{"RSA", args{mustGenerateJWK(t, "RSA", "", "RS256", "sig", "", 1024)}, false},
		{"RSA", args{mustGenerateJWK(t, "RSA", "", "PS256", "enc", "", 1024)}, false},
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
		{"RSA", args{mustGenerateJWK(t, "RSA", "", "RS256", "sig", "", 1024)}, true},
		{"RSA", args{mustGenerateJWK(t, "RSA", "", "PS256", "enc", "", 1024)}, true},
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
		{"trim", args{errors.New("square/go-jose: an error")}, errors.New("an error")},
		{"no trim", args{errors.New("json: an error")}, errors.New("json: an error")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := TrimPrefix(tt.args.err); !reflect.DeepEqual(err, tt.wantErr) && err.Error() != tt.wantErr.Error() {
				t.Errorf("TrimPrefix() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
