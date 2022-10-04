package x509util

import (
	"crypto/x509"
	"testing"
)

func TestFingerprint(t *testing.T) {
	ecdsaCrt := decodeCertificateFile(t, "testdata/google.crt")
	rsaCrt := decodeCertificateFile(t, "testdata/smallstep.crt")
	ed25519Crt := decodeCertificateFile(t, "testdata/ed25519.crt")

	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"ecdsaCert", args{ecdsaCrt}, "38011621ecdcc2172e933a1ef2317efc535a161c00333aee3f84abfab4e640bf"},
		{"rsaCert", args{rsaCrt}, "5eeaf6dd1d1f064f6f95c5d74c39ad0abca33bdba59d2844d0b5e6d8453f6c4b"},
		{"ed25519Cert", args{ed25519Crt}, "047b2fff20997a5009d1b36864af95b03f168c09dc2ed1a71ee36ccf973c9d31"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Fingerprint(tt.args.cert); got != tt.want {
				t.Errorf("Fingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncodedFingerprint(t *testing.T) {
	ecdsaCrt := decodeCertificateFile(t, "testdata/google.crt")

	type args struct {
		cert     *x509.Certificate
		encoding FingerprintEncoding
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"default", args{ecdsaCrt, 0}, "38011621ecdcc2172e933a1ef2317efc535a161c00333aee3f84abfab4e640bf"},
		{"HexFingerprint", args{ecdsaCrt, HexFingerprint}, "38011621ecdcc2172e933a1ef2317efc535a161c00333aee3f84abfab4e640bf"},
		{"Base64Fingerprint", args{ecdsaCrt, Base64Fingerprint}, "OAEWIezcwhcukzoe8jF+/FNaFhwAMzruP4Sr+rTmQL8="},
		{"Base64URLFingerprint", args{ecdsaCrt, Base64URLFingerprint}, "OAEWIezcwhcukzoe8jF-_FNaFhwAMzruP4Sr-rTmQL8="},
		{"Base64RawFingerprint", args{ecdsaCrt, Base64RawFingerprint}, "OAEWIezcwhcukzoe8jF+/FNaFhwAMzruP4Sr+rTmQL8"},
		{"Base64RawURLFingerprint", args{ecdsaCrt, Base64RawURLFingerprint}, "OAEWIezcwhcukzoe8jF-_FNaFhwAMzruP4Sr-rTmQL8"},
		{"EmojiFingerprint", args{ecdsaCrt, EmojiFingerprint}, "💨🎱🌼📆🎠🎉🎿🚙🍪🌊♦️💡✌️🐮🔒❌🖕😬🌼👦👍👑♦️🇬🇧👂🔬📌♿🚀🚜🍆🐑"},
		{"Unknown", args{ecdsaCrt, 100}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EncodedFingerprint(tt.args.cert, tt.args.encoding); got != tt.want {
				t.Errorf("EncodedFingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}
