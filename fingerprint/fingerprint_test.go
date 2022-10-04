package fingerprint

import (
	"crypto"
	"errors"
	"hash"
	"testing"
)

type failHash struct{}

func (h failHash) Write(b []byte) (int, error) {
	return 0, errors.New("failed to write")
}
func (h failHash) Sum(b []byte) []byte { return nil }
func (h failHash) Reset()              {}
func (h failHash) Size() int           { return 32 }
func (h failHash) BlockSize() int      { return 32 }

func TestNew(t *testing.T) {
	data := []byte(`Lorem ipsum dolor sit amet`)
	// This overwrites MD4 with failHash
	crypto.RegisterHash(1, func() hash.Hash {
		return failHash{}
	})
	type args struct {
		data     []byte
		h        crypto.Hash
		encoding Encoding
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"sha256", args{data, crypto.SHA256, HexFingerprint}, "16aba5393ad72c0041f5600ad3c2c52ec437a2f0c7fc08fadfc3c0fe9641d7a3", false},
		{"unavailable", args{data, crypto.Hash(1000), HexFingerprint}, "", true},
		{"fail encoding", args{data, crypto.SHA256, Encoding(1000)}, "", true},
		{"fail write", args{data, crypto.Hash(1), HexFingerprint}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.data, tt.args.h, tt.args.encoding)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFingerprint(t *testing.T) {
	digest := []byte{
		0x38, 0x01, 0x16, 0x21, 0xec, 0xdc, 0xc2, 0x17,
		0x2e, 0x93, 0x3a, 0x1e, 0xf2, 0x31, 0x7e, 0xfc,
		0x53, 0x5a, 0x16, 0x1c, 0x00, 0x33, 0x3a, 0xee,
		0x3f, 0x84, 0xab, 0xfa, 0xb4, 0xe6, 0x40, 0xbf,
	}
	type args struct {
		digest   []byte
		encoding Encoding
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"HexFingerprint", args{digest, HexFingerprint}, "38011621ecdcc2172e933a1ef2317efc535a161c00333aee3f84abfab4e640bf"},
		{"Base64Fingerprint", args{digest, Base64Fingerprint}, "OAEWIezcwhcukzoe8jF+/FNaFhwAMzruP4Sr+rTmQL8="},
		{"Base64URLFingerprint", args{digest, Base64URLFingerprint}, "OAEWIezcwhcukzoe8jF-_FNaFhwAMzruP4Sr-rTmQL8="},
		{"Base64RawFingerprint", args{digest, Base64RawFingerprint}, "OAEWIezcwhcukzoe8jF+/FNaFhwAMzruP4Sr+rTmQL8"},
		{"Base64RawURLFingerprint", args{digest, Base64RawURLFingerprint}, "OAEWIezcwhcukzoe8jF-_FNaFhwAMzruP4Sr-rTmQL8"},
		{"EmojiFingerprint", args{digest, EmojiFingerprint}, "💨🎱🌼📆🎠🎉🎿🚙🍪🌊♦️💡✌️🐮🔒❌🖕😬🌼👦👍👑♦️🇬🇧👂🔬📌♿🚀🚜🍆🐑"},
		{"Unknown", args{digest, 0}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Fingerprint(tt.args.digest, tt.args.encoding); got != tt.want {
				t.Errorf("Fingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}
