package tss2

import (
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	type args struct {
		pub  []byte
		priv []byte
		opts []TPMOption
	}
	tests := []struct {
		name string
		args args
		want *TPMKey
	}{
		{"ok", args{[]byte("public"), []byte("private"), nil}, &TPMKey{
			Type:       oidLoadableKey,
			EmptyAuth:  true,
			Parent:     0x40000001,
			PublicKey:  append([]byte{0, 6}, []byte("public")...),
			PrivateKey: append([]byte{0, 7}, []byte("private")...),
		}},
		{"ok with options", args{[]byte("public"), []byte("private"), []TPMOption{
			func(k *TPMKey) {
				k.EmptyAuth = false
			},
			func(k *TPMKey) {
				k.Policy = append(k.Policy, TPMPolicy{CommandCode: 1, CommandPolicy: []byte("command-policy")})
			},
		}}, &TPMKey{
			Type:       oidLoadableKey,
			EmptyAuth:  false,
			Policy:     []TPMPolicy{{CommandCode: 1, CommandPolicy: []byte("command-policy")}},
			Parent:     0x40000001,
			PublicKey:  append([]byte{0, 6}, []byte("public")...),
			PrivateKey: append([]byte{0, 7}, []byte("private")...),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, New(tt.args.pub, tt.args.priv, tt.args.opts...))
		})
	}
}

func TestTPMKey_Encode(t *testing.T) {
	tests := []struct {
		name      string
		tpmKey    *TPMKey
		want      *pem.Block
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", New([]byte("public"), []byte("private")), &pem.Block{
			Type: "TSS2 PRIVATE KEY",
			Bytes: []byte{
				0x30, 0x28,
				0x6, 0x6, 0x67, 0x81, 0x5, 0xa, 0x1, 0x3,
				0xa0, 0x3, 0x1, 0x1, 0xff,
				0x2, 0x4, 0x40, 0x0, 0x0, 0x1,
				0x4, 0x8, 0x0, 0x6, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
				0x4, 0x9, 0x0, 0x7, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
			},
		}, assert.NoError},
		{"fail", nil, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.tpmKey.Encode()
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTPMKey_EncodeToMemory(t *testing.T) {
	tests := []struct {
		name      string
		tpmKey    *TPMKey
		want      []byte
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", New([]byte("public"), []byte("private")), []byte(`-----BEGIN TSS2 PRIVATE KEY-----
MCgGBmeBBQoBA6ADAQH/AgRAAAABBAgABnB1YmxpYwQJAAdwcml2YXRl
-----END TSS2 PRIVATE KEY-----
`), assert.NoError},
		{"fail", nil, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.tpmKey.EncodeToMemory()
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEncode(t *testing.T) {
	type args struct {
		pub  []byte
		priv []byte
		opts []TPMOption
	}
	tests := []struct {
		name      string
		args      args
		want      *pem.Block
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", args{[]byte("public"), []byte("private"), nil}, &pem.Block{
			Type: "TSS2 PRIVATE KEY",
			Bytes: []byte{
				0x30, 0x28,
				0x6, 0x6, 0x67, 0x81, 0x5, 0xa, 0x1, 0x3,
				0xa0, 0x3, 0x1, 0x1, 0xff,
				0x2, 0x4, 0x40, 0x0, 0x0, 0x1,
				0x4, 0x8, 0x0, 0x6, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
				0x4, 0x9, 0x0, 0x7, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
			},
		}, assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Encode(tt.args.pub, tt.args.priv, tt.args.opts...)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEncodeToMemory(t *testing.T) {
	type args struct {
		pub  []byte
		priv []byte
		opts []TPMOption
	}
	tests := []struct {
		name      string
		args      args
		want      []byte
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", args{[]byte("public"), []byte("private"), nil}, []byte(`-----BEGIN TSS2 PRIVATE KEY-----
MCgGBmeBBQoBA6ADAQH/AgRAAAABBAgABnB1YmxpYwQJAAdwcml2YXRl
-----END TSS2 PRIVATE KEY-----
`), assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeToMemory(tt.args.pub, tt.args.priv, tt.args.opts...)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
