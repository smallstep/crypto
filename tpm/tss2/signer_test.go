package tss2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"io"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var defaultKeyParamsEC = tpm2.Public{
	Type:       tpm2.AlgECC,
	NameAlg:    tpm2.AlgSHA256,
	Attributes: tpm2.FlagSignerDefault ^ tpm2.FlagRestricted,
	ECCParameters: &tpm2.ECCParams{
		Sign: &tpm2.SigScheme{
			Alg:  tpm2.AlgECDSA,
			Hash: tpm2.AlgSHA256,
		},
		CurveID: tpm2.CurveNISTP256,
	},
}

var defaultKeyParamsRSA = tpm2.Public{
	Type:       tpm2.AlgRSA,
	NameAlg:    tpm2.AlgSHA256,
	Attributes: tpm2.FlagSignerDefault ^ tpm2.FlagRestricted,
	RSAParameters: &tpm2.RSAParams{
		Sign: &tpm2.SigScheme{
			Alg:  tpm2.AlgRSASSA,
			Hash: tpm2.AlgSHA256,
		},
		KeyBits: 2048,
	},
}

var defaultKeyParamsRSAPSS = tpm2.Public{
	Type:       tpm2.AlgRSA,
	NameAlg:    tpm2.AlgSHA256,
	Attributes: tpm2.FlagSignerDefault ^ tpm2.FlagRestricted,
	RSAParameters: &tpm2.RSAParams{
		Sign: &tpm2.SigScheme{
			Alg:  tpm2.AlgRSAPSS,
			Hash: tpm2.AlgSHA256,
		},
		KeyBits: 2048,
	},
}

func TestSign(t *testing.T) {
	rw := openTPM(t)
	t.Cleanup(func() {
		assert.NoError(t, rw.Close())
	})

	keyHnd, _, err := tpm2.CreatePrimary(rw, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", ECCSRKTemplate)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, tpm2.FlushContext(rw, keyHnd))
	})

	tests := []struct {
		name   string
		params tpm2.Public
		opts   crypto.SignerOpts
	}{
		{"ok ECDSA", defaultKeyParamsEC, crypto.SHA256},
		{"ok RSA", defaultKeyParamsRSA, crypto.SHA256},
		{"ok RSAPSS", defaultKeyParamsRSAPSS, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, pub, _, _, _, err := tpm2.CreateKey(rw, keyHnd, tpm2.PCRSelection{}, "", "", tt.params)
			require.NoError(t, err)

			signer, err := CreateSigner(rw, New(pub, priv))
			require.NoError(t, err)

			// Set the ECC SRK template used for testing.
			signer.SetSRKTemplate(ECCSRKTemplate)

			hash := crypto.SHA256.New()
			hash.Write([]byte("rulingly-quailed-cloacal-indifferentist-roughhoused-self-mad"))
			sum := hash.Sum(nil)

			sig, err := signer.Sign(rand.Reader, sum, tt.opts)
			require.NoError(t, err)

			switch pub := signer.Public().(type) {
			case *ecdsa.PublicKey:
				assert.Equal(t, tpm2.AlgECC, tt.params.Type)
				assert.True(t, ecdsa.VerifyASN1(pub, sum, sig))
			case *rsa.PublicKey:
				assert.Equal(t, tpm2.AlgRSA, tt.params.Type)
				switch tt.params.RSAParameters.Sign.Alg {
				case tpm2.AlgRSASSA:
					assert.NoError(t, rsa.VerifyPKCS1v15(pub, tt.opts.HashFunc(), sum, sig))
				case tpm2.AlgRSAPSS:
					assert.NoError(t, rsa.VerifyPSS(pub, crypto.SHA256, sum, sig, nil))
				default:
					t.Errorf("unexpected RSAParameters.Sign.Alg %v", tt.params.RSAParameters.Sign.Alg)
				}
			default:
				t.Errorf("unexpected PublicKey type %T", pub)
			}
		})
	}
}

func TestCreateSigner(t *testing.T) {
	parsePEM := func(s string) []byte {
		block, _ := pem.Decode([]byte(s))
		return block.Bytes
	}

	var rw bytes.Buffer
	key, err := ParsePrivateKey(parsePEM(p256TSS2PEM))
	require.NoError(t, err)

	pub, err := tpm2.DecodePublic(key.PublicKey[2:])
	require.NoError(t, err)
	publicKey, err := pub.Key()
	require.NoError(t, err)

	modKey := func(fn TPMOption) *TPMKey {
		return New(key.PublicKey[2:], key.PrivateKey[2:], fn)
	}

	type args struct {
		rw  io.ReadWriter
		key *TPMKey
	}
	tests := []struct {
		name      string
		args      args
		want      *Signer
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", args{&rw, key}, &Signer{
			rw: &rw, publicKey: publicKey, tpmKey: key, srkTemplate: RSASRKTemplate,
		}, assert.NoError},
		{"fail rw", args{nil, key}, nil, assert.Error},
		{"fail type", args{&rw, modKey(func(k *TPMKey) {
			k.Type = oidSealedKey
		})}, nil, assert.Error},
		{"fail policy", args{&rw, modKey(func(k *TPMKey) {
			k.Policy = []TPMPolicy{{CommandCode: 1, CommandPolicy: []byte("command-policy")}}
		})}, nil, assert.Error},
		{"fail authPolicy", args{&rw, modKey(func(k *TPMKey) {
			k.AuthPolicy = []TPMAuthPolicy{{Name: "auth", Policy: []TPMPolicy{{CommandCode: 1, CommandPolicy: []byte("command-policy")}}}}
		})}, nil, assert.Error},
		{"fail secret", args{&rw, modKey(func(k *TPMKey) {
			k.Secret = []byte("secret")
		})}, nil, assert.Error},
		{"fail parent", args{&rw, modKey(func(k *TPMKey) {
			k.Parent = 0
		})}, nil, assert.Error},
		{"fail publicKey", args{&rw, modKey(func(k *TPMKey) {
			k.PublicKey = key.PublicKey[2:]
		})}, nil, assert.Error},
		{"fail privateKey", args{&rw, modKey(func(k *TPMKey) {
			k.PrivateKey = key.PrivateKey[2:]
		})}, nil, assert.Error},
		{"fail decodePublic", args{&rw, modKey(func(k *TPMKey) {
			k.PublicKey = append([]byte{0, 6}, []byte("public")...)
		})}, nil, assert.Error},
		{"fail type", args{&rw, modKey(func(k *TPMKey) {
			p := tpm2.Public{
				Type:       tpm2.AlgSymCipher,
				NameAlg:    tpm2.AlgAES,
				Attributes: tpm2.FlagSignerDefault ^ tpm2.FlagRestricted,
				SymCipherParameters: &tpm2.SymCipherParams{
					Symmetric: &tpm2.SymScheme{
						Alg:     tpm2.AlgAES,
						KeyBits: 128,
						Mode:    tpm2.AlgCFB,
					},
					Unique: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
				},
			}
			b, err := p.Encode()
			if assert.NoError(t, err) {
				k.PublicKey = addPrefixLength(b)
			}
		})}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateSigner(tt.args.rw, tt.args.key)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
