package tss2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
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

func assertMaybeError(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
	return true
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
		name      string
		params    tpm2.Public
		opts      crypto.SignerOpts
		assertion assert.ErrorAssertionFunc
	}{
		{"ok ECDSA", defaultKeyParamsEC, crypto.SHA256, assert.NoError},
		{"ok RSA", defaultKeyParamsRSA, crypto.SHA256, assert.NoError},
		{"ok RSAPSS PSSSaltLengthAuto", defaultKeyParamsRSAPSS, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256,
		}, assert.NoError},
		{"ok RSAPSS PSSSaltLengthEqualsHash", defaultKeyParamsRSAPSS, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256,
		}, assert.NoError},
		{"ok RSAPSS SaltLength=32", defaultKeyParamsRSAPSS, &rsa.PSSOptions{
			SaltLength: 32, Hash: crypto.SHA256,
		}, assert.NoError},
		// 222 is the largest salt possible when signing with a 2048 bit key. Go
		// crypto will use this value when rsa.PSSSaltLengthAuto is set.
		//
		// TPM 2.0's TPM_ALG_RSAPSS algorithm, uses the maximum possible salt
		// length. However, as of TPM revision 1.16, TPMs which follow FIPS
		// 186-4 will interpret TPM_ALG_RSAPSS using salt length equal to the
		// digest length.
		{"RSAPSS SaltLength=222", defaultKeyParamsRSAPSS, &rsa.PSSOptions{
			SaltLength: 222, Hash: crypto.SHA256,
		}, assertMaybeError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, pub, _, _, _, err := tpm2.CreateKey(rw, keyHnd, tpm2.PCRSelection{}, "", "", tt.params)
			require.NoError(t, err)

			signer, err := CreateSigner(rw, New(pub, priv))
			require.NoError(t, err)

			// Set the ECC SRK template used for testing
			signer.SetSRKTemplate(ECCSRKTemplate)

			hash := crypto.SHA256.New()
			hash.Write([]byte("rulingly-quailed-cloacal-indifferentist-roughhoused-self-mad"))
			sum := hash.Sum(nil)

			sig, err := signer.Sign(rand.Reader, sum, tt.opts)
			tt.assertion(t, err)
			if err != nil {
				return
			}

			// Signature validation using Go crypto
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
					opts, ok := tt.opts.(*rsa.PSSOptions)
					require.True(t, ok)
					assert.NoError(t, rsa.VerifyPSS(pub, opts.Hash, sum, sig, opts))
				default:
					t.Errorf("unexpected RSAParameters.Sign.Alg %v", tt.params.RSAParameters.Sign.Alg)
				}
			default:
				t.Errorf("unexpected PublicKey type %T", pub)
			}
		})
	}
}

func TestSign_SetTPM(t *testing.T) {
	var signer *Signer

	if t.Run("Setup", func(t *testing.T) {
		rw := openTPM(t)
		t.Cleanup(func() {
			assert.NoError(t, rw.Close())
		})
		keyHnd, _, err := tpm2.CreatePrimary(rw, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", ECCSRKTemplate)
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, tpm2.FlushContext(rw, keyHnd))
		})

		priv, pub, _, _, _, err := tpm2.CreateKey(rw, keyHnd, tpm2.PCRSelection{}, "", "", defaultKeyParamsEC)
		require.NoError(t, err)

		signer, err = CreateSigner(rw, New(pub, priv))
		require.NoError(t, err)
	}) {
		rw := openTPM(t)
		t.Cleanup(func() {
			assert.NoError(t, rw.Close())
		})
		require.NotNil(t, signer)

		// Set new tpm channel
		signer.SetCommandChannel(rw)

		// Set the ECC SRK template used for testing
		signer.SetSRKTemplate(ECCSRKTemplate)

		hash := crypto.SHA256.New()
		hash.Write([]byte("ungymnastic-theirn-cotwin-Summer-pemphigous-propagate"))
		sum := hash.Sum(nil)

		sig, err := signer.Sign(rand.Reader, sum, crypto.SHA256)
		require.NoError(t, err)

		publicKey, ok := signer.Public().(*ecdsa.PublicKey)
		require.True(t, ok)
		assert.True(t, ecdsa.VerifyASN1(publicKey, sum, sig))
	}
}

func TestCreateSigner(t *testing.T) {
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
		{"fail key", args{&rw, nil}, nil, assert.Error},
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

func Test_curveSigScheme(t *testing.T) {
	type args struct {
		curve elliptic.Curve
	}
	tests := []struct {
		name      string
		args      args
		want      *tpm2.SigScheme
		assertion assert.ErrorAssertionFunc
	}{
		{"ok P-256", args{elliptic.P256()}, &tpm2.SigScheme{
			Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256,
		}, assert.NoError},
		{"ok P-2384", args{elliptic.P384()}, &tpm2.SigScheme{
			Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA384,
		}, assert.NoError},
		{"ok P-521", args{elliptic.P521()}, &tpm2.SigScheme{
			Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA512,
		}, assert.NoError},
		{"fail P-224", args{elliptic.P224()}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := curveSigScheme(tt.args.curve)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_signECDSA_fail(t *testing.T) {
	rw := openTPM(t)
	t.Cleanup(func() {
		assert.NoError(t, rw.Close())
	})

	digest := func(h crypto.Hash) []byte {
		hh := h.New()
		hh.Write([]byte("Subotica-chronique-radiancy-inspirationally-transuming-Melbeta"))
		return hh.Sum(nil)
	}

	type args struct {
		rw     io.ReadWriter
		key    tpmutil.Handle
		digest []byte
		curve  elliptic.Curve
	}
	tests := []struct {
		name      string
		args      args
		want      []byte
		assertion assert.ErrorAssertionFunc
	}{
		{"fail curve", args{rw, handleOwner, digest(crypto.SHA224), elliptic.P224()}, nil, assert.Error},
		{"fail sign", args{nil, handleOwner, digest(crypto.SHA256), elliptic.P256()}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := signECDSA(tt.args.rw, tt.args.key, tt.args.digest, tt.args.curve)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_signRSA_fail(t *testing.T) {
	rw := openTPM(t)
	t.Cleanup(func() {
		assert.NoError(t, rw.Close())
	})

	h := crypto.SHA256.New()
	h.Write([]byte("murmur-squinance-hoghide-jubilation-enteraden-samadh"))
	digest := h.Sum(nil)

	type args struct {
		rw     io.ReadWriter
		key    tpmutil.Handle
		digest []byte
		opts   crypto.SignerOpts
	}
	tests := []struct {
		name      string
		args      args
		want      []byte
		assertion assert.ErrorAssertionFunc
	}{
		{"fail HashToAlgorithm", args{rw, handleOwner, digest, crypto.SHA224}, nil, assert.Error},
		{"fail PSSOptions", args{rw, handleOwner, digest, &rsa.PSSOptions{
			Hash: crypto.SHA256, SaltLength: 222,
		}}, nil, assert.Error},
		{"fail sign", args{nil, handleOwner, digest, crypto.SHA256}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := signRSA(tt.args.rw, tt.args.key, tt.args.digest, tt.args.opts)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
