//go:build darwin && cgo && !nomackms

// Copyright (c) Smallstep Labs, Inc.
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

package mackms

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cf "go.step.sm/crypto/internal/darwin/corefoundation"
	"go.step.sm/crypto/internal/darwin/security"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/randutil"
)

func createPrivateKeyOnly(t *testing.T, name string, signatureAlgorithm apiv1.SignatureAlgorithm) *apiv1.CreateKeyResponse {
	t.Helper()

	u, err := parseURI(name)
	require.NoError(t, err)
	u.sigAlgorithm = signatureAlgorithm
	u.keySize = signatureAlgorithmMapping[signatureAlgorithm].Size

	// Define key attributes
	cfTag, err := cf.NewData([]byte(u.tag))
	require.NoError(t, err)
	defer cfTag.Release()

	cfLabel, err := cf.NewString(u.label)
	require.NoError(t, err)
	defer cfLabel.Release()

	keyAttributesDict := cf.Dictionary{
		security.KSecAttrApplicationTag: cfTag,
		security.KSecAttrIsPermanent:    cf.True,
	}

	keyAttributes, err := cf.NewDictionary(keyAttributesDict)
	require.NoError(t, err)
	defer keyAttributes.Release()

	bits := cf.NewNumber(u.keySize)
	defer bits.Release()

	// Define key attributes
	attrsDict := cf.Dictionary{
		security.KSecAttrLabel:         cfLabel,
		security.KSecAttrKeySizeInBits: bits,
		security.KSecPrivateKeyAttrs:   keyAttributes,
	}

	switch u.sigAlgorithm {
	case apiv1.UnspecifiedSignAlgorithm:
		attrsDict[security.KSecAttrKeyType] = security.KSecAttrKeyTypeECSECPrimeRandom
	case apiv1.ECDSAWithSHA256, apiv1.ECDSAWithSHA384, apiv1.ECDSAWithSHA512:
		attrsDict[security.KSecAttrKeyType] = security.KSecAttrKeyTypeECSECPrimeRandom
	case apiv1.SHA256WithRSA, apiv1.SHA384WithRSA, apiv1.SHA512WithRSA:
		attrsDict[security.KSecAttrKeyType] = security.KSecAttrKeyTypeRSA
	case apiv1.SHA256WithRSAPSS, apiv1.SHA384WithRSAPSS, apiv1.SHA512WithRSAPSS:
		attrsDict[security.KSecAttrKeyType] = security.KSecAttrKeyTypeRSA
	default:
		t.Fatalf("unsupported signature algorithm %s", u.sigAlgorithm)
	}

	attrs, err := cf.NewDictionary(attrsDict)
	require.NoError(t, err)
	defer attrs.Release()

	secKeyRef, err := security.SecKeyCreateRandomKey(attrs)
	require.NoError(t, err)
	defer secKeyRef.Release()

	pub, hash, err := extractPublicKey(secKeyRef)
	require.NoError(t, err)

	return &apiv1.CreateKeyResponse{
		Name: uri.New(Scheme, url.Values{
			"label": []string{u.label},
			"tag":   []string{u.tag},
			"hash":  []string{hex.EncodeToString(hash)},
		}).String(),
		PublicKey: pub,
	}
}

func TestNew(t *testing.T) {
	type args struct {
		in0 context.Context
		in1 apiv1.Options
	}
	tests := []struct {
		name      string
		args      args
		want      *MacKMS
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", args{context.Background(), apiv1.Options{}}, &MacKMS{}, assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.in0, tt.args.in1)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMacKMS(t *testing.T) {
	type verifier func(*testing.T, *MacKMS, *apiv1.CreateKeyRequest, *apiv1.CreateKeyResponse)

	verifyWithType := func(typ crypto.PublicKey, bits int) verifier {
		return func(t *testing.T, kms *MacKMS, req *apiv1.CreateKeyRequest, resp *apiv1.CreateKeyResponse) {
			require.NotNil(t, resp)
			require.NotEmpty(t, resp.Name)
			require.NotNil(t, resp.PublicKey)
			require.NotEmpty(t, resp.CreateSignerRequest)

			if assert.IsType(t, typ, resp.PublicKey) {
				switch p := resp.PublicKey.(type) {
				case *ecdsa.PublicKey:
					assert.Equal(t, bits, p.Curve.Params().BitSize)
				case *rsa.PublicKey:
					assert.Equal(t, bits, p.N.BitLen())
				default:
					t.Fatalf("unsupported public key type %T", p)
				}
			}

			// GetPublicKey
			pub, err := kms.GetPublicKey(&apiv1.GetPublicKeyRequest{
				Name: resp.Name,
			})
			require.NoError(t, err)
			assert.Equal(t, resp.PublicKey, pub)

			// CreateSigner
			message, err := randutil.Bytes(256)
			require.NoError(t, err)

			var opts crypto.SignerOpts
			switch req.SignatureAlgorithm {
			case apiv1.UnspecifiedSignAlgorithm, apiv1.ECDSAWithSHA256, apiv1.SHA256WithRSA:
				opts = crypto.SHA256
			case apiv1.ECDSAWithSHA384, apiv1.SHA384WithRSA:
				opts = crypto.SHA384
			case apiv1.ECDSAWithSHA512, apiv1.SHA512WithRSA:
				opts = crypto.SHA512
			case apiv1.SHA256WithRSAPSS:
				opts = &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthEqualsHash,
					Hash:       crypto.SHA256,
				}
			case apiv1.SHA384WithRSAPSS:
				opts = &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthAuto,
					Hash:       crypto.SHA384,
				}
			case apiv1.SHA512WithRSAPSS:
				opts = &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthAuto,
					Hash:       crypto.SHA512,
				}
			default:
				t.Fatalf("unsupported signature algorithm %s", req.SignatureAlgorithm)
			}

			h := opts.HashFunc().New()
			h.Write(message)
			digest := h.Sum(nil)

			signer, err := kms.CreateSigner(&resp.CreateSignerRequest)
			require.NoError(t, err)

			signature, err := signer.Sign(rand.Reader, digest, opts)
			require.NoError(t, err)

			assert.Equal(t, pub, signer.Public())

			switch p := pub.(type) {
			case *ecdsa.PublicKey:
				assert.True(t, ecdsa.VerifyASN1(p, digest, signature))
			case *rsa.PublicKey:
				if o, ok := opts.(*rsa.PSSOptions); ok {
					assert.NoError(t, rsa.VerifyPSS(p, o.HashFunc(), digest, signature, o))
				} else {
					assert.NoError(t, rsa.VerifyPKCS1v15(p, opts.HashFunc(), digest, signature))
				}
			}
		}
	}

	type args struct {
		req *apiv1.CreateKeyRequest
	}
	tests := []struct {
		name      string
		k         *MacKMS
		args      args
		verify    verifier
		assertion assert.ErrorAssertionFunc
	}{
		{"ok default", &MacKMS{}, args{&apiv1.CreateKeyRequest{
			Name:               "mackms:label=test-default",
			SignatureAlgorithm: apiv1.UnspecifiedSignAlgorithm,
		}}, verifyWithType(&ecdsa.PublicKey{}, 256), assert.NoError},
		{"ok p256", &MacKMS{}, args{&apiv1.CreateKeyRequest{
			Name:               "mackms:label=test-p256",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, verifyWithType(&ecdsa.PublicKey{}, 256), assert.NoError},
		{"ok p384", &MacKMS{}, args{&apiv1.CreateKeyRequest{
			Name:               "mackms:label=test-p384",
			SignatureAlgorithm: apiv1.ECDSAWithSHA384,
		}}, verifyWithType(&ecdsa.PublicKey{}, 384), assert.NoError},
		{"ok p521", &MacKMS{}, args{&apiv1.CreateKeyRequest{
			Name:               "mackms:label=test-p521",
			SignatureAlgorithm: apiv1.ECDSAWithSHA512,
		}}, verifyWithType(&ecdsa.PublicKey{}, 521), assert.NoError},
		{"ok RSA", &MacKMS{}, args{&apiv1.CreateKeyRequest{
			Name:               "mackms:label=test-rsa",
			SignatureAlgorithm: apiv1.SHA256WithRSA,
		}}, verifyWithType(&rsa.PublicKey{}, 3072), assert.NoError},
		{"ok RSA 2048", &MacKMS{}, args{&apiv1.CreateKeyRequest{
			Name:               "mackms:label=test-2048",
			SignatureAlgorithm: apiv1.SHA256WithRSA,
			Bits:               2048,
		}}, verifyWithType(&rsa.PublicKey{}, 2048), assert.NoError},
		{"ok RSA 3072", &MacKMS{}, args{&apiv1.CreateKeyRequest{
			Name:               "mackms:label=test-3072",
			SignatureAlgorithm: apiv1.SHA384WithRSA,
			Bits:               3072,
		}}, verifyWithType(&rsa.PublicKey{}, 3072), assert.NoError},
		{"ok RSA 4096", &MacKMS{}, args{&apiv1.CreateKeyRequest{
			Name:               "mackms:label=test-4096",
			SignatureAlgorithm: apiv1.SHA512WithRSA,
			Bits:               4096,
		}}, verifyWithType(&rsa.PublicKey{}, 4096), assert.NoError},
		{"ok RSA-PSS 2048", &MacKMS{}, args{&apiv1.CreateKeyRequest{
			Name:               "mackms:label=test-2048-pss",
			SignatureAlgorithm: apiv1.SHA256WithRSAPSS,
			Bits:               2048,
		}}, verifyWithType(&rsa.PublicKey{}, 2048), assert.NoError},
		{"ok RSA-PSS 3072", &MacKMS{}, args{&apiv1.CreateKeyRequest{
			Name:               "mackms:label=test-3072-pss",
			SignatureAlgorithm: apiv1.SHA384WithRSAPSS,
			Bits:               3072,
		}}, verifyWithType(&rsa.PublicKey{}, 3072), assert.NoError},
		{"ok RSA-PSS 4096", &MacKMS{}, args{&apiv1.CreateKeyRequest{
			Name:               "mackms:label=test-4096-pss",
			SignatureAlgorithm: apiv1.SHA512WithRSAPSS,
			Bits:               4096,
		}}, verifyWithType(&rsa.PublicKey{}, 4096), assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &MacKMS{}
			t.Cleanup(func() {
				assert.NoError(t, k.DeleteKey(&apiv1.DeleteKeyRequest{
					Name: tt.args.req.Name,
				}))
			})
			got, err := k.CreateKey(tt.args.req)
			tt.assertion(t, err)
			tt.verify(t, k, tt.args.req, got)
		})
	}
}

func TestMacKMS_GetPublicKey(t *testing.T) {
	kms := &MacKMS{}
	r1, err := kms.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "mackms:label=test-p256",
		SignatureAlgorithm: apiv1.ECDSAWithSHA256,
	})
	require.NoError(t, err)

	// Create private keys only
	r2 := createPrivateKeyOnly(t, "mackms:label=test-ecdsa", apiv1.ECDSAWithSHA256)
	r3 := createPrivateKeyOnly(t, "mackms:label=test-rsa", apiv1.SHA256WithRSA)

	t.Cleanup(func() {
		assert.NoError(t, kms.DeleteKey(&apiv1.DeleteKeyRequest{
			Name: r1.Name,
		}))
		assert.NoError(t, kms.DeleteKey(&apiv1.DeleteKeyRequest{
			Name: r2.Name,
		}))
		assert.NoError(t, kms.DeleteKey(&apiv1.DeleteKeyRequest{
			Name: r3.Name,
		}))
	})

	type args struct {
		req *apiv1.GetPublicKeyRequest
	}
	tests := []struct {
		name      string
		k         *MacKMS
		args      args
		want      crypto.PublicKey
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: r1.Name}}, r1.PublicKey, assert.NoError},
		{"ok private only ECDSA ", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: "mackms:label=test-ecdsa"}}, r2.PublicKey, assert.NoError},
		{"ok private only RSA ", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: r3.Name}}, r3.PublicKey, assert.NoError},
		{"ok no uri", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: "test-p256"}}, r1.PublicKey, assert.NoError},
		{"ok uri simple", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: "mackms:test-p256"}}, r1.PublicKey, assert.NoError},
		{"ok uri label", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: "mackms:label=test-p256"}}, r1.PublicKey, assert.NoError},
		{"ok uri label + tag", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: "mackms:label=test-p256;tag=com.smallstep.crypto"}}, r1.PublicKey, assert.NoError},
		{"fail bad label", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: "mackms:label=test-fail-p256"}}, nil, assert.Error},
		{"fail bad tag", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: "mackms:label=test-p256;tag=com.step.crypto"}}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &MacKMS{}
			got, err := k.GetPublicKey(tt.args.req)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMacKMS_CreateKey(t *testing.T) {
	t.Cleanup(func() {
		kms := &MacKMS{}
		assert.NoError(t, kms.DeleteKey(&apiv1.DeleteKeyRequest{
			Name: "mackms:label=test-p256",
		}))
	})

	type args struct {
		req *apiv1.CreateKeyRequest
	}
	tests := []struct {
		name      string
		k         *MacKMS
		args      args
		verify    require.ValueAssertionFunc
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", &MacKMS{}, args{&apiv1.CreateKeyRequest{Name: "mackms:label=test-p256"}},
			func(tt require.TestingT, i1 interface{}, i2 ...interface{}) {
				require.IsType(tt, &apiv1.CreateKeyResponse{}, i1)
				resp := i1.(*apiv1.CreateKeyResponse)
				require.NotEmpty(tt, resp.Name)
				require.NotNil(tt, resp.PublicKey)
				require.Nil(tt, resp.PrivateKey)
				require.NotEmpty(tt, resp.CreateSignerRequest)

				u, err := parseURI(resp.Name)
				require.NoError(tt, err)
				require.NotEmpty(tt, u.label)
				require.NotEmpty(tt, u.tag)
				require.NotEmpty(tt, u.hash)
			}, assert.NoError},
		{"fail name", &MacKMS{}, args{&apiv1.CreateKeyRequest{}}, require.Nil, assert.Error},
		{"fail uri", &MacKMS{}, args{&apiv1.CreateKeyRequest{Name: "mackms:name=test-p256"}}, require.Nil, assert.Error},
		{"fail signatureAlgorithm", &MacKMS{}, args{&apiv1.CreateKeyRequest{
			Name: "mackms:label=test-p256", SignatureAlgorithm: apiv1.PureEd25519,
		}}, require.Nil, assert.Error},
		{"fail signatureAlgorithm secureEnclave", &MacKMS{}, args{&apiv1.CreateKeyRequest{
			Name: "mackms:label=test-p256;se=true", SignatureAlgorithm: apiv1.ECDSAWithSHA512,
		}}, require.Nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &MacKMS{}
			got, err := k.CreateKey(tt.args.req)
			tt.assertion(t, err)
			tt.verify(t, got)
		})
	}
}

func TestMacKMS_CreateSigner(t *testing.T) {
	kms := &MacKMS{}
	resp, err := kms.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "mackms:label=test-p256",
		SignatureAlgorithm: apiv1.SHA256WithRSA,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, kms.DeleteKey(&apiv1.DeleteKeyRequest{
			Name: resp.Name,
		}))
	})

	assertSigner := func(tt require.TestingT, i1 interface{}, i2 ...interface{}) {
		require.IsType(tt, &Signer{}, i1)
		signer := i1.(crypto.Signer)
		require.Equal(tt, resp.PublicKey, signer.Public())
		b, err := randutil.Bytes(256)
		require.NoError(t, err)
		digest := sha256.Sum256(b)
		signature, err := signer.Sign(nil, digest[:], crypto.SHA256)
		require.NoError(tt, err)
		switch k := signer.Public().(type) {
		case *ecdsa.PublicKey:
			require.True(tt, ecdsa.VerifyASN1(k, digest[:], signature))
		case *rsa.PublicKey:
			require.NoError(tt, rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], signature))
		default:
			tt.Errorf("unexpected key type %T", k)
		}
	}

	type args struct {
		req *apiv1.CreateSignerRequest
	}
	tests := []struct {
		name      string
		k         *MacKMS
		args      args
		verify    require.ValueAssertionFunc
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", &MacKMS{}, args{&apiv1.CreateSignerRequest{
			SigningKey: resp.Name,
		}}, assertSigner, assert.NoError},
		{"ok simple name", &MacKMS{}, args{&apiv1.CreateSignerRequest{
			SigningKey: "mackms:label=test-p256",
		}}, assertSigner, assert.NoError},
		{"fail signingKey", &MacKMS{}, args{&apiv1.CreateSignerRequest{}}, require.Nil, assert.Error},
		{"fail uri", &MacKMS{}, args{&apiv1.CreateSignerRequest{SigningKey: "mackms:tag=foo"}}, require.Nil, assert.Error},
		{"fail missing", &MacKMS{}, args{&apiv1.CreateSignerRequest{SigningKey: "mackms:label=test-p384"}}, require.Nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &MacKMS{}
			got, err := k.CreateSigner(tt.args.req)
			tt.assertion(t, err)
			tt.verify(t, got)
		})
	}
}

func TestMacKMS_DeleteKey(t *testing.T) {
	kms := &MacKMS{}
	r1, err := kms.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "mackms:label=test-p256",
		SignatureAlgorithm: apiv1.SHA256WithRSA,
	})
	require.NoError(t, err)
	r2, err := kms.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "mackms:label=test-rsa",
		SignatureAlgorithm: apiv1.SHA256WithRSA,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.Error(t, kms.DeleteKey(&apiv1.DeleteKeyRequest{
			Name: r1.Name,
		}))
		assert.Error(t, kms.DeleteKey(&apiv1.DeleteKeyRequest{
			Name: r2.Name,
		}))
	})

	type args struct {
		req *apiv1.DeleteKeyRequest
	}
	tests := []struct {
		name      string
		m         *MacKMS
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", &MacKMS{}, args{&apiv1.DeleteKeyRequest{Name: r1.Name}}, assert.NoError},
		{"ok simple name", &MacKMS{}, args{&apiv1.DeleteKeyRequest{Name: "mackms:label=test-rsa"}}, assert.NoError},
		{"fail name", &MacKMS{}, args{&apiv1.DeleteKeyRequest{}}, assert.Error},
		{"fail uri", &MacKMS{}, args{&apiv1.DeleteKeyRequest{Name: "mackms:hash=foo"}}, assert.Error},
		{"fail missing", &MacKMS{}, args{&apiv1.DeleteKeyRequest{Name: r1.Name}}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MacKMS{}
			tt.assertion(t, m.DeleteKey(tt.args.req))
		})
	}
}

func Test_parseURI(t *testing.T) {
	type args struct {
		rawuri string
	}
	tests := []struct {
		name      string
		args      args
		want      *keyAttributes
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", args{"mackms:label=the-label;tag=the-tag;hash=0102abcd"}, &keyAttributes{label: "the-label", tag: "the-tag", hash: []byte{1, 2, 171, 205}}, assert.NoError},
		{"ok label", args{"the-label"}, &keyAttributes{label: "the-label", tag: DefaultTag}, assert.NoError},
		{"ok label uri", args{"mackms:label=the-label"}, &keyAttributes{label: "the-label", tag: DefaultTag}, assert.NoError},
		{"fail parse", args{"mackms:::label=the-label"}, nil, assert.Error},
		{"fail missing label", args{"mackms:hash=0102abcd"}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseURI(tt.args.rawuri)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_parseECDSAPublicKey(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	marshal := func(k *ecdsa.PrivateKey) []byte {
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		ret := make([]byte, 1+2*byteLen)
		ret[0] = 4 // uncompressed point
		k.X.FillBytes(ret[1 : 1+byteLen])
		k.Y.FillBytes(ret[1+byteLen : 1+2*byteLen])
		return ret
	}
	mustRand := func(size int) []byte {
		b, err := randutil.Bytes(size)
		require.NoError(t, err)
		return b
	}

	type args struct {
		raw []byte
	}
	tests := []struct {
		name      string
		args      args
		want      crypto.PublicKey
		assertion assert.ErrorAssertionFunc
	}{
		{"ok P-256", args{marshal(p256)}, p256.Public(), assert.NoError},
		{"ok P-384", args{marshal(p384)}, p384.Public(), assert.NoError},
		{"ok P-521", args{marshal(p521)}, p521.Public(), assert.NoError},
		{"fail P-224", args{marshal(p224)}, nil, assert.Error},
		{"fail P-256", args{mustRand(65)}, nil, assert.Error},
		{"fail P-384", args{mustRand(97)}, nil, assert.Error},
		{"fail P-521", args{mustRand(133)}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseECDSAPublicKey(tt.args.raw)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_parseECDSAPrivateKey(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	marshal := func(k *ecdsa.PrivateKey) []byte {
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		ret := make([]byte, 1+3*byteLen)
		ret[0] = 4 // uncompressed point
		k.X.FillBytes(ret[1 : 1+byteLen])
		k.Y.FillBytes(ret[1+byteLen : 1+2*byteLen])
		k.D.FillBytes(ret[1+2*byteLen:])
		return ret
	}
	zeroKey := func(size int) []byte {
		return make([]byte, size)
	}

	type args struct {
		raw []byte
	}
	tests := []struct {
		name      string
		args      args
		want      crypto.PublicKey
		assertion assert.ErrorAssertionFunc
	}{
		{"ok P-256", args{marshal(p256)}, p256.Public(), assert.NoError},
		{"ok P-384", args{marshal(p384)}, p384.Public(), assert.NoError},
		{"ok P-521", args{marshal(p521)}, p521.Public(), assert.NoError},
		{"fail P-224", args{marshal(p224)}, nil, assert.Error},
		{"fail P-256", args{zeroKey(97)}, nil, assert.Error},
		{"fail P-384", args{zeroKey(145)}, nil, assert.Error},
		{"fail P-521", args{zeroKey(199)}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseECDSAPrivateKey(tt.args.raw)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_ecdhToECDSAPublicKey(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	toECDH := func(k *ecdsa.PrivateKey) *ecdh.PublicKey {
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		b := make([]byte, 1+2*byteLen)
		b[0] = 4 // uncompressed point
		k.X.FillBytes(b[1 : 1+byteLen])
		k.Y.FillBytes(b[1+byteLen : 1+2*byteLen])

		switch k.Curve {
		case elliptic.P256():
			key, err := ecdh.P256().NewPublicKey(b)
			require.NoError(t, err)
			return key
		case elliptic.P384():
			key, err := ecdh.P384().NewPublicKey(b)
			require.NoError(t, err)
			return key
		case elliptic.P521():
			key, err := ecdh.P521().NewPublicKey(b)
			require.NoError(t, err)
			return key
		default:
			return &ecdh.PublicKey{}
		}
	}

	type args struct {
		key *ecdh.PublicKey
	}
	tests := []struct {
		name      string
		args      args
		want      *ecdsa.PublicKey
		assertion assert.ErrorAssertionFunc
	}{
		{"ok P-256", args{toECDH(p256)}, &p256.PublicKey, assert.NoError},
		{"ok P-384", args{toECDH(p384)}, &p384.PublicKey, assert.NoError},
		{"ok P-521", args{toECDH(p521)}, &p521.PublicKey, assert.NoError},
		{"fail X25519", args{x25519.PublicKey()}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ecdhToECDSAPublicKey(tt.args.key)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
