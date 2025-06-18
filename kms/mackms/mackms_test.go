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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cf "go.step.sm/crypto/internal/darwin/corefoundation"
	"go.step.sm/crypto/internal/darwin/security"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/randutil"
)

func mustCreateKey(t *testing.T, name string, signatureAlgorithm apiv1.SignatureAlgorithm) *apiv1.CreateKeyResponse {
	t.Helper()

	kms := &MacKMS{}
	resp, err := kms.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "mackms:label=" + name,
		SignatureAlgorithm: signatureAlgorithm,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		err := kms.DeleteKey(&apiv1.DeleteKeyRequest{
			Name: resp.Name,
		})
		if err != nil && !errors.Is(err, apiv1.NotFoundError{}) {
			require.NoError(t, err)
		}
	})

	return resp
}

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
	r3 := createPrivateKeyOnly(t, "mackms:label=test-rsa;tag=", apiv1.SHA256WithRSA)

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
		{"ok no tag", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: "mackms:label=test-p256;tag="}}, r1.PublicKey, assert.NoError},
		{"ok private only ECDSA ", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: "mackms:label=test-ecdsa"}}, r2.PublicKey, assert.NoError},
		{"ok private only RSA", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: r3.Name}}, r3.PublicKey, assert.NoError},
		{"ok private only RSA with retry", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: "mackms:label=test-rsa"}}, r3.PublicKey, assert.NoError},
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
		assert.NoError(t, kms.DeleteKey(&apiv1.DeleteKeyRequest{
			Name: "mackms:label=test-p256-2;tag=",
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
		{"ok no tag", &MacKMS{}, args{&apiv1.CreateKeyRequest{Name: "mackms:label=test-p256-2;tag="}},
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
				require.Empty(tt, u.tag)
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
	r1 := mustCreateKey(t, "test-p256", apiv1.ECDSAWithSHA256)
	_ = mustCreateKey(t, "test-rsa", apiv1.SHA256WithRSA)
	_ = mustCreateKey(t, "test-p384", apiv1.ECDSAWithSHA384)

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
		{"fail secureEnclave", &MacKMS{}, args{&apiv1.DeleteKeyRequest{Name: "mackms:label=test-p384;se=true"}}, assert.Error},
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
		{"ok label", args{"the-label"}, &keyAttributes{label: "the-label", tag: DefaultTag, retry: true}, assert.NoError},
		{"ok label uri", args{"mackms:label=the-label"}, &keyAttributes{label: "the-label", tag: DefaultTag, retry: true}, assert.NoError},
		{"ok label uri simple", args{"mackms:the-label"}, &keyAttributes{label: "the-label", tag: DefaultTag, retry: true}, assert.NoError},
		{"ok label empty tag", args{"mackms:label=the-label;tag="}, &keyAttributes{label: "the-label", tag: ""}, assert.NoError},
		{"ok label empty tag no equal", args{"mackms:label=the-label;tag"}, &keyAttributes{label: "the-label", tag: ""}, assert.NoError},
		{"fail parse", args{"mackms:%label=the-label"}, nil, assert.Error},
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

func Test_encodeSerialNumber(t *testing.T) {
	getBigInt := func(s string) *big.Int {
		b, err := hex.DecodeString(s)
		require.NoError(t, err)
		return new(big.Int).SetBytes(b)
	}
	getBytes := func(s string) []byte {
		b, err := hex.DecodeString(s)
		require.NoError(t, err)
		return b
	}

	type args struct {
		s *big.Int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{"ok zero", args{big.NewInt(0)}, []byte{0}},
		{"ok no pad", args{getBigInt("7df0e2ea242fd1a0650cf652aa31bfa0")}, getBytes("7df0e2ea242fd1a0650cf652aa31bfa0")},
		{"ok with pad", args{getBigInt("c4b3e6e28985f1a012aa38e7493b6f35")}, getBytes("00c4b3e6e28985f1a012aa38e7493b6f35")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, encodeSerialNumber(tt.args.s))
		})
	}
}

func deleteCertificate(t *testing.T, label string, cert *x509.Certificate) {
	if label == "" {
		label = cert.Subject.CommonName
	}

	kms := &MacKMS{}
	require.NoError(t, kms.DeleteCertificate(&apiv1.DeleteCertificateRequest{
		Name: "mackms:label=" + label + ";serial=" + hex.EncodeToString(cert.SerialNumber.Bytes()),
	}))
}

func TestMacKMS_LoadCertificate(t *testing.T) {
	testName := t.Name()
	ca, err := minica.New(minica.WithName(testName))
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert1, err := ca.Sign(&x509.Certificate{
		Subject:        pkix.Name{CommonName: testName + "1@example.com"},
		EmailAddresses: []string{testName + "1@example.com"},
		PublicKey:      key.Public(),
	})
	require.NoError(t, err)

	cert2, err := ca.Sign(&x509.Certificate{
		Subject:        pkix.Name{CommonName: testName + "2@example.com"},
		EmailAddresses: []string{testName + "2@example.com"},
		PublicKey:      key.Public(),
	})
	require.NoError(t, err)

	suffix, err := randutil.Alphanumeric(8)
	require.NoError(t, err)
	label := "test-" + suffix

	kms := &MacKMS{}
	require.NoError(t, kms.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name: "mackms:", Certificate: cert1,
	}))
	t.Cleanup(func() { deleteCertificate(t, "", cert1) })

	require.NoError(t, kms.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name: "mackms:label=" + label, Certificate: cert2,
	}))
	t.Cleanup(func() { deleteCertificate(t, label, cert2) })

	type args struct {
		req *apiv1.LoadCertificateRequest
	}
	tests := []struct {
		name      string
		k         *MacKMS
		args      args
		want      *x509.Certificate
		assertion assert.ErrorAssertionFunc
	}{
		{"ok commonName", &MacKMS{}, args{&apiv1.LoadCertificateRequest{
			Name: "mackms:label=" + cert1.Subject.CommonName,
		}}, cert1, assert.NoError},
		{"ok commonName short uri", &MacKMS{}, args{&apiv1.LoadCertificateRequest{
			Name: "mackms:" + cert1.Subject.CommonName,
		}}, cert1, assert.NoError},
		{"ok commonName with keychain", &MacKMS{}, args{&apiv1.LoadCertificateRequest{
			Name: "mackms:keychain=login;label=" + cert1.Subject.CommonName,
		}}, cert1, assert.NoError},
		{"ok commonName no uri", &MacKMS{}, args{&apiv1.LoadCertificateRequest{
			Name: cert1.Subject.CommonName,
		}}, cert1, assert.NoError},
		{"ok custom label", &MacKMS{}, args{&apiv1.LoadCertificateRequest{
			Name: "mackms:label=" + label,
		}}, cert2, assert.NoError},
		{"ok serial number", &MacKMS{}, args{&apiv1.LoadCertificateRequest{
			Name: "mackms:serial=" + hex.EncodeToString(cert1.SerialNumber.Bytes()),
		}}, cert1, assert.NoError},
		{"ok custom label with keychain", &MacKMS{}, args{&apiv1.LoadCertificateRequest{
			Name: "mackms:keychain=login;label=" + label,
		}}, cert2, assert.NoError},
		{"fail name", &MacKMS{}, args{&apiv1.LoadCertificateRequest{}}, nil, assert.Error},
		{"fail uri", &MacKMS{}, args{&apiv1.LoadCertificateRequest{Name: "mackms:"}}, nil, assert.Error},
		{"fail missing label", &MacKMS{}, args{&apiv1.LoadCertificateRequest{Name: "mackms:label=missing-" + suffix}}, nil, assert.Error},
		{"fail missing serial", &MacKMS{}, args{&apiv1.LoadCertificateRequest{Name: "mackms:serial=010a020b030c"}}, nil, assert.Error},
		{"fail with keychain", &MacKMS{}, args{&apiv1.LoadCertificateRequest{
			Name: "mackms:keychain=dataProtection;label=" + label,
		}}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &MacKMS{}
			got, err := k.LoadCertificate(tt.args.req)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMacKMS_StoreCertificate(t *testing.T) {
	testName := t.Name()

	ca, err := minica.New(minica.WithName(testName))
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert, err := ca.Sign(&x509.Certificate{
		Subject:        pkix.Name{CommonName: testName + "@example.com"},
		EmailAddresses: []string{testName + "@example.com"},
		PublicKey:      key.Public(),
	})
	require.NoError(t, err)

	verifyCertificate := func(name, label string, cert *x509.Certificate) func(t *testing.T) {
		return func(t *testing.T) {
			t.Helper()

			kms := &MacKMS{}
			got, err := kms.LoadCertificate(&apiv1.LoadCertificateRequest{
				Name: name,
			})
			if assert.NoError(t, err) && assert.Equal(t, cert, got) {
				deleteCertificate(t, label, cert)
			}
		}
	}
	commonName := func(cert *x509.Certificate) string {
		return cert.Subject.CommonName
	}
	serial := func(cert *x509.Certificate) string {
		return hex.EncodeToString(cert.SerialNumber.Bytes())
	}
	randLabel := func(n int) string {
		s, err := randutil.Alphanumeric(n)
		require.NoError(t, err)
		return s
	}

	rootLabel := "test-" + randLabel(8)
	intermediateLabel := "test-" + randLabel(8)
	certLabel := "test-" + randLabel(8)

	type args struct {
		req *apiv1.StoreCertificateRequest
	}
	tests := []struct {
		name      string
		k         *MacKMS
		args      args
		verify    func(*testing.T)
		assertion assert.ErrorAssertionFunc
	}{
		{"ok root", &MacKMS{}, args{&apiv1.StoreCertificateRequest{
			Name:        "mackms:",
			Certificate: ca.Root,
		}}, verifyCertificate("mackms:label="+commonName(ca.Root), "", ca.Root), assert.NoError},
		{"ok intermediate", &MacKMS{}, args{&apiv1.StoreCertificateRequest{
			Name:        "mackms:",
			Certificate: ca.Intermediate,
		}}, verifyCertificate("mackms:serial="+serial(ca.Intermediate), "", ca.Intermediate), assert.NoError},
		{"ok cert", &MacKMS{}, args{&apiv1.StoreCertificateRequest{
			Name:        "mackms:",
			Certificate: cert,
		}}, verifyCertificate("mackms:label="+commonName(cert)+";serial="+serial(cert), "", cert), assert.NoError},
		{"ok root with label", &MacKMS{}, args{&apiv1.StoreCertificateRequest{
			Name:        "mackms:label=" + rootLabel,
			Certificate: ca.Root,
		}}, verifyCertificate("mackms:label="+rootLabel, rootLabel, ca.Root), assert.NoError},
		{"ok intermediate with label", &MacKMS{}, args{&apiv1.StoreCertificateRequest{
			Name:        intermediateLabel,
			Certificate: ca.Intermediate,
		}}, verifyCertificate("mackms:serial="+serial(ca.Intermediate), intermediateLabel, ca.Intermediate), assert.NoError},
		{"ok cert with label", &MacKMS{}, args{&apiv1.StoreCertificateRequest{
			Name:        "mackms:" + certLabel,
			Certificate: cert,
		}}, verifyCertificate("mackms:label="+certLabel+";serial="+serial(cert), certLabel, cert), assert.NoError},
		{"ok cert with keychain", &MacKMS{}, args{&apiv1.StoreCertificateRequest{
			Name:        "mackms:keychain=login;label=" + certLabel,
			Certificate: cert,
		}}, verifyCertificate("mackms:label="+certLabel+";serial="+serial(cert), certLabel, cert), assert.NoError},
		{"ok cert no name", &MacKMS{}, args{&apiv1.StoreCertificateRequest{
			Certificate: cert,
		}}, verifyCertificate("mackms:serial="+serial(cert), "", cert), assert.NoError},
		{"fail certificate", &MacKMS{}, args{&apiv1.StoreCertificateRequest{
			Name: "mackms:label=my-label",
		}}, func(t *testing.T) {}, assert.Error},
		{"fail uri", &MacKMS{}, args{&apiv1.StoreCertificateRequest{
			Name: "mackms",
		}}, func(t *testing.T) {}, assert.Error},
		{"fail with dataPrectction", &MacKMS{}, args{&apiv1.StoreCertificateRequest{
			Name:        "mackms:keychain=dataProtection;label=" + certLabel,
			Certificate: cert,
		}}, func(t *testing.T) {}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &MacKMS{}
			tt.assertion(t, k.StoreCertificate(tt.args.req))
			tt.verify(t)
		})
	}
}

func TestMacKMS_StoreCertificate_duplicated(t *testing.T) {
	ca, err := minica.New(minica.WithName(t.Name()))
	require.NoError(t, err)

	suffix, err := randutil.Alphanumeric(8)
	require.NoError(t, err)
	label := "test-" + suffix

	type args struct {
		req *apiv1.StoreCertificateRequest
	}
	tests := []struct {
		name    string
		k       *MacKMS
		args    args
		cleanup func(t *testing.T)
	}{
		{"ok", &MacKMS{}, args{&apiv1.StoreCertificateRequest{
			Name:        "mackms:",
			Certificate: ca.Root,
		}}, func(t *testing.T) {
			deleteCertificate(t, "", ca.Root)
		}},
		{"ok with label", &MacKMS{}, args{&apiv1.StoreCertificateRequest{
			Name:        "mackms:label=" + label,
			Certificate: ca.Intermediate,
		}}, func(t *testing.T) {
			deleteCertificate(t, label, ca.Intermediate)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() { tt.cleanup(t) })
			k := &MacKMS{}
			if assert.NoError(t, k.StoreCertificate(tt.args.req)) {
				assert.Error(t, k.StoreCertificate(tt.args.req))
			}
		})
	}
}

func TestMacKMS_StoreCertificate_privatekey(t *testing.T) {
	testName := t.Name()

	ca, err := minica.New(minica.WithName(testName))
	require.NoError(t, err)

	resp := createKey(t, testName, apiv1.SHA256WithRSA)
	cert, err := ca.Sign(&x509.Certificate{
		Subject:        pkix.Name{CommonName: testName + "@example.com"},
		EmailAddresses: []string{testName + "@example.com"},
		PublicKey:      resp.PublicKey,
	})
	require.NoError(t, err)

	type args struct {
		req *apiv1.StoreCertificateRequest
	}
	tests := []struct {
		name    string
		k       *MacKMS
		args    args
		cleanup func(t *testing.T)
	}{
		{"ok", &MacKMS{}, args{&apiv1.StoreCertificateRequest{
			Name:        "mackms:" + testName,
			Certificate: cert,
		}}, func(t *testing.T) {
			deleteCertificate(t, testName, cert)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() { tt.cleanup(t) })
			k := &MacKMS{}
			if assert.NoError(t, k.StoreCertificate(tt.args.req)) {
				assert.Error(t, k.StoreCertificate(tt.args.req))
			}
		})
	}
}

func TestMacKMS_LoadCertificateChain(t *testing.T) {
	testName := t.Name()
	ca, err := minica.New(minica.WithName(testName))
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert, err := ca.Sign(&x509.Certificate{
		Subject:        pkix.Name{CommonName: testName + "@example.com"},
		EmailAddresses: []string{testName + "@example.com"},
		PublicKey:      key.Public(),
	})
	require.NoError(t, err)

	kms := &MacKMS{}
	require.NoError(t, kms.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name: "mackms:", Certificate: ca.Root,
	}))
	t.Cleanup(func() { deleteCertificate(t, "", ca.Root) })

	require.NoError(t, kms.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name: "mackms:", Certificate: ca.Intermediate,
	}))
	t.Cleanup(func() { deleteCertificate(t, "", ca.Intermediate) })

	require.NoError(t, kms.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name: "mackms:", Certificate: cert,
	}))
	t.Cleanup(func() { deleteCertificate(t, "", cert) })

	type args struct {
		req *apiv1.LoadCertificateChainRequest
	}
	tests := []struct {
		name      string
		k         *MacKMS
		args      args
		want      []*x509.Certificate
		assertion assert.ErrorAssertionFunc
	}{
		{"ok label", &MacKMS{}, args{&apiv1.LoadCertificateChainRequest{
			Name: "mackms:label=" + cert.Subject.CommonName,
		}}, []*x509.Certificate{cert, ca.Intermediate}, assert.NoError},
		{"ok serial", &MacKMS{}, args{&apiv1.LoadCertificateChainRequest{
			Name: "mackms:serial=" + hex.EncodeToString(cert.SerialNumber.Bytes()),
		}}, []*x509.Certificate{cert, ca.Intermediate}, assert.NoError},
		{"ok label and serial", &MacKMS{}, args{&apiv1.LoadCertificateChainRequest{
			Name: "mackms:labeld=" + cert.Subject.CommonName + ";serial=" + hex.EncodeToString(cert.SerialNumber.Bytes()),
		}}, []*x509.Certificate{cert, ca.Intermediate}, assert.NoError},
		{"ok self-signed", &MacKMS{}, args{&apiv1.LoadCertificateChainRequest{
			Name: "mackms:label=" + ca.Root.Subject.CommonName,
		}}, []*x509.Certificate{ca.Root}, assert.NoError},
		{"fail name", &MacKMS{}, args{&apiv1.LoadCertificateChainRequest{}}, nil, assert.Error},
		{"fail uri", &MacKMS{}, args{&apiv1.LoadCertificateChainRequest{Name: "mackms:"}}, nil, assert.Error},
		{"fail missing", &MacKMS{}, args{&apiv1.LoadCertificateChainRequest{Name: "mackms:label=missing-" + testName}}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &MacKMS{}
			got, err := k.LoadCertificateChain(tt.args.req)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMacKMS_StoreCertificateChain(t *testing.T) {
	testName := t.Name()
	ca, err := minica.New(minica.WithName(testName))
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert, err := ca.Sign(&x509.Certificate{
		Subject:        pkix.Name{CommonName: testName + "@example.com"},
		EmailAddresses: []string{testName + "@example.com"},
		PublicKey:      key.Public(),
	})
	require.NoError(t, err)

	verifyCertificates := func(name, label string, chain []*x509.Certificate) func(t *testing.T) {
		return func(t *testing.T) {
			t.Helper()

			kms := &MacKMS{}
			got, err := kms.LoadCertificateChain(&apiv1.LoadCertificateChainRequest{
				Name: name,
			})
			if assert.NoError(t, err) && assert.Equal(t, chain, got) {
				deleteCertificate(t, label, chain[0])
				for _, crt := range chain[1:] {
					deleteCertificate(t, "", crt)
				}
			}
		}
	}

	suffix, err := randutil.Alphanumeric(8)
	require.NoError(t, err)
	label := "test-" + suffix

	type args struct {
		req *apiv1.StoreCertificateChainRequest
	}
	tests := []struct {
		name      string
		k         *MacKMS
		args      args
		verify    func(*testing.T)
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", &MacKMS{}, args{&apiv1.StoreCertificateChainRequest{
			Name:             "mackms:",
			CertificateChain: []*x509.Certificate{cert, ca.Intermediate, ca.Root},
		}}, func(t *testing.T) {
			t.Cleanup(func() {
				deleteCertificate(t, "", ca.Root)
			})
			fn := verifyCertificates("mackms:label="+cert.Subject.CommonName, "", []*x509.Certificate{cert, ca.Intermediate})
			fn(t)
		}, assert.NoError},
		{"ok leaf", &MacKMS{}, args{&apiv1.StoreCertificateChainRequest{
			Name:             "",
			CertificateChain: []*x509.Certificate{cert},
		}}, verifyCertificates("mackms:label="+cert.Subject.CommonName, "", []*x509.Certificate{cert}), assert.NoError},
		{"ok with label", &MacKMS{}, args{&apiv1.StoreCertificateChainRequest{
			Name:             "mackms:label=" + label,
			CertificateChain: []*x509.Certificate{cert, ca.Intermediate},
		}}, verifyCertificates("mackms:label="+label, label, []*x509.Certificate{cert, ca.Intermediate}), assert.NoError},
		{"ok already exists", &MacKMS{}, args{&apiv1.StoreCertificateChainRequest{
			Name:             "mackms:",
			CertificateChain: []*x509.Certificate{cert, ca.Intermediate, ca.Intermediate},
		}}, verifyCertificates("mackms:label="+cert.Subject.CommonName, "", []*x509.Certificate{cert, ca.Intermediate}), assert.NoError},
		{"fail certificates", &MacKMS{}, args{&apiv1.StoreCertificateChainRequest{
			Name: "mackms:",
		}}, func(t *testing.T) {}, assert.Error},
		{"fail uri", &MacKMS{}, args{&apiv1.StoreCertificateChainRequest{
			Name:             "mackms",
			CertificateChain: []*x509.Certificate{cert, ca.Intermediate},
		}}, func(t *testing.T) {}, assert.Error},
		{"fail store certificate", &MacKMS{}, args{&apiv1.StoreCertificateChainRequest{
			Name:             "mackms:",
			CertificateChain: []*x509.Certificate{{}, ca.Intermediate},
		}}, func(t *testing.T) {}, assert.Error},
		{"fail store certificate chain", &MacKMS{}, args{&apiv1.StoreCertificateChainRequest{
			Name:             "mackms:",
			CertificateChain: []*x509.Certificate{cert, {}},
		}}, verifyCertificates("mackms:label="+cert.Subject.CommonName, "", []*x509.Certificate{cert}), assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "fail duplicated" {
				t.Log("foo")
			}
			k := &MacKMS{}
			tt.assertion(t, k.StoreCertificateChain(tt.args.req))
			tt.verify(t)
		})
	}
}

func TestMacKMS_StoreCertificateChain_privatekey(t *testing.T) {
	testName := t.Name()

	ca, err := minica.New(minica.WithName(testName))
	require.NoError(t, err)

	resp := createKey(t, testName, apiv1.SHA256WithRSA)
	cert, err := ca.Sign(&x509.Certificate{
		Subject:        pkix.Name{CommonName: testName + "@example.com"},
		EmailAddresses: []string{testName + "@example.com"},
		PublicKey:      resp.PublicKey,
	})
	require.NoError(t, err)

	type args struct {
		req *apiv1.StoreCertificateChainRequest
	}
	tests := []struct {
		name    string
		k       *MacKMS
		args    args
		cleanup func(t *testing.T)
	}{
		{"ok", &MacKMS{}, args{&apiv1.StoreCertificateChainRequest{
			Name:             "mackms:" + testName,
			CertificateChain: []*x509.Certificate{cert, ca.Intermediate},
		}}, func(t *testing.T) {
			deleteCertificate(t, testName, cert)
			deleteCertificate(t, ca.Intermediate.Subject.CommonName, ca.Intermediate)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() { tt.cleanup(t) })
			k := &MacKMS{}
			if assert.NoError(t, k.StoreCertificateChain(tt.args.req)) {
				assert.Error(t, k.StoreCertificateChain(tt.args.req))
			}
		})
	}
}

func TestMacKMS_DeleteCertificate(t *testing.T) {
	testName := t.Name()
	ca, err := minica.New(minica.WithName(testName))
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert1, err := ca.Sign(&x509.Certificate{
		Subject:        pkix.Name{CommonName: testName + "1@example.com"},
		EmailAddresses: []string{testName + "1@example.com"},
		PublicKey:      key.Public(),
	})
	require.NoError(t, err)

	cert2, err := ca.Sign(&x509.Certificate{
		Subject:        pkix.Name{CommonName: testName + "2@example.com"},
		EmailAddresses: []string{testName + "2@example.com"},
		PublicKey:      key.Public(),
	})
	require.NoError(t, err)

	cert3, err := ca.Sign(&x509.Certificate{
		Subject:        pkix.Name{CommonName: testName + "3@example.com"},
		EmailAddresses: []string{testName + "3@example.com"},
		PublicKey:      key.Public(),
	})
	require.NoError(t, err)

	suffix, err := randutil.Alphanumeric(8)
	require.NoError(t, err)

	notExistsCheck := func(cert *x509.Certificate) {
		kms := &MacKMS{}
		_, err := kms.LoadCertificate(&apiv1.LoadCertificateRequest{
			Name: "mackms:serial=" + hex.EncodeToString(cert.SerialNumber.Bytes()),
		})
		assert.ErrorIs(t, err, apiv1.NotFoundError{})
	}

	kms := &MacKMS{}
	require.NoError(t, kms.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name: "mackms:", Certificate: ca.Root,
	}))
	t.Cleanup(func() { notExistsCheck(ca.Root) })
	require.NoError(t, kms.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name: "mackms:label=test-intermediate-" + suffix, Certificate: ca.Intermediate,
	}))
	t.Cleanup(func() { notExistsCheck(ca.Intermediate) })
	require.NoError(t, kms.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name: "mackms:", Certificate: cert1,
	}))
	t.Cleanup(func() { notExistsCheck(cert1) })
	require.NoError(t, kms.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name: "mackms:label=test-leaf-" + suffix, Certificate: cert2,
	}))
	t.Cleanup(func() { notExistsCheck(cert2) })
	require.NoError(t, kms.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name: "mackms:", Certificate: cert3,
	}))
	t.Cleanup(func() {
		deleteCertificate(t, "", cert3)
		notExistsCheck(cert3)
	})

	type args struct {
		req *apiv1.DeleteCertificateRequest
	}
	tests := []struct {
		name      string
		m         *MacKMS
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", &MacKMS{}, args{&apiv1.DeleteCertificateRequest{
			Name: "mackms:" + ca.Root.Subject.CommonName,
		}}, assert.NoError},
		{"ok label", &MacKMS{}, args{&apiv1.DeleteCertificateRequest{
			Name: "mackms:label=test-intermediate-" + suffix,
		}}, assert.NoError},
		{"ok serial", &MacKMS{}, args{&apiv1.DeleteCertificateRequest{
			Name: "mackms:serial=" + hex.EncodeToString(cert1.SerialNumber.Bytes()),
		}}, assert.NoError},
		{"ok label and serial", &MacKMS{}, args{&apiv1.DeleteCertificateRequest{
			Name: "mackms:label=test-leaf-" + suffix + ";serial=" + hex.EncodeToString(cert2.SerialNumber.Bytes()),
		}}, assert.NoError},
		{"fail name", &MacKMS{}, args{&apiv1.DeleteCertificateRequest{}}, assert.Error},
		{"fail uri", &MacKMS{}, args{&apiv1.DeleteCertificateRequest{Name: "mackms"}}, assert.Error},
		{"fail missing", &MacKMS{}, args{&apiv1.DeleteCertificateRequest{Name: "mackms:label=" + testName}}, assert.Error},
		{"fail keychain", &MacKMS{}, args{&apiv1.DeleteCertificateRequest{Name: "mackms:keychain=dataProtection;label=" + cert3.Subject.CommonName}}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MacKMS{}
			tt.assertion(t, m.DeleteCertificate(tt.args.req))
		})
	}
}

func Test_apiv1Error(t *testing.T) {
	type args struct {
		err error
	}
	tests := []struct {
		name      string
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		{"ok not found", args{security.ErrNotFound}, func(t assert.TestingT, err error, msg ...interface{}) bool {
			return assert.ErrorIs(t, err, apiv1.NotFoundError{}, msg...)
		}},
		{"ok not found wrapped", args{fmt.Errorf("something happened: %w", security.ErrNotFound)}, func(t assert.TestingT, err error, msg ...interface{}) bool {
			return assert.ErrorIs(t, err, apiv1.NotFoundError{}, msg...)
		}},
		{"ok already exists", args{security.ErrAlreadyExists}, func(t assert.TestingT, err error, msg ...interface{}) bool {
			return assert.ErrorIs(t, err, apiv1.AlreadyExistsError{}, msg...)
		}},
		{"ok already exists wrapped", args{fmt.Errorf("something happened: %w", security.ErrAlreadyExists)}, func(t assert.TestingT, err error, msg ...interface{}) bool {
			return assert.ErrorIs(t, err, apiv1.AlreadyExistsError{}, msg...)
		}},
		{"ok other", args{io.ErrUnexpectedEOF}, func(t assert.TestingT, err error, msg ...interface{}) bool {
			return assert.ErrorIs(t, err, io.ErrUnexpectedEOF, msg...)
		}},
		{"ok other wrapped", args{fmt.Errorf("something happened: %w", io.ErrUnexpectedEOF)}, func(t assert.TestingT, err error, msg ...interface{}) bool {
			return assert.ErrorIs(t, err, io.ErrUnexpectedEOF, msg...)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, apiv1Error(tt.args.err))
		})
	}
}

func TestMacKMS_SearchKeys(t *testing.T) {
	name, err := randutil.Hex(10)
	require.NoError(t, err)
	tag := fmt.Sprintf("com.smallstep.crypto.test.%s", name) // unique tag per test execution

	// initialize MacKMS
	k := &MacKMS{}

	// search by tag; expect 0 keys before the test
	got, err := k.SearchKeys(&apiv1.SearchKeysRequest{Query: fmt.Sprintf("mackms:tag=%s", tag)})
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Len(t, got.Results, 0)

	key1, err := k.CreateKey(&apiv1.CreateKeyRequest{Name: fmt.Sprintf("mackms:name=test-step-1;label=test-step-1;tag=%s;se=false", tag)})
	require.NoError(t, err)
	key2, err := k.CreateKey(&apiv1.CreateKeyRequest{Name: fmt.Sprintf("mackms:name=test-step-2;label=test-step-2;tag=%s;se=false", tag)})
	require.NoError(t, err)
	u1, err := uri.ParseWithScheme(Scheme, key1.Name)
	require.NoError(t, err)
	u2, err := uri.ParseWithScheme(Scheme, key2.Name)
	require.NoError(t, err)
	expectedHashes := []string{u1.Get("hash"), u2.Get("hash")}
	require.Len(t, expectedHashes, 2)
	t.Cleanup(func() {
		err = k.DeleteKey(&apiv1.DeleteKeyRequest{Name: key1.Name})
		require.NoError(t, err)
		err = k.DeleteKey(&apiv1.DeleteKeyRequest{Name: key2.Name})
		require.NoError(t, err)
	})

	// search by tag
	got, err = k.SearchKeys(&apiv1.SearchKeysRequest{Query: fmt.Sprintf("mackms:tag=%s", tag)})
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Len(t, got.Results, 2)

	// check if the correct keys were found by comparing hashes
	var hashes []string
	for _, key := range got.Results {
		u, err := uri.ParseWithScheme(Scheme, key.Name)
		require.NoError(t, err)
		assert.Equal(t, tag, u.Get("tag"))
		if hash := u.Get("hash"); hash != "" {
			hashes = append(hashes, hash)
		}

	}

	assert.Equal(t, expectedHashes, hashes)
}

func Test_keyAttributes_retryAttributes(t *testing.T) {
	type fields struct {
		label string
		tag   string
		hash  []byte
		retry bool
	}

	mustFields := func(s string) fields {
		t.Helper()
		u, err := parseURI(s)
		require.NoError(t, err)
		return fields{
			label: u.label,
			tag:   u.tag,
			hash:  u.hash,
			retry: u.retry,
		}
	}

	tests := []struct {
		name   string
		fields fields
		want   *keyAttributes
	}{
		{"with tag", mustFields("mackms:label=label;tag=tag"), nil},
		{"with tag and hash", mustFields("mackms:label=label;hash=FF00;tag=tag"), nil},
		{"with empty tag", mustFields("mackms:label=label;tag="), nil},
		{"with no tag", mustFields("mackms:label=label;hash=FF00"), &keyAttributes{
			label: "label",
			hash:  []byte{0xFF, 0x00},
		}},
		{"legacy name only", mustFields("label"), &keyAttributes{
			label: "label",
		}},
		{"legacy with schema", mustFields("mackms:label"), &keyAttributes{
			label: "label",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &keyAttributes{
				label: tt.fields.label,
				tag:   tt.fields.tag,
				hash:  tt.fields.hash,
				retry: tt.fields.retry,
			}
			if tt.name == "with no tag" {
				t.Log("foo")
			}
			assert.Equal(t, tt.want, k.retryAttributes())
		})
	}
}

func Test_isDataProtectionKeychain(t *testing.T) {
	v := UseDataProtectionKeychain
	t.Cleanup(func() {
		UseDataProtectionKeychain = v
	})

	type fields struct {
		useDataProtectionKeychain bool
	}
	type args struct {
		s string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{"dataProtection", fields{false}, args{"dataProtection"}, true},
		{"login", fields{false}, args{"login"}, false},
		{"system", fields{false}, args{"system"}, false},
		{"default", fields{false}, args{""}, false},
		{"default dataProtection", fields{true}, args{""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			UseDataProtectionKeychain = tt.fields.useDataProtectionKeychain
			assert.Equal(t, tt.want, isDataProtectionKeychain(tt.args.s))
		})
	}
}

func Test_createHash(t *testing.T) {
	testName := t.Name()

	ecKey := mustCreateKey(t, testName+"-ec", apiv1.ECDSAWithSHA256)
	rsaKey := mustCreateKey(t, testName+"-rsa", apiv1.SHA256WithRSA)

	edKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ec224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	getHash := func(r *apiv1.CreateKeyResponse) []byte {
		t.Helper()
		u, err := parseURI(r.Name)
		require.NoError(t, err)
		return u.hash
	}

	type args struct {
		key crypto.PublicKey
	}
	tests := []struct {
		name      string
		args      args
		want      []byte
		assertion assert.ErrorAssertionFunc
	}{
		{"ok ec", args{ecKey.PublicKey}, getHash(ecKey), assert.NoError},
		{"ok rsa", args{rsaKey.PublicKey}, getHash(rsaKey), assert.NoError},
		{"fail ed25519", args{edKey}, nil, assert.Error},
		{"fail ec224", args{ec224}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createHash(tt.args.key)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
