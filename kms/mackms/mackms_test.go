//go:build darwin && cgo

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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/randutil"
)

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
		{"ok", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: resp.Name}}, resp.PublicKey, assert.NoError},
		{"ok no uri", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: "test-p256"}}, resp.PublicKey, assert.NoError},
		{"ok uri simple", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: "mackms:test-p256"}}, resp.PublicKey, assert.NoError},
		{"ok uri label", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: "mackms:label=test-p256"}}, resp.PublicKey, assert.NoError},
		{"ok uri label + tag", &MacKMS{}, args{&apiv1.GetPublicKeyRequest{Name: "mackms:label=test-p256;tag=com.smallstep.crypto"}}, resp.PublicKey, assert.NoError},
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
