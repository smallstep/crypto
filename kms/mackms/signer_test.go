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
//
// Part of this code is based on
// https://github.com/facebookincubator/sks/blob/183e7561ecedc71992f23b2d37983d2948391f4c/macos/macos.go

package mackms

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/kms/apiv1"
)

func createKey(t *testing.T, name string, sa apiv1.SignatureAlgorithm) *apiv1.CreateKeyResponse {
	t.Helper()

	kms := &MacKMS{}
	resp, err := kms.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "mackms:label=" + name,
		SignatureAlgorithm: sa,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, kms.DeleteKey(&apiv1.DeleteKeyRequest{
			Name: resp.Name,
		}))
	})
	return resp
}

func TestECDH_ECDH(t *testing.T) {
	goP256, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	goP384, err := ecdh.P384().GenerateKey(rand.Reader)
	require.NoError(t, err)
	goP521, err := ecdh.P521().GenerateKey(rand.Reader)
	require.NoError(t, err)
	goX25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	kms := &MacKMS{}
	p256 := createKey(t, t.Name()+"-p256", apiv1.ECDSAWithSHA256)
	s256, err := kms.CreateSigner(&p256.CreateSignerRequest)
	require.NoError(t, err)
	p384 := createKey(t, t.Name()+"-p384", apiv1.ECDSAWithSHA384)
	s384, err := kms.CreateSigner(&p384.CreateSignerRequest)
	require.NoError(t, err)
	p521 := createKey(t, t.Name()+"-p521", apiv1.ECDSAWithSHA512)
	s521, err := kms.CreateSigner(&p521.CreateSignerRequest)
	require.NoError(t, err)

	type fields struct {
		Signer *Signer
	}
	type args struct {
		pub *ecdh.PublicKey
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantFunc  func(t *testing.T, got []byte)
		assertion assert.ErrorAssertionFunc
	}{
		{"ok P256", fields{s256.(*Signer)}, args{goP256.PublicKey()}, func(t *testing.T, got []byte) {
			pub, ok := s256.Public().(*ecdsa.PublicKey)
			require.True(t, ok)
			ecdhPub, err := pub.ECDH()
			require.NoError(t, err)
			sharedSecret, err := goP256.ECDH(ecdhPub)
			require.NoError(t, err)
			assert.Equal(t, sharedSecret, got)
		}, assert.NoError},
		{"ok P384", fields{s384.(*Signer)}, args{goP384.PublicKey()}, func(t *testing.T, got []byte) {
			pub, ok := s384.Public().(*ecdsa.PublicKey)
			require.True(t, ok)
			ecdhPub, err := pub.ECDH()
			require.NoError(t, err)
			sharedSecret, err := goP384.ECDH(ecdhPub)
			require.NoError(t, err)
			assert.Equal(t, sharedSecret, got)
		}, assert.NoError},
		{"ok P521", fields{s521.(*Signer)}, args{goP521.PublicKey()}, func(t *testing.T, got []byte) {
			pub, ok := s521.Public().(*ecdsa.PublicKey)
			require.True(t, ok)
			ecdhPub, err := pub.ECDH()
			require.NoError(t, err)
			sharedSecret, err := goP521.ECDH(ecdhPub)
			require.NoError(t, err)
			assert.Equal(t, sharedSecret, got)
		}, assert.NoError},
		{"fail missing", fields{&Signer{
			keyAttributes: &keyAttributes{tag: DefaultTag, label: t.Name() + "-missing"},
		}}, args{goP256.PublicKey()}, func(t *testing.T, got []byte) {
			assert.Nil(t, got)
		}, assert.Error},
		{"fail SecKeyCreateWithData", fields{s256.(*Signer)}, args{goX25519.PublicKey()}, func(t *testing.T, got []byte) {
			assert.Nil(t, got)
		}, assert.Error},
		{"fail SecKeyCopyKeyExchangeResult", fields{s256.(*Signer)}, args{goP384.PublicKey()}, func(t *testing.T, got []byte) {
			assert.Nil(t, got)
		}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ECDH{
				Signer: tt.fields.Signer,
			}
			got, err := e.ECDH(tt.args.pub)
			tt.assertion(t, err)
			tt.wantFunc(t, got)
		})
	}
}

func TestECDH_Curve(t *testing.T) {
	kms := &MacKMS{}
	p256 := createKey(t, t.Name()+"-p256", apiv1.ECDSAWithSHA256)
	s256, err := kms.CreateSigner(&p256.CreateSignerRequest)
	require.NoError(t, err)
	p384 := createKey(t, t.Name()+"-p384", apiv1.ECDSAWithSHA384)
	s384, err := kms.CreateSigner(&p384.CreateSignerRequest)
	require.NoError(t, err)
	p521 := createKey(t, t.Name()+"-p521", apiv1.ECDSAWithSHA512)
	s521, err := kms.CreateSigner(&p521.CreateSignerRequest)
	require.NoError(t, err)

	rsaKey := createKey(t, t.Name()+"-rsa", apiv1.SHA256WithRSA)
	rsaSigmer, err := kms.CreateSigner(&rsaKey.CreateSignerRequest)
	require.NoError(t, err)

	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	type fields struct {
		Signer *Signer
	}
	tests := []struct {
		name   string
		fields fields
		want   ecdh.Curve
	}{
		{"P256", fields{s256.(*Signer)}, ecdh.P256()},
		{"P384", fields{s384.(*Signer)}, ecdh.P384()},
		{"P521", fields{s521.(*Signer)}, ecdh.P521()},
		{"P224", fields{&Signer{pub: p224.Public()}}, nil},
		{"RSA", fields{rsaSigmer.(*Signer)}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ECDH{
				Signer: tt.fields.Signer,
			}
			assert.Equal(t, tt.want, e.Curve())
		})
	}
}

func TestECDH_PublicKey(t *testing.T) {
	kms := &MacKMS{}
	p256 := createKey(t, t.Name()+"-p256", apiv1.ECDSAWithSHA256)
	s256, err := kms.CreateSigner(&p256.CreateSignerRequest)
	require.NoError(t, err)
	p384 := createKey(t, t.Name()+"-p384", apiv1.ECDSAWithSHA384)
	s384, err := kms.CreateSigner(&p384.CreateSignerRequest)
	require.NoError(t, err)
	p521 := createKey(t, t.Name()+"-p521", apiv1.ECDSAWithSHA512)
	s521, err := kms.CreateSigner(&p521.CreateSignerRequest)
	require.NoError(t, err)

	rsaKey := createKey(t, t.Name()+"-rsa", apiv1.SHA256WithRSA)
	rsaSigmer, err := kms.CreateSigner(&rsaKey.CreateSignerRequest)
	require.NoError(t, err)

	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	mustPublicKey := func(k crypto.PublicKey) *ecdh.PublicKey {
		pub, ok := k.(*ecdsa.PublicKey)
		require.True(t, ok)
		ecdhPub, err := pub.ECDH()
		require.NoError(t, err)
		return ecdhPub
	}

	type fields struct {
		Signer *Signer
	}
	tests := []struct {
		name   string
		fields fields
		want   *ecdh.PublicKey
	}{
		{"P256", fields{s256.(*Signer)}, mustPublicKey(p256.PublicKey)},
		{"P384", fields{s384.(*Signer)}, mustPublicKey(p384.PublicKey)},
		{"P521", fields{s521.(*Signer)}, mustPublicKey(p521.PublicKey)},
		{"P224", fields{&Signer{pub: p224.Public()}}, nil},
		{"RSA", fields{rsaSigmer.(*Signer)}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ECDH{
				Signer: tt.fields.Signer,
			}
			assert.Equal(t, tt.want, e.PublicKey())
		})
	}
}
