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
	"crypto/rsa"
	"fmt"
	"io"

	cf "go.step.sm/crypto/internal/darwin/corefoundation"
	"go.step.sm/crypto/internal/darwin/security"
)

// Signer implements the [crypto.Signer] interface using macOS Keychain or the
// Secure Enclave.
type Signer struct {
	*keyAttributes
	pub crypto.PublicKey
}

// Public returns the public key corresponding to the private key.
func (s *Signer) Public() crypto.PublicKey {
	return s.pub
}

// Sign signs digest with the private key. For an RSA key, the resulting
// signature will be either a PKCS #1 v1.5 or PSS signature (as indicated by
// opts). For an ECDSA key, it will be a DER-serialized, ASN.1 signature
// structure.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	algo, err := getSecKeyAlgorithm(s.pub, opts)
	if err != nil {
		return nil, fmt.Errorf("mackms Sign failed: %w", err)
	}

	key, err := getPrivateKey(s.keyAttributes)
	if err != nil {
		return nil, fmt.Errorf("mackms Sign failed: %w", err)
	}
	defer key.Release()

	cfDigest, err := cf.NewData(digest)
	if err != nil {
		return nil, fmt.Errorf("mackms Sign failed: %w", err)
	}
	defer cfDigest.Release()

	signature, err := security.SecKeyCreateSignature(key, algo, cfDigest)
	if err != nil {
		return nil, fmt.Errorf("mackms Sign failed: %w", err)
	}
	defer signature.Release()

	return signature.Bytes(), nil
}

// getSecKeyAlgorithm returns the appropriate SecKeyAlgorithm for the given key
// and options.
func getSecKeyAlgorithm(pub crypto.PublicKey, opts crypto.SignerOpts) (security.SecKeyAlgorithm, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return security.KSecKeyAlgorithmECDSASignatureDigestX962, nil
	case *rsa.PublicKey:
		size := opts.HashFunc().Size()
		// RSA-PSS
		if _, ok := opts.(*rsa.PSSOptions); ok {
			switch size {
			case 32: // SHA256
				return security.KSecKeyAlgorithmRSASignatureDigestPSSSHA256, nil
			case 48: // SHA384
				return security.KSecKeyAlgorithmRSASignatureDigestPSSSHA384, nil
			case 64: // SHA512
				return security.KSecKeyAlgorithmRSASignatureDigestPSSSHA512, nil
			default:
				return 0, fmt.Errorf("unsupported hash function %s", opts.HashFunc().String())
			}
		}
		// RSA PKCS#1
		switch size {
		case 32: // SHA256
			return security.KSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256, nil
		case 48: // SHA384
			return security.KSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384, nil
		case 64: // SHA512
			return security.KSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512, nil
		default:
			return 0, fmt.Errorf("unsupported hash function %s", opts.HashFunc().String())
		}
	default:
		return 0, fmt.Errorf("unsupported key type %T", pub)
	}
}

// ECDH extends [Signer] with ECDH exchange method.
//
// # Experimental
//
// Notice: This API is EXPERIMENTAL and may be changed or removed in a later
// release.
type ECDH struct {
	*Signer
}

// ECDH performs an ECDH exchange and returns the shared secret. The private key
// and public key must use the same curve.
//
// For NIST curves, this performs ECDH as specified in SEC 1, Version 2.0,
// Section 3.3.1, and returns the x-coordinate encoded according to SEC 1,
// Version 2.0, Section 2.3.5. The result is never the point at infinity.
//
// # Experimental
//
// Notice: This API is EXPERIMENTAL and may be changed or removed in a later
// release.
func (e *ECDH) ECDH(pub *ecdh.PublicKey) ([]byte, error) {
	key, err := getPrivateKey(e.Signer.keyAttributes)
	if err != nil {
		return nil, fmt.Errorf("mackms ECDH failed: %w", err)
	}
	defer key.Release()

	pubData, err := cf.NewData(pub.Bytes())
	if err != nil {
		return nil, fmt.Errorf("mackms ECDH failed: %w", err)
	}
	defer pubData.Release()

	pubDict, err := cf.NewDictionary(cf.Dictionary{
		security.KSecAttrKeyType:  security.KSecAttrKeyTypeECSECPrimeRandom,
		security.KSecAttrKeyClass: security.KSecAttrKeyClassPublic,
	})
	if err != nil {
		return nil, fmt.Errorf("mackms ECDH failed: %w", err)
	}
	defer pubDict.Release()

	pubRef, err := security.SecKeyCreateWithData(pubData, pubDict)
	if err != nil {
		return nil, fmt.Errorf("macOS SecKeyCreateWithData failed: %w", err)
	}
	defer pubRef.Release()

	sharedSecret, err := security.SecKeyCopyKeyExchangeResult(key, security.KSecKeyAlgorithmECDHKeyExchangeStandard, pubRef, &cf.DictionaryRef{})
	if err != nil {
		return nil, fmt.Errorf("macOS SecKeyCopyKeyExchangeResult failed: %w", err)
	}
	defer sharedSecret.Release()

	return sharedSecret.Bytes(), nil
}

// Curve returns the [ecdh.Curve] of the key. If the key is not an ECDSA key it
// will return nil.
//
// # Experimental
//
// Notice: This API is EXPERIMENTAL and may be changed or removed in a later
// release.
func (e *ECDH) Curve() ecdh.Curve {
	pub, ok := e.Signer.pub.(*ecdsa.PublicKey)
	if !ok {
		return nil
	}
	switch pub.Curve {
	case elliptic.P256():
		return ecdh.P256()
	case elliptic.P384():
		return ecdh.P384()
	case elliptic.P521():
		return ecdh.P521()
	default:
		return nil
	}
}

// PublicKey returns the [ecdh.PublicKey] representation of the key. If the key
// is not an ECDSA or it cannot be converted it will return nil.
//
// # Experimental
//
// Notice: This API is EXPERIMENTAL and may be changed or removed in a later
// release.
func (e *ECDH) PublicKey() *ecdh.PublicKey {
	pub, ok := e.Signer.pub.(*ecdsa.PublicKey)
	if !ok {
		return nil
	}
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return nil
	}
	return ecdhPub
}
