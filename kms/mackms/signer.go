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
	"crypto/ecdsa"
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
