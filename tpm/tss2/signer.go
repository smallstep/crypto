// Copyright 2023 Smallstep Labs, Inc
// Copyright 2023 David Woodhouse, @dwmw2
// Copyright 2023 @google/go-tpm-admin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tss2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	// ECCSRKTemplate contains the TCG reference ECC-P256 SRK template.
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	ECCSRKTemplate = tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagStorageDefault | tpm2.FlagNoDA,
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			Sign: &tpm2.SigScheme{
				Alg: tpm2.AlgNull,
			},
			CurveID: tpm2.CurveNISTP256,
		},
	}

	// RSASRKTemplate contains the TCG reference RSA-2048 SRK template.
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	RSASRKTemplate = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagStorageDefault | tpm2.FlagNoDA,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			ModulusRaw: make([]byte, 256),
			KeyBits:    2048,
		},
	}
)

// Public returns the Go version of the public key.
func (k *TPMKey) Public() (crypto.PublicKey, error) {
	public, err := tpm2.DecodePublic(k.PublicKey[2:])
	if err != nil {
		return nil, err
	}
	return public.Key()
}

// Signer implements [crypto.Signer] using a [TPMKey].
type Signer struct {
	m           sync.Mutex
	rw          io.ReadWriter
	publicKey   crypto.PublicKey
	tpmKey      *TPMKey
	srkTemplate tpm2.Public
}

// CreateSigner creates a new [crypto.Signer] with the given TPM (rw) and
// [TPMKey]. The caller is responsible for opening and closing the TPM.
func CreateSigner(rw io.ReadWriter, key *TPMKey) (*Signer, error) {
	switch {
	case rw == nil:
		return nil, fmt.Errorf("invalid TPM channel: rw cannot be nil")
	case key == nil:
		return nil, fmt.Errorf("invalid TPM key: key cannot be nil")
	case !key.Type.Equal(oidLoadableKey):
		return nil, fmt.Errorf("invalid TSS2 key: type %q is not valid", key.Type.String())
	case len(key.Policy) != 0:
		return nil, errors.New("invalid TSS2 key: policy is not implemented")
	case len(key.AuthPolicy) != 0:
		return nil, errors.New("invalid TSS2 key: auth policy is not implemented")
	case len(key.Secret) > 0:
		return nil, errors.New("invalid TSS2 key: secret should not be set")
	case !validateParent(key.Parent):
		return nil, fmt.Errorf("invalid TSS2 key: parent '%d' is not valid", key.Parent)
	case !validateKey(key.PublicKey):
		return nil, errors.New("invalid TSS2 key: public key is invalid")
	case !validateKey(key.PrivateKey):
		return nil, errors.New("invalid TSS2 key: private key key is invalid")
	}

	publicKey, err := key.Public()
	if err != nil {
		return nil, fmt.Errorf("error decoding TSS2 public key: %w", err)
	}

	return &Signer{
		rw:          rw,
		publicKey:   publicKey,
		tpmKey:      key,
		srkTemplate: RSASRKTemplate,
	}, nil
}

// SetSRKTemplate allows to change the Storage Root Key (SRK) template used
// to load the the public/private blobs into an object in the TPM.
//
// It currently defaults to [RSASRKTemplate], the same used as the default in the
// [go.step.sm/crypto/tpm] package.
//
// # Experimental
//
// Notice: This API is EXPERIMENTAL and may be changed or removed in a later
// release.
func (s *Signer) SetSRKTemplate(p tpm2.Public) {
	s.m.Lock()
	s.srkTemplate = p
	s.m.Unlock()
}

// SetCommandChannel allows to change the TPM channel. This operation is useful
// if the channel set in [CreateSigner] is closed and opened again before
// calling [Signer.Sign].
//
// # Experimental
//
// Notice: This API is EXPERIMENTAL and may be changed or removed in a later
// release.
func (s *Signer) SetCommandChannel(rw io.ReadWriter) {
	s.m.Lock()
	s.rw = rw
	s.m.Unlock()
}

// Public implements the [crypto.Signer] interface.
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign implements the [crypto.Signer] interface.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	parentHandle := tpmutil.Handle(s.tpmKey.Parent)
	if !handleIsPersistent(s.tpmKey.Parent) {
		parentHandle, _, err = tpm2.CreatePrimary(s.rw, parentHandle, tpm2.PCRSelection{}, "", "", s.srkTemplate)
		if err != nil {
			return nil, fmt.Errorf("error creating primary: %w", err)
		}
		defer tpm2.FlushContext(s.rw, parentHandle)
	}

	keyHandle, _, err := tpm2.Load(s.rw, parentHandle, "", s.tpmKey.PublicKey[2:], s.tpmKey.PrivateKey[2:])
	if err != nil {
		return nil, fmt.Errorf("error loading key handle: %w", err)
	}
	defer tpm2.FlushContext(s.rw, keyHandle)

	switch p := s.publicKey.(type) {
	case *ecdsa.PublicKey:
		return signECDSA(s.rw, keyHandle, digest, p.Curve)
	case *rsa.PublicKey:
		return signRSA(s.rw, keyHandle, digest, opts)
	default:
		return nil, fmt.Errorf("unsupported signing key type %T", s.publicKey)
	}
}

// https://github.com/smallstep/go-attestation/blob/f5480326fb6d63859537ec89fbea7c62485bc4da/attest/wrapped_tpm20.go#L513
func signECDSA(rw io.ReadWriter, key tpmutil.Handle, digest []byte, curve elliptic.Curve) ([]byte, error) {
	scheme, err := curveSigScheme(curve)
	if err != nil {
		return nil, err
	}
	sig, err := tpm2.Sign(rw, key, "", digest, nil, scheme)
	if err != nil {
		return nil, fmt.Errorf("error creating ECDSA signature: %w", err)
	}
	if sig.ECC == nil {
		return nil, fmt.Errorf("expected ECDSA signature, got: %v", sig.Alg)
	}
	return asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{sig.ECC.R, sig.ECC.S})
}

// https://github.com/smallstep/go-attestation/blob/f5480326fb6d63859537ec89fbea7c62485bc4da/attest/wrapped_tpm20.go#L527
func signRSA(rw io.ReadWriter, key tpmutil.Handle, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	h, err := tpm2.HashToAlgorithm(opts.HashFunc())
	if err != nil {
		return nil, fmt.Errorf("error getting algorithm: %w", err)
	}

	scheme := &tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: h,
	}

	if pss, ok := opts.(*rsa.PSSOptions); ok {
		if pss.SaltLength != rsa.PSSSaltLengthAuto && pss.SaltLength != rsa.PSSSaltLengthEqualsHash && pss.SaltLength != len(digest) {
			return nil, fmt.Errorf("invalid PSS salt length %d, expected rsa.PSSSaltLengthAuto, rsa.PSSSaltLengthEqualsHash or %d", pss.SaltLength, len(digest))
		}
		scheme.Alg = tpm2.AlgRSAPSS
	}

	sig, err := tpm2.Sign(rw, key, "", digest, nil, scheme)
	if err != nil {
		return nil, fmt.Errorf("error creating RSA signature: %w", err)
	}
	if sig.RSA == nil {
		return nil, fmt.Errorf("unexpected signature scheme %v", sig.Alg)
	}
	return sig.RSA.Signature, nil
}

func curveSigScheme(curve elliptic.Curve) (*tpm2.SigScheme, error) {
	scheme := &tpm2.SigScheme{
		Alg: tpm2.AlgECDSA,
	}
	switch curve {
	case elliptic.P256():
		scheme.Hash = tpm2.AlgSHA256
	case elliptic.P384():
		scheme.Hash = tpm2.AlgSHA384
	case elliptic.P521():
		scheme.Hash = tpm2.AlgSHA512
	default:
		return nil, fmt.Errorf("unsupported curve %s", curve.Params().Name)
	}

	return scheme, nil
}

func handleIsPersistent(h int) bool {
	return (h >> 24) == int(tpm2.HandleTypePersistent)
}

func validateParent(parent int) bool {
	return handleIsPersistent(parent) ||
		parent == int(tpm2.HandleOwner) ||
		parent == int(tpm2.HandleNull) ||
		parent == int(tpm2.HandleEndorsement) ||
		parent == int(tpm2.HandlePlatform)
}

func validateKey(b []byte) bool {
	return len(b) >= 2 && len(b)-2 == (int(b[0])<<8)+int(b[1])
}
