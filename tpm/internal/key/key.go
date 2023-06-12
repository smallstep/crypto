// CODE COPIED FROM github.com/google/go-attestation; DO NOT EDIT!
//
// Copyright 2019 Google Inc.
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

//nolint:errorlint,revive // copied code from github.com/google/go-attestation
package key

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	// Defined in "Registry of reserved TPM 2.0 handles and localities".
	nvramCertIndex    = 0x1c00002
	nvramEkNonceIndex = 0x1c00003

	// Defined in "Registry of reserved TPM 2.0 handles and localities", and checked on a glinux machine.
	commonSrkEquivalentHandle = 0x81000001
	commonEkEquivalentHandle  = 0x81010001
)

// Key encodings
const (
	keyEncodingInvalid keyEncoding = iota
	// Managed by the OS but loadable by name.
	keyEncodingOSManaged
	// Key fully represented but in encrypted form.
	keyEncodingEncrypted
	// Parameters stored, but key must be regenerated before use.
	keyEncodingParameterized
)

// keyEncoding indicates how an exported TPM key is represented.
type keyEncoding uint8

func (e keyEncoding) String() string {
	switch e {
	case keyEncodingInvalid:
		return "invalid"
	case keyEncodingOSManaged:
		return "os-managed"
	case keyEncodingEncrypted:
		return "encrypted"
	case keyEncodingParameterized:
		return "parameterized"
	default:
		return fmt.Sprintf("keyEncoding<%d>", int(e))
	}
}

// serializedKey represents a loadable, TPM-backed key.
type serializedKey struct {
	// Encoding describes the strategy by which the key should be
	// loaded/unloaded.
	Encoding keyEncoding `json:"KeyEncoding"`
	// TPMVersion describes the version of the TPM which the key was generated
	// on. deserializeKey() returns an error if it attempts to deserialize a key
	// which is from a different TPM version to the currently opened TPM.
	TPMVersion uint8

	// Public represents the public key, in a TPM-specific format. This
	// field is populated on all platforms and TPM versions.
	Public []byte
	// The following fields are only valid for TPM 2.0 hardware, holding
	// information returned as the result to a TPM2_CertifyCreation command.
	// These are stored alongside the key for later use, as the certification
	// can only be obtained immediately after the key is generated.
	CreateData        []byte
	CreateAttestation []byte
	CreateSignature   []byte

	// Name is only valid for KeyEncodingOSManaged, which is only used
	// on Windows.
	Name string
	// Blob represents the key material for KeyEncodingEncrypted keys. This
	// is only used on Linux.
	Blob []byte `json:"KeyBlob"`
}

// Serialize represents the key in a persistent format which may be
// loaded at a later time using deserializeKey().
func (k *serializedKey) Serialize() ([]byte, error) {
	return json.Marshal(k)
}

type CreateConfig struct {
	// Algorithm to be used, either RSA or ECDSA.
	Algorithm string
	// Size is used to specify the bit size of the key or elliptic curve. For
	// example, '256' is used to specify curve P-256.
	Size int
}

func (c *CreateConfig) Validate() error {
	switch c.Algorithm {
	case "RSA":
		if c.Size > 2048 {
			return fmt.Errorf("%d bits RSA keys are (currently) not supported; maximum is 2048", c.Size)
		}
	case "ECDSA":
		break
	default:
		return fmt.Errorf("unsupported algorithm %q", c.Algorithm)
	}
	return nil
}

var tpmEkTemplate *tpm2.Public

func ekTemplate(rwc io.ReadWriteCloser) (tpm2.Public, error) {
	if tpmEkTemplate != nil {
		return *tpmEkTemplate, nil
	}

	nonce, err := tpm2.NVReadEx(rwc, nvramEkNonceIndex, tpm2.HandleOwner, "", 0)
	if err != nil {
		tpmEkTemplate = &defaultEKTemplate // No nonce, use the default template
	} else {
		template := defaultEKTemplate
		copy(template.RSAParameters.ModulusRaw, nonce)
		tpmEkTemplate = &template
	}

	return *tpmEkTemplate, nil
}

// Return value: handle, whether we generated a new one, error
func getPrimaryKeyHandle(rwc io.ReadWriteCloser, pHnd tpmutil.Handle) (tpmutil.Handle, bool, error) {
	_, _, _, err := tpm2.ReadPublic(rwc, pHnd)
	if err == nil {
		// Found the persistent handle, assume it's the key we want.
		return pHnd, false, nil
	}
	rerr := err // Preserve this failure for later logging, if needed

	var keyHnd tpmutil.Handle
	switch pHnd {
	case commonSrkEquivalentHandle:
		keyHnd, _, err = tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", defaultSRKTemplate)
	case commonEkEquivalentHandle:
		var tmpl tpm2.Public
		if tmpl, err = ekTemplate(rwc); err != nil {
			return 0, false, fmt.Errorf("ek template: %v", err)
		}
		keyHnd, _, err = tpm2.CreatePrimary(rwc, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", tmpl)
	}
	if err != nil {
		return 0, false, fmt.Errorf("ReadPublic failed (%v), and then CreatePrimary failed: %v", rerr, err)
	}
	defer tpm2.FlushContext(rwc, keyHnd)

	err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, keyHnd, pHnd)
	if err != nil {
		return 0, false, fmt.Errorf("EvictControl failed: %v", err)
	}

	return pHnd, true, nil
}

// Algorithm indicates an asymmetric algorithm to be used.
type Algorithm string

// Algorithm types supported.
const (
	ECDSA Algorithm = "ECDSA"
	RSA   Algorithm = "RSA"
)

type KeyConfig struct {
	Algorithm Algorithm
	Size      int
}

var (
	defaultSRKTemplate = tpm2.Public{
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
	// Default EK template defined in:
	// https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
	defaultEKTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{
			0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
			0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
			0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
			0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
			0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
			0x69, 0xAA,
		},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}
	// Basic template for an ECDSA key signing outside-TPM objects. Other
	// fields are populated depending on the key creation options.
	ecdsaKeyTemplate = tpm2.Public{
		Type:       tpm2.AlgECC,
		Attributes: tpm2.FlagSignerDefault ^ tpm2.FlagRestricted,
		ECCParameters: &tpm2.ECCParams{
			Sign: &tpm2.SigScheme{
				Alg: tpm2.AlgECDSA,
			},
		},
	}
	// Basic template for an RSA key signing outside-TPM objects. Other
	// fields are populated depending on the key creation options.
	rsaKeyTemplate = tpm2.Public{
		Type:          tpm2.AlgRSA,
		NameAlg:       tpm2.AlgSHA256,
		Attributes:    tpm2.FlagSignerDefault ^ tpm2.FlagRestricted,
		RSAParameters: &tpm2.RSAParams{},
	}
)

func templateFromConfig(opts *KeyConfig) (tpm2.Public, error) {
	var tmpl tpm2.Public
	switch opts.Algorithm {
	case RSA:
		tmpl = rsaKeyTemplate
		if opts.Size < 0 || opts.Size > 65535 { // basic sanity check
			return tmpl, fmt.Errorf("incorrect size parameter")
		}
		tmpl.RSAParameters.KeyBits = uint16(opts.Size)

	case ECDSA:
		tmpl = ecdsaKeyTemplate
		switch opts.Size {
		case 256:
			tmpl.NameAlg = tpm2.AlgSHA256
			tmpl.ECCParameters.Sign.Hash = tpm2.AlgSHA256
			tmpl.ECCParameters.CurveID = tpm2.CurveNISTP256
			tmpl.ECCParameters.Point = tpm2.ECPoint{
				XRaw: make([]byte, 32),
				YRaw: make([]byte, 32),
			}
		case 384:
			tmpl.NameAlg = tpm2.AlgSHA384
			tmpl.ECCParameters.Sign.Hash = tpm2.AlgSHA384
			tmpl.ECCParameters.CurveID = tpm2.CurveNISTP384
			tmpl.ECCParameters.Point = tpm2.ECPoint{
				XRaw: make([]byte, 48),
				YRaw: make([]byte, 48),
			}
		case 521:
			tmpl.NameAlg = tpm2.AlgSHA512
			tmpl.ECCParameters.Sign.Hash = tpm2.AlgSHA512
			tmpl.ECCParameters.CurveID = tpm2.CurveNISTP521
			tmpl.ECCParameters.Point = tpm2.ECPoint{
				XRaw: make([]byte, 66),
				YRaw: make([]byte, 66),
			}
		default:
			return tmpl, fmt.Errorf("unsupported key size: %v", opts.Size)
		}
	default:
		return tmpl, fmt.Errorf("unsupported algorithm type: %q", opts.Algorithm)
	}

	return tmpl, nil
}
