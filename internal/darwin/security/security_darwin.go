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

package security

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"

	cf "go.step.sm/crypto/internal/darwin/corefoundation"
)

const (
	nilSecKey           C.SecKeyRef           = 0
	nilSecAccessControl C.SecAccessControlRef = 0
	nilCFString         C.CFStringRef         = 0
)

var ErrNotFound = errors.New("not found")

var (
	KSecAttrAccessControl                            = cf.TypeRef(C.kSecAttrAccessControl)
	KSecAttrAccessibleWhenUnlocked                   = cf.TypeRef(C.kSecAttrAccessibleWhenUnlocked)
	KSecAttrAccessibleWhenPasscodeSetThisDeviceOnly  = cf.TypeRef(C.kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)
	KSecAttrAccessibleWhenUnlockedThisDeviceOnly     = cf.TypeRef(C.kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
	KSecAttrAccessibleAfterFirstUnlock               = cf.TypeRef(C.kSecAttrAccessibleAfterFirstUnlock)
	KSecAttrAccessibleAfterFirstUnlockThisDeviceOnly = cf.TypeRef(C.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
	KSecAttrApplicationLabel                         = cf.TypeRef(C.kSecAttrApplicationLabel)
	KSecAttrApplicationTag                           = cf.TypeRef(C.kSecAttrApplicationTag)
	KSecAttrIsPermanent                              = cf.TypeRef(C.kSecAttrIsPermanent)
	KSecAttrKeyClass                                 = cf.TypeRef(C.kSecAttrKeyClass)
	KSecAttrKeyClassPrivate                          = cf.TypeRef(C.kSecAttrKeyClassPrivate)
	KSecAttrKeyClassPublic                           = cf.TypeRef(C.kSecAttrKeyClassPublic)
	KSecAttrKeySizeInBits                            = cf.TypeRef(C.kSecAttrKeySizeInBits)
	KSecAttrKeyType                                  = cf.TypeRef(C.kSecAttrKeyType)
	KSecAttrKeyTypeECSECPrimeRandom                  = cf.TypeRef(C.kSecAttrKeyTypeECSECPrimeRandom)
	KSecAttrKeyTypeRSA                               = cf.TypeRef(C.kSecAttrKeyTypeRSA)
	KSecAttrLabel                                    = cf.TypeRef(C.kSecAttrLabel)
	KSecAttrTokenID                                  = cf.TypeRef(C.kSecAttrTokenID)
	KSecAttrTokenIDSecureEnclave                     = cf.TypeRef(C.kSecAttrTokenIDSecureEnclave)
	KSecClass                                        = cf.TypeRef(C.kSecClass)
	KSecClassKey                                     = cf.TypeRef(C.kSecClassKey)
	KSecMatchLimit                                   = cf.TypeRef(C.kSecMatchLimit)
	KSecMatchLimitOne                                = cf.TypeRef(C.kSecMatchLimitOne)
	KSecPublicKeyAttrs                               = cf.TypeRef(C.kSecPublicKeyAttrs)
	KSecPrivateKeyAttrs                              = cf.TypeRef(C.kSecPrivateKeyAttrs)
	KSecReturnRef                                    = cf.TypeRef(C.kSecReturnRef)
	KSecValueRef                                     = cf.TypeRef(C.kSecValueRef)
)

type SecKeyAlgorithm = C.SecKeyAlgorithm

var (
	KSecKeyAlgorithmECDSASignatureDigestX962         = SecKeyAlgorithm(C.kSecKeyAlgorithmECDSASignatureDigestX962)
	KSecKeyAlgorithmECDSASignatureDigestX962SHA256   = SecKeyAlgorithm(C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256)
	KSecKeyAlgorithmECDSASignatureDigestX962SHA384   = SecKeyAlgorithm(C.kSecKeyAlgorithmECDSASignatureDigestX962SHA384)
	KSecKeyAlgorithmECDSASignatureDigestX962SHA512   = SecKeyAlgorithm(C.kSecKeyAlgorithmECDSASignatureDigestX962SHA512)
	KSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256 = SecKeyAlgorithm(C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256)
	KSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384 = SecKeyAlgorithm(C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384)
	KSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512 = SecKeyAlgorithm(C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512)
	KSecKeyAlgorithmRSASignatureDigestPSSSHA256      = SecKeyAlgorithm(C.kSecKeyAlgorithmRSASignatureDigestPSSSHA256)
	KSecKeyAlgorithmRSASignatureDigestPSSSHA384      = SecKeyAlgorithm(C.kSecKeyAlgorithmRSASignatureDigestPSSSHA384)
	KSecKeyAlgorithmRSASignatureDigestPSSSHA512      = SecKeyAlgorithm(C.kSecKeyAlgorithmRSASignatureDigestPSSSHA512)
)

type SecAccessControlCreateFlags = C.SecAccessControlCreateFlags

const (
	// Enable a private key to be used in signing a block of data or verifying a
	// signed block.
	KSecAccessControlPrivateKeyUsage = SecAccessControlCreateFlags(C.kSecAccessControlPrivateKeyUsage)

	// Option to use an application-provided password for data encryption key
	// generation.
	KSecAccessControlApplicationPassword = SecAccessControlCreateFlags(C.kSecAccessControlApplicationPassword)

	// Constraint to access an item with a passcode.
	KSecAccessControlDevicePasscode = SecAccessControlCreateFlags(C.kSecAccessControlDevicePasscode)

	// Constraint to access an item with Touch ID for any enrolled fingers, or
	// Face ID.
	KSecAccessControlBiometryAny = SecAccessControlCreateFlags(C.kSecAccessControlBiometryAny)

	// Constraint to access an item with Touch ID for currently enrolled
	// fingers, or from Face ID with the currently enrolled user.
	KSecAccessControlBiometryCurrentSet = SecAccessControlCreateFlags(C.kSecAccessControlBiometryCurrentSet)

	// Constraint to access an item with either biometry or passcode.
	KSecAccessControlUserPresence = SecAccessControlCreateFlags(C.kSecAccessControlUserPresence)

	// Constraint to access an item with a watch.
	KSecAccessControlWatch = SecAccessControlCreateFlags(C.kSecAccessControlWatch)

	// Indicates that all constraints must be satisfied.
	KSecAccessControlAnd = SecAccessControlCreateFlags(C.kSecAccessControlAnd)

	// Indicates that at least one constraint must be satisfied.
	KSecAccessControlOr = SecAccessControlCreateFlags(C.kSecAccessControlOr)
)

type SecKeyRef struct {
	Value C.SecKeyRef
}

func NewSecKeyRef(ref cf.TypeRef) *SecKeyRef {
	return &SecKeyRef{
		Value: C.SecKeyRef(ref),
	}
}

func (v *SecKeyRef) Release()              { cf.Release(v) }
func (v *SecKeyRef) TypeRef() cf.CFTypeRef { return cf.CFTypeRef(v.Value) }

type SecAccessControlRef struct {
	ref C.SecAccessControlRef
}

func (v *SecAccessControlRef) Release()              { cf.Release(v) }
func (v *SecAccessControlRef) TypeRef() cf.CFTypeRef { return cf.CFTypeRef(v.ref) }

func SecItemAdd(attributes *cf.DictionaryRef, result *cf.TypeRef) error {
	status := C.SecItemAdd(C.CFDictionaryRef(attributes.Value), (*C.CFTypeRef)(result))
	return goOSStatus(status)
}

func SecItemDelete(query *cf.DictionaryRef) error {
	status := C.SecItemDelete(C.CFDictionaryRef(query.Value))
	return goOSStatus(status)
}

func SecItemCopyMatching(query *cf.DictionaryRef, result *cf.TypeRef) error {
	status := C.SecItemCopyMatching(C.CFDictionaryRef(query.Value), (*C.CFTypeRef)(result))
	return goOSStatus(status)
}

func SecKeyCreateRandomKey(parameters *cf.DictionaryRef) (*SecKeyRef, error) {
	var cerr C.CFErrorRef
	key := C.SecKeyCreateRandomKey(C.CFDictionaryRef(parameters.Value), &cerr)
	if err := goCFErrorRef(cerr); err != nil {
		return nil, err
	}
	return &SecKeyRef{
		Value: key,
	}, nil
}

func SecKeyCopyPublicKey(key *SecKeyRef) (*SecKeyRef, error) {
	publicKey := C.SecKeyCopyPublicKey(key.Value)
	if publicKey == nilSecKey {
		return nil, ErrNotFound
	}
	return &SecKeyRef{
		Value: publicKey,
	}, nil
}

func SecKeyCopyAttributes(key *SecKeyRef) *cf.DictionaryRef {
	attr := C.SecKeyCopyAttributes(key.Value)
	return &cf.DictionaryRef{
		Value: cf.CFDictionaryRef(attr),
	}
}

func SecKeyCopyExternalRepresentation(key *SecKeyRef) (*cf.DataRef, error) {
	var err C.CFErrorRef
	data := C.SecKeyCopyExternalRepresentation(key.Value, &err)
	return &cf.DataRef{
		Value: cf.CFDataRef(data),
	}, goCFErrorRef(err)
}

func SecAccessControlCreateWithFlags(protection cf.TypeRef, flags SecAccessControlCreateFlags) (*SecAccessControlRef, error) {
	var err C.CFErrorRef
	access := C.SecAccessControlCreateWithFlags(C.kCFAllocatorDefault, C.CFTypeRef(protection), flags, &err)
	if err := goCFErrorRef(err); err != nil {
		return nil, err
	}
	return &SecAccessControlRef{
		ref: access,
	}, nil
}

func SecKeyCreateSignature(key *SecKeyRef, algorithm SecKeyAlgorithm, dataToSign *cf.DataRef) (*cf.DataRef, error) {
	var err C.CFErrorRef
	signature := C.SecKeyCreateSignature(key.Value, algorithm, C.CFDataRef(dataToSign.Value), &err)
	if err := goCFErrorRef(err); err != nil {
		return nil, err
	}
	return &cf.DataRef{
		Value: cf.CFDataRef(signature),
	}, nil
}

func SecCopyErrorMessageString(status C.OSStatus) *cf.StringRef {
	s := C.SecCopyErrorMessageString(status, nil)
	return &cf.StringRef{
		Value: cf.CFStringRef(s),
	}
}

func GetSecAttrApplicationLabel(v *cf.DictionaryRef) []byte {
	data := C.CFDataRef(C.CFDictionaryGetValue(C.CFDictionaryRef(v.Value), unsafe.Pointer(C.kSecAttrApplicationLabel)))
	return C.GoBytes(
		unsafe.Pointer(C.CFDataGetBytePtr(data)),
		C.int(C.CFDataGetLength(data)),
	)
}

func GetSecValueData(v *cf.DictionaryRef) []byte {
	data := C.CFDataRef(C.CFDictionaryGetValue(C.CFDictionaryRef(v.Value), unsafe.Pointer(C.kSecValueData)))
	return C.GoBytes(
		unsafe.Pointer(C.CFDataGetBytePtr(data)),
		C.int(C.CFDataGetLength(data)),
	)
}

type osStatusError struct {
	code    int
	message string
}

func (e osStatusError) Error() string {
	if e.message == "" {
		if e.code == -25300 {
			return fmt.Sprintf("OSStatus %d: %w", ErrNotFound)
		}
		return fmt.Sprintf("OSStatus %d: unknown error", e.code)
	}
	return fmt.Sprintf("OSStatus %d: %s", e.code, e.message)
}

func goOSStatus(status C.OSStatus) error {
	if status == 0 {
		return nil
	}
	if status == C.errSecItemNotFound {
		return ErrNotFound
	}

	var message string
	if ref := SecCopyErrorMessageString(status); ref.Value != 0 {
		if cstr := C.CFStringGetCStringPtr(C.CFStringRef(ref.Value), C.kCFStringEncodingUTF8); cstr != nil {
			message = C.GoString(cstr)
		}
		defer ref.Release()
	}
	return osStatusError{
		code:    int(status),
		message: message,
	}
}

type cfError struct {
	code    int
	message string
}

func (e cfError) Error() string {
	if e.message == "" {
		return fmt.Sprintf("CFError %d: unknown error", e.code)
	}
	return fmt.Sprintf("CFError %d: %s", e.code, e.message)
}

func goCFErrorRef(ref C.CFErrorRef) error {
	if ref == 0 {
		return nil
	}
	var message string
	if desc := C.CFErrorCopyDescription(ref); desc != nilCFString {
		defer C.CFRelease(C.CFTypeRef(desc))
		if cstr := C.CFStringGetCStringPtr(desc, C.kCFStringEncodingUTF8); cstr != nil {
			message = C.GoString(cstr)
		}
	}
	return &cfError{
		code:    int(C.CFErrorGetCode(ref)),
		message: message,
	}
}
