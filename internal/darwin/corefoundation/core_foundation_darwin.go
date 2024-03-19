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

//nolint:gocritic // open issue https://github.com/go-critic/go-critic/issues/845
package corefoundation

/*
#cgo LDFLAGS: -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

const (
	nilCFData       C.CFDataRef       = 0
	nilCFString     C.CFStringRef     = 0
	nilCFDictionary C.CFDictionaryRef = 0
	nilCFError      C.CFErrorRef      = 0
	nilCFType       C.CFTypeRef       = 0
)

type TypeReferer interface {
	TypeRef() CFTypeRef
}

func Release(ref TypeReferer) {
	C.CFRelease(ref.TypeRef())
}

type CFTypeRef = C.CFTypeRef
type CFStringRef = C.CFStringRef
type CFErrorRef = C.CFErrorRef
type CFDictionaryRef = C.CFDictionaryRef
type CFDataRef = C.CFDataRef

type TypeRef C.CFTypeRef

func (v TypeRef) Release()           { Release(v) }
func (v TypeRef) TypeRef() CFTypeRef { return C.CFTypeRef(v) }

type BooleanRef C.CFBooleanRef

var (
	True  = BooleanRef(C.kCFBooleanTrue)
	False = BooleanRef(C.kCFBooleanFalse)
)

func (v BooleanRef) TypeRef() CFTypeRef { return C.CFTypeRef(C.CFBooleanRef(v)) }

type AllocatorRef = C.CFAllocatorRef

var AllocatorDefault = C.kCFAllocatorDefault

type NumberRef struct {
	Value C.CFNumberRef
}

func NewNumber(v int) *NumberRef {
	return &NumberRef{
		Value: C.CFNumberCreate(0, C.kCFNumberIntType, unsafe.Pointer(&v)),
	}
}

func (v *NumberRef) Release()           { Release(v) }
func (v *NumberRef) TypeRef() CFTypeRef { return C.CFTypeRef(v.Value) }

type DataRef struct {
	Value C.CFDataRef
}

func NewData(d []byte) (*DataRef, error) {
	p := (*C.uchar)(C.CBytes(d))
	defer C.free(unsafe.Pointer(p))

	ref := C.CFDataCreate(C.kCFAllocatorDefault, p, C.CFIndex(len(d)))
	if ref == nilCFData {
		return nil, fmt.Errorf("error creating CFData")
	}
	return &DataRef{
		Value: ref,
	}, nil
}

func (v *DataRef) Bytes() []byte {
	return C.GoBytes(
		unsafe.Pointer(C.CFDataGetBytePtr(v.Value)),
		C.int(C.CFDataGetLength(v.Value)),
	)
}

func (v *DataRef) Release()           { Release(v) }
func (v *DataRef) TypeRef() CFTypeRef { return C.CFTypeRef(v.Value) }

type StringRef struct {
	Value C.CFStringRef
}

func NewString(s string) (*StringRef, error) {
	p := C.CString(s)
	defer C.free(unsafe.Pointer(p))

	ref := C.CFStringCreateWithCString(C.kCFAllocatorDefault, p, C.kCFStringEncodingUTF8)
	if ref == nilCFString {
		return nil, fmt.Errorf("error creating CFString")
	}
	return &StringRef{
		Value: ref,
	}, nil
}

func (v *StringRef) Release()           { Release(v) }
func (v *StringRef) TypeRef() CFTypeRef { return C.CFTypeRef(v.Value) }

type Dictionary map[TypeRef]TypeReferer

type DictionaryRef struct {
	Value C.CFDictionaryRef
}

func NewDictionary(m Dictionary) (*DictionaryRef, error) {
	var (
		keys   []unsafe.Pointer
		values []unsafe.Pointer
	)

	for k, v := range m {
		keys = append(keys, unsafe.Pointer(C.CFTypeRef(k)))
		values = append(values, unsafe.Pointer(v.TypeRef()))
	}

	// If the map will contain only CFType objects, we must pass a pointer to
	// kCFTypeDictionaryKeyCallBacks and kCFTypeDictionaryValueCallBacks
	ref := C.CFDictionaryCreate(C.kCFAllocatorDefault, &keys[0], &values[0], C.CFIndex(len(m)),
		&C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
	if ref == nilCFDictionary {
		return nil, fmt.Errorf("error creating CFDictionary")
	}
	return &DictionaryRef{
		Value: ref,
	}, nil
}

func NewDictionaryRef(ref TypeRef) *DictionaryRef {
	return &DictionaryRef{
		Value: C.CFDictionaryRef(ref),
	}
}

func (v *DictionaryRef) Release()           { Release(v) }
func (v *DictionaryRef) TypeRef() CFTypeRef { return C.CFTypeRef(v.Value) }

//nolint:errname // type name matches original name
type ErrorRef C.CFErrorRef

func (e ErrorRef) Error() string {
	ref := C.CFErrorRef(e)
	code := int(C.CFErrorGetCode(ref))
	if desc := C.CFErrorCopyDescription(ref); desc != nilCFString {
		defer C.CFRelease(C.CFTypeRef(desc))
		if cstr := C.CFStringGetCStringPtr(desc, C.kCFStringEncodingUTF8); cstr != nil {
			str := C.GoString(cstr)
			return fmt.Sprintf("CFError %d: %s", code, str)
		}
	}

	return fmt.Sprintf("CFError %d", code)
}

func (e ErrorRef) Release()           { Release(e) }
func (e ErrorRef) TypeRef() CFTypeRef { return C.CFTypeRef(C.CFErrorRef(e)) }
