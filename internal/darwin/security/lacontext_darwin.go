// Copyright (c) Smallstep Labs, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//nolint:gocritic // mirrors security_darwin.go style
package security

/*
#cgo CFLAGS: -x objective-c -fno-objc-arc
#cgo LDFLAGS: -framework Foundation -framework LocalAuthentication

#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

static CFTypeRef smallstepNewLAContext(void) {
    LAContext *ctx = [[LAContext alloc] init];
    return (CFTypeRef)ctx;
}

static void smallstepLAContextRelease(CFTypeRef ref) {
    if (ref == NULL) return;
    LAContext *ctx = (LAContext *)ref;
    [ctx release];
}

static void smallstepLAContextSetLocalizedReason(CFTypeRef ref, const char *reason) {
    if (ref == NULL || reason == NULL) return;
    LAContext *ctx = (LAContext *)ref;
    ctx.localizedReason = [NSString stringWithUTF8String:reason];
}

static void smallstepLAContextSetReuseDuration(CFTypeRef ref, double seconds) {
    if (ref == NULL) return;
    LAContext *ctx = (LAContext *)ref;
    ctx.touchIDAuthenticationAllowableReuseDuration = (NSTimeInterval)seconds;
}
*/
import "C"

import (
	"time"
	"unsafe"

	cf "go.step.sm/crypto/internal/darwin/corefoundation"
)

// LAContextMaxReuseDuration mirrors
// LATouchIDAuthenticationMaximumAllowableReuseDuration (300s). Reuse durations
// larger than this are silently clamped by the platform.
const LAContextMaxReuseDuration = 300 * time.Second

// LAContextRef wraps an LAContext object so it can be passed to a keychain
// operation via the kSecUseAuthenticationContext attribute.
//
// The reference owns one retain on the underlying Objective-C object; call
// Release exactly once when finished.
type LAContextRef struct {
	ref C.CFTypeRef
}

// NewLAContext creates a new LAContext with the given localized reason and
// reuse duration. An empty reason leaves the LAContext's reason unset (macOS
// will surface a default). A non-positive reuseDuration leaves the underlying
// touchIDAuthenticationAllowableReuseDuration at its default of 0 (no caching);
// values above LAContextMaxReuseDuration are clamped.
func NewLAContext(reason string, reuseDuration time.Duration) *LAContextRef {
	ref := C.smallstepNewLAContext()
	if ref == 0 {
		return nil
	}
	if reason != "" {
		cReason := C.CString(reason)
		C.smallstepLAContextSetLocalizedReason(ref, cReason)
		C.free(unsafe.Pointer(cReason))
	}
	if reuseDuration > 0 {
		if reuseDuration > LAContextMaxReuseDuration {
			reuseDuration = LAContextMaxReuseDuration
		}
		C.smallstepLAContextSetReuseDuration(ref, C.double(reuseDuration.Seconds()))
	}
	return &LAContextRef{ref: ref}
}

// Release frees the underlying LAContext. Safe to call on a nil receiver and
// idempotent — only the first call releases.
func (l *LAContextRef) Release() {
	if l == nil || l.ref == 0 {
		return
	}
	C.smallstepLAContextRelease(l.ref)
	l.ref = 0
}

// TypeRef exposes the underlying object as a CFTypeRef so callers can place it
// in a CFDictionary under kSecUseAuthenticationContext. Returns 0 if the
// receiver is nil or has been released.
func (l *LAContextRef) TypeRef() cf.CFTypeRef {
	if l == nil {
		return 0
	}
	return cf.CFTypeRef(l.ref)
}
