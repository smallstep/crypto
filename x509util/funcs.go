package x509util

import (
	"text/template"

	"go.step.sm/crypto/internal/templates"
)

// templateFuncs holds functions contributed by the application for X.509
// templates. Its reserved set is this package's own function map, so a
// registration cannot shadow sprig, the time helpers or the ASN.1 encoders.
var templateFuncs = templates.NewRegistry(func() map[string]struct{} {
	names := map[string]struct{}{}
	for name := range builtinFuncMap(new(TemplateError)) {
		names[name] = struct{}{}
	}
	return names
})

// RegisterTemplateFunc makes fn available to X.509 certificate templates as
// name, for the functions a certificate template needs that this library
// cannot provide.
//
// The template renderer is a leaf: [WithTemplate] builds its function map
// internally and is reached through provisioners the CA constructs for itself,
// so there is no call path along which a function can be passed down to it.
// This is how one gets there instead.
//
// A template rendered before the function is registered fails to parse, since
// text/template resolves function names at parse time, so register during
// start-up rather than lazily. Registering a name that is already built in, or
// already registered, is an error: a template calling toJson has to get this
// library's toJson, or a template's meaning would depend on which packages a
// binary happened to link.
//
// The function receives only its own arguments. A function needing the data
// being rendered takes it as a parameter, which a template supplies with $:
//
//	x509util.RegisterTemplateFunc("cel", func(expr string, data any) (any, error) {
//	    // ...
//	})
//
//	{{ cel "device.serial" $ | toJson }}
//
// Use $ rather than . — inside a range block the dot is rebound to the element,
// while $ is always the value the template was executed with.
func RegisterTemplateFunc(name string, fn any) error {
	return templateFuncs.Register(name, fn)
}

// ReplaceTemplateFunc registers fn as name whether or not something already
// answers to it, built in or previously registered.
//
// It exists for the case where an application deliberately supersedes a
// function this library provides, having decided its own is the one its
// templates should get. [RegisterTemplateFunc] is the right call otherwise: an
// accidental shadow is a bug worth hearing about, and only the caller knows
// which of the two this is.
func ReplaceTemplateFunc(name string, fn any) error {
	return templateFuncs.Replace(name, fn)
}

// UnregisterTemplateFunc removes a function registered with
// [RegisterTemplateFunc] and reports whether one was removed.
func UnregisterTemplateFunc(name string) bool {
	return templateFuncs.Unregister(name)
}

// builtinFuncMap returns the functions this package provides, without any the
// application has registered.
func builtinFuncMap(err *TemplateError) template.FuncMap {
	funcMap := templates.GetFuncMap(&err.Message)
	// asn1 methods
	funcMap["asn1Enc"] = asn1Encode
	funcMap["asn1Marshal"] = asn1Marshal
	funcMap["asn1Seq"] = asn1Sequence
	funcMap["asn1Set"] = asn1Set
	return funcMap
}
