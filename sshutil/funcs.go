package sshutil

import (
	"text/template"

	"go.step.sm/crypto/internal/templates"
)

// templateFuncs holds functions contributed by the application for SSH
// templates. It is separate from the X.509 registry so that registering for one
// kind of certificate does not silently affect the other.
var templateFuncs = templates.NewRegistry(func() map[string]struct{} {
	names := map[string]struct{}{}
	for name := range builtinFuncMap(new(TemplateError)) {
		names[name] = struct{}{}
	}
	return names
})

// RegisterTemplateFunc makes fn available to SSH certificate templates as name,
// for the functions a certificate template needs that this library cannot
// provide.
//
// The template renderer is a leaf: [WithTemplate] builds its function map
// internally and is reached through provisioners the CA constructs for itself,
// so there is no call path along which a function can be passed down to it.
// This is how one gets there instead.
//
// A template rendered before the function is registered fails to parse, since
// text/template resolves function names at parse time, so register during
// start-up rather than lazily. Registering a name that is already built in, or
// already registered, is an error.
//
// The function receives only its own arguments. A function needing the data
// being rendered takes it as a parameter, which a template supplies with $:
//
//	{{ cel "ssh.principals" $ | toJson }}
//
// Use $ rather than . — inside a range block the dot is rebound to the element,
// while $ is always the value the template was executed with.
//
// Registering for SSH templates is separate from registering for X.509 ones;
// an application wanting a function in both calls
// [go.step.sm/crypto/x509util.RegisterTemplateFunc] as well.
func RegisterTemplateFunc(name string, fn any) error {
	return templateFuncs.Register(name, fn)
}

// UnregisterTemplateFunc removes a function registered with
// [RegisterTemplateFunc] and reports whether one was removed.
func UnregisterTemplateFunc(name string) bool {
	return templateFuncs.Unregister(name)
}

// builtinFuncMap returns the functions this package provides, without any the
// application has registered.
func builtinFuncMap(err *TemplateError) template.FuncMap {
	return templates.GetFuncMap(&err.Message)
}
