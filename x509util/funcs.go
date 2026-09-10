package x509util

import (
	"crypto/x509"
	"reflect"
	"text/template"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"
	"go.step.sm/crypto/internal/templates"
)

// templateFuncs holds the functions registered by the application. The reserved
// set is this package's own function map, so a registration cannot shadow one.
var templateFuncs = templates.NewRegistry(func() map[string]struct{} {
	names := map[string]struct{}{}
	for name := range builtinFuncMap(TemplateData{}, new(TemplateError)) {
		names[name] = struct{}{}
	}
	return names
})

// RegisterTemplateFunc adds fn to the functions available to X.509 certificate
// templates. It returns an error if name is already registered or built in.
//
// Register during start-up. "text/template" resolves function names when it
// parses, so a template rendered before the call will fail to parse.
//
// A function receives only its own arguments. One that needs the template data
// takes it as a parameter, which the template passes as "$" rather than ".",
// as the dot is rebound inside a range block:
//
//	{{ deviceAttr "serial" $ | toJson }}
func RegisterTemplateFunc(name string, fn any) error {
	return templateFuncs.Register(name, fn)
}

// ReplaceTemplateFunc adds fn to the functions available to X.509 certificate
// templates, replacing a built-in or previously registered function with the
// same name. Use [RegisterTemplateFunc] unless the replacement is intended.
func ReplaceTemplateFunc(name string, fn any) error {
	return templateFuncs.Replace(name, fn)
}

// UnregisterTemplateFunc removes a registered function. It returns true if a
// function was removed.
func UnregisterTemplateFunc(name string) bool {
	return templateFuncs.Unregister(name)
}

// builtinFuncMap returns the functions provided by this package, excluding
// those registered by the application.
func builtinFuncMap(data TemplateData, err *TemplateError) template.FuncMap {
	funcMap := templates.GetFuncMap(&err.Message)
	// asn1 methods
	funcMap["asn1Enc"] = asn1Encode
	funcMap["asn1Marshal"] = asn1Marshal
	funcMap["asn1Seq"] = asn1Sequence
	funcMap["asn1Set"] = asn1Set
	// cel methods
	funcMap["cel"] = celEnv.Func(data)
	return funcMap
}

// SetCELCostLimit changes the evaluation cost ceiling for the CEL expressions
// in certificate templates. The metered cost is the work an expression actually
// does, so it scales with the data; the default admits collections of several
// hundred elements while still canceling runaway expressions. The limit is
// process-wide, shared by X.509 and SSH template evaluation, and applies to
// subsequent evaluations, including expressions already compiled.
func SetCELCostLimit(limit uint64) {
	templates.SetCostLimit(limit)
}

// CELCostLimit returns the current evaluation cost ceiling for the CEL
// expressions in certificate templates.
func CELCostLimit() uint64 {
	return templates.CostLimit()
}

// celEnv holds a common environment to eval CEL expressions.
var celEnv = templates.NewEnvironment(100, func() []cel.EnvOption {
	return append(templates.BaseEnvOptions(),
		cel.Variable(SubjectKey, cel.DynType),
		cel.Variable(SANsKey, cel.ListType(cel.DynType)),
		cel.Variable(TokenKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(WebhooksKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(InsecureKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(AuthorizationCrtKey, cel.DynType),
		cel.Variable(AuthorizationChainKey, cel.ListType(cel.DynType)),
		ext.NativeTypes(reflect.TypeOf(SubjectAlternativeName{}), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeOf(Subject{}), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeOf(Certificate{}), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeOf(CertificateRequest{}), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeOf(x509.Certificate{}), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeOf(x509.CertificateRequest{}), ext.ParseStructTag("cel")),
	)
})
