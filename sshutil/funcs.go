package sshutil

import (
	"crypto/x509"
	"reflect"
	"text/template"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"
	"go.step.sm/crypto/internal/templates"
	"golang.org/x/crypto/ssh"
)

// templateFuncs holds the functions registered by the application. It is
// separate from the X.509 registry, so registering for one kind of certificate
// does not affect the other.
var templateFuncs = templates.NewRegistry(func() map[string]struct{} {
	names := map[string]struct{}{}
	for name := range builtinFuncMap(TemplateData{}, new(TemplateError)) {
		names[name] = struct{}{}
	}
	return names
})

// RegisterTemplateFunc adds fn to the functions available to SSH certificate
// templates. It returns an error if name is already registered or built in.
//
// It behaves as [go.step.sm/crypto/x509util.RegisterTemplateFunc] does, over a
// separate registry; an application that wants a function in both calls both.
func RegisterTemplateFunc(name string, fn any) error {
	return templateFuncs.Register(name, fn)
}

// ReplaceTemplateFunc adds fn to the functions available to SSH certificate
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
	// cel methods
	funcMap["cel"] = celEnv.Func(data)
	return funcMap
}

// celEnv holds a common environment to eval CEL expressions.
var celEnv = templates.NewEnvironment(100, func() []cel.EnvOption {
	return append(templates.BaseEnvOptions(),
		cel.Variable(TypeKey, cel.StringType),
		cel.Variable(KeyIDKey, cel.StringType),
		cel.Variable(PrincipalsKey, cel.ListType(cel.StringType)),
		cel.Variable(ExtensionsKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(CriticalOptionsKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(TokenKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(WebhooksKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(InsecureKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(AuthorizationCrtKey, cel.DynType),
		cel.Variable(AuthorizationChainKey, cel.ListType(cel.DynType)),
		ext.NativeTypes(reflect.TypeOf(Certificate{}), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeOf(CertificateRequest{}), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeOf(ssh.Certificate{}), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeOf(x509.Certificate{}), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeOf(x509.CertificateRequest{}), ext.ParseStructTag("cel")),
	)
})
