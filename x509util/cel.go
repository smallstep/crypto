package x509util

import (
	"crypto/x509"
	"reflect"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"

	"go.step.sm/crypto/celutil"
)

// celEnv is the environment for the "cel" function in X.509 templates. It is
// built at most once and reused for every certificate; see [celutil.Environment].
var celEnv = celutil.NewEnvironment(celEnvOptions)

// CELEnvOptions returns the environment options the "cel" template function
// declares for X.509 templates.
//
// It is exported so a caller that validates expressions ahead of time can build
// the same environment the renderer will use, rather than approximating it. An
// expression accepted against this environment plus any registered
// [celutil.Extension] is one this package can evaluate.
func CELEnvOptions() []cel.EnvOption {
	return celEnvOptions()
}

func celEnvOptions() []cel.EnvOption {
	return []cel.EnvOption{
		// Extension libraries.
		ext.Strings(), ext.Encoders(), ext.Lists(), ext.Sets(), ext.Network(),
		cel.OptionalTypes(), // required by regex
		ext.Regex(),
		// Types.
		cel.Variable(SubjectKey, cel.ObjectType(celTypeName[Subject]())),
		cel.Variable(SANsKey, cel.ListType(cel.ObjectType(celTypeName[SubjectAlternativeName]()))),
		cel.Variable(TokenKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(WebhooksKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(InsecureKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(AuthorizationCrtKey, cel.DynType),
		cel.Variable(AuthorizationChainKey, cel.ListType(cel.DynType)),
		ext.NativeTypes(reflect.TypeFor[SubjectAlternativeName](), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeFor[Subject](), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeFor[Certificate](), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeFor[CertificateRequest](), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeFor[x509.Certificate](), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeFor[x509.CertificateRequest](), ext.ParseStructTag("cel")),
	}
}

// celTypeName returns the name ext.NativeTypes gives a Go struct, so the
// declaration of a variable and the registration of its type cannot drift
// apart.
func celTypeName[T any]() string {
	return reflect.TypeFor[T]().String()
}

// celFunc returns the "cel" template function bound to one certificate's data.
//
// It returns the result as a Go value rather than as pre-formatted text, so a
// template can pipe it: {{ cel "SANs.map(s, s.Value)" | toJson }} produces a
// JSON array, and the same pipeline is correct for a string, a list or a
// number. Formatting the result to a string here would make toJson produce a
// quoted string for every type, which is wrong everywhere a template needs a
// list.
func celFunc(data TemplateData) func(string) (any, error) {
	return func(expr string) (any, error) {
		return celEnv.Eval(expr, data)
	}
}
