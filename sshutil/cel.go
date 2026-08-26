package sshutil

import (
	"reflect"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"

	"go.step.sm/crypto/celutil"
)

// celEnv is the environment for the "cel" function in SSH templates. It is
// built at most once and reused for every certificate; see
// [celutil.Environment].
var celEnv = celutil.NewEnvironment(celEnvOptions)

// CELEnvOptions returns the environment options the "cel" template function
// declares for SSH templates.
//
// It is exported so a caller that validates expressions ahead of time can build
// the same environment the renderer will use, rather than approximating it.
func CELEnvOptions() []cel.EnvOption {
	return celEnvOptions()
}

func celEnvOptions() []cel.EnvOption {
	return []cel.EnvOption{
		// Extension libraries, matching the set available to X.509 templates.
		ext.Strings(), ext.Encoders(), ext.Lists(), ext.Sets(), ext.Network(),
		cel.OptionalTypes(), // required by regex
		ext.Regex(),
		// The certificate's own fields, which this package does know the shape
		// of. Extensions and CriticalOptions are declared with a dyn value
		// because a template may add arbitrary entries to either.
		cel.Variable(TypeKey, cel.StringType),
		cel.Variable(KeyIDKey, cel.StringType),
		cel.Variable(PrincipalsKey, cel.ListType(cel.StringType)),
		cel.Variable(ExtensionsKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(CriticalOptionsKey, cel.MapType(cel.StringType, cel.DynType)),
		// Everything below arrives from outside — a token, a webhook, the
		// request — so its shape is not knowable here and it is declared dyn.
		// A caller that does know can declare typed variables for it with a
		// [celutil.Extension].
		cel.Variable(TokenKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(WebhooksKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(InsecureKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(UserKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(AuthorizationCrtKey, cel.DynType),
		cel.Variable(AuthorizationChainKey, cel.ListType(cel.DynType)),
		ext.NativeTypes(reflect.TypeFor[Certificate](), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeFor[CertificateRequest](), ext.ParseStructTag("cel")),
	}
}

// celFunc returns the "cel" template function bound to one certificate's data.
// The result is a Go value rather than pre-formatted text so a template can
// pipe it, e.g. {{ cel "Principals.map(p, p.lowerAscii())" | toJson }}.
func celFunc(data TemplateData) func(string) (any, error) {
	return func(expr string) (any, error) {
		return celEnv.Eval(expr, data)
	}
}
