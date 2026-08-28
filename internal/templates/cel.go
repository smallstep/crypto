package templates

import (
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/ext"
	"google.golang.org/protobuf/types/known/structpb"

	"go.step.sm/crypto/internal/lru"
)

// costLimit bounds the work a single expression may do at evaluation time.
// Expressions are metered and cancelled once they exceed it, so a template
// cannot make signing arbitrarily expensive.
var costLimit atomic.Uint64

func init() {
	costLimit.Store(DefaultCostLimit)
}

// DefaultCostLimit is the evaluation cost ceiling applied unless a caller sets
// another with [SetCostLimit].
const DefaultCostLimit = 1000

// CostLimit returns the current evaluation cost ceiling.
func CostLimit() uint64 { return costLimit.Load() }

// SetCostLimit changes the evaluation cost ceiling.
func SetCostLimit(limit uint64) {
	costLimit.Store(limit)
}

var anyType = reflect.TypeFor[any]()

// Environment is a lazily built, cached CEL environment: a fixed set of base
// options contributed by x509util or sshutil, plus whatever extensions are
// registered.
type Environment struct {
	// base is built at most once. Constructing an environment registers native
	// types by reflection and initialises every extension library, which costs
	// on the order of 140µs and 280KB — per signature, if it were built inside
	// the render path.
	base     func() (*cel.Env, error)
	programs lru.Cache[string, cel.Program]
}

// NewEnvironment returns an environment built from the given base options. The
// options function is called at most once.
func NewEnvironment(capacity int, baseOptions func() []cel.EnvOption) *Environment {
	return &Environment{
		base: sync.OnceValues(func() (*cel.Env, error) {
			env, err := cel.NewEnv(baseOptions()...)
			if err != nil {
				return nil, fmt.Errorf("error creating CEL environment: %w", err)
			}
			return env, nil
		}),
		programs: lru.New[string, cel.Program](capacity),
	}
}

// Program compiles expr, reusing a previously compiled program when the same
// expression is seen again. Compiling costs roughly 60µs against evaluation's
// 1µs, and a template's expressions do not change between signatures.
func (e *Environment) Program(expr string) (cel.Program, error) {
	env, err := e.base()
	if err != nil {
		return nil, err
	}

	if prg, ok := e.programs.Get(expr); ok {
		return prg, nil
	}

	ast, iss := env.Compile(expr)
	if err := iss.Err(); err != nil {
		return nil, fmt.Errorf("error compiling CEL expression: %w", err)
	}

	prg, err := env.Program(ast,
		cel.EvalOptions(cel.OptOptimize),
		cel.CostLimit(costLimit.Load()),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating CEL program: %w", err)
	}
	e.programs.Put(expr, prg)

	return prg, nil
}

// Eval evaluates expr against the template data and returns the result as a
// plain Go value.
//
// The conversion is deliberate. A result taken through ref.Val.Value() is CEL's
// internal representation, and for a list backed by a Go slice that marshals to
// {} rather than to an array — so a template piping the result to toJson would
// silently produce an object where the certificate needs a list. ConvertToNative
// gets the rest right, and normalize fixes the two results it does not.
func (e *Environment) Eval(expr string, data map[string]any) (any, error) {
	prg, err := e.Program(expr)
	if err != nil {
		return nil, err
	}

	out, _, err := prg.Eval(data)
	if err != nil {
		return nil, fmt.Errorf("error evaluating CEL expression: %w", err)
	}

	native, err := out.ConvertToNative(anyType)
	if err != nil {
		return nil, fmt.Errorf("error converting CEL result: %w", err)
	}

	return normalize(native), nil
}

// normalize rewrites the values ConvertToNative produces that do not render or
// marshal correctly from a template. CEL's null converts to a protobuf enum,
// which text/template renders as "NULL_VALUE" and encoding/json marshals as 0;
// it becomes nil. CEL maps convert to map[any]any, which encoding/json refuses
// to marshal; they become map[string]any. Values are rewritten recursively,
// into fresh maps and slices because ConvertToNative can return a map held in
// the template data, which an evaluation must not modify.
func normalize(v any) any {
	switch v := v.(type) {
	case structpb.NullValue:
		return nil
	case map[any]any:
		m := make(map[string]any, len(v))
		for key, value := range v {
			m[fmt.Sprint(key)] = normalize(value)
		}
		return m
	case map[string]any:
		m := make(map[string]any, len(v))
		for key, value := range v {
			m[key] = normalize(value)
		}
		return m
	case []any:
		s := make([]any, len(v))
		for i, value := range v {
			s[i] = normalize(value)
		}
		return s
	default:
		return v
	}
}

// Func returns the template function that evaluates an expresion with the given
// data. The function also accepts the data as an optional final argument, which
// the template passes as "$", for a func map built without data, like the one
// returned by GetFuncMap.
func (e *Environment) Func(data map[string]any) func(string, ...map[string]any) (any, error) {
	return func(expr string, override ...map[string]any) (any, error) {
		if len(override) > 0 {
			return e.Eval(expr, override[len(override)-1])
		}
		return e.Eval(expr, data)
	}
}

// BaseEnvOptions returns the common environment options used in X.509 and SSH
// templates. The list contains the list of extensions.
func BaseEnvOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.OptionalTypes(), // required by regex
		ext.Strings(), ext.Encoders(), ext.Lists(), ext.Sets(), ext.Network(),
		ext.Regex(), ext.TwoVarComprehensions(),
		// Custom methods
		mapGetFunction(),
	}
}

// mapGetFunction declares a total accessor for string maps:
//
//	metadata.get("department")      // "" when the key is absent
//
// Indexing a map is not total — metadata["absent"] raises "no such key" during
// signing — and the optional form, metadata[?"absent"].orValue(""), is a lot of
// syntax to demand for the common case. Custom metadata is the one genuinely
// map-shaped input in the environment, so it gets an accessor that behaves like
// every other field: absent reads as empty.
func mapGetFunction() cel.EnvOption {
	strMap := cel.MapType(cel.StringType, cel.StringType)
	return cel.Function("get",
		cel.MemberOverload("crypto_map_get_string",
			[]*cel.Type{strMap, cel.StringType}, cel.StringType,
			cel.BinaryBinding(func(m, k ref.Val) ref.Val {
				mapper, ok := m.(traits.Mapper)
				if !ok {
					return types.String("")
				}
				v, found := mapper.Find(k)
				if !found || v == nil {
					return types.String("")
				}
				s, ok := v.Value().(string)
				if !ok {
					return types.String("")
				}
				return types.String(s)
			})))
}
