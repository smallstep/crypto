package templates

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/ext"
	"cel.dev/cel-go/interpreter"
	"google.golang.org/protobuf/types/known/structpb"

	"go.step.sm/crypto/internal/lru"
)

// costLimit bounds the work a single expression may do at evaluation time.
// Expressions are metered and canceled once they exceed it, so a template
// cannot make signing arbitrarily expensive.
var costLimit atomic.Uint64

func init() {
	costLimit.Store(DefaultCostLimit)
}

// DefaultCostLimit is the evaluation cost ceiling applied unless a caller sets
// another with [SetCostLimit]. The metered cost is the work an expression
// actually does, so it scales with the data: iterating an element of a list or
// map costs a handful of units. The default admits collections of several
// hundred elements while still canceling runaway expressions.
const DefaultCostLimit = 10_000

// CostLimit returns the current evaluation cost ceiling.
func CostLimit() uint64 { return costLimit.Load() }

// SetCostLimit changes the evaluation cost ceiling. It applies to subsequent
// evaluations, including expressions already cached: a program compiled under
// another limit is recompiled on its next use.
func SetCostLimit(limit uint64) {
	costLimit.Store(limit)
}

var anyType = reflect.TypeFor[any]()

// Environment is a lazily built, cached CEL environment: a fixed set of base
// options contributed by x509util or sshutil, plus whatever extensions are
// registered.
type Environment struct {
	// base is built at most once. Constructing an environment registers native
	// types by reflection and initializes every extension library, which costs
	// on the order of 140µs and 280KB — per signature, if it were built inside
	// the render path.
	base     func() (*cel.Env, error)
	programs *lru.Cache[string, program]
}

// program pairs a compiled program with the cost limit fixed into it at
// compile time, so a limit change invalidates the cached entry instead of
// silently keeping the old ceiling.
type program struct {
	prg   cel.Program
	limit uint64
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
		programs: lru.New[string, program](capacity),
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

	limit := costLimit.Load()
	if p, ok := e.programs.Get(expr); ok && p.limit == limit {
		return p.prg, nil
	}

	ast, iss := env.Compile(expr)
	if err := iss.Err(); err != nil {
		return nil, fmt.Errorf("error compiling CEL expression: %w", err)
	}

	prg, err := env.Program(ast,
		cel.EvalOptions(cel.OptOptimize),
		cel.CostLimit(limit),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating CEL program: %w", err)
	}
	e.programs.Put(expr, program{prg: prg, limit: limit})

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
		return nil, newEvalError(expr, err)
	}

	native, err := out.ConvertToNative(anyType)
	if err != nil {
		return nil, fmt.Errorf("error converting CEL result: %w", err)
	}

	return normalize(native), nil
}

// EvalError reports an expression that failed to evaluate. Its message names
// the expression and not the data, because cel-go builds the value it was
// working on into the error it returns: a map key taken from a token claim, an
// index computed from a webhook payload, a struct it could not convert. The
// message does not say where a value came from — "no such key: Serial" and
// "no such key: <a token subject>" are the same sentence — so none of it is
// repeated, and Detail hands it to a caller that has somewhere safe to put it.
type EvalError struct {
	// Expr is the expression that failed. It comes from the template, not
	// from the request, so it is safe to report.
	Expr string

	detail error
}

// Error returns a message that carries no template data.
func (e *EvalError) Error() string {
	return fmt.Sprintf("error evaluating CEL expression %q", e.Expr)
}

// Detail returns the error cel-go reported. It can carry values from the
// template data, so it belongs in a log the operator controls rather than in a
// response to whoever asked for the certificate.
//
// It is deliberately not an Unwrap. An unwrap chain is something a caller's
// error formatting walks into by accident, and this text should move only when
// somebody decides that it should.
func (e *EvalError) Detail() error { return e.detail }

// newEvalError classifies what an evaluation reported. Exceeding the cost limit
// is the one failure with a remedy the operator can act on, and cel-go reports
// it with a typed error whose message is fixed and holds no data, so it keeps
// its text. Everything else is held back in an EvalError.
func newEvalError(expr string, err error) error {
	var canceled interpreter.EvalCancelledError
	if errors.As(err, &canceled) && canceled.Cause == interpreter.CostLimitExceeded {
		return fmt.Errorf("error evaluating CEL expression %q: %w; the limit is %d and can be raised with SetCELCostLimit",
			expr, err, costLimit.Load())
	}
	return &EvalError{Expr: expr, detail: err}
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
		// CEL allows heterogeneous map keys, so distinct keys can print alike —
		// {1: "a", "1": "b"} yields one "1" entry, and which value survives
		// depends on map iteration order. String keys, the only kind these
		// templates produce, never collide.
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

// Func returns the template function that evaluates an expression with the
// given data. The function also accepts the data as an optional final argument,
// which the template passes as "$", for a func map built without data, like the
// one returned by GetFuncMap.
func (e *Environment) Func(data map[string]any) func(string, ...map[string]any) (any, error) {
	return func(expr string, override ...map[string]any) (any, error) {
		switch len(override) {
		case 0:
			return e.Eval(expr, data)
		case 1:
			return e.Eval(expr, override[0])
		default:
			return nil, errors.New("cel accepts at most one data argument")
		}
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

// mapGetFunction declares a total accessor for string-keyed maps:
//
//	metadata.get("department")      // "" when the key is absent
//
// Indexing a map is not total — metadata["absent"] raises "no such key" during
// signing — and the optional form, metadata[?"absent"].orValue(""), is a lot of
// syntax to demand for the common case. Custom metadata is the one genuinely
// map-shaped input in the environment, so it gets an accessor that behaves like
// every other field: absent or null reads as empty. The values are dyn — the
// maps this is for (webhook payloads, token claims) carry whatever JSON held —
// so a non-string value converts with CEL's string conversion (a numeric serial
// reads as its decimal form) instead of failing the signature, and a value with
// no string form reads as empty.
func mapGetFunction() cel.EnvOption {
	dynMap := cel.MapType(cel.StringType, cel.DynType)
	return cel.Function("get",
		cel.MemberOverload("crypto_map_get_string",
			[]*cel.Type{dynMap, cel.StringType}, cel.StringType,
			cel.BinaryBinding(func(m, k ref.Val) ref.Val {
				mapper, ok := m.(traits.Mapper)
				if !ok {
					return types.String("")
				}
				v, found := mapper.Find(k)
				if !found || v == nil {
					return types.String("")
				}
				if _, isNull := v.(types.Null); isNull {
					return types.String("")
				}
				if s := v.ConvertToType(types.StringType); !types.IsError(s) {
					return s
				}
				return types.String("")
			})))
}
