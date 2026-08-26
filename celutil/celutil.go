// Package celutil builds and caches the CEL environments used by the "cel"
// function in X.509 and SSH certificate templates.
//
// The environment a certificate template can see is fixed by this library: the
// subject, the SANs, the certificate request, and whatever a webhook returned.
// The last of those arrives as decoded JSON with no schema, so it is declared
// as dyn and the checker cannot see through it.
//
// Callers that do know the shape of their own data can say so, by registering
// an [Extension] that declares typed variables and supplies their values at
// render time. An expression then reads device.serial as a string rather than
// Webhooks.Agent.Device.Serial as a dyn, which means a wrong type or a
// misspelled field is caught when the template is written instead of when a
// certificate is signed.
package celutil

import (
	"fmt"
	"maps"
	"reflect"
	"sync"
	"sync/atomic"

	"cel.dev/cel-go/cel"
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

// SetCostLimit changes the evaluation cost ceiling. The limit is fixed into a
// program when it is compiled, so this discards programs compiled under the
// previous limit.
func SetCostLimit(limit uint64) {
	costLimit.Store(limit)
	generation.Add(1)
}

// Extension contributes variables to the CEL environment.
//
// EnvOptions declares them — typically ext.NativeTypes for a struct plus a
// cel.Variable for each name — and Activation supplies their values for one
// render, given the template data. Every variable declared must be bound on
// every render, including with a zero value: an unbound variable is an
// evaluation error, not an empty value.
type Extension struct {
	// Name identifies the extension in error messages and prevents the same
	// one being registered twice.
	Name string
	// EnvOptions declares the extension's types and variables.
	EnvOptions []cel.EnvOption
	// Activation returns the values for those variables, derived from the
	// template data for the certificate being rendered. It may be nil for an
	// extension that only adds functions.
	Activation func(data map[string]any) map[string]any
}

var (
	registryMu sync.Mutex
	registry   []Extension
	// generation changes whenever the registry does, so cached environments
	// know to rebuild rather than silently serve a stale set of variables.
	generation atomic.Uint64
)

// Register adds an extension to every environment built afterwards, and
// invalidates any already built. It is safe to call at any point, though the
// natural place is program start-up, before anything is signed.
//
// Registering the same name twice replaces the first, so a process that
// re-registers during tests does not accumulate stale declarations.
func Register(ext Extension) error {
	if ext.Name == "" {
		return fmt.Errorf("celutil: extension name is required")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	for i, e := range registry {
		if e.Name == ext.Name {
			registry[i] = ext
			generation.Add(1)
			return nil
		}
	}
	registry = append(registry, ext)
	generation.Add(1)
	return nil
}

// Unregister removes a previously registered extension. It reports whether one
// was removed.
func Unregister(name string) bool {
	registryMu.Lock()
	defer registryMu.Unlock()
	for i, e := range registry {
		if e.Name == name {
			registry = append(registry[:i], registry[i+1:]...)
			generation.Add(1)
			return true
		}
	}
	return false
}

func extensions() []Extension {
	registryMu.Lock()
	defer registryMu.Unlock()
	out := make([]Extension, len(registry))
	copy(out, registry)
	return out
}

// Environment is a lazily built, cached CEL environment: a fixed set of base
// options contributed by x509util or sshutil, plus whatever extensions are
// registered.
type Environment struct {
	// base is built at most once. Constructing an environment registers native
	// types by reflection and initialises every extension library, which costs
	// on the order of 140µs and 280KB — per signature, if it were built inside
	// the render path.
	base func() (*cel.Env, error)

	mu       sync.Mutex
	gen      uint64
	env      *cel.Env
	err      error
	programs map[string]cel.Program
}

// NewEnvironment returns an environment built from the given base options. The
// options function is called at most once.
func NewEnvironment(baseOptions func() []cel.EnvOption) *Environment {
	return &Environment{
		base: sync.OnceValues(func() (*cel.Env, error) {
			env, err := cel.NewEnv(baseOptions()...)
			if err != nil {
				return nil, fmt.Errorf("error creating CEL environment: %w", err)
			}
			return env, nil
		}),
	}
}

// Env returns the environment, extending the base with the registered
// extensions and caching the result until the registry changes.
func (e *Environment) Env() (*cel.Env, error) {
	env, _, err := e.envAt(generation.Load())
	return env, err
}

// envAt returns the environment for a given registry generation, along with the
// generation it was actually built for. Callers that cache something derived
// from the environment use the returned generation to check the cache is still
// the right one to write into.
func (e *Environment) envAt(gen uint64) (*cel.Env, uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.env != nil && e.gen == gen {
		return e.env, gen, nil
	}
	if e.err != nil && e.gen == gen {
		return nil, gen, e.err
	}

	base, err := e.base()
	if err != nil {
		e.gen, e.env, e.err, e.programs = gen, nil, err, nil
		return nil, gen, err
	}

	env := base
	for _, ext := range extensions() {
		if len(ext.EnvOptions) == 0 {
			continue
		}
		if env, err = env.Extend(ext.EnvOptions...); err != nil {
			err = fmt.Errorf("error applying CEL extension %q: %w", ext.Name, err)
			e.gen, e.env, e.err, e.programs = gen, nil, err, nil
			return nil, gen, err
		}
	}

	e.gen, e.env, e.err = gen, env, nil
	// Programs are compiled against a specific environment and a specific cost
	// limit, so a rebuild invalidates them along with it.
	e.programs = map[string]cel.Program{}
	return env, gen, nil
}

// Program compiles expr, reusing a previously compiled program when the same
// expression is seen again. Compiling costs roughly 60µs against evaluation's
// 1µs, and a template's expressions do not change between signatures.
func (e *Environment) Program(expr string) (cel.Program, error) {
	gen := generation.Load()
	env, gen, err := e.envAt(gen)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	prg, ok := e.programs[expr]
	e.mu.Unlock()
	if ok {
		return prg, nil
	}

	ast, iss := env.Compile(expr)
	if err := iss.Err(); err != nil {
		return nil, fmt.Errorf("error compiling CEL expression: %w", err)
	}
	prg, err = env.Program(ast,
		cel.EvalOptions(cel.OptOptimize),
		cel.CostLimit(costLimit.Load()),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating CEL program: %w", err)
	}

	// Only cache against the environment this program was compiled for. If the
	// registry changed in between, the cache now belongs to a different
	// environment and this entry does not belong in it.
	e.mu.Lock()
	if e.programs != nil && e.gen == gen {
		e.programs[expr] = prg
	}
	e.mu.Unlock()

	return prg, nil
}

// Eval evaluates expr against the template data and returns the result as a
// plain Go value.
//
// The conversion is deliberate. A result taken through ref.Val.Value() is CEL's
// internal representation, and for a list backed by a Go slice that marshals to
// {} rather than to an array — so a template piping the result to toJson would
// silently produce an object where the certificate needs a list.
// ConvertToNative is correct for every result type.
func (e *Environment) Eval(expr string, data map[string]any) (any, error) {
	prg, err := e.Program(expr)
	if err != nil {
		return nil, err
	}

	out, _, err := prg.Eval(activation(data))
	if err != nil {
		return nil, fmt.Errorf("error evaluating CEL expression: %w", err)
	}

	native, err := out.ConvertToNative(anyType)
	if err != nil {
		return nil, fmt.Errorf("error converting CEL result: %w", err)
	}
	return native, nil
}

// activation merges the template data with the bindings contributed by each
// registered extension. Extensions are applied after the template data so a
// typed variable is not shadowed by a same-named key that happened to be in the
// data; the two use different naming conventions precisely to avoid the clash.
func activation(data map[string]any) map[string]any {
	exts := extensions()
	if len(exts) == 0 {
		return data
	}

	merged := make(map[string]any, len(data)+len(exts))
	maps.Copy(merged, data)
	for _, ext := range exts {
		if ext.Activation == nil {
			continue
		}
		maps.Copy(merged, ext.Activation(data))
	}
	return merged
}

var anyType = reflect.TypeFor[any]()
