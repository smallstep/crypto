package templates

import (
	"fmt"
	"reflect"
	"sync"
	"text/template"
)

// Registry holds template functions contributed by the application embedding
// this library, for the functions a certificate template needs that this
// library cannot provide.
//
// The template renderer is a leaf: WithTemplate builds its function map
// internally and is reached through provisioners the CA constructs for itself,
// so there is no call path along which an application can pass a function down
// to it. Registration is how one gets there instead.
type Registry struct {
	// reserved names the registry refuses, resolved once on first use. It is a
	// function so a package can describe its own built-ins without this file
	// needing to know them.
	reserved func() map[string]struct{}
	once     sync.Once
	names    map[string]struct{}

	mu    sync.RWMutex
	funcs map[string]any
}

// NewRegistry returns a registry that refuses to shadow any name the reserved
// function reports.
func NewRegistry(reserved func() map[string]struct{}) *Registry {
	return &Registry{reserved: reserved, funcs: map[string]any{}}
}

// Register makes fn available to templates as name.
//
// Call it during start-up, before anything is signed: a template rendered
// before the function is registered fails to parse, because text/template
// resolves function names when it parses.
//
// It refuses to shadow a built-in. A template that calls toJson or fail must
// get this library's implementation, not one an application replaced, and a
// registry that allowed the substitution would make every template's meaning
// depend on which packages happened to be linked in.
func (r *Registry) Register(name string, fn any) error {
	if err := validate(name, fn); err != nil {
		return err
	}

	r.once.Do(func() { r.names = r.reserved() })
	if _, ok := r.names[name]; ok {
		return fmt.Errorf("template function %q is built in and cannot be replaced", name)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.funcs[name]; ok {
		return fmt.Errorf("template function %q is already registered", name)
	}
	r.funcs[name] = fn
	return nil
}

// Replace registers fn as name whether or not something already answers to it,
// built in or previously registered.
//
// It exists for the case where an application deliberately supersedes a
// function this library provides, having decided its own is the one its
// templates should get. Register is the right call otherwise: an accidental
// shadow is a bug worth hearing about, and only the caller knows which of the
// two this is.
func (r *Registry) Replace(name string, fn any) error {
	if err := validate(name, fn); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.funcs[name] = fn
	return nil
}

func validate(name string, fn any) error {
	switch {
	case name == "":
		return fmt.Errorf("template function name is required")
	case fn == nil:
		return fmt.Errorf("template function %q is nil", name)
	case reflect.TypeOf(fn).Kind() != reflect.Func:
		return fmt.Errorf("template function %q is a %s, not a function", name, reflect.TypeOf(fn).Kind())
	case !validName(name):
		return fmt.Errorf("template function name %q is not a valid identifier", name)
	}
	return nil
}

// Unregister removes a previously registered function and reports whether one
// was removed.
func (r *Registry) Unregister(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.funcs[name]; !ok {
		return false
	}
	delete(r.funcs, name)
	return true
}

// Apply adds the registered functions to a function map. Built-ins are already
// protected at registration, so nothing here can overwrite one.
func (r *Registry) Apply(funcMap template.FuncMap) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for name, fn := range r.funcs {
		funcMap[name] = fn
	}
}

// validName reports whether name is usable as a template function name, which
// text/template requires to be a Go identifier.
func validName(name string) bool {
	for i, c := range name {
		switch {
		case c == '_':
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
