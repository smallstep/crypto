package celutil

import (
	"reflect"
	"testing"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testEnv() *Environment {
	return NewEnvironment(func() []cel.EnvOption {
		return []cel.EnvOption{
			cel.Variable("name", cel.StringType),
			cel.Variable("tags", cel.ListType(cel.StringType)),
		}
	})
}

func TestEnvironmentIsBuiltOnce(t *testing.T) {
	var builds int
	e := NewEnvironment(func() []cel.EnvOption {
		builds++
		return []cel.EnvOption{cel.Variable("name", cel.StringType)}
	})

	for range 5 {
		_, err := e.Env()
		require.NoError(t, err)
	}
	assert.Equal(t, 1, builds, "the base environment must be constructed once, not per call")
}

func TestEnvironmentCachesPrograms(t *testing.T) {
	e := testEnv()

	first, err := e.Program(`name + "!"`)
	require.NoError(t, err)
	second, err := e.Program(`name + "!"`)
	require.NoError(t, err)
	assert.Same(t, first, second)
}

func TestEval(t *testing.T) {
	e := testEnv()
	data := map[string]any{"name": "example", "tags": []string{"a", "b"}}

	tests := []struct {
		expr string
		want any
	}{
		{`name`, "example"},
		{`name.upperAscii() == "EXAMPLE"`, false}, // upperAscii needs ext.Strings, absent here
		{`tags`, []any{"a", "b"}},
		{`size(tags)`, int64(2)},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			got, err := e.Eval(tt.expr, data)
			if err != nil {
				// The second case is only there to show the base options are
				// exactly what the caller passed and nothing more.
				assert.Contains(t, err.Error(), "undeclared reference")
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestEvalConvertsResults guards the conversion: a list must come back as a Go
// slice, not as CEL's internal representation, or a template piping it to
// toJson silently produces an object instead of an array.
func TestEvalConvertsResults(t *testing.T) {
	e := testEnv()
	got, err := e.Eval(`tags`, map[string]any{"name": "x", "tags": []string{"a", "b"}})
	require.NoError(t, err)
	assert.Equal(t, []any{"a", "b"}, got)
}

func TestRegister(t *testing.T) {
	e := testEnv()

	// Not declared yet.
	_, err := e.Eval(`extra`, map[string]any{"name": "x", "tags": []string{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "undeclared reference")

	require.NoError(t, Register(Extension{
		Name:       "extra",
		EnvOptions: []cel.EnvOption{cel.Variable("extra", cel.StringType)},
		Activation: func(map[string]any) map[string]any {
			return map[string]any{"extra": "value"}
		},
	}))
	t.Cleanup(func() { Unregister("extra") })

	got, err := e.Eval(`extra`, map[string]any{"name": "x", "tags": []string{}})
	require.NoError(t, err)
	assert.Equal(t, "value", got)
}

func TestRegisterReplacesByName(t *testing.T) {
	e := testEnv()

	require.NoError(t, Register(Extension{
		Name:       "dup",
		EnvOptions: []cel.EnvOption{cel.Variable("dup", cel.StringType)},
		Activation: func(map[string]any) map[string]any {
			return map[string]any{"dup": "first"}
		},
	}))
	t.Cleanup(func() { Unregister("dup") })

	got, err := e.Eval(`dup`, map[string]any{})
	require.NoError(t, err)
	assert.Equal(t, "first", got)

	// Re-registering the same name replaces it rather than declaring the
	// variable twice, which would fail to build the environment.
	require.NoError(t, Register(Extension{
		Name:       "dup",
		EnvOptions: []cel.EnvOption{cel.Variable("dup", cel.StringType)},
		Activation: func(map[string]any) map[string]any {
			return map[string]any{"dup": "second"}
		},
	}))

	got, err = e.Eval(`dup`, map[string]any{})
	require.NoError(t, err)
	assert.Equal(t, "second", got)
}

func TestRegisterRequiresName(t *testing.T) {
	require.Error(t, Register(Extension{}))
}

func TestUnregister(t *testing.T) {
	assert.False(t, Unregister("never-registered"))

	require.NoError(t, Register(Extension{
		Name:       "temp",
		EnvOptions: []cel.EnvOption{cel.Variable("temp", cel.StringType)},
	}))
	assert.True(t, Unregister("temp"))
}

// TestActivationDoesNotShadowTemplateData checks the merge order: an extension
// supplies its own names, and the template data supplies the rest.
func TestActivationDoesNotShadowTemplateData(t *testing.T) {
	e := testEnv()

	require.NoError(t, Register(Extension{
		Name:       "merge",
		EnvOptions: []cel.EnvOption{cel.Variable("extra", cel.StringType)},
		Activation: func(data map[string]any) map[string]any {
			// Derived from the data it was given, as a real projection would be.
			name, _ := data["name"].(string)
			return map[string]any{"extra": name + "-derived"}
		},
	}))
	t.Cleanup(func() { Unregister("merge") })

	got, err := e.Eval(`name + "/" + extra`, map[string]any{"name": "example", "tags": []string{}})
	require.NoError(t, err)
	assert.Equal(t, "example/example-derived", got)
}

func TestCostLimit(t *testing.T) {
	e := NewEnvironment(func() []cel.EnvOption {
		return []cel.EnvOption{cel.Variable("name", cel.StringType)}
	})

	original := CostLimit()
	t.Cleanup(func() { SetCostLimit(original) })

	const expr = `name + name + name + name`
	data := map[string]any{"name": "example"}

	require.Equal(t, uint64(DefaultCostLimit), original)
	_, err := e.Eval(expr, data)
	require.NoError(t, err)

	// Lowering the limit must also discard the program already compiled under
	// the old one, or the change would appear to do nothing.
	SetCostLimit(1)
	_, err = e.Eval(expr, data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cost limit exceeded")

	SetCostLimit(original)
	_, err = e.Eval(expr, data)
	require.NoError(t, err)
}

func TestEnvironmentPropagatesBuildErrors(t *testing.T) {
	var builds int
	e := NewEnvironment(func() []cel.EnvOption {
		builds++
		// ext.NativeTypes rejects anything that is not a struct.
		return []cel.EnvOption{ext.NativeTypes(reflect.TypeFor[string]())}
	})

	_, err := e.Env()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error creating CEL environment")

	// The failure is cached rather than recomputed on every call.
	_, err = e.Env()
	require.Error(t, err)
	assert.Equal(t, 1, builds)
}
