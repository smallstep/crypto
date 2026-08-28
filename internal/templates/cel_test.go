package templates

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSubject mirrors the shape of the native types x509util and sshutil
// register, so the tests exercise the same reflection path a real environment
// does.
type testSubject struct {
	CommonName string   `cel:"commonName"`
	Names      []string `cel:"names"`
}

// testEnvOptions is a small stand-in for the base options x509util contributes.
func testEnvOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.OptionalTypes(),
		ext.Strings(), ext.Encoders(), ext.Lists(),
		cel.Variable("Token", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("Subject", cel.ObjectType("templates.testSubject")),
		ext.NativeTypes(reflect.TypeFor[testSubject](), ext.ParseStructTag("cel")),
	}
}

// testEnvData is the template data the expressions below are evaluated against.
func testEnvData() map[string]any {
	return map[string]any{
		"Token": map[string]any{
			"email": "jane@example.com",
			"n":     3,
		},
		"Subject": testSubject{
			CommonName: "leaf",
			Names:      []string{"a", "b"},
		},
	}
}

// newTestEnvironment returns an environment built from testEnvOptions.
func newTestEnvironment(capacity int) *Environment {
	return NewEnvironment(capacity, testEnvOptions)
}

// badEnvOptions cannot build an environment: NativeTypes wants a reflect.Type.
func badEnvOptions() []cel.EnvOption {
	return []cel.EnvOption{ext.NativeTypes(42)}
}

// withCostLimit sets the global cost limit for the duration of the test.
// Because the limit is global, tests that call it must not run in parallel.
func withCostLimit(t *testing.T, limit uint64) {
	t.Helper()
	prev := CostLimit()
	t.Cleanup(func() { SetCostLimit(prev) })
	SetCostLimit(limit)
}

func TestCostLimit(t *testing.T) {
	assert.Equal(t, uint64(DefaultCostLimit), CostLimit())
}

func TestSetCostLimit(t *testing.T) {
	withCostLimit(t, DefaultCostLimit)

	SetCostLimit(42)
	assert.Equal(t, uint64(42), CostLimit())

	SetCostLimit(0)
	assert.Equal(t, uint64(0), CostLimit())

	SetCostLimit(DefaultCostLimit)
	assert.Equal(t, uint64(DefaultCostLimit), CostLimit())
}

func TestSetCostLimit_enforced(t *testing.T) {
	const expr = `"a" + "b" + "c" + Token.email + Token.email`
	e := newTestEnvironment(10)

	// The default limit is generous enough for an ordinary expression.
	got, err := e.Eval(expr, testEnvData())
	require.NoError(t, err)
	assert.Equal(t, "abcjane@example.comjane@example.com", got)

	// A tight limit cancels it, even though its program is already cached.
	withCostLimit(t, 1)
	_, err = e.Eval(expr, testEnvData())
	require.Error(t, err)
	assert.ErrorContains(t, err, "actual cost limit exceeded")

	// Even a trivial expression is metered, but stays under the limit.
	got, err = e.Eval(`1`, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(1), got)
}

// TestSetCostLimit_cachedProgram pins that a limit change reaches expressions
// already cached: a cached program keeps the limit it was compiled under, so
// Program treats it as a miss and recompiles it under the new limit.
func TestSetCostLimit_cachedProgram(t *testing.T) {
	const expr = `"a" + "b" + "c" + Token.email + Token.email`
	e := newTestEnvironment(10)

	got, err := e.Eval(expr, testEnvData())
	require.NoError(t, err)
	assert.Equal(t, "abcjane@example.comjane@example.com", got)
	assert.Equal(t, 1, e.programs.Len())

	// Lowering the limit invalidates the cached program.
	withCostLimit(t, 1)
	_, err = e.Eval(expr, testEnvData())
	assert.ErrorContains(t, err, "actual cost limit exceeded")

	// Restoring it recompiles once more, and evaluation recovers.
	SetCostLimit(DefaultCostLimit)
	got, err = e.Eval(expr, testEnvData())
	require.NoError(t, err)
	assert.Equal(t, "abcjane@example.comjane@example.com", got)
	assert.Equal(t, 1, e.programs.Len())
}

func TestNewEnvironment(t *testing.T) {
	var calls atomic.Int64
	e := NewEnvironment(3, func() []cel.EnvOption {
		calls.Add(1)
		return testEnvOptions()
	})

	require.NotNil(t, e)
	assert.Equal(t, 3, e.programs.Capacity())
	assert.Zero(t, e.programs.Len())
	assert.Zero(t, calls.Load(), "base options must not be built before first use")

	for range 5 {
		_, err := e.Program(`1 + 1`)
		require.NoError(t, err)
	}
	_, err := e.Eval(`"a" + "b"`, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(1), calls.Load(), "base options must be built at most once")
}

func TestNewEnvironment_concurrent(t *testing.T) {
	var calls atomic.Int64
	e := NewEnvironment(100, func() []cel.EnvOption {
		calls.Add(1)
		return testEnvOptions()
	})

	var wg sync.WaitGroup
	for i := range 20 {
		// Half the goroutines share an expression and half bring their own, so
		// this races cache hits against cache writes.
		expr := fmt.Sprintf(`Token.email + "/%d"`, i%10)
		wg.Go(func() {
			got, err := e.Eval(expr, map[string]any{
				"Token": map[string]any{"email": "jane@example.com"},
			})
			assert.NoError(t, err)
			assert.Equal(t, fmt.Sprintf("jane@example.com/%d", i%10), got)
		})
	}
	wg.Wait()

	assert.Equal(t, 10, e.programs.Len())

	assert.Equal(t, int64(1), calls.Load())
}

func TestEnvironment_Program(t *testing.T) {
	e := newTestEnvironment(10)

	prg, err := e.Program(`1 + 1`)
	require.NoError(t, err)
	require.NotNil(t, prg)
	assert.Equal(t, 1, e.programs.Len())

	// The same expression returns the cached program rather than recompiling.
	again, err := e.Program(`1 + 1`)
	require.NoError(t, err)
	assert.Same(t, prg, again)
	assert.Equal(t, 1, e.programs.Len())

	// A different expression gets its own entry.
	other, err := e.Program(`1 + 2`)
	require.NoError(t, err)
	assert.NotSame(t, prg, other)
	assert.Equal(t, []string{`1 + 1`, `1 + 2`}, e.programs.Keys())
}

func TestEnvironment_Program_evicts(t *testing.T) {
	e := newTestEnvironment(2)

	for _, expr := range []string{`1`, `2`, `3`} {
		_, err := e.Program(expr)
		require.NoError(t, err)
	}

	assert.Equal(t, 2, e.programs.Len())
	assert.Equal(t, []string{`2`, `3`}, e.programs.Keys())
}

func TestEnvironment_Program_error(t *testing.T) {
	tests := []struct {
		name     string
		env      *Environment
		expr     string
		contains string
	}{
		{
			name:     "fail/environment",
			env:      NewEnvironment(10, badEnvOptions),
			expr:     `1 + 1`,
			contains: "error creating CEL environment",
		},
		{
			name:     "fail/syntax",
			env:      newTestEnvironment(10),
			expr:     `1 +`,
			contains: "error compiling CEL expression",
		},
		{
			name:     "fail/undeclared-reference",
			env:      newTestEnvironment(10),
			expr:     `nosuchvar`,
			contains: "undeclared reference to 'nosuchvar'",
		},
		{
			name:     "fail/type-mismatch",
			env:      newTestEnvironment(10),
			expr:     `1 + "a"`,
			contains: "error compiling CEL expression",
		},
		{
			name:     "fail/unknown-field",
			env:      newTestEnvironment(10),
			expr:     `Subject.nosuchfield`,
			contains: "error compiling CEL expression",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prg, err := tt.env.Program(tt.expr)
			require.Error(t, err)
			assert.Nil(t, prg)
			assert.ErrorContains(t, err, tt.contains)

			// A failure is not cached, and it is reported again on retry.
			assert.Zero(t, tt.env.programs.Len())
			_, err = tt.env.Program(tt.expr)
			assert.ErrorContains(t, err, tt.contains)
		})
	}
}

func TestEnvironment_Eval(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want any
	}{
		{"int", `1 + 1`, int64(2)},
		{"uint", `uint(3)`, uint64(3)},
		{"double", `1.5 * 2.0`, 3.0},
		{"string", `"a" + "b"`, "ab"},
		{"bool", `1 < 2`, true},
		{"bytes", `b"abc"`, []byte("abc")},
		{"null", `null`, nil},
		{"duration", `duration("1h")`, time.Hour},
		{"timestamp", `timestamp("2020-01-01T00:00:00Z")`, time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)},
		{"list-string", `["a", "b"]`, []any{"a", "b"}},
		{"list-int", `[1, 2]`, []any{int64(1), int64(2)}},
		{"list-empty", `[]`, []any{}},
		{"map", `{"a": 1}`, map[string]any{"a": int64(1)}},
		{"map-int-key", `{1: "a"}`, map[string]any{"1": "a"}},
		{"map-nested", `{"a": {"b": null}}`, map[string]any{"a": map[string]any{"b": nil}}},
		{"list-with-null", `["a", null]`, []any{"a", nil}},
		{"optional", `optional.of(1)`, int64(1)},
		{"variable-string", `Token.email`, "jane@example.com"},
		{"variable-int", `Token.n`, int64(3)},
		{"variable-map", `Token`, map[string]any{"email": "jane@example.com", "n": int64(3)}},
		{"native-field", `Subject.commonName`, "leaf"},
		{"native-list-field", `Subject.names`, []any{"a", "b"}},
		{"has", `has(Token.email)`, true},
		{"conditional", `Token.n > 1 ? "big" : "small"`, "big"},
		{"ext-strings", `Token.email.split("@")`, []any{"jane", "example.com"}},
		{"ext-strings-upper", `"leaf".upperAscii()`, "LEAF"},
		{"ext-encoders", `base64.encode(b"abc")`, "YWJj"},
		{"ext-lists", `[3, 1, 2].sort()`, []any{int64(1), int64(2), int64(3)}},
		{"macro", `["a", "bb"].map(s, s.size())`, []any{int64(1), int64(2)}},
		{"macro-filter", `[1, 2, 3].filter(i, i > 1)`, []any{int64(2), int64(3)}},
	}

	e := newTestEnvironment(len(tests))
	data := testEnvData()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := e.Eval(tt.expr, data)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestEnvironment_Eval_json covers the reason Eval converts to a native value
// instead of returning ref.Val.Value(): a list must marshal to a JSON array so
// a template can pipe it to toJson.
func TestEnvironment_Eval_json(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want string
	}{
		{"list-string", `["a", "b"]`, `["a","b"]`},
		{"list-empty", `[]`, `[]`},
		{"list-from-split", `Token.email.split("@")`, `["jane","example.com"]`},
		{"list-from-native", `Subject.names`, `["a","b"]`},
		{"list-of-list", `[["a"], ["b"]]`, `[["a"],["b"]]`},
		{"string", `Token.email`, `"jane@example.com"`},
		{"int", `Token.n`, `3`},
		{"bool", `true`, `true`},
		{"null", `null`, `null`},
		{"map", `{"a": 1}`, `{"a":1}`},
		{"map-from-variable", `Token`, `{"email":"jane@example.com","n":3}`},
		{"map-with-null", `{"a": null}`, `{"a":null}`},
	}

	e := newTestEnvironment(len(tests))
	data := testEnvData()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := e.Eval(tt.expr, data)
			require.NoError(t, err)

			b, err := json.Marshal(got)
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(b))
		})
	}
}

// TestEnvironment_Eval_copies pins that a map result is a copy: ConvertToNative
// can return the very map held in the template data, and modifying an
// evaluation result must not modify the data.
func TestEnvironment_Eval_copies(t *testing.T) {
	e := newTestEnvironment(1)
	data := testEnvData()

	got, err := e.Eval(`Token`, data)
	require.NoError(t, err)

	m, ok := got.(map[string]any)
	require.True(t, ok)
	m["email"] = "changed"

	assert.Equal(t, "jane@example.com", data["Token"].(map[string]any)["email"])
}

func TestEnvironment_Eval_error(t *testing.T) {
	tests := []struct {
		name     string
		env      *Environment
		expr     string
		data     map[string]any
		contains string
	}{
		{
			name:     "fail/environment",
			env:      NewEnvironment(10, badEnvOptions),
			expr:     `1 + 1`,
			contains: "error creating CEL environment",
		},
		{
			name:     "fail/compile",
			env:      newTestEnvironment(10),
			expr:     `1 +`,
			contains: "error compiling CEL expression",
		},
		{
			name:     "fail/division-by-zero",
			env:      newTestEnvironment(10),
			expr:     `1 / 0`,
			contains: "error evaluating CEL expression \"1 / 0\"",
		},
		{
			name:     "fail/index-out-of-bounds",
			env:      newTestEnvironment(10),
			expr:     `[1, 2][5]`,
			contains: "error evaluating CEL expression \"[1, 2][5]\"",
		},
		{
			name:     "fail/missing-key",
			env:      newTestEnvironment(10),
			expr:     `Token.missing`,
			contains: "error evaluating CEL expression \"Token.missing\"",
		},
		{
			name:     "fail/missing-variable",
			env:      newTestEnvironment(10),
			expr:     `Token.email`,
			data:     map[string]any{},
			contains: "error evaluating CEL expression",
		},
		{
			name:     "fail/convert-native-struct",
			env:      newTestEnvironment(10),
			expr:     `Subject`,
			contains: "error converting CEL result",
		},
		{
			name:     "fail/convert-type",
			env:      newTestEnvironment(10),
			expr:     `type(1)`,
			contains: "error converting CEL result",
		},
		{
			name:     "fail/convert-empty-optional",
			env:      newTestEnvironment(10),
			expr:     `optional.none()`,
			contains: "error converting CEL result",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.data
			if data == nil {
				data = testEnvData()
			}
			got, err := tt.env.Eval(tt.expr, data)
			require.Error(t, err)
			assert.Nil(t, got)
			assert.ErrorContains(t, err, tt.contains)
		})
	}
}

// testCreds is a struct cel-go has no adapter for, so converting it fails with
// the value formatted into the error.
type testCreds struct{ Password string }

// TestEnvironment_Eval_errorHoldsBackDetail pins that an evaluation error does
// not repeat template data. Both of the ways a value reaches one of these
// errors are covered: a key computed from a claim, which cel-go reports with
// the same "no such key" sentence it uses for a key written in the expression,
// and a value it cannot convert at all, which it formats whole.
func TestEnvironment_Eval_errorHoldsBackDetail(t *testing.T) {
	e := newTestEnvironment(10)

	t.Run("computed key", func(t *testing.T) {
		_, err := e.Eval(`Token[Token.email]`, testEnvData())
		require.Error(t, err)
		assert.EqualError(t, err, `error evaluating CEL expression "Token[Token.email]"`)
		assert.NotContains(t, err.Error(), "jane@example.com")

		var evalErr *EvalError
		require.ErrorAs(t, err, &evalErr)
		assert.Equal(t, `Token[Token.email]`, evalErr.Expr)
		assert.ErrorContains(t, evalErr.Detail(), "no such key: jane@example.com")
	})

	t.Run("unconvertible value", func(t *testing.T) {
		data := map[string]any{"Token": testCreds{Password: "hunter2"}}
		_, err := e.Eval(`Token.password`, data)
		require.Error(t, err)
		assert.EqualError(t, err, `error evaluating CEL expression "Token.password"`)
		assert.NotContains(t, err.Error(), "hunter2")

		var evalErr *EvalError
		require.ErrorAs(t, err, &evalErr)
		assert.ErrorContains(t, evalErr.Detail(), "hunter2")
	})

	// Exceeding the cost limit keeps its text: it holds no data, and it is the
	// one failure the operator can do something about.
	t.Run("cost limit", func(t *testing.T) {
		withCostLimit(t, 1)
		_, err := e.Eval(`Token.email + Token.email`, testEnvData())
		require.Error(t, err)
		assert.ErrorContains(t, err, `error evaluating CEL expression "Token.email + Token.email"`)
		assert.ErrorContains(t, err, "actual cost limit exceeded")

		var evalErr *EvalError
		assert.NotErrorAs(t, err, &evalErr)
	})
}

func TestEnvironment_Func(t *testing.T) {
	e := newTestEnvironment(10)

	fn := e.Func(testEnvData())
	require.NotNil(t, fn)

	got, err := fn(`Subject.commonName + "@" + Token.email`)
	require.NoError(t, err)
	assert.Equal(t, "leaf@jane@example.com", got)

	// A second function binds different data to the same cached programs.
	other := e.Func(map[string]any{
		"Token":   map[string]any{"email": "john@example.com"},
		"Subject": testSubject{CommonName: "other"},
	})
	got, err = other(`Subject.commonName + "@" + Token.email`)
	require.NoError(t, err)
	assert.Equal(t, "other@john@example.com", got)
	assert.Equal(t, 1, e.programs.Len())

	// The original binding is unaffected.
	got, err = fn(`Subject.commonName + "@" + Token.email`)
	require.NoError(t, err)
	assert.Equal(t, "leaf@jane@example.com", got)

	got, err = fn(`1 +`)
	assert.ErrorContains(t, err, "error compiling CEL expression")
	assert.Nil(t, got)

	// A final argument overrides the bound data, so a function bound to empty
	// data works when the template passes the data as "$".
	unbound := e.Func(map[string]any{})
	got, err = unbound(`Subject.commonName + "@" + Token.email`)
	assert.ErrorContains(t, err, "error evaluating CEL expression")
	assert.Nil(t, got)

	got, err = unbound(`Subject.commonName + "@" + Token.email`, testEnvData())
	require.NoError(t, err)
	assert.Equal(t, "leaf@jane@example.com", got)

	got, err = fn(`Token.email`, map[string]any{
		"Token": map[string]any{"email": "john@example.com"},
	})
	require.NoError(t, err)
	assert.Equal(t, "john@example.com", got)
}

func TestMapGetFunction(t *testing.T) {
	// The function ships with BaseEnvOptions, so it is tested through them, with
	// Metadata declared as the map<string, string> the overload targets. Loose is
	// declared the same but supplies map[string]any data, the shape a dyn-typed
	// value reaching a variable has at runtime.
	e := NewEnvironment(10, func() []cel.EnvOption {
		return append(BaseEnvOptions(),
			cel.Variable("Metadata", cel.MapType(cel.StringType, cel.StringType)),
			cel.Variable("Loose", cel.MapType(cel.StringType, cel.StringType)),
		)
	})
	data := map[string]any{
		"Metadata": map[string]string{"department": "eng"},
		"Loose": map[string]any{
			"s":    "x",
			"n":    3,
			"f":    12345.0,
			"null": nil,
			"m":    map[string]any{"a": "b"},
		},
		"Foo": "Bar",
	}

	tests := []struct {
		name string
		expr string
		want any
	}{
		{"present", `Metadata.get("department")`, "eng"},
		{"absent", `Metadata.get("absent")`, ""},
		{"literal", `{"a": "b"}.get("a")`, "b"},
		{"literal-absent", `{"a": "b"}.get("x")`, ""},
		{"empty-literal", `{}.get("a")`, ""},
		{"chained", `Metadata.get("department").upperAscii()`, "ENG"},
		{"total-in-conditional", `Metadata.get("absent") == "" ? "fallback" : "set"`, "fallback"},
		{"any-map-string-value", `Loose.get("s")`, "x"},
		{"any-map-absent", `Loose.get("absent")`, ""},
		{"any-map-int-value", `Loose.get("n")`, "3"},
		{"any-map-double-value", `Loose.get("f")`, "12345"},
		{"any-map-null-value", `Loose.get("null")`, ""},
		{"any-map-map-value", `Loose.get("m")`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := e.Eval(tt.expr, data)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	// The overload is declared over map receivers only, so a non-map receiver
	// still fails at compile time.
	_, err := e.Eval(`"abc".get("a")`, data)
	assert.ErrorContains(t, err, "error compiling CEL expression")
}
