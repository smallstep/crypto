package templates

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
)

func Test_GetFuncMap_fail(t *testing.T) {
	var failMesage string
	fns := GetFuncMap(&failMesage)
	fail := fns["fail"].(func(s string) (string, error))
	s, err := fail("the fail message")
	if err == nil {
		t.Errorf("fail() error = %v, wantErr %v", err, errors.New("the fail message"))
	}
	if s != "" {
		t.Errorf("fail() = \"%s\", want \"the fail message\"", s)
	}
	if failMesage != "the fail message" {
		t.Errorf("fail() message = \"%s\", want \"the fail message\"", failMesage)
	}
}

func TestGetFuncMap_toTime(t *testing.T) {
	now := time.Now()
	numericDate := jose.NewNumericDate(now)
	expected := now.UTC().Format(time.RFC3339)
	loc, err := time.LoadLocation("America/Los_Angeles")
	require.NoError(t, err)

	type args struct {
		v any
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"time", args{now}, expected},
		{"time pointer", args{&now}, expected},
		{"time UTC", args{now.UTC()}, expected},
		{"time with location", args{now.In(loc)}, expected},
		{"unix", args{now.Unix()}, expected},
		{"unix int", args{int(now.Unix())}, expected},
		{"unix int32", args{int32(now.Unix())}, expected},
		{"unix float64", args{float64(now.Unix())}, expected},
		{"unix float64", args{float64(now.Unix()) + 0.999}, expected},
		{"jose.NumericDate", args{*numericDate}, expected},
		{"jose.NumericDate pointer", args{numericDate}, expected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var failMesage string
			fns := GetFuncMap(&failMesage)
			fn := fns["toTime"].(func(any) string)
			assert.Equal(t, tt.want, fn(tt.args.v))
		})
	}

	t.Run("default", func(t *testing.T) {
		var failMesage string
		fns := GetFuncMap(&failMesage)
		fn := fns["toTime"].(func(any) string)
		want := time.Now()
		got, err := time.Parse(time.RFC3339, fn(nil))
		require.NoError(t, err)
		assert.WithinDuration(t, want, got, time.Second)
		assert.Equal(t, time.UTC, got.Location())
	})
}
