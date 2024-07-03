package templates

import (
	"bytes"
	"errors"
	"strconv"
	"testing"
	"text/template"
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

func TestGetFuncMap_toTime_formatTime(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	numericDate := jose.NewNumericDate(now)
	expected := now.UTC()
	loc, err := time.LoadLocation("America/Los_Angeles")
	require.NoError(t, err)

	type args struct {
		v any
	}
	tests := []struct {
		name string
		args args
		want time.Time
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
			toTimeFunc := fns["toTime"].(func(any) time.Time)
			assert.Equal(t, tt.want, toTimeFunc(tt.args.v))
			formatTimeFunc := fns["formatTime"].(func(any) string)
			assert.Equal(t, tt.want.Format(time.RFC3339), formatTimeFunc(tt.args.v))
		})
	}

	t.Run("default", func(t *testing.T) {
		var failMesage string
		fns := GetFuncMap(&failMesage)
		toTimeFunc := fns["toTime"].(func(any) time.Time)
		got := toTimeFunc(nil)
		assert.WithinDuration(t, time.Now(), got, time.Second)

		formatTimeFunc := fns["formatTime"].(func(any) string)
		got, err := time.Parse(time.RFC3339, formatTimeFunc(nil))
		require.NoError(t, err)
		assert.WithinDuration(t, time.Now(), got, time.Second)
		assert.Equal(t, time.UTC, got.Location())
	})
}

func TestGetFuncMap_parseTime_mustParseTime(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	loc := time.Local
	if zone, _ := now.Zone(); zone == "UTC" {
		loc = time.UTC
	}

	losAngeles, err := time.LoadLocation("America/Los_Angeles")
	require.NoError(t, err)

	type args struct {
		v []string
	}
	tests := []struct {
		name      string
		args      args
		want      time.Time
		assertion assert.ErrorAssertionFunc
	}{
		{"now", args{[]string{now.Format(time.RFC3339)}}, now.In(loc), assert.NoError},
		{"with real layout", args{[]string{time.UnixDate, now.UTC().Format(time.UnixDate)}}, now.UTC(), assert.NoError},
		{"with name layout", args{[]string{"time.UnixDate", now.Format(time.UnixDate)}}, now.In(loc), assert.NoError},
		{"with locale UTC", args{[]string{"time.UnixDate", now.UTC().Format(time.UnixDate), "UTC"}}, now.UTC(), assert.NoError},
		{"with locale other", args{[]string{"time.UnixDate", now.In(losAngeles).Format(time.UnixDate), "America/Los_Angeles"}}, now.In(losAngeles), assert.NoError},
		{"fail parse", args{[]string{now.Format(time.UnixDate)}}, time.Time{}, assert.Error},
		{"fail parse with layout", args{[]string{"time.UnixDate", now.Format(time.RFC3339)}}, time.Time{}, assert.Error},
		{"fail parse with locale", args{[]string{"time.UnixDate", now.Format(time.RFC3339), "america/Los_Angeles"}}, time.Time{}, assert.Error},
		{"fail load locale", args{[]string{"time.UnixDate", now.In(losAngeles).Format(time.UnixDate), "America/The_Angels"}}, time.Time{}, assert.Error},
		{"fail arguments", args{[]string{"time.Layout", now.Format(time.Layout), "America/The_Angels", "extra"}}, time.Time{}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var failMesage string
			fns := GetFuncMap(&failMesage)
			parseTimeFunc := fns["parseTime"].(func(...string) time.Time)
			assert.Equal(t, tt.want, parseTimeFunc(tt.args.v...))

			mustParseTimeFunc := fns["mustParseTime"].(func(...string) (time.Time, error))
			got, err := mustParseTimeFunc(tt.args.v...)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	t.Run("default", func(t *testing.T) {
		var failMesage string
		fns := GetFuncMap(&failMesage)
		parseTimeFunc := fns["parseTime"].(func(...string) time.Time)
		got := parseTimeFunc()
		assert.WithinDuration(t, time.Now(), got, time.Second)

		mustParseTimeFunc := fns["mustParseTime"].(func(...string) (time.Time, error))
		got, err := mustParseTimeFunc()
		require.NoError(t, err)
		assert.WithinDuration(t, time.Now(), got, time.Second)
		assert.Equal(t, time.UTC, got.Location())
	})
}

func TestGetFuncMap_toLayout(t *testing.T) {
	type args struct {
		fmt string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"format", args{time.RFC3339}, time.RFC3339},
		{"time.Layout", args{"time.Layout"}, time.Layout},
		{"time.ANSIC", args{"time.ANSIC"}, time.ANSIC},
		{"time.UnixDate", args{"time.UnixDate"}, time.UnixDate},
		{"time.RubyDate", args{"time.RubyDate"}, time.RubyDate},
		{"time.RFC822", args{"time.RFC822"}, time.RFC822},
		{"time.RFC822Z", args{"time.RFC822Z"}, time.RFC822Z},
		{"time.RFC850", args{"time.RFC850"}, time.RFC850},
		{"time.RFC1123", args{"time.RFC1123"}, time.RFC1123},
		{"time.RFC1123Z", args{"time.RFC1123Z"}, time.RFC1123Z},
		{"time.RFC3339", args{"time.RFC3339"}, time.RFC3339},
		{"time.RFC3339Nano", args{"time.RFC3339Nano"}, time.RFC3339Nano},
		{"time.Kitchen", args{"time.Kitchen"}, time.Kitchen},
		{"time.Stamp", args{"time.Stamp"}, time.Stamp},
		{"time.StampMilli", args{"time.StampMilli"}, time.StampMilli},
		{"time.StampMicro", args{"time.StampMicro"}, time.StampMicro},
		{"time.StampNano", args{"time.StampNano"}, time.StampNano},
		{"time.DateTime", args{"time.DateTime"}, time.DateTime},
		{"time.DateOnly", args{"time.DateOnly"}, time.DateOnly},
		{"time.TimeOnly", args{"time.TimeOnly"}, time.TimeOnly},
		{"default", args{"time.MyFormat"}, "time.MyFormat"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var failMesage string
			fns := GetFuncMap(&failMesage)
			toLayoutFunc := fns["toLayout"].(func(string) string)
			assert.Equal(t, tt.want, toLayoutFunc(tt.args.fmt))
		})
	}
}

func TestTemplates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	mustParse := func(t *testing.T, text string, msg *string, assertion assert.ErrorAssertionFunc) string {
		t.Helper()

		tmpl, err := template.New(t.Name()).Funcs(GetFuncMap(msg)).Parse(text)
		require.NoError(t, err)
		buf := new(bytes.Buffer)
		err = tmpl.Execute(buf, map[string]any{
			"nbf":       now.Unix(),
			"float64":   float64(now.Unix()),
			"notBefore": now.Format(time.RFC3339),
			"notAfter":  now.Add(time.Hour).Format(time.UnixDate),
		})
		assertion(t, err)
		return buf.String()
	}

	type args struct {
		text string
	}
	tests := []struct {
		name           string
		args           args
		want           string
		errorAssertion assert.ErrorAssertionFunc
		failAssertion  assert.ValueAssertionFunc
	}{
		{"toTime int64", args{`{{ .nbf | toTime }}`}, now.String(), assert.NoError, assert.Empty},
		{"toTime int64 toJson", args{`{{ .nbf | toTime | toJson }}`}, strconv.Quote(now.Format(time.RFC3339)), assert.NoError, assert.Empty},
		{"toTime float64 toJson", args{`{{ .float64 | toTime | toJson }}`}, strconv.Quote(now.Format(time.RFC3339)), assert.NoError, assert.Empty},
		{"formatTime", args{`{{ .nbf | formatTime }}`}, now.Format(time.RFC3339), assert.NoError, assert.Empty},
		{"formatTime float64", args{`{{ .float64 | formatTime }}`}, now.Format(time.RFC3339), assert.NoError, assert.Empty},
		{"formatTime in sprig", args{`{{ dateInZone "2006-01-02T15:04:05Z07:00" .float64 "UTC" }}`}, now.UTC().Format(time.RFC3339), assert.NoError, assert.Empty},
		{"parseTime", args{`{{ .notBefore | parseTime }}`}, now.String(), assert.NoError, assert.Empty},
		{"parseTime toJson", args{`{{ .notBefore | parseTime | toJson }}`}, strconv.Quote(now.Format(time.RFC3339)), assert.NoError, assert.Empty},
		{"parseTime time.UnixDate", args{`{{ .notAfter | parseTime "time.UnixDate" }}`}, now.Add(time.Hour).String(), assert.NoError, assert.Empty},
		{"parseTime time.UnixDate toJson", args{`{{ .notAfter | parseTime "time.UnixDate" | toJson }}`}, strconv.Quote(now.Add(time.Hour).Format(time.RFC3339)), assert.NoError, assert.Empty},
		{"parseTime time.UnixDate America/Los_Angeles", args{`{{ parseTime "time.UnixDate" .notAfter "America/Los_Angeles" }}`}, now.Add(time.Hour).String(), assert.NoError, assert.Empty},
		{"parseTime in sprig ", args{`{{ toDate "Mon Jan _2 15:04:05 MST 2006" .notAfter }}`}, now.Add(time.Hour).String(), assert.NoError, assert.Empty},
		{"toTime toLayout date", args{`{{ .nbf | toTime | date (toLayout "time.RFC3339") }}`}, now.Local().Format(time.RFC3339), assert.NoError, assert.Empty},
		{"parseTime error", args{`{{ parseTime "time.UnixDate" .notAfter "America/FooBar" }}`}, "0001-01-01 00:00:00 +0000 UTC", assert.NoError, assert.Empty},
		{"mustParseTime error", args{`{{ mustParseTime "time.UnixDate" .notAfter "America/FooBar" }}`}, "", assert.Error, assert.Empty},
		{"fail", args{`{{ fail "error" }}`}, "", assert.Error, assert.NotEmpty},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var failMesage string
			got := mustParse(t, tt.args.text, &failMesage, tt.errorAssertion)
			tt.failAssertion(t, failMesage)
			assert.Equal(t, tt.want, got)
		})
	}
}
