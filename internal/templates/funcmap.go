package templates

import (
	"errors"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"go.step.sm/crypto/jose"
)

// GetFuncMap returns the list of functions provided by sprig. It adds the
// function "toTime" and changes the function "fail". 
//
// The "toTime" function receives a time or a Unix epoch and formats it to 
// RFC3339 in UTC. The "fail" function sets the provided message, so that 
// template errors are reported directly to the template without having the
// wrapper that text/template adds.
// 
//
// sprig "env" and "expandenv" functions are removed to avoid the leak of
// information.
func GetFuncMap(failMessage *string) template.FuncMap {
	m := sprig.TxtFuncMap()
	delete(m, "env")
	delete(m, "expandenv")
	m["fail"] = func(msg string) (string, error) {
		*failMessage = msg
		return "", errors.New(msg)
	}
	m["toTime"] = toTime
	return m
}

func toTime(v any) string {
	var t time.Time
	switch date := v.(type) {
	case time.Time:
		t = date
	case *time.Time:
		t = *date
	case int64:
		t = time.Unix(date, 0)
	case float64: // from json
		t = time.Unix(int64(date), 0)
	case int:
		t = time.Unix(int64(date), 0)
	case int32:
		t = time.Unix(int64(date), 0)
	case jose.NumericDate:
		t = date.Time()
	case *jose.NumericDate:
		t = date.Time()
	default:
		t = time.Now()
	}
	return t.UTC().Format(time.RFC3339)
}
