package templates

import (
	"errors"
	"testing"
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
