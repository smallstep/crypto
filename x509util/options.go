package x509util

import (
	"bytes"
	"crypto/x509"
	encoding_asn1 "encoding/asn1"
	"encoding/base64"
	"os"
	"strings"
	"text/template"

	"github.com/pkg/errors"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	"go.step.sm/crypto/internal/step"
	"go.step.sm/crypto/internal/templates"
)

// Options are the options that can be passed to NewCertificate.
type Options[T templatable] struct {
	CertBuffer *bytes.Buffer
}

func (o *Options[T]) apply(t T, opts []Option[T]) (*Options[T], error) {
	for _, fn := range opts {
		if err := fn(t, o); err != nil {
			return o, err
		}
	}
	return o, nil
}

type templatable interface {
	*x509.CertificateRequest | *x509.Certificate
}

type Option[T templatable] func(t T, o *Options[T]) error

// WithTemplate is an options that executes the given template text with the
// given data.
func WithTemplate[T templatable](text string, data TemplateData) Option[T] {
	return func(t T, o *Options[T]) error {
		terr := new(TemplateError)
		funcMap := templates.GetFuncMap(&terr.Message)
		// asn1 methods
		funcMap["asn1Enc"] = asn1Encode
		funcMap["asn1Marshal"] = asn1Marshal
		funcMap["asn1Seq"] = asn1Sequence
		funcMap["asn1Set"] = asn1Set

		// Parse template
		tmpl, err := template.New("template").Funcs(funcMap).Parse(text)
		if err != nil {
			return errors.Wrapf(err, "error parsing template")
		}

		buf := new(bytes.Buffer)
		if cr, ok := any(t).(*x509.CertificateRequest); ok {
			data.SetCertificateRequest(cr)
		}
		if err := tmpl.Execute(buf, data); err != nil {
			if terr.Message != "" {
				return terr
			}
			return errors.Wrapf(err, "error executing template")
		}
		o.CertBuffer = buf
		return nil
	}
}

// WithTemplateBase64 is an options that executes the given template base64
// string with the given data.
func WithTemplateBase64[T templatable](s string, data TemplateData) Option[T] {
	return func(t T, o *Options[T]) error {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return errors.Wrap(err, "error decoding template")
		}
		fn := WithTemplate[T](string(b), data)
		return fn(t, o)
	}
}

// WithTemplateFile is an options that reads the template file and executes it
// with the given data.
func WithTemplateFile[T templatable](path string, data TemplateData) Option[T] {
	return func(t T, o *Options[T]) error {
		filename := step.Abs(path)
		b, err := os.ReadFile(filename)
		if err != nil {
			return errors.Wrapf(err, "error reading %s", path)
		}
		fn := WithTemplate[T](string(b), data)
		return fn(t, o)
	}
}

func asn1Encode(str string) (string, error) {
	value, params := str, "printable"
	if strings.Contains(value, sanTypeSeparator) {
		params = strings.SplitN(value, sanTypeSeparator, 2)[0]
		value = value[len(params)+1:]
	}
	b, err := marshalValue(value, params)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func asn1Marshal(v interface{}, params ...string) (string, error) {
	b, err := encoding_asn1.MarshalWithParams(v, strings.Join(params, ","))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func asn1Sequence(b64enc ...string) (string, error) {
	var builder cryptobyte.Builder
	builder.AddASN1(asn1.SEQUENCE, func(child *cryptobyte.Builder) {
		for _, s := range b64enc {
			b, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				child.SetError(err)
				return
			}
			child.AddBytes(b)
		}
	})
	b, err := builder.Bytes()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func asn1Set(b64enc ...string) (string, error) {
	var builder cryptobyte.Builder
	builder.AddASN1(asn1.SET, func(child *cryptobyte.Builder) {
		for _, s := range b64enc {
			b, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				child.SetError(err)
				return
			}
			child.AddBytes(b)
		}
	})
	b, err := builder.Bytes()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
