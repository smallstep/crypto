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

type Options TOptions[*x509.CertificateRequest]

func (o *Options) apply(cr *x509.CertificateRequest, opts []Option) (*Options, error) {
	to := &TOptions[*x509.CertificateRequest]{}
	for _, fn := range opts {
		if err := fn(cr, to); err != nil {
			return o, err
		}
	}
	o.CertBuffer = to.CertBuffer
	return o, nil
}

type Templatable interface {
	*x509.CertificateRequest | *x509.Certificate
}

type Option TOption[*x509.CertificateRequest]

type TOptions[T Templatable] struct {
	CertBuffer *bytes.Buffer
}

type TOption[T Templatable] func(t T, o *TOptions[T]) error

func (o *TOptions[T]) apply(t T, opts []TOption[T]) (*TOptions[T], error) {
	for _, fn := range opts {
		if err := fn(t, o); err != nil {
			return o, err
		}
	}
	return o, nil
}

func WithTemplatable[T Templatable](text string, data TemplateData) TOption[T] {
	return func(t T, o *TOptions[T]) error {
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

// WithTemplate is an options that executes the given template text with the
// given data.
func WithTemplate(text string, data TemplateData) Option {
	o := WithTemplatable[*x509.CertificateRequest](text, data)
	return Option(o)
}

// WithTemplateBase64 is an options that executes the given template base64
// string with the given data.
func WithTemplateBase64(s string, data TemplateData) Option {
	return func(cr *x509.CertificateRequest, o *TOptions[*x509.CertificateRequest]) error {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return errors.Wrap(err, "error decoding template")
		}
		fn := WithTemplatable[*x509.CertificateRequest](string(b), data)
		return fn(cr, o)
	}
}

// WithTemplateFile is an options that reads the template file and executes it
// with the given data.
func WithTemplateFile(path string, data TemplateData) Option {
	return func(cr *x509.CertificateRequest, o *TOptions[*x509.CertificateRequest]) error {
		filename := step.Abs(path)
		b, err := os.ReadFile(filename)
		if err != nil {
			return errors.Wrapf(err, "error reading %s", path)
		}
		fn := WithTemplatable[*x509.CertificateRequest](string(b), data)
		return fn(cr, o)
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
