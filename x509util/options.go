package x509util

import (
	"bytes"
	"crypto/x509"
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
type Options struct {
	CertBuffer *bytes.Buffer
}

func (o *Options) apply(cr *x509.CertificateRequest, opts []Option) (*Options, error) {
	for _, fn := range opts {
		if err := fn(cr, o); err != nil {
			return o, err
		}
	}
	return o, nil
}

// Option is the type used as a variadic argument in NewCertificate.
type Option func(cr *x509.CertificateRequest, o *Options) error

// WithTemplate is an options that executes the given template text with the
// given data.
func WithTemplate(text string, data TemplateData) Option {
	return func(cr *x509.CertificateRequest, o *Options) error {
		terr := new(TemplateError)
		funcMap := templates.GetFuncMap(&terr.Message)
		// asn1 methods
		funcMap["asn1enc"] = asn1Encode
		funcMap["asn1Seq"] = asn1Sequence
		funcMap["asn1Set"] = asn1Set
		funcMap["mustASN1Enc"] = mustASN1Encode
		funcMap["mustASN1Seq"] = mustASN1Sequence
		funcMap["mustASN1Set"] = mustASN1Set

		// Parse template
		tmpl, err := template.New("template").Funcs(funcMap).Parse(text)
		if err != nil {
			return errors.Wrapf(err, "error parsing template")
		}

		buf := new(bytes.Buffer)
		data.SetCertificateRequest(cr)
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
func WithTemplateBase64(s string, data TemplateData) Option {
	return func(cr *x509.CertificateRequest, o *Options) error {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return errors.Wrap(err, "error decoding template")
		}
		fn := WithTemplate(string(b), data)
		return fn(cr, o)
	}
}

// WithTemplateFile is an options that reads the template file and executes it
// with the given data.
func WithTemplateFile(path string, data TemplateData) Option {
	return func(cr *x509.CertificateRequest, o *Options) error {
		filename := step.Abs(path)
		b, err := os.ReadFile(filename)
		if err != nil {
			return errors.Wrapf(err, "error reading %s", path)
		}
		fn := WithTemplate(string(b), data)
		return fn(cr, o)
	}
}

func asn1Encode(str string) string {
	b64, err := mustASN1Encode(str)
	if err != nil {
		return err.Error()
	}
	return b64
}

func asn1Sequence(b64enc ...string) string {
	b64, err := mustASN1Sequence(b64enc...)
	if err != nil {
		return err.Error()
	}
	return b64
}

func asn1Set(b64enc ...string) string {
	b64, err := mustASN1Set(b64enc...)
	if err != nil {
		return err.Error()
	}
	return b64
}

func mustASN1Encode(str string) (string, error) {
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

func mustASN1Sequence(b64enc ...string) (string, error) {
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

func mustASN1Set(b64enc ...string) (string, error) {
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
