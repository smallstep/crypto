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

// GetFuncMap returns the list of functions used by the templates. It will
// return all the functions supported by "sprig.TxtFuncMap()" but exclude "env"
// and "expandenv", removed to avoid the leak of information. It will also add
// the "cel" function to evaluate CEL expressions and functions to encode data
// using ASN.1.
//
// A func map returned here is not bound to any template data, so a template
// using it passes the data to "cel" as a final argument:
//
//	{{ cel "Token.sub" $ }}
//
// An expression reads the template data through the variables below. A
// variable the request did not set is absent rather than empty, and reading it
// fails the evaluation instead of rendering nothing:
//
//   - Subject: the requested subject.
//   - SANs: the requested subject alternative names, each with Type, Value and
//     ASN1Value.
//   - Token: the claims of the token that authorized the request.
//   - Webhooks: the data returned by the enriching webhooks, keyed by the name
//     of the webhook that returned it.
//   - Insecure: data that has not been verified, holding User, the object the
//     requester sent, and CR, the certificate request.
//   - AuthorizationCrt: the certificate that authorized the request.
//   - AuthorizationChain: the certificate chain that authorized the request.
//
// Expressions are evaluated with these CEL extensions enabled: optional types,
// "strings", "encoders", "lists", "sets", "network", "regex" and two-variable
// comprehensions. Maps carry one addition, a total accessor that reads an
// absent or null key as the empty string, for the payloads that hold whatever
// JSON gave them:
//
//	{{ cel "Webhooks.Device.get('Serial')" }}
//
// An expression is metered and cancelled once it exceeds a cost ceiling, so a
// template cannot make signing arbitrarily expensive. See [SetCELCostLimit].
//
// The following functions encode data using ASN.1:
//
//   - asn1Enc: encodes the given string to ASN.1. By default, it will use the
//     PrintableString format but it can be change using the suffix ":<format>".
//     Supported formats are: "printable", "utf8", "ia5", "numeric", "int", "oid",
//     "utc", "generalized", and "raw".
//   - asn1Marshal: encodes the given string with the given params using Go's
//     asn1.MarshalWithParams.
//   - asn1Seq: encodes a sequence of the given ASN.1 data.
//   - asn1Set: encodes a set of the given ASN.1 data.
func GetFuncMap() template.FuncMap {
	return getFuncMap(TemplateData{}, new(TemplateError))
}

func getFuncMap(data TemplateData, err *TemplateError) template.FuncMap {
	funcMap := builtinFuncMap(data, err)
	templateFuncs.Apply(funcMap)
	return funcMap
}

// WithTemplate is an options that executes the given template text with the
// given data.
func WithTemplate(text string, data TemplateData) Option {
	return func(cr *x509.CertificateRequest, o *Options) error {
		terr := new(TemplateError)
		funcMap := getFuncMap(data, terr)

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
		b, err := os.ReadFile(path)
		if err != nil {
			return errors.Wrapf(err, "error reading %s", path)
		}
		fn := WithTemplate(string(b), data)
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
