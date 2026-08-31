package sshutil

import (
	"bytes"
	"encoding/base64"
	"os"
	"text/template"

	"github.com/pkg/errors"
)

// Options are the options that can be passed to NewCertificate.
type Options struct {
	CertBuffer *bytes.Buffer
}

func (o *Options) apply(cr CertificateRequest, opts []Option) (*Options, error) {
	for _, fn := range opts {
		if err := fn(cr, o); err != nil {
			return o, err
		}
	}
	return o, nil
}

// Option is the type used as a variadic argument in NewCertificate.
type Option func(cr CertificateRequest, o *Options) error

// GetFuncMap returns the list of functions used by the templates. It will
// return all the functions supported by "sprig.TxtFuncMap()" but exclude "env"
// and "expandenv", removed to avoid the leak of information. It will also add
// the "cel" function to evaluate CEL expressions.
//
// A func map returned here is not bound to any template data, so a template
// using it passes the data to "cel" as a final argument:
//
//	{{ cel "Token.sub" $ }}
//
// An expression reads the template data through the variables below. A variable
// the request did not set is absent rather than empty, and reading it fails the
// evaluation instead of rendering nothing:
//
//   - Type: the certificate type, "user" or "host".
//   - KeyID: the requested key id.
//   - Principals: the requested principals.
//   - Extensions: the certificate extensions.
//   - CriticalOptions: the certificate critical options.
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
// An expression is metered and canceled once it exceeds a cost ceiling, so a
// template cannot make signing arbitrarily expensive. See [SetCELCostLimit].
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
	return func(cr CertificateRequest, o *Options) error {
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
	return func(cr CertificateRequest, o *Options) error {
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
	return func(cr CertificateRequest, o *Options) error {
		b, err := os.ReadFile(path)
		if err != nil {
			return errors.Wrapf(err, "error reading %s", path)
		}
		fn := WithTemplate(string(b), data)
		return fn(cr, o)
	}
}
