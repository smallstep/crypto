package x509util

import (
	"bytes"
	"crypto/x509"
	encoding_asn1 "encoding/asn1"
	"encoding/base64"
	"fmt"
	"os"
	"reflect"
	"strings"
	"text/template"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"
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
// the following functions to encode data using ASN.1:
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
	return getFuncMap(new(TemplateError))
}

func getFuncMap(err *TemplateError) template.FuncMap {
	funcMap := builtinFuncMap(err)
	templateFuncs.Apply(funcMap)
	return funcMap
}

type celFunc struct {
	data TemplateData
	env  *cel.Env
}

func newCelFunc(data TemplateData) (*celFunc, error) {
	env, err := cel.NewEnv(
		// Extensions
		ext.Strings(), ext.Encoders(), ext.Lists(), ext.Sets(), ext.Network(),
		cel.OptionalTypes(), // required by regex
		ext.Regex(),
		// Types
		cel.Variable(SubjectKey, cel.ObjectType("x509util.Subject")),
		cel.Variable(SANsKey, cel.ListType(cel.ObjectType("x509util.SubjectAlternativeName"))),
		cel.Variable(TokenKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(WebhooksKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(InsecureKey, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(AuthorizationCrtKey, cel.DynType),
		cel.Variable(AuthorizationChainKey, cel.ListType(cel.DynType)),
		cel.Variable(CertificateRequestKey, cel.ObjectType("x509util.CertificateRequest")),
		ext.NativeTypes(reflect.TypeOf(SubjectAlternativeName{}), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeOf(Subject{}), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeOf(Certificate{}), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeOf(CertificateRequest{}), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeOf(x509.Certificate{}), ext.ParseStructTag("cel")),
		ext.NativeTypes(reflect.TypeOf(x509.CertificateRequest{}), ext.ParseStructTag("cel")),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating CEL environment: %w", err)
	}

	return &celFunc{
		data: data,
		env:  env,
	}, nil
}

func (c *celFunc) call(expr string) (string, error) {
	ast, iss := c.env.Compile(expr)
	if err := iss.Err(); err != nil {
		return "", fmt.Errorf("error compiling CEL expression: %w", err)
	}

	prg, err := c.env.Program(ast, cel.EvalOptions(cel.OptOptimize), cel.CostLimit(1000))
	if err != nil {
		return "", fmt.Errorf("error creating CEL program: %w", err)
	}

	out, _, err := prg.Eval(map[string]any(c.data))
	if err != nil {
		return "", fmt.Errorf("error evaluating CEL expresion: %w", err)
	}

	return fmt.Sprint(out), nil
}

// WithTemplate is an options that executes the given template text with the
// given data.
func WithTemplate(text string, data TemplateData) Option {
	return func(cr *x509.CertificateRequest, o *Options) error {
		celfn, err := newCelFunc(data)
		if err != nil {
			return err
		}

		terr := new(TemplateError)
		funcMap := getFuncMap(terr)
		funcMap["cel"] = celfn.call

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
