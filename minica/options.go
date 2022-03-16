package minica

import (
	"crypto"
	"crypto/x509"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/x509util"
)

type options struct {
	Name                 string
	RootTemplate         string
	IntermediateTemplate string
	GetSigner            func() (crypto.Signer, error)
}

// Option is the type used to pass custom attributes to the constructor.
type Option func(o *options)

func newOptions() *options {
	return &options{
		Name:                 "MiniCA",
		RootTemplate:         x509util.DefaultRootTemplate,
		IntermediateTemplate: x509util.DefaultIntermediateTemplate,
		GetSigner:            keyutil.GenerateDefaultSigner,
	}
}

func (o *options) apply(opts []Option) *options {
	for _, fn := range opts {
		fn(o)
	}
	return o
}

// WithName is an option that allows to overwrite the default name MiniCA. With
// the default templates, the root and intermediate certificate common names
// would be "<name> Root CA" and "<name> Intermediate CA".
func WithName(name string) Option {
	return func(o *options) {
		o.Name = name
	}
}

// WithRootTemplate is an option that allows to overwrite the template used to
// create the root certificate.
func WithRootTemplate(template string) Option {
	return func(o *options) {
		o.RootTemplate = template
	}
}

// WithIntermediateTemplate is an option that allows to overwrite the template
// used to create the intermediate certificate.
func WithIntermediateTemplate(template string) Option {
	return func(o *options) {
		o.IntermediateTemplate = template
	}
}

// WithGetSignerFunc is an option that allows to overwrite the default function to
// create a signer.
func WithGetSignerFunc(fn func() (crypto.Signer, error)) Option {
	return func(o *options) {
		o.GetSigner = fn
	}
}

type signOptions struct {
	Template string
	Modify   func(*x509.Certificate) error
}

// SignOption is the type used to pass custom attributes when signing a
// certificate request.
type SignOption func(o *signOptions)

func newSignOptions() *signOptions {
	return &signOptions{
		Template: x509util.DefaultLeafTemplate,
	}
}

func (o *signOptions) apply(opts []SignOption) *signOptions {
	for _, fn := range opts {
		fn(o)
	}
	return o
}

// WithTemplate allows to update the template used to convert a CSR into a
// certificate.
func WithTemplate(template string) SignOption {
	return func(o *signOptions) {
		o.Template = template
	}
}

// WithModifyFunc allows to update the certificate template before the signing
// it.
func WithModifyFunc(fn func(*x509.Certificate) error) SignOption {
	return func(o *signOptions) {
		o.Modify = fn
	}
}
