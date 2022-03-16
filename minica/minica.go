package minica

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"go.step.sm/crypto/sshutil"
	"go.step.sm/crypto/x509util"
	"golang.org/x/crypto/ssh"
)

// CA is the implementation of a simple X.509 and SSH CA.
type CA struct {
	Root          *x509.Certificate
	Intermediate  *x509.Certificate
	Signer        crypto.Signer
	SSHHostSigner ssh.Signer
	SSHUserSigner ssh.Signer
}

// New creates a new MiniCA, the custom options allows to overwrite templates,
// signer types and certificate names.
func New(opts ...Option) (*CA, error) {
	now := time.Now()
	o := newOptions().apply(opts)

	// Create root
	rootSubject := o.Name + " Root CA"
	rootSigner, err := o.GetSigner()
	if err != nil {
		return nil, err
	}
	rootCR, err := x509util.CreateCertificateRequest(rootSubject, []string{}, rootSigner)
	if err != nil {
		return nil, err
	}
	cert, err := x509util.NewCertificate(rootCR, x509util.WithTemplate(o.RootTemplate, x509util.CreateTemplateData(rootSubject, []string{})))
	if err != nil {
		return nil, err
	}
	template := cert.GetCertificate()
	template.NotBefore = now
	template.NotAfter = now.Add(24 * time.Hour)
	root, err := x509util.CreateCertificate(template, template, rootSigner.Public(), rootSigner)
	if err != nil {
		return nil, err
	}

	// Create intermediate
	intSubject := o.Name + " Intermediate CA"
	intSigner, err := o.GetSigner()
	if err != nil {
		return nil, err
	}
	intCR, err := x509util.CreateCertificateRequest(intSubject, []string{}, intSigner)
	if err != nil {
		return nil, err
	}
	cert, err = x509util.NewCertificate(intCR, x509util.WithTemplate(o.IntermediateTemplate, x509util.CreateTemplateData(intSubject, []string{})))
	if err != nil {
		return nil, err
	}
	template = cert.GetCertificate()
	template.NotBefore = now
	template.NotAfter = now.Add(24 * time.Hour)
	intermediate, err := x509util.CreateCertificate(template, root, intSigner.Public(), rootSigner)
	if err != nil {
		return nil, err
	}

	// Ssh host signer
	signer, err := o.GetSigner()
	if err != nil {
		return nil, err
	}
	sshHostSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, err
	}

	// Ssh user signer
	signer, err = o.GetSigner()
	if err != nil {
		return nil, err
	}
	sshUserSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, err
	}

	return &CA{
		Root:          root,
		Intermediate:  intermediate,
		Signer:        intSigner,
		SSHHostSigner: sshHostSigner,
		SSHUserSigner: sshUserSigner,
	}, nil
}

// Sign signs an X.509 certificate template using the intermediate certificate.
func (c *CA) Sign(template *x509.Certificate) (*x509.Certificate, error) {
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now()
	}
	if template.NotAfter.IsZero() {
		template.NotAfter = template.NotBefore.Add(24 * time.Hour)
	}
	return x509util.CreateCertificate(template, c.Intermediate, template.PublicKey, c.Signer)
}

// SignCSR signs an X.509 certificate signing request. The custom options allows to change the template used for
func (c *CA) SignCSR(csr *x509.CertificateRequest, opts ...SignOption) (*x509.Certificate, error) {
	sans := append([]string{}, csr.DNSNames...)
	sans = append(sans, csr.EmailAddresses...)
	for _, ip := range csr.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, u := range csr.URIs {
		sans = append(sans, u.String())
	}

	o := newSignOptions().apply(opts)
	crt, err := x509util.NewCertificate(csr, x509util.WithTemplate(o.Template, x509util.CreateTemplateData(csr.Subject.CommonName, sans)))
	if err != nil {
		return nil, err
	}

	cert := crt.GetCertificate()
	if o.Modify != nil {
		if err := o.Modify(cert); err != nil {
			return nil, err
		}
	}

	return c.Sign(cert)
}

// SignSSH signs an SSH host or user certificate.
func (c *CA) SignSSH(cert *ssh.Certificate) (*ssh.Certificate, error) {
	if cert.ValidAfter == 0 {
		cert.ValidAfter = uint64(time.Now().Unix())
	}
	if cert.ValidBefore == 0 {
		cert.ValidBefore = cert.ValidAfter + 24*60*60
	}

	switch cert.CertType {
	case ssh.HostCert:
		return sshutil.CreateCertificate(cert, c.SSHHostSigner)
	case ssh.UserCert:
		return sshutil.CreateCertificate(cert, c.SSHUserSigner)
	default:
		return nil, fmt.Errorf("unknown certificate type")
	}

}
