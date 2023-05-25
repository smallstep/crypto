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
	RootSigner    crypto.Signer
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
		RootSigner:    rootSigner,
		Intermediate:  intermediate,
		Signer:        intSigner,
		SSHHostSigner: sshHostSigner,
		SSHUserSigner: sshUserSigner,
	}, nil
}

// Sign signs an X.509 certificate template using the intermediate certificate.
// Sign will automatically populate the following fields if they are not
// specified:
//
//   - NotBefore will be set to the current time.
//   - NotAfter will be set to 24 hours after NotBefore.
//   - SerialNumber will be automatically generated.
//   - SubjectKeyId will be automatically generated.
func (c *CA) Sign(template *x509.Certificate) (*x509.Certificate, error) {
	mut := *template
	if mut.NotBefore.IsZero() {
		mut.NotBefore = time.Now()
	}
	if mut.NotAfter.IsZero() {
		mut.NotAfter = mut.NotBefore.Add(24 * time.Hour)
	}
	return x509util.CreateCertificate(&mut, c.Intermediate, mut.PublicKey, c.Signer)
}

// SignCSR signs an X.509 certificate signing request. The custom options allows
// to change the template used to convert the CSR to a certificate.
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

// SignSSH signs an SSH host or user certificate. SignSSH will automatically
// populate the following fields if they are not specified:
//
//   - ValidAfter will be set to the current time unless ValidBefore is set to ssh.CertTimeInfinity.
//   - ValidBefore will be set to 24 hours after ValidAfter.
//   - Nonce will be automatically generated.
//   - Serial will be automatically generated.
//
// If the SSH signer is an RSA key, it will use rsa-sha2-256 instead of the
// default ssh-rsa (SHA-1), this method is currently deprecated and
// rsa-sha2-256/512 are supported since OpenSSH 7.2 (2016).
func (c *CA) SignSSH(template *ssh.Certificate) (*ssh.Certificate, error) {
	mut := *template
	if mut.ValidAfter == 0 && mut.ValidBefore != ssh.CertTimeInfinity {
		mut.ValidAfter = uint64(time.Now().Unix())
	}
	if mut.ValidBefore == 0 {
		mut.ValidBefore = mut.ValidAfter + 24*60*60
	}

	switch mut.CertType {
	case ssh.HostCert:
		return sshutil.CreateCertificate(&mut, c.SSHHostSigner)
	case ssh.UserCert:
		return sshutil.CreateCertificate(&mut, c.SSHUserSigner)
	default:
		return nil, fmt.Errorf("unknown certificate type")
	}
}
