package tlsutil

import (
	"crypto/tls"
	"fmt"
)

// ServerRenewFunc defines the type of the functions used to get a new tls
// certificate.
type ServerRenewFunc func(hello *tls.ClientHelloInfo) (*tls.Certificate, *tls.Config, error)

// ServerCredentials is a type that manages the credentials of a server.
type ServerCredentials struct {
	RenewFunc ServerRenewFunc
	cache     *credentialsCache
}

// NewServerCredentials returns a new ServerCredentials that will get
// certificates from the given function.
func NewServerCredentials(fn ServerRenewFunc) (*ServerCredentials, error) {
	return &ServerCredentials{
		RenewFunc: fn,
		cache:     newCredentialsCache(),
	}, nil
}

// GetCertificate returns the certificate for the SNI in the hello message.
func (c *ServerCredentials) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName == "" {
		return nil, fmt.Errorf("server name indication cannot be empty")
	}

	sni, err := SanitizeName(hello.ServerName)
	if err != nil {
		return nil, err
	}

	// Attempt to load a certificate.
	if v, ok := c.cache.Load(sni); ok {
		return v.renewer.GetCertificate(hello)
	}

	renewer, err := c.getCertificate(sni, hello)
	if err != nil {
		return nil, err
	}

	return renewer.GetCertificate(hello)
}

// GetConfigForClient returns the tls.Config used per request.
func (c *ServerCredentials) GetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	if hello.ServerName == "" {
		return nil, fmt.Errorf("server name indication cannot be empty")
	}

	sni, err := SanitizeName(hello.ServerName)
	if err != nil {
		return nil, err
	}

	if v, ok := c.cache.Load(sni); ok {
		return v.renewer.GetConfigForClient(hello)
	}

	renewer, err := c.getCertificate(sni, hello)
	if err != nil {
		return nil, err
	}

	return renewer.GetConfigForClient(hello)
}

func (c *ServerCredentials) getCertificate(sni string, hello *tls.ClientHelloInfo) (*Renewer, error) {
	cert, tlsConfig, err := c.RenewFunc(hello)
	if err != nil {
		return nil, err
	}

	renewer, err := NewRenewer(cert, tlsConfig, func() (*tls.Certificate, *tls.Config, error) {
		return c.RenewFunc(hello)
	})
	if err != nil {
		return nil, err
	}
	renewer.Run()

	c.cache.Store(sni, &credentialsCacheElement{
		sni:     sni,
		renewer: renewer,
	})

	return renewer, nil
}
