package tlsutil

import (
	"go.step.sm/crypto/x509util"
	"net"
)

// SanitizeName converts the given domain to its ASCII form.
var SanitizeName = x509util.SanitizeName

// SanitizeHost returns the ASCII form of the host part in a host:port address.
func SanitizeHost(host string) (string, error) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return x509util.SanitizeName(h)
	}
	return x509util.SanitizeName(host)
}
