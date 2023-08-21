package tpmkms

import "errors"

var (
	ErrIdentityCertificateUnavailable = errors.New("AK certificate not available")
	ErrIdentityCertificateNotYetValid = errors.New("AK certificate not yet valid")
	ErrIdentityCertificateExpired     = errors.New("AK certificate has expired")
	ErrIdentityCertificateIsExpiring  = errors.New("AK certificate will expire soon")
	ErrIdentityCertificateInvalid     = errors.New("AK certificate does not contain valid identity")
)
