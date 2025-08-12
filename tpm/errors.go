package tpm

import (
	"go.step.sm/crypto/tpm/storage"
)

// ErrNotFound is returned when a Key or AK cannot be found
var ErrNotFound = storage.ErrNotFound

// ErrExists is returned when a Key or AK already exists
var ErrExists = storage.ErrExists

// ErrNoStorageConfigured is returned when a TPM operation is
// performed that requires a storage to have been configured
var ErrNoStorageConfigured = storage.ErrNoStorageConfigured
