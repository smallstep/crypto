package tpm

import (
	"errors"

	"go.step.sm/crypto/tpm/storage"
)

// ErrNotFound is returned when a Key or AK cannot be found
var ErrNotFound = errors.New("not found")

// ErrExists is returned when a Key or AK already exists
var ErrExists = errors.New("already exists")

// ErrNoStorageConfigured is returned when a TPM operation is
// performed that requires a storage to have been configured
var ErrNoStorageConfigured = storage.ErrNoStorageConfigured
