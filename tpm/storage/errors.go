package storage

import "errors"

// TODO: provide key/ak name in the error?

// ErrNotFound is returned when a Key or AK cannot be found in storage
var ErrNotFound = errors.New("not found")

// ErrExists is returned when a Key or AK already exists in storage
var ErrExists = errors.New("already exists")

// ErrNoStorageConfigured is returned when a TPM operation is
// performed that requires a storage to have been configured
var ErrNoStorageConfigured = errors.New("no storage configured")
