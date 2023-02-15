package tpm

import "errors"

// ErrNotFound is returned when a Key or AK cannot be found
var ErrNotFound = errors.New("not found")

// ErrExists is returned when a Key or AK already exists
var ErrExists = errors.New("already exists")
