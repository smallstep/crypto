package storage

import "errors"

// TODO: provide key/ak name in the error?
var ErrNotFound = errors.New("not found")
var ErrExists = errors.New("already exists")
