package tpm

import (
	"errors"
	"fmt"

	"go.step.sm/crypto/tpm/storage"
)

// ErrNotFound is returned when a Key or AK cannot be found
var ErrNotFound = errors.New("not found")

// ErrExists is returned when a Key or AK already exists
var ErrExists = errors.New("already exists")

// ErrNoStorageConfigured is returned when a TPM operation is
// performed that requires a storage to have been configured
var ErrNoStorageConfigured = storage.ErrNoStorageConfigured

// PartialDeleteError is returned by DeleteKey or DeleteAK when the
// in-TPM (NCrypt PCP / attest) deletion failed but the file-store
// entry was successfully removed. Callers can use [errors.As] to
// detect this case and decide whether to treat it as a transient
// failure (the named entry is gone from local bookkeeping; the
// underlying TPM key may or may not still exist).
//
// Cleaning up the file-store entry even on PCP failure prevents
// repeated retries from re-encountering the same failing entry,
// which is the failure mode that motivated this type.
type PartialDeleteError struct {
	// Name is the key/AK name that was being deleted.
	Name string
	// Underlying is the error returned by the in-TPM deletion.
	Underlying error
}

func (e *PartialDeleteError) Error() string {
	return fmt.Sprintf("file-store entry %q removed but TPM deletion failed: %v", e.Name, e.Underlying)
}

func (e *PartialDeleteError) Unwrap() error { return e.Underlying }
