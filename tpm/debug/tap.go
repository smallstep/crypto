package debug

import (
	"io"
)

// Tap is an interface providing TPM communication tapping
// capabilities. [Tx] and [Rx] provide access to [io.Writer]s
// that correspond to all (serialized) transmitted and received
// TPM commands and responses, respectively.
type Tap interface {
	Tx() io.Writer
	Rx() io.Writer
}
