package debug

import (
	"io"
	"sync"
)

// NewBinTap creates a new TPM tap that writes the
// the outgoing and incoming TPM communication verbatim
// to the (single) underlying [io.Writer].
func NewBinTap(w io.Writer) Tap {
	return &binTap{w: w}
}

type binTap struct {
	sync.Mutex
	w io.Writer
}

func (t *binTap) Rx() io.Writer {
	return t
}

func (t *binTap) Tx() io.Writer {
	return t
}

// Write implements [io.Writer] and writes the provided data
// to the underlying [io.Writer] verbatim for both TPM commands
// and responses.
func (t *binTap) Write(data []byte) (int, error) {
	t.Lock()
	defer t.Unlock()

	return t.w.Write(data)
}
