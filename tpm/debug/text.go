package debug

import (
	"fmt"
	"io"
)

// NewTextTap creates a new TPM tap that writes the
// the outgoing and incoming TPM communication in hex
// format.
func NewTextTap(reads, writes io.Writer) Tap {
	return &tap{
		in:  &directionalWrapper{reads, true},
		out: &directionalWrapper{writes, false},
	}
}

type tap struct {
	in  io.Writer
	out io.Writer
}

func (t *tap) Rx() io.Writer {
	return t.in
}

func (t *tap) Tx() io.Writer {
	return t.out
}

type directionalWrapper struct {
	w  io.Writer
	in bool
}

// Write implements [io.Writer] and writes the provided data
// to the underlying [io.Writer], formatted as hex, and prefixed
// with the direction of the data.
func (w directionalWrapper) Write(data []byte) (int, error) {
	if w.in {
		return fmt.Fprintf(w.w, "<- %x\n", data)
	}

	return fmt.Fprintf(w.w, "-> %x\n", data)
}
