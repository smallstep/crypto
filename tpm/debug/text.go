package debug

import (
	"fmt"
	"io"
)

func NewTextTap(reads, writes io.Writer) Tap {
	return &tap{
		in:  &wrapper{reads, true},
		out: &wrapper{writes, false},
	}
}

type wrapper struct {
	w  io.Writer
	in bool
}

func (w *wrapper) Write(data []byte) (int, error) {
	if w.in {
		return fmt.Fprintf(w.w, "<- %x\n", data)
	}

	return fmt.Fprintf(w.w, "-> %x\n", data)
}
