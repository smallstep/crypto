package debug

import (
	"fmt"
	"io"
)

func NewTextTap(reads io.Writer, writes io.Writer) Tap {
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
		return w.w.Write([]byte(fmt.Sprintf("<- %x\n", data)))
	} else {
		return w.w.Write([]byte(fmt.Sprintf("-> %x\n", data)))
	}
}
