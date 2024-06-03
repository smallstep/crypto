package debug

import (
	"fmt"
	"io"
)

type Tap interface {
	Tx() io.Writer
	Rx() io.Writer
}

type tap struct {
	in  io.Writer
	out io.Writer
}

func (t tap) Rx() io.Writer {
	return t.in
}

func (t tap) Tx() io.Writer {
	return t.out
}

func NewTap(rx io.Writer, tx io.Writer) Tap {
	return &tap{
		in:  rx,
		out: tx,
	}
}

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
