package debug

import (
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
