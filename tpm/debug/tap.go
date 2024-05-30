package debug

import "io"

type Tap interface {
	In() io.Writer
	Out() io.Writer
}

type tap struct {
	in  io.Writer
	out io.Writer
}

func (t tap) In() io.Writer {
	return t.in
}

func (t tap) Out() io.Writer {
	return t.out
}

func NewTap(reads io.Writer, writes io.Writer) Tap {
	return &tap{
		in:  reads,
		out: writes,
	}
}
