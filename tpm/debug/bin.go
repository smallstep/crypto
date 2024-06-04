package debug

import (
	"io"
	"sync"
)

type binTap struct {
	sync.Mutex
	w io.Writer
}

func (t *binTap) Rx() io.Writer {
	return t.w
}

func (t *binTap) Tx() io.Writer {
	return t.w
}

func NewBinTap(w io.Writer) Tap {
	return &binTap{w: w}
}

func (t *binTap) Write(data []byte) (int, error) {
	t.Lock()
	defer t.Unlock()

	return t.w.Write(data)
}
