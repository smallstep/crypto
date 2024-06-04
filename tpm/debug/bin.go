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

func (w *binTap) Write(data []byte) (int, error) {
	w.Lock()
	defer w.Unlock()

	return w.w.Write(data)
}
