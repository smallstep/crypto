package close

import "io"

func RWC(rwc io.ReadWriteCloser) error {
	return closeRWC(rwc)
}
