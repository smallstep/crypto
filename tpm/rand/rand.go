package rand

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"

	tpmp "go.step.sm/crypto/tpm"
)

type generator struct {
	t         *tpmp.TPM
	readError error
}

func New(opts ...tpmp.NewTPMOption) (io.Reader, error) {
	t, err := tpmp.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed creating TPM instance: %w", err)
	}
	return &generator{
		t: t,
	}, nil
}

func (g *generator) Read(p []byte) (n int, err error) {
	if g.readError != nil {
		errMsg := g.readError.Error() // multiple wrapped errors not (yet) allowed
		return 0, fmt.Errorf("failed generating random bytes in previous call to Read: %s: %w", errMsg, io.EOF)
	}
	if len(p) > math.MaxUint16 {
		return 0, fmt.Errorf("number of random bytes to read cannot exceed %d", math.MaxUint16)
	}
	ctx := context.Background()
	var result []byte
	requestedLength := len(p)
	singleRequestLength := uint16(len(p))
	for len(result) < requestedLength {
		if r, err := g.t.GenerateRandom(ctx, singleRequestLength); err == nil {
			result = append(result, r...)
		} else {
			var s tpmp.ShortRandomReadError
			if errors.As(err, &s) && s.Generated > 0 {
				// adjust number of bytes to request if at least some data was read and continue loop
				singleRequestLength = uint16(s.Generated)
				result = append(result, r...)
			} else {
				g.readError = err // store the error to be returned for future calls to Read
				n = copy(p, result)
				return n, nil // return the result recorded so far and no error
			}
		}
	}

	n = copy(p, result)
	return
}

var _ io.Reader = (*generator)(nil)
