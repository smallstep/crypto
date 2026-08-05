//go:build !go1.27

package pemutil

import (
	"encoding/pem"
	"fmt"
)

func serialize(in any) (*pem.Block, bool, error) {
	return nil, false, fmt.Errorf("cannot serialize type '%T', value '%v'", in, in)
}
