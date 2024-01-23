package tss2

import (
	"encoding/pem"
)

// handle owner is the reserved handle TPM_RH_OWNER.
const handleOwner = 0x40000001

// TPMOption is the type used to modify a [TPMKey].
type TPMOption func(*TPMKey)

// WithParent sets the [TPMKey] parent's handle
func WithParent(parent int) TPMOption {
	return func(t *TPMKey) {
		t.Parent = parent
	}
}

// New creates a new [TPMKey] with the given public and private keys.
func New(pub, priv []byte, opts ...TPMOption) *TPMKey {
	key := &TPMKey{
		Type:       oidLoadableKey,
		EmptyAuth:  true,
		Parent:     handleOwner,
		PublicKey:  addPrefixLength(pub),
		PrivateKey: addPrefixLength(priv),
	}
	for _, fn := range opts {
		fn(key)
	}
	return key
}

// Encode encodes the [TPMKey] returns a [*pem.Block].
func (k *TPMKey) Encode() (*pem.Block, error) {
	b, err := MarshalPrivateKey(k)
	if err != nil {
		return nil, err
	}
	return &pem.Block{
		Type:  "TSS2 PRIVATE KEY",
		Bytes: b,
	}, nil
}

// EncodeToMemory encodes the [TPMKey]  and returns an encoded PEM block.
func (k *TPMKey) EncodeToMemory() ([]byte, error) {
	block, err := k.Encode()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

// Encode encodes the given public and private key and returns a [*pem.Block].
func Encode(pub, priv []byte, opts ...TPMOption) (*pem.Block, error) {
	return New(pub, priv, opts...).Encode()
}

// EncodeToMemory encodes the given public and private key and returns an
// encoded PEM block.
func EncodeToMemory(pub, priv []byte, opts ...TPMOption) ([]byte, error) {
	return New(pub, priv, opts...).EncodeToMemory()
}

func addPrefixLength(b []byte) []byte {
	s := len(b)
	return append([]byte{byte(s >> 8 & 0xFF), byte(s & 0xFF)}, b...)
}
