package nssdb

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// Object is an entry in nssPublic or nssPrivate plus any related entries in
// the metaData table. The encoding for and meaning of most attributes can be
// found in the PKCS #11 spec.
type Object struct {
	ID                  uint32
	Attributes          map[string][]byte
	ULongAttributes     map[string]uint32
	EncryptedAttributes map[string][]byte
	Metadata            []*Metadata
}

func (obj *Object) Print() {
	fmt.Printf("ID: %d\n", obj.ID)

	for k, data := range obj.EncryptedAttributes {
		fmt.Printf("%s (encrypted): %x\n", k, data)
	}

	for _, meta := range obj.Metadata {
		fmt.Printf("%s: %x\n", meta.ID, meta.Item1)
	}

	for k, u := range obj.ULongAttributes {
		fmt.Printf("%s: %d\n", k, u)
	}

	for k, data := range obj.Attributes {
		fmt.Printf("%s: %x\n", k, data)
	}
}

func (obj Object) ValidateULong(name string, want uint32) error {
	attr, ok := obj.ULongAttributes[name]
	if !ok {
		return fmt.Errorf("object is missing attribute %s", name)
	}
	if attr != want {
		return fmt.Errorf("%s expected %d but got %d", name, attr, want)
	}
	return nil
}

func (obj Object) Validate(name string, want []byte) error {
	attr, ok := obj.Attributes[name]
	if !ok {
		return fmt.Errorf("object is missing attribute %s", name)
	}
	if !bytes.Equal(attr, want) {
		return fmt.Errorf("%s has value %q, expected %q", name, hex.EncodeToString(attr), hex.EncodeToString(want))
	}
	return nil
}
