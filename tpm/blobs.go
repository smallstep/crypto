package tpm

import (
	"bytes"
	"fmt"

	"github.com/google/go-tpm/tpmutil"
)

// Blobs is a container for the private and public blobs of data
// that represent a TPM2 object.
type Blobs struct {
	private []byte
	public  []byte
}

// Private returns the private data blob of a TPM2 object including
// a 16-bit header. The blob can be used with tpm2-tools.
func (b *Blobs) Private() (blob []byte, err error) {
	if blob, err = toTPM2Tools(b.private); err != nil {
		return nil, fmt.Errorf("failed transforming private blob bytes: %w", err)
	}
	return
}

// Public returns the public data blob of a TPM2 object including
// a 16-bit header. The blob can be used with tpm2-tools.
func (b *Blobs) Public() (blob []byte, err error) {
	if blob, err = toTPM2Tools(b.public); err != nil {
		return nil, fmt.Errorf("failed transforming public blob bytes: %w", err)
	}
	return
}

func toTPM2Tools(blob []byte) ([]byte, error) {
	buf := bytes.Buffer{}
	bytesWithHeader := tpmutil.U16Bytes(blob)
	if err := bytesWithHeader.TPMMarshal(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (ak *AK) setBlobs(private, public []byte) {
	ak.blobs = &Blobs{
		private: private,
		public:  public,
	}
}

func (k *Key) setBlobs(private, public []byte) {
	k.blobs = &Blobs{
		private: private,
		public:  public,
	}
}
