package tpm

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

type closeSimulator struct {
	closeErr error
}

func (s *closeSimulator) Open() error {
	return nil
}

func (s *closeSimulator) Close() error {
	return s.closeErr
}

func (s *closeSimulator) Read([]byte) (int, error) {
	return -1, nil
}

func (s *closeSimulator) Write([]byte) (int, error) {
	return -1, nil
}

func (s *closeSimulator) MeasurementLog() ([]byte, error) {
	return nil, nil
}

var _ io.ReadWriteCloser = (*closeSimulator)(nil)

func newOpenedTPM(t *testing.T) *TPM {
	t.Helper()
	tpm, err := New(WithSimulator(&closeSimulator{}))
	require.NoError(t, err)
	err = tpm.open(context.Background())
	require.NoError(t, err)
	return tpm
}

func newCloseErrorTPM(t *testing.T) *TPM {
	t.Helper()
	tpm, err := New(WithSimulator(&closeSimulator{
		closeErr: errors.New("closeErr"),
	}))
	require.NoError(t, err)
	err = tpm.open(context.Background())
	require.NoError(t, err)
	tpm.simulator = nil // required to skip returning when similator is configured
	return tpm
}

func Test_close(t *testing.T) {
	var emptyErr error
	anErr := errors.New("anErr")
	var closeErr error

	tpm := newOpenedTPM(t)
	closeTPM(context.Background(), tpm, &emptyErr)
	require.NoError(t, emptyErr)

	tpm = newOpenedTPM(t)
	closeTPM(context.Background(), tpm, &anErr)
	require.EqualError(t, anErr, "anErr")

	tpm = newCloseErrorTPM(t)
	require.Nil(t, tpm.simulator)
	closeTPM(context.Background(), newCloseErrorTPM(t), &closeErr)
	require.EqualError(t, closeErr, "failed closing attest.TPM: closeErr") // attest.TPM is backed by the closeSimulator
}
