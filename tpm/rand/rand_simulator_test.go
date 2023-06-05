//go:build tpmsimulator
// +build tpmsimulator

package rand

import (
	"errors"
	"io"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tpmp "go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/simulator"
	"go.step.sm/crypto/tpm/storage"
)

func newSimulatedTPM(t *testing.T) *tpmp.TPM {
	t.Helper()
	tmpDir := t.TempDir()
	tpm, err := tpmp.New(withSimulator(t), tpmp.WithStore(storage.NewDirstore(tmpDir))) // TODO: provide in-memory storage implementation instead
	require.NoError(t, err)
	return tpm
}

func newErrorTPM(t *testing.T) *tpmp.TPM {
	t.Helper()
	tmpDir := t.TempDir()
	tpm, err := tpmp.New(withWriteErrorSimulator(t), tpmp.WithStore(storage.NewDirstore(tmpDir))) // TODO: provide in-memory storage implementation instead
	require.NoError(t, err)
	return tpm
}

func withSimulator(t *testing.T) tpmp.NewTPMOption {
	t.Helper()
	var sim simulator.Simulator
	t.Cleanup(func() {
		if sim == nil {
			return
		}
		err := sim.Close()
		require.NoError(t, err)
	})
	sim = simulator.New()
	err := sim.Open()
	require.NoError(t, err)
	return tpmp.WithSimulator(sim)
}

func withWriteErrorSimulator(t *testing.T) tpmp.NewTPMOption {
	t.Helper()
	var sim simulator.Simulator
	t.Cleanup(func() {
		if sim == nil {
			return
		}
		err := sim.Close()
		require.NoError(t, err)
	})
	sim = &writeErrorSimulator{}
	err := sim.Open()
	require.NoError(t, err)
	return tpmp.WithSimulator(sim)
}

type writeErrorSimulator struct {
}

func (s *writeErrorSimulator) Open() error {
	return nil
}

func (s *writeErrorSimulator) Close() error {
	return nil
}

func (s *writeErrorSimulator) Read([]byte) (int, error) {
	return -1, nil
}

func (s *writeErrorSimulator) Write([]byte) (int, error) {
	return 0, errors.New("forced write error") // writing command fails
}

func (s *writeErrorSimulator) MeasurementLog() ([]byte, error) {
	return nil, nil
}

var _ io.ReadWriteCloser = (*writeErrorSimulator)(nil)

func Test_generator_Read(t *testing.T) {
	tpm := newSimulatedTPM(t)
	errorTPM := newErrorTPM(t)
	type fields struct {
		t *tpmp.TPM
	}
	type args struct {
		data []byte
	}
	short := make([]byte, 8)
	long := make([]byte, 32)
	tooLongForSimulator := make([]byte, 256) // I've observed the simulator to return 64 at most in one go; we loop through it, so we can get more than 64 random bytes
	maximumLength := make([]byte, math.MaxUint16)
	longerThanMax := make([]byte, math.MaxUint16+1)
	readError := make([]byte, 32)
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
		expErr error
	}{
		{"ok/short", fields{tpm}, args{data: short}, 8, nil},
		{"ok/long", fields{tpm}, args{data: long}, 32, nil},
		{"ok/tooLongForSimulator", fields{tpm}, args{data: tooLongForSimulator}, 256, nil},
		{"ok/max", fields{tpm}, args{data: maximumLength}, math.MaxUint16, nil},
		{"ok/readError", fields{errorTPM}, args{data: readError}, 0, nil},
		{"fail/longerThanMax", fields{tpm}, args{data: longerThanMax}, 0, errors.New("number of random bytes to read cannot exceed 65535")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &generator{
				t: tt.fields.t,
			}
			got, err := g.Read(tt.args.data)
			if tt.expErr != nil {
				assert.EqualError(t, err, tt.expErr.Error())
				assert.Equal(t, 0, got)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)

			// for the test cases that use the errorTPM, check that trying
			// to read (again) from the same generator fails with the previous
			// error.
			if g.t == errorTPM {
				newShort := make([]byte, 8)
				n, err := g.Read(newShort)
				assert.Zero(t, n)
				assert.EqualError(t, err, "failed generating random bytes in previous call to Read: failed generating random data: forced write error: EOF")
				assert.ErrorIs(t, err, io.EOF)
			}
		})
	}
}
