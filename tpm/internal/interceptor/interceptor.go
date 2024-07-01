package interceptor

import (
	"io"

	"github.com/smallstep/go-attestation/attest"

	"go.step.sm/crypto/tpm/debug"
)

type CommandChannel struct {
	in      io.Writer
	out     io.Writer
	wrapped attest.CommandChannelTPM20
}

func CommandChannelFromTap(tap debug.Tap) *CommandChannel {
	return &CommandChannel{
		in:  tap.Rx(),
		out: tap.Tx(),
	}
}

func (c *CommandChannel) Wrap(cc attest.CommandChannelTPM20) *CommandChannel {
	c.wrapped = cc
	return c
}

func (c *CommandChannel) Unwrap() attest.CommandChannelTPM20 {
	return c.wrapped
}

func (c *CommandChannel) Close() error {
	return c.wrapped.Close()
}

func (c *CommandChannel) MeasurementLog() ([]byte, error) {
	return c.wrapped.MeasurementLog()
}

func (c *CommandChannel) Read(data []byte) (int, error) {
	n, err := c.wrapped.Read(data)
	if err != nil {
		return n, err
	}

	_, _ = c.in.Write(data[:n])

	return n, nil
}

func (c *CommandChannel) Write(data []byte) (int, error) {
	n, err := c.wrapped.Write(data)
	if err != nil {
		return n, err
	}

	_, _ = c.out.Write(data[:n])
	return n, nil
}

var _ attest.CommandChannelTPM20 = (*CommandChannel)(nil)

type RWC struct {
	in      io.Writer
	out     io.Writer
	wrapped io.ReadWriteCloser
}

func RWCFromTap(tap debug.Tap) *RWC {
	return &RWC{
		in:  tap.Rx(),
		out: tap.Tx(),
	}
}

func (c *RWC) Wrap(rwc io.ReadWriteCloser) *RWC {
	c.wrapped = rwc
	return c
}

func (c *RWC) Unwrap() io.ReadWriteCloser {
	return c.wrapped
}

func (c *RWC) Close() error {
	return c.wrapped.Close()
}

func (c *RWC) Read(data []byte) (int, error) {
	n, err := c.wrapped.Read(data)
	if err != nil {
		return n, err
	}

	_, _ = c.in.Write(data[:n])

	return n, nil
}

func (c *RWC) Write(data []byte) (int, error) {
	n, err := c.wrapped.Write(data)
	if err != nil {
		return n, err
	}

	_, _ = c.out.Write(data[:n])
	return n, nil
}

var _ io.ReadWriteCloser = (*RWC)(nil)
