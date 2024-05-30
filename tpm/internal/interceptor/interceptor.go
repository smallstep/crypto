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

func FromTap(tap debug.Tap) *CommandChannel {
	return &CommandChannel{
		in:  tap.In(),
		out: tap.Out(),
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
