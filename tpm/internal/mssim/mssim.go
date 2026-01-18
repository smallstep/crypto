package mssim

import (
	"fmt"
	"io"
	"net"
	"strconv"

	"go.step.sm/crypto/kms/uri"
)

func New(u *uri.URI) (rwc io.ReadWriteCloser, err error) {
	host := "127.0.0.1"
	port := 2321
	if h := u.Get("host"); h != "" {
		host = h
	}
	if p := u.Get("port"); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("failed parsing %q as integer: %w", p, err)
		}
	}

	c := config{
		commandAddress:       net.JoinHostPort(host, fmt.Sprint(port)),
		platformAddress:      net.JoinHostPort(host, fmt.Sprint(port+1)),
		skipPlatformCommands: true, // TODO(hs): assumes these steps are performed out of band; does that make sense?
	}

	rwc, err = open(c)
	if err != nil {
		return nil, fmt.Errorf("failed opening connection to TPM: %w", err)
	}

	// TODO(hs): make connection open lazily? And/or support connection management internally?
	// Sometimes it happens that the connection is very slow, or there seems to be no connection
	// at all. This is likely due to how we've implemented opening the TPM (once, generally), and
	// then reusing that instance.

	return
}

type CommandChannelWithoutMeasurementLog struct {
	io.ReadWriteCloser
}

func (c *CommandChannelWithoutMeasurementLog) MeasurementLog() ([]byte, error) {
	return nil, nil
}
