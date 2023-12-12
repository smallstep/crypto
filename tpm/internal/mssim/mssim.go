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

	return
}

type CommandChannelWithoutMeasurementLog struct {
	io.ReadWriteCloser
}

func (c *CommandChannelWithoutMeasurementLog) MeasurementLog() ([]byte, error) {
	return nil, nil
}
