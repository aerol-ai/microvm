//go:build !linux

package mounts

import (
	"errors"
	"os"
	"os/exec"
)

// Isolated mount tools need Linux: /dev/fuse, memfds and no-new-privs.

var errToolsLinuxOnly = errors.New("isolated mount tools are Linux only")

func openFuseFD(string, string, uint32, uint32, bool) (*os.File, error) {
	return nil, errToolsLinuxOnly
}

func newCredMemfd([]byte, uint32, uint32) (*os.File, error) { return nil, errToolsLinuxOnly }

func startNoNewPrivs(*exec.Cmd) error { return errToolsLinuxOnly }
