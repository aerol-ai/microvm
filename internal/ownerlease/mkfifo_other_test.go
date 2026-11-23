//go:build !unix

package ownerlease

import "errors"

func mkfifo(string) error { return errors.New("no FIFOs on this platform") }
