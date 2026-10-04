package main

import (
	"os"

	"golang.org/x/term"
)

// terminal is the local terminal for `exec -t`.
type terminal interface {
	// Size returns the terminal's columns and rows.
	Size() (cols, rows int, ok bool)
	// MakeRaw puts stdin in raw mode so keystrokes (Ctrl-C included) reach
	// the remote PTY; restore undoes it.
	MakeRaw() (restore func(), err error)
}

type osTerminal struct{}

func (osTerminal) Size() (int, int, bool) {
	cols, rows, err := term.GetSize(int(os.Stdout.Fd()))
	return cols, rows, err == nil
}

func (osTerminal) MakeRaw() (func(), error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return func() {}, nil
	}
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	return func() { _ = term.Restore(fd, state) }, nil
}

func isTerminal(f *os.File) bool {
	return f != nil && term.IsTerminal(int(f.Fd()))
}
