package main

import (
	"context"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/aerol-ai/microvm/internal/agenttools"
)

// terminal is the local terminal for `exec -t` and `shell`.
type terminal interface {
	// Size returns the terminal's columns and rows.
	Size() (cols, rows int, ok bool)
	// MakeRaw puts stdin in raw mode so keystrokes (Ctrl-C included) reach
	// the remote PTY; restore undoes it.
	MakeRaw() (restore func(), err error)
	// NotifyResize signals on changes each time the terminal is resized,
	// until stop is called.
	NotifyResize() (changes <-chan struct{}, stop func())
	// ReadSecret reads a line from the terminal without echoing it.
	ReadSecret() (string, error)
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

func (osTerminal) ReadSecret() (string, error) {
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	return string(b), err
}

func isTerminal(f *os.File) bool {
	return f != nil && term.IsTerminal(int(f.Fd()))
}

// resizes reports the terminal's size each time it changes, until ctx ends.
// Only the latest size matters, so one the remote hasn't taken yet is
// replaced rather than queued.
func (a *app) resizes(ctx context.Context) <-chan agenttools.TermSize {
	out := make(chan agenttools.TermSize, 1)
	changes, stop := a.term.NotifyResize()
	go func() {
		defer stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-changes:
				cols, rows, ok := a.term.Size()
				if !ok {
					continue
				}
				select {
				case <-out:
				default:
				}
				out <- agenttools.TermSize{Cols: cols, Rows: rows}
			}
		}
	}()
	return out
}

// remoteTerm is the TERM a remote terminal starts with. Sandbox images
// usually carry only ncurses' base terminfo, so a terminal-specific TERM
// (xterm-kitty, xterm-ghostty, alacritty) makes vim, less and clear fail
// with "unknown terminal type". Those terminals all emulate xterm-256color,
// which every image knows. Windows consoles leave TERM unset.
func (a *app) remoteTerm() string {
	switch t := strings.TrimSpace(a.getenv("TERM")); t {
	case "xterm", "xterm-256color", "xterm-color", "screen", "screen-256color",
		"tmux", "tmux-256color", "vt100", "vt220", "linux", "ansi", "dumb":
		return t
	}
	return "xterm-256color"
}
