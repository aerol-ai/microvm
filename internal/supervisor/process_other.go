//go:build !linux

package supervisor

import (
	"errors"
	"log/slog"
	"sync/atomic"
)

var errNeedsLinux = errors.New("the runtime supervisor runs on Linux only")

func BecomeReaper() error                          { return errNeedsLinux }
func Reap(*atomic.Int64, chan<- int, *slog.Logger) {}
func StartInGroup(string, []string) (int, error)   { return 0, errNeedsLinux }
func Terminate(int)                                {}
func LowerOwnOOMScore() error                      { return errNeedsLinux }
