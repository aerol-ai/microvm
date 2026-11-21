//go:build !linux

package supervisor

import (
	"errors"
	"log/slog"
	"os"
	"sync/atomic"
)

var errNeedsLinux = errors.New("the runtime supervisor runs on Linux only")

func BecomeReaper() error                                             { return errNeedsLinux }
func Reap(*atomic.Int64, chan<- int, *slog.Logger)                    {}
func StartInGroup(string, []string) (int, error)                      { return 0, errNeedsLinux }
func Terminate(int)                                                   {}
func Unmount(string) error                                            { return errNeedsLinux }
func LowerOwnOOMScore() error                                         { return errNeedsLinux }
func StartHelper(string, string, []string, []*os.File) (Child, error) { return nil, errNeedsLinux }
func openPidfd(int) (pidHandle, error)                                { return nil, errNeedsLinux }
