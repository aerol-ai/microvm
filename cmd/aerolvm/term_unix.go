//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func (osTerminal) NotifyResize() (<-chan struct{}, func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGWINCH)
	changes := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-sig:
				select {
				case changes <- struct{}{}:
				default:
				}
			case <-done:
				return
			}
		}
	}()
	return changes, func() {
		signal.Stop(sig)
		close(done)
	}
}
