//go:build windows

package main

import "time"

// Windows consoles have no SIGWINCH, so the size is polled instead.
const resizePoll = 250 * time.Millisecond

func (t osTerminal) NotifyResize() (<-chan struct{}, func()) {
	changes := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(resizePoll)
		defer ticker.Stop()
		lastCols, lastRows, _ := t.Size()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				cols, rows, ok := t.Size()
				if !ok || (cols == lastCols && rows == lastRows) {
					continue
				}
				lastCols, lastRows = cols, rows
				select {
				case changes <- struct{}{}:
				default:
				}
			}
		}
	}()
	return changes, func() { close(done) }
}
