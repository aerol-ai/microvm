//go:build linux

package rootd

import "golang.org/x/sys/unix"

// mkfifoAt makes a FIFO at name in the folder dfd.
func mkfifoAt(dfd int, _, name string, mode uint32) error { return unix.Mkfifoat(dfd, name, mode) }
