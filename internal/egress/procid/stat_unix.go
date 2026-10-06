//go:build unix

package procid

import (
	"fmt"
	"os"
	"syscall"
)

// statID follows symlinks, as /proc/<pid>/exe needs.
func statID(p string) (FileID, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return FileID{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return FileID{}, fmt.Errorf("procid: no inode for %s", p)
	}
	return FileID{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, nil
}
