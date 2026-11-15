//go:build unix && !linux

package wasm

import (
	"os"

	experimentalsys "github.com/tetratelabs/wazero/experimental/sys"
	"github.com/tetratelabs/wazero/sys"
	"golang.org/x/sys/unix"
)

func datasyncFile(f *os.File) experimentalsys.Errno {
	// No fdatasync here; a full sync is a superset, as in wazero's DirFS.
	return experimentalsys.UnwrapOSError(f.Sync())
}

// futimensFile sets f's times through its descriptor. x/sys/unix has no
// futimens off Linux, so this uses futimes (microsecond precision) and fills
// an omitted time from the descriptor's own stat. Production workers run on
// Linux; this keeps darwin development builds working.
func futimensFile(f *os.File, atim, mtim int64) experimentalsys.Errno {
	if atim == experimentalsys.UTIME_OMIT && mtim == experimentalsys.UTIME_OMIT {
		return 0
	}
	if atim == experimentalsys.UTIME_OMIT || mtim == experimentalsys.UTIME_OMIT {
		fi, err := f.Stat()
		if err != nil {
			return experimentalsys.UnwrapOSError(err)
		}
		st := sys.NewStat_t(fi)
		if atim == experimentalsys.UTIME_OMIT {
			atim = st.Atim
		}
		if mtim == experimentalsys.UTIME_OMIT {
			mtim = st.Mtim
		}
	}
	tv := []unix.Timeval{unix.NsecToTimeval(atim), unix.NsecToTimeval(mtim)}
	return controlFile(f, func(fd int) error { return unix.Futimes(fd, tv) })
}
