//go:build !unix

package wasm

import (
	"os"

	experimentalsys "github.com/tetratelabs/wazero/experimental/sys"
)

// WASM sandboxes run on Linux (and darwin for development). Elsewhere the
// calls that need *at system calls fail closed rather than fall back to a
// path-based call the kernel could carry outside the mount.

func withPlatformOflag(_ experimentalsys.Oflag, flag int) int { return flag }

func unlinkInRoot(*os.Root, string) experimentalsys.Errno { return experimentalsys.ENOSYS }

func rmdirInRoot(*os.Root, string) experimentalsys.Errno { return experimentalsys.ENOSYS }

func renameInRoot(*os.Root, string, string) experimentalsys.Errno { return experimentalsys.ENOSYS }

func setNonblockFile(*os.File, bool) experimentalsys.Errno { return experimentalsys.ENOSYS }

func datasyncFile(f *os.File) experimentalsys.Errno {
	return experimentalsys.UnwrapOSError(f.Sync())
}

func futimensFile(*os.File, int64, int64) experimentalsys.Errno { return experimentalsys.ENOSYS }
