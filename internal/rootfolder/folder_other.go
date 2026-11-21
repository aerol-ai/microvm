//go:build !linux

package rootfolder

import "golang.org/x/sys/unix"

// FolderFlags: no O_PATH off Linux, where only tests run root's code.
const FolderFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
