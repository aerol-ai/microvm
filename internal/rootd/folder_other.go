//go:build !linux

package rootd

import "golang.org/x/sys/unix"

// folderFlags: no O_PATH off Linux, where only tests run the helper.
const folderFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
