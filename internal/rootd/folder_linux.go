//go:build linux

package rootd

import "golang.org/x/sys/unix"

// folderFlags open a folder for its handle alone: O_PATH needs no read
// right on it, and O_NOFOLLOW refuses a link in its place.
const folderFlags = unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
