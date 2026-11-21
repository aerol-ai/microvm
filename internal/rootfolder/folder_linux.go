//go:build linux

package rootfolder

import "golang.org/x/sys/unix"

// FolderFlags open a folder for its handle alone: O_PATH needs no read
// right on it, and O_NOFOLLOW refuses a link in its place.
const FolderFlags = unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
