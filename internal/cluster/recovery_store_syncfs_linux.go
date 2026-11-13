//go:build linux

package cluster

import "golang.org/x/sys/unix"

// syncFilesystem flushes the filesystem that holds dir with one syncfs(2):
// every dirty page and inode on it, the directory entries too, then one
// device flush. Linux 5.8 and later report a writeback error on that
// filesystem here, as fsync does for one file.
func syncFilesystem(dir string) (bool, error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return true, err
	}
	defer unix.Close(fd)
	return true, unix.Syncfs(fd)
}
