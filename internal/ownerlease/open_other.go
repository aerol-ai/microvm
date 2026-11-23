//go:build !unix

package ownerlease

import "os"

// openNoFollow is a plain open where there are no such flags; Read still
// takes only a regular file.
func openNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}
