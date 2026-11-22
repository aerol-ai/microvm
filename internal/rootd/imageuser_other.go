//go:build !linux

package rootd

import "errors"

// readImageFiles needs Linux's mount API and openat2. Off Linux
// only tests run the helper, and they give it a reader of their own
// (Options.ReadImageFiles).
func readImageFiles(string, string, []string) (UserFiles, error) {
	return UserFiles{}, errors.New("reading an image's users needs Linux")
}
