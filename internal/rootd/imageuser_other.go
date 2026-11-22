//go:build !linux

package rootd

import (
	"context"
	"errors"
)

// readImageFiles needs Linux's mount namespaces and openat2. Off Linux
// only tests run the helper, and they give it a reader of their own
// (Options.ReadImageFiles).
func readImageFiles(context.Context, string, string, []string) (UserFiles, error) {
	return UserFiles{}, errors.New("reading an image's users needs Linux")
}
