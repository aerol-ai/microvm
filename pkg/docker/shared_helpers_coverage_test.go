package docker

import (
	"os"
	"testing"
)

func coverageReadyDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
