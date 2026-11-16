package wasm

import (
	"os"
	"testing"

	"github.com/aerol-ai/microvm/internal/wasmtestguest"
)

// ensureWasip1HTTPWasm returns the path to the wasip1 HTTP guest, compiling it
// on demand.
//
// The driver tests used to skip-if-missing, which made their coverage depend on
// package run order: `go test ./...` runs packages as separate processes, so
// these tests only executed when pkg/wasm or pkg/wasm/worker happened to
// compile the artifact into the shared checkout first. Compiling on demand
// through the shared internal/wasmtestguest helper makes the coverage
// unconditional; it skips only where the artifact cannot be produced at all.
func ensureWasip1HTTPWasm(t *testing.T) string {
	t.Helper()
	return wasmtestguest.Path(t, wasmtestguest.HTTP)
}

// shortRunDir is a run dir of the test's own, short enough for the worker
// sockets under it (sun_path is 104 bytes on macOS, too short for
// t.TempDir). Never a fixed name: test processes of other packages and
// other checkouts run at the same time and share TMPDIR, and two of them
// on one socket path talk to each other's workers.
func shortRunDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "aw-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
