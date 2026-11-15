// Package wasmtestguest compiles the wasip1 test guests kept as Go source
// under pkg/wasm/testdata/<guest> into pkg/wasm/testdata/wasip1-<name>.wasm.
//
// The binaries are gitignored and built on demand by whichever test package
// needs them first. pkg/wasm, pkg/wasm/worker and internal/runtime/wasm each
// carried their own copy of this helper; one copy means one place that knows
// how to find the source, when a cached binary is stale, and how to publish a
// build that a parallel package run may be racing to produce.
package wasmtestguest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Guest names (directories under pkg/wasm/testdata).
const (
	HTTP  = "aerolhttp"
	Stdio = "aerolstdio"
)

// errUnavailable marks an environment that cannot produce the artifact at
// all (no source checkout, no Go toolchain, Windows). Tests skip on it; any
// other build failure is a real defect and fails the test.
var errUnavailable = errors.New("wasip1 test guest unavailable")

// lookPath and goos are seams so the unavailable branches are testable.
var (
	lookPath = exec.LookPath
	goos     = runtime.GOOS
)

// Path returns the compiled guest, building it when it is missing or older
// than its source.
func Path(tb testing.TB, guest string) string {
	tb.Helper()
	root, err := repoRoot()
	if err != nil {
		tb.Skip(err)
	}
	out, err := build(root, guest)
	if errors.Is(err, errUnavailable) {
		tb.Skip(err)
	}
	if err != nil {
		tb.Fatal(err)
	}
	return out
}

// OutputName is the gitignored file name a guest compiles to:
// aerolhttp -> wasip1-http.wasm.
func OutputName(guest string) string {
	return "wasip1-" + strings.TrimPrefix(guest, "aerol") + ".wasm"
}

// repoRoot walks up from the test's working directory (its package folder)
// to the module root. runtime.Caller would break under -trimpath.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("%w: %v", errUnavailable, err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("%w: no go.mod above the test directory", errUnavailable)
		}
		dir = parent
	}
}

func build(root, guest string) (string, error) {
	testdata := filepath.Join(root, "pkg", "wasm", "testdata")
	src := filepath.Join(testdata, guest)
	out := filepath.Join(testdata, OutputName(guest))
	newest, err := newestSource(src)
	if err != nil {
		return "", err
	}
	// Rebuild when the source changed: a binary kept from an older guest
	// would make a test pass or fail against code nobody can see.
	if st, err := os.Stat(out); err == nil && st.Size() > 0 && !st.ModTime().Before(newest) {
		return out, nil
	}
	if goos == "windows" {
		return "", fmt.Errorf("%w: wasip1 guests are not built on windows", errUnavailable)
	}
	if _, err := lookPath("go"); err != nil {
		return "", fmt.Errorf("%w: go toolchain not found", errUnavailable)
	}
	// go test runs packages in parallel processes that may all want the same
	// guest. Each builds into its own temp file and renames it into place, so
	// no reader ever sees a half-written module.
	tmp, err := os.CreateTemp(testdata, "."+OutputName(guest)+".*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpName)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", tmpName, ".")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	cmd.Dir = src
	if combined, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("compile %s: %v\n%s", OutputName(guest), err, combined)
	}
	if err := os.Rename(tmpName, out); err != nil {
		return "", err
	}
	return out, nil
}

// newestSource is the latest modification time of the guest's .go files.
func newestSource(src string) (time.Time, error) {
	entries, err := os.ReadDir(src)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: guest source %s: %v", errUnavailable, src, err)
	}
	var newest time.Time
	found := false
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return time.Time{}, err
		}
		found = true
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	if !found {
		return time.Time{}, fmt.Errorf("%w: no Go source in %s", errUnavailable, src)
	}
	return newest, nil
}
