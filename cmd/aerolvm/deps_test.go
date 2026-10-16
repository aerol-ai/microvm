package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenDeps keeps aerolvm a thin, static client (§5.1). Importing a
// server package would pull in the containerd, Raft and SQLite trees and
// break the CGO-free cross-compiled release.
var forbiddenDeps = []string{
	"github.com/aerol-ai/microvm/internal/service",
	"github.com/aerol-ai/microvm/internal/store",
	"github.com/aerol-ai/microvm/internal/cluster",
	"github.com/aerol-ai/microvm/internal/runtime",
	"github.com/aerol-ai/microvm/internal/pool",
	"github.com/aerol-ai/microvm/pkg/api",
	"github.com/aerol-ai/microvm/pkg/caddy",
	"github.com/aerol-ai/microvm/pkg/daemon",
	"github.com/aerol-ai/microvm/pkg/docker",
	"github.com/containerd/",
	"github.com/hashicorp/raft",
	"github.com/mattn/go-sqlite3",
}

func TestDependencyGuard(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the go toolchain")
	}
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, bad := range forbiddenDeps {
			if strings.HasPrefix(dep, bad) {
				t.Errorf("cmd/aerolvm depends on %s", dep)
			}
		}
	}
	// Every release target, not only this host: a dependency that compiles
	// on Linux and macOS but not on Windows (a unix-only syscall) would
	// otherwise surface only when release.yml cross-compiles.
	for _, target := range releaseTargets {
		build := exec.Command("go", "build", "-o", filepath.Join(t.TempDir(), "aerolvm"), ".")
		build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+target.goos, "GOARCH="+target.goarch)
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("CGO_ENABLED=0 GOOS=%s GOARCH=%s go build: %v\n%s", target.goos, target.goarch, err, out)
		}
	}
}
