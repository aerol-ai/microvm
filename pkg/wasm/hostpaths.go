package wasm

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aerol-ai/microvm/pkg/hostproc"
)

// Host paths a worker reaches through descriptors sandboxd handed it.
//
// A WASM worker drops to a non-root uid before it serves (pkg/wasm/worker),
// but the paths sandboxd names in its messages — module files, the sandbox's
// /work, its mount folders, snapshot files — sit under directories only
// root may search (/var/lib/sandboxd and /run/sandboxd are 0700 on
// purpose). So sandboxd, as root, opens each path a message names and
// passes the open descriptor with the message; the worker records it here,
// under the path, and every place the engine opens a host path asks here
// first:
//
//   - a granted directory, or a path beneath one, is reached through
//     /proc/self/fd/N: the kernel follows that link to the directory itself
//     without walking its parents, so only the directory's own permissions
//     apply (sandboxd makes the dirs a worker writes owned by its uid);
//   - a granted file is read through its descriptor, never reopened, so it
//     needs no permission of its own (module and snapshot files stay
//     root-owned and unreadable to every other worker).
//
// Callers keep passing the original paths: the capabilities a worker keeps
// for re-instantiation, the stream payloads and the engine all name host
// paths as before, and a path nothing granted is opened as it always was. A
// worker that is still root (the drop is off, or not Linux) gets the same
// grants and opens through them the same way.
//
// Off Linux there is no /proc/self/fd: a grant is closed at once and paths
// are opened directly, as they always were there.

type hostGrant struct {
	f      *os.File
	dir    bool
	scopes map[string]struct{}
}

var hostGrants = struct {
	mu     sync.RWMutex
	byPath map[string]*hostGrant
}{byPath: map[string]*hostGrant{}}

// GrantHostPath records f as the handle for path, held for scope (a sandbox
// id, or "" for the worker itself). A later grant for the same path
// replaces the handle: sandboxd sends a fresh one with every message, and
// a directory that was removed and made again must be reached through the
// new one. The registry owns f from here on.
func GrantHostPath(scope, path string, f *os.File) {
	if f == nil {
		return
	}
	path = cleanHostPath(path)
	if path == "" || hostproc.ConfinedProcFD(f.Fd()) == "" {
		_ = f.Close()
		return
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return
	}
	hostGrants.mu.Lock()
	defer hostGrants.mu.Unlock()
	g := hostGrants.byPath[path]
	if g == nil {
		g = &hostGrant{scopes: map[string]struct{}{}}
		hostGrants.byPath[path] = g
	} else if g.f != nil {
		_ = g.f.Close()
	}
	g.f, g.dir = f, st.IsDir()
	g.scopes[scope] = struct{}{}
}

// ReleaseHostGrants drops scope's hold on every path. A path no scope holds
// any more is closed. Opens already made through it stay open: each is its
// own descriptor.
func ReleaseHostGrants(scope string) {
	hostGrants.mu.Lock()
	defer hostGrants.mu.Unlock()
	for path, g := range hostGrants.byPath {
		if _, ok := g.scopes[scope]; !ok {
			continue
		}
		delete(g.scopes, scope)
		if len(g.scopes) == 0 {
			_ = g.f.Close()
			delete(hostGrants.byPath, path)
		}
	}
}

// grantedHostPaths counts the paths held (tests).
func grantedHostPaths() int {
	hostGrants.mu.RLock()
	defer hostGrants.mu.RUnlock()
	return len(hostGrants.byPath)
}

func cleanHostPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}

// WithHostPath calls fn with the path to open for path: through the
// granted directory that is path or its nearest parent, or path itself
// when none is. fn gets its own duplicate of the grant's descriptor, closed
// when fn returns, so a grant replaced meanwhile can neither close it nor
// hand its number to another file; and the registry is not held while fn
// works (a snapshot write takes seconds).
func WithHostPath(path string, fn func(string) error) error {
	via, release, err := resolveHostPath(path)
	if err != nil {
		return err
	}
	defer release()
	return fn(via)
}

func resolveHostPath(path string) (string, func(), error) {
	clean := cleanHostPath(path)
	none := func() {}
	if clean == "" {
		return path, none, nil
	}
	hostGrants.mu.RLock()
	defer hostGrants.mu.RUnlock()
	for dir := clean; ; dir = filepath.Dir(dir) {
		if g := hostGrants.byPath[dir]; g != nil && g.dir {
			fd, err := dupCloexec(g.f.Fd())
			if err != nil {
				return "", none, fmt.Errorf("granted %s: %w", dir, err)
			}
			return hostproc.ConfinedProcFD(fd) + strings.TrimPrefix(clean, dir), func() { closeFD(fd) }, nil
		}
		if parent := filepath.Dir(dir); parent == dir {
			return path, none, nil
		}
	}
}

// ReadHostFile reads the file at path: through its granted descriptor when
// sandboxd passed one (no reopen, so no permission on the file or its
// parents is needed), else from disk.
func ReadHostFile(path string) ([]byte, error) {
	clean := cleanHostPath(path)
	hostGrants.mu.RLock()
	g := hostGrants.byPath[clean]
	if g == nil || g.dir {
		hostGrants.mu.RUnlock()
		var b []byte
		err := WithHostPath(path, func(p string) error {
			var err error
			b, err = os.ReadFile(p)
			return err
		})
		return b, err
	}
	defer hostGrants.mu.RUnlock()
	st, err := g.f.Stat()
	if err != nil {
		return nil, err
	}
	// One buffer of the file's size, as os.ReadFile makes, filled with
	// positional reads: the descriptor is shared with any concurrent
	// reader of the same grant and its offset is never moved.
	b := make([]byte, st.Size())
	n, err := g.f.ReadAt(b, 0)
	if err == io.EOF {
		err = nil
	}
	return b[:n], err
}
