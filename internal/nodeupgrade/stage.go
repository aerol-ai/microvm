package nodeupgrade

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Staging (plans/kubectl-style-cluster-ops.md §6.7, CEO D8): before any node
// restarts, every node puts the target's files into its FileStore and checks
// it can run the upgrade, so a node that can't fails the rollout while
// nothing has stopped. A later apply then reads the files from the store
// (FileStore.Materialize into Request.From) and downloads nothing.

// StageRequest is one stage step.
type StageRequest struct {
	// Files maps every asset this node must hold to its SHA-256: its own
	// CPU type's files, and on a server every CPU type the rollout carries,
	// since workers and ingress nodes copy from servers (§6.3).
	Files map[string]string
	// Install is the subset of Files this node will install. Its swap needs
	// room for the upgrader's staged copy and the new copy beside each
	// installed file, which the space check adds.
	Install map[string]string
	// Fetch opens one file. The store checks what it returns against sum,
	// so Fetch may read from anywhere: the release URL, the leader, a server.
	Fetch func(ctx context.Context, asset, sum string) (io.ReadCloser, error)
}

// StageResult says what one stage step did.
type StageResult struct {
	// Fetched lists the assets copied into the store now; Present those it
	// already held (a repeated stage downloads nothing).
	Fetched []string
	Present []string
	Bytes   int64
}

// ErrStageTool is a stage that fails because the host lacks a tool the
// apply step needs.
var ErrStageTool = errors.New("this node cannot run an upgrade")

// Stage checks this node can take the upgrade and puts every file of req in
// store (§6.7): systemd-run exists (Launch needs it), there is room for the
// files, the upgrader's staged copies, the new copies beside the installed
// binaries and the database backup, and each file hashes to its SHA-256.
// Files already in the store are not fetched again.
func Stage(ctx context.Context, p Paths, host Host, store FileStore, req StageRequest) (StageResult, error) {
	var res StageResult
	if len(req.Files) == 0 {
		return res, usageErr("stage needs at least one file")
	}
	for _, bin := range []string{"systemctl", "systemd-run"} {
		if _, err := host.LookPath(bin); err != nil {
			return res, fmt.Errorf("%w: %s not found; the node upgrader runs under systemd", ErrStageTool, bin)
		}
	}
	names := make([]string, 0, len(req.Files))
	for name, sum := range req.Files {
		if !hashRe.MatchString(sum) {
			return res, usageErr("%s: %q is not a hex SHA-256", name, sum)
		}
		if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) {
			return res, usageErr("bad file name %q", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	if err := stageSpace(p, host, store, req, names); err != nil {
		return res, err
	}
	for _, name := range names {
		sum := req.Files[name]
		if store.Has(sum) {
			res.Present = append(res.Present, name)
			continue
		}
		if req.Fetch == nil {
			return res, fmt.Errorf("%s is not staged and there is no source to fetch it from", name)
		}
		rc, err := req.Fetch(ctx, name, sum)
		if err != nil {
			return res, fmt.Errorf("get %s: %w", name, err)
		}
		_, n, err := store.Put(sum, rc)
		_ = rc.Close()
		if err != nil {
			return res, fmt.Errorf("stage %s: %w", name, err)
		}
		res.Fetched = append(res.Fetched, name)
		res.Bytes += n
	}
	return res, nil
}

// stageSpace adds up what the whole upgrade will write, per file system,
// before anything is fetched: the store copy of each missing file, then for
// each installed file the upgrader's staged copy (state directory) and the
// new copy beside the installed binary (its own directory; the *.prev is a
// hard link and costs nothing), and one database backup.
func stageSpace(p Paths, host Host, store FileStore, req StageRequest, names []string) error {
	type need struct {
		dir   string
		bytes uint64
		free  uint64
	}
	needs := map[uint64]*need{}
	var errs []error
	add := func(dir string, n uint64) {
		if dir == "" || n == 0 {
			return
		}
		free, dev, err := host.FreeBytes(dir)
		if err != nil {
			errs = append(errs, err)
			return
		}
		if needs[dev] == nil {
			needs[dev] = &need{dir: dir, free: free}
		}
		needs[dev].bytes += n
	}
	for _, name := range names {
		size := stagedSizeEstimate(p, name)
		if !store.Has(req.Files[name]) {
			add(store.Dir, size)
		}
		if _, installs := req.Install[name]; installs {
			add(p.StateDir, size)
			if dst := installedPath(p, name); dst != "" {
				add(filepath.Dir(dst), size)
			}
		}
	}
	if len(req.Install) > 0 {
		add(p.StateDir, dbBytes(p.DBPath))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	devs := make([]uint64, 0, len(needs))
	for d := range needs {
		devs = append(devs, d)
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i] < devs[j] })
	for _, d := range devs {
		n := needs[d]
		if n.free < n.bytes+spaceMargin {
			return fmt.Errorf("not enough free space on the file system of %s: staging and the upgrade need %d MiB (release files, staged copies, new copies beside the installed binaries, database backup) plus %d MiB spare, and %d MiB is free",
				n.dir, n.bytes>>20, spaceMargin>>20, n.free>>20)
		}
	}
	return nil
}

// assetBinary is the binary an asset name carries (sandboxd, toolboxd,
// caddy), for any CPU type, or the release metadata.
func assetBinary(asset string) string {
	if asset == roleRelease {
		return roleRelease
	}
	if m := assetRe.FindStringSubmatch(asset); m != nil {
		return m[1]
	}
	return ""
}

// installedPath is where this node keeps the binary an asset carries; ""
// for release.json and for Caddy on a node without it.
func installedPath(p Paths, asset string) string {
	switch assetBinary(asset) {
	case roleSandboxd:
		return p.Sandboxd
	case roleToolboxd:
		return p.Toolboxd
	case roleCaddy:
		return p.Caddy
	}
	return ""
}

// stagedSizeEstimate guesses a file's size before it is fetched: the
// installed binary it replaces, with room to grow, else a fixed guess.
func stagedSizeEstimate(p Paths, asset string) uint64 {
	if assetBinary(asset) == roleRelease {
		return 1 << 20
	}
	if dst := installedPath(p, asset); dst != "" {
		if n := fileSize(dst); n > 0 {
			return uint64(n) + uint64(n)/4
		}
	}
	return unknownFileEstimate
}

// InstalledFiles hashes the binaries this node runs now, by role
// (sandboxd, toolboxd, caddy): what a node reports at staging so the
// rollout keeps the previous version's files for a rollback (§6.6).
func InstalledFiles(p Paths) (map[string]string, error) {
	out := map[string]string{}
	for role, path := range map[string]string{roleSandboxd: p.Sandboxd, roleToolboxd: p.Toolboxd, roleCaddy: p.Caddy} {
		if path == "" {
			continue
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", path, err)
		}
		if sum != "" {
			out[role] = sum
		}
	}
	return out, nil
}

// LockHolder reports whether an upgrade holds this node's lock right now,
// and its op ID when the holder wrote one. A caller that is about to Launch
// asks it first, so a second upgrade is refused up front (upgrade_running)
// instead of starting an upgrader that exits at once on ErrBusy.
func LockHolder(stateDir string) (string, bool) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", false
	}
	lk, err := acquireLock(stateDir, "")
	if err == nil {
		lk.release()
		return "", false
	}
	if !errors.Is(err, ErrBusy) {
		return "", false
	}
	raw, _ := os.ReadFile(filepath.Join(stateDir, "lock"))
	return strings.TrimSpace(string(raw)), true
}

// PutLocalCopy puts into store the installed binary, or its *.prev, whose
// hash is sum, if this node has one. A rollback uses it: a node's own
// *.prev is the previous version's file, so it needs no copy from a server.
func PutLocalCopy(p Paths, store FileStore, sum string) bool {
	if store.Has(sum) {
		return true
	}
	for _, path := range []string{p.Sandboxd, p.Toolboxd, p.Caddy} {
		if path == "" {
			continue
		}
		for _, cand := range []string{path + ".prev", path} {
			if got, err := fileSHA256(cand); err != nil || got != sum {
				continue
			}
			f, err := os.Open(cand)
			if err != nil {
				continue
			}
			_, _, err = store.Put(sum, f)
			_ = f.Close()
			if err == nil {
				return true
			}
		}
	}
	return false
}
