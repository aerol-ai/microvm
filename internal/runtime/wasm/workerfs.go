package wasm

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// What a worker that dropped its privileges (cfg.Worker, pkg/wasm/worker)
// may change on the host, and how the driver keeps it to that:
//
//   - the sandbox's /work: owned by the worker uid, mode 0700. Its parent,
//     the run dir, stays root's, so a worker can reach a /work only through
//     the descriptor sandboxd passes with each message, never another
//     sandbox's by name.
//   - a checkpoint's staging folder, ModulesDir/<id>/.mem.snap-stage, the
//     worker's for one checkpoint. promoteCheckpoint takes it back before
//     anything of it is read as root, so mem.snap itself is always root's
//     and every root reader of it (restore, push, migrate) reads plain
//     files it checked.
//   - its owner's compile cache (compileCacheFor).
//
// Everything else a worker uses it only reads, through descriptors sandboxd
// opens as root: module files and snapshot files, which stay root's.
//
// Without cfg.Worker (the drop is off, or sandboxd is not root) nothing is
// chowned and the same paths are used as before.

// workerOwns reports whether workers drop to cfg.Worker's uid/gid.
func (d *Driver) workerOwns() bool { return d.cfg.Worker.Enabled() }

// ensureWorkDir makes the sandbox's /work and hands it to the worker uid. A
// /work made before workers dropped (root's, with what root workers wrote
// in it) is handed over whole, once: after that, what the guest writes is
// the worker's already and what the toolbox writes it chowns as it goes.
func (d *Driver) ensureWorkDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if !d.workerOwns() {
		return nil
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if uid, _, _, ok := fileIDs(st); ok && uid == d.cfg.Worker.UID {
		return nil
	}
	return chownTree(dir, d.cfg.Worker.UID, d.cfg.Worker.GID)
}

// chownTree gives dir and its directories and regular files to uid/gid,
// through an os.Root on dir, so no symlink in the tree leads it outside.
// It never follows or changes a symlink, a device, a socket or a FIFO, and
// skips a file with more than one name: a hard link may name a file
// outside the tree. An entry it cannot change is skipped (it stays
// root's: the guest can read it but not change it, as before).
func chownTree(dir string, uid, gid int) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if path == "." {
				return err
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		if !takeable(info) {
			return nil
		}
		if err := root.Lchown(path, uid, gid); err != nil && path == "." {
			return err
		}
		return nil
	})
}

// takeable is a directory, or a regular file with one name.
func takeable(info fs.FileInfo) bool {
	if info.IsDir() {
		return true
	}
	if !info.Mode().IsRegular() {
		return false
	}
	_, _, nlink, ok := fileIDs(info)
	return ok && nlink == 1
}

// fileIDs is the owner and link count of info.
func fileIDs(info fs.FileInfo) (uid, gid int, nlink uint64, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, false
	}
	return int(st.Uid), int(st.Gid), uint64(st.Nlink), true
}

// checkpointStageName is the staging folder a checkpoint writes mem.snap
// into, beside the published one. One fixed name per sandbox: the worker
// keeps the descriptor it was granted for it until the next checkpoint
// replaces it, so a fresh name each time would pile them up.
const checkpointStageName = ".mem.snap-stage"

// stageCheckpoint makes an empty staging folder for final (a mem.snap
// path) and returns where the worker writes its mem.snap. The folder above
// it stays root's.
func (d *Driver) stageCheckpoint(final string) (string, error) {
	parent := filepath.Dir(final)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", err
	}
	stage := filepath.Join(parent, checkpointStageName)
	if err := os.RemoveAll(stage); err != nil {
		return "", err
	}
	if err := os.Mkdir(stage, 0o700); err != nil {
		return "", err
	}
	if d.workerOwns() {
		if err := os.Chown(stage, d.cfg.Worker.UID, d.cfg.Worker.GID); err != nil {
			_ = os.RemoveAll(stage)
			return "", err
		}
	}
	return filepath.Join(stage, "mem.snap"), nil
}

// errStagedSnapshot refuses a staged checkpoint that is not a folder of
// plain files.
var errStagedSnapshot = errors.New("checkpoint staging holds something other than a folder of plain files")

// promoteCheckpoint publishes the worker's staged mem.snap at final. Taking
// a thing back means owner and mode both: root's, folders 0700, files 0600.
// The owner alone would leave a mode the worker chose (0777), and with the
// handle it kept the worker could still swap a file for a link after the
// publish. It first takes the staging folder back (to sandboxd's own uid: root), so from then on the worker can
// neither add, remove nor swap a name in it, whatever descriptor it kept;
// then mem.snap, then each file in it after checking it is a plain file
// with one name. Only then is it moved into place. The staging folder is
// removed either way.
func (d *Driver) promoteCheckpoint(staged, final string) error {
	stage := filepath.Dir(staged)
	defer os.RemoveAll(stage)
	uid, gid := os.Geteuid(), os.Getegid()
	if err := takeBack(stage, uid, gid, 0o700, d.workerOwns()); err != nil {
		return err
	}
	st, err := os.Lstat(staged)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return errStagedSnapshot
	}
	if err := takeBack(staged, uid, gid, 0o700, d.workerOwns()); err != nil {
		return err
	}
	entries, err := os.ReadDir(staged)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(staged, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.IsDir() || !takeable(info) {
			return fmt.Errorf("%w: %s", errStagedSnapshot, entry.Name())
		}
		if err := takeBack(path, uid, gid, 0o600, d.workerOwns()); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(final); err != nil {
		return err
	}
	return os.Rename(staged, final)
}

// takeBack gives path (checked not to be a link, inside a folder the worker
// can no longer change) to uid/gid with mode: the owner first, so the
// worker loses the right to change the mode, then the mode.
func takeBack(path string, uid, gid int, mode os.FileMode, chown bool) error {
	if chown {
		if err := os.Lchown(path, uid, gid); err != nil {
			return err
		}
	}
	return os.Chmod(path, mode)
}

// compileCacheFor is the compile cache of an owner's workers, made for the
// worker uid: one per owner (and one for operator creates, owner ""), so no
// tenant's worker writes compiled code another tenant's worker loads. ""
// when there is no cache root or it cannot be made: the worker then
// compiles without one.
func (d *Driver) compileCacheFor(ownerRef string) string {
	name := "operator"
	if ownerRef != "" {
		name = "owner-" + shortHash(ownerRef)
	}
	return d.compileCacheNamed(name)
}

// residentCacheName is the cache a resident bucket's hosts use: the owner's
// whose sandboxes the bucket serves, read off the bucket id
// (residentBucketID), so an adopted bucket, whose owner is not known by
// name, gets the same one.
func residentCacheName(bucketID string) string {
	if m := residentOwnerPrefix.FindStringSubmatch(bucketID); m != nil {
		return "owner-" + m[1]
	}
	return "operator"
}

var residentOwnerPrefix = regexp.MustCompile(`^o([0-9a-f]{16})-`)

func (d *Driver) compileCacheNamed(name string) string {
	if d.cfg.CompileCacheDir == "" {
		return ""
	}
	return d.prepareCompileCache(filepath.Join(d.cfg.CompileCacheDir, "owners", name))
}

// SlotCompileCache is the compile cache of a warm-pool slot's worker: a
// folder of its own inside the slot's folder, so it goes when the slot
// does (the pool and Destroy remove that folder). A slot is warmed before
// any create takes it, so it cannot have its owner's cache, and a cache
// that slots shared would let the tenant who takes one plant compiled code
// the tenant who takes the next one loads. Operator modules are still a
// cache read: the shared cache's entries are linked in.
func (d *Driver) SlotCompileCache(slotDir string) string {
	if d.cfg.CompileCacheDir == "" || slotDir == "" {
		return ""
	}
	return d.prepareCompileCache(filepath.Join(slotDir, "cache"))
}

// prepareCompileCache makes dir (whose parent is root's) for the worker uid
// and links the shared entries in. "" when it cannot be made.
func (d *Driver) prepareCompileCache(dir string) string {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		d.logger.Warn("wasm compile cache not created; workers compile without it", "dir", dir, "error", err)
		return ""
	}
	if d.workerOwns() {
		if err := os.Chown(dir, d.cfg.Worker.UID, d.cfg.Worker.GID); err != nil {
			d.logger.Warn("wasm compile cache not handed to the worker uid; workers compile without it", "dir", dir, "error", err)
			return ""
		}
	}
	d.linkShared(dir)
	return dir
}

// withCompileCache puts the owner's compile cache on ctx for the worker
// supervisor (worker.WithCompileCache).
func (d *Driver) withCompileCache(ctx context.Context, ownerRef string) context.Context {
	return worker.WithCompileCache(ctx, d.compileCacheFor(ownerRef))
}

// workerStartCtx is what a sandbox's own worker starts with: its owner's
// compile cache, a spill folder named for the sandbox (the drain stamps
// its records with that sandbox), and, for a sandbox whose s3/rclone mounts
// were started for root before workers dropped, a root worker.
func (d *Driver) workerStartCtx(ctx context.Context, sandboxID, ownerRef string, legacyRoot bool) context.Context {
	ctx = d.withCompileCache(ctx, ownerRef)
	ctx = worker.WithSpillLabel(ctx, sandboxSpillLabel(sandboxID))
	if legacyRoot {
		ctx = worker.WithoutConfinement(ctx)
	}
	return ctx
}

// sandboxSpillLabel names a sandbox's own spill folder.
func sandboxSpillLabel(sandboxID string) string { return "sb-" + sandboxID }

// legacyRoot reports whether a sandbox keeps a root worker: workers drop
// their privileges, but one of its s3/rclone mounts lets only root in
// (mounts.ContainerBind.RootOnly), because it was started before the
// upgrade and taken over as it ran. A live mount is never restarted under
// a sandbox (rclone may hold writes it has not flushed), so the sandbox
// keeps today's root worker until it is recreated, and never goes to a
// shared resident host. It is said once per sandbox.
func (d *Driver) legacyRoot(sandboxID string, binds []mounts.ContainerBind) bool {
	if !d.workerOwns() {
		return false
	}
	for _, b := range binds {
		if !b.RootOnly {
			continue
		}
		if _, said := d.legacyLogged.LoadOrStore(sandboxID, struct{}{}); !said && d.logger != nil {
			d.logger.Warn("wasm sandbox keeps a root worker: its mounts were started before workers dropped their privileges; recreate it to finish the upgrade",
				"sandbox_id", sandboxID, "mount", b.ContainerPath)
		}
		return true
	}
	return false
}

// LegacyRootWorkers counts the sandboxes that keep a root worker
// (legacyRoot): the aerolvm_wasm_workers_legacy_root gauge.
func (d *Driver) LegacyRootWorkers() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, inst := range d.byID {
		if inst.legacyRoot {
			n++
		}
	}
	return n
}
