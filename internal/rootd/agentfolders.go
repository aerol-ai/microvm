package rootd

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/rootfolder"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// The agent's folders on a VM in privilege mode split (plans/security-gaps-
// m1-m4.md §3.3, "On first start, the helper moves ownership of the agent's
// data folders ... from root to the agent's user"; M1 PR 10).
//
// A node that ran in privilege mode single has every file sandboxd made
// owned by root. Root tools still make files there in split mode: `sandboxd
// init` and `join` write the cluster certificates and the Raft folder,
// `sandboxd key wrap` the server key, the upgrader puts a database backup
// back, `sandboxd-restore.sh` a whole database. sandboxd, now a user with no
// rights, cannot open any of them. So the helper's binary runs as root just
// before every sandboxd start (install.sh puts `aerolvm-rootd agent-folders`
// in sandboxd.service as ExecStartPre=+) and gives the agent what root left
// in the agent's folders. After the first start there is nothing left to
// move, and the walk only reads.
//
// It changes only what root owns. Files of other users (the WASM worker's,
// uid 61000; a V8 jail's) keep their owner, with one exception: a WASM
// compile cache privilege mode single gave the worker is removed
// (singleWasmCache), so split makes the cache again in a way its workers
// can use. It follows no link: each entry
// is opened without following one (O_PATH|O_NOFOLLOW on Linux), its owner,
// kind and link count are read from that handle, and the chown goes
// through the same handle, so a name swapped between the look and the
// change changes nothing else. It does not enter a mount: an entry that is
// the root of a mount (statx's STATX_ATTR_MOUNT_ROOT, Linux 5.8 and later,
// which also sees a bind mount from the same disk) or on another device is
// skipped. And it leaves a file with more than one name alone: with a
// second name in a folder only root can reach, a chown here would hand
// that file over too.

// defaultClusterCADir is sandboxd's default CA store (internal/config
// SB_CLUSTER_CA_DIR).
const defaultClusterCADir = "/etc/sandboxd/cluster-ca"

// AgentFolders are the folders the ownership move walks, and whose they
// become.
type AgentFolders struct {
	// Dirs are absolute, clean, and none inside another.
	Dirs []string
	// UID and GID are the agent's user and its primary group. A file
	// root's group owns gets GID; any other group is kept.
	UID, GID uint32
	// WasmCacheRoot is the WASM compile cache root as sandboxd and the
	// helper work it out (wasmCacheRoot), and WasmWorkerUID the WASM
	// worker's user: together they name the caches single mode left
	// (singleWasmCache). An empty root turns that off.
	WasmCacheRoot string
	WasmWorkerUID uint32
}

// AgentFolderResult is what one walk did.
type AgentFolderResult struct {
	// Changed is the number of files and folders now the agent's.
	Changed int
	// Walked is everything the walk looked at.
	Walked int
	// SkippedLinks are files left as they were because they have more than
	// one name; SkippedMounts are other file systems inside a folder.
	SkippedLinks, SkippedMounts int
	// Missing are folders that are not there yet (a node with no cluster
	// certificates, say): nothing to move.
	Missing []string
	// ForgottenCaches are the WASM compile caches single mode left that
	// the walk removed. CacheErrors say why one could not be removed; it
	// is left as it was, and the walk goes on.
	ForgottenCaches int
	CacheErrors     []string
}

// maxAgentFolderDepth bounds the walk. sandboxd's deepest folders are a few
// levels below its data folder (mounts/<sandbox>/<index>, raft/snapshots/
// <id>); a deeper tree is not one sandboxd made.
const maxAgentFolderDepth = 32

// notAgentFolders are folders that hold more than the agent's files. A
// setting that names one (SB_DB_PATH=/state.db makes the data folder "/")
// is refused rather than walked: the walk would give the agent the
// machine.
var notAgentFolders = []string{
	"/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64", "/media", "/mnt", "/opt",
	"/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var",
	"/etc/sandboxd", "/etc/systemd", "/run/aerolvm", "/usr/local", "/usr/local/bin", "/usr/local/lib",
	"/var/lib", "/var/lib/containerd", "/var/lib/docker", "/var/run", "/var/tmp",
}

// helperFolderRoots are the helper's own folders and the node's settings:
// an agent folder may be neither one of them nor hold one.
var helperFolderRoots = []string{
	DefaultStateDir, "/run/aerolvm-rootd", "/usr/local/lib/aerolvm-rootd", "/etc/sandboxd/rootd.env",
	"/etc/sandboxd/sandboxd.env", "/etc/sandboxd/node.json", "/var/lib/aerolvm-upgrade",
}

// AgentFoldersFromEnv reads the agent's folders from sandboxd's own
// settings (the unit's environment: sandboxd.env and cluster.env), with
// sandboxd's defaults, and user, the agent's user (a name or a uid).
func AgentFoldersFromEnv(getenv func(string) string, who string) (AgentFolders, error) {
	uid, gid, err := agentIDs(who)
	if err != nil {
		return AgentFolders{}, err
	}
	if uid == 0 {
		return AgentFolders{}, errors.New("agent folders: the agent must not be root")
	}
	get := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	var dirs []string
	add := func(name, dir string) error {
		if dir == "" {
			return nil
		}
		if !filepath.IsAbs(dir) {
			return fmt.Errorf("agent folders: %s=%q: want an absolute path", name, dir)
		}
		dir = filepath.Clean(dir)
		if slices.Contains(notAgentFolders, dir) {
			return fmt.Errorf("agent folders: %s names %s, which holds more than sandboxd's files", name, dir)
		}
		for _, h := range helperFolderRoots {
			if h == dir || strings.HasPrefix(h, dir+"/") || strings.HasPrefix(dir, h+"/") {
				return fmt.Errorf("agent folders: %s names %s, which is (or holds) the root helper's %s", name, dir, h)
			}
		}
		dirs = append(dirs, dir)
		return nil
	}
	for _, d := range []struct{ name, dir string }{
		// sandboxd's defaults (internal/config).
		{"SB_DB_PATH", filepath.Dir(get("SB_DB_PATH", defaultDBPath))},
		{"SB_MOUNTS_CRED_DIR", get("SB_MOUNTS_CRED_DIR", defaultCredDir)},
		{"SB_MOUNTS_ROOT", get("SB_MOUNTS_ROOT", defaultMountsRoot)},
		{"SB_CONTAINERD_RUN_DIR", get("SB_CONTAINERD_RUN_DIR", defaultRunDir)},
		// Only where they are set: the cluster's files (sandboxd init and
		// join write them as root) and the Raft log on a disk of its own.
		{"SB_RAFT_DATA_DIR", strings.TrimSpace(getenv("SB_RAFT_DATA_DIR"))},
		{"SB_RAFT_WAL_DIR", strings.TrimSpace(getenv("SB_RAFT_WAL_DIR"))},
		{"SB_CLUSTER_TLS_DIR", strings.TrimSpace(getenv("SB_CLUSTER_TLS_DIR"))},
		// The CA store has sandboxd's default (internal/config), which
		// `sandboxd init` writes ca.key into as root, and which nodejoin
		// leaves out of cluster.env. A node with no cluster has no such
		// folder, and the walk skips it.
		{"SB_CLUSTER_CA_DIR", get("SB_CLUSTER_CA_DIR", defaultClusterCADir)},
	} {
		if err := add(d.name, d.dir); err != nil {
			return AgentFolders{}, err
		}
	}
	cacheRoot, worker := wasmCacheSettings(getenv, uid)
	return AgentFolders{Dirs: outermost(dirs), UID: uid, GID: gid, WasmCacheRoot: cacheRoot, WasmWorkerUID: worker}, nil
}

// wasmCacheSettings are the WASM compile cache root and the WASM worker's
// uid, from sandboxd's settings, for singleWasmCache. A setting that is
// not usable (a relative path, a uid that is not a number) turns the
// removal off rather than stopping sandboxd's start: the helper checks
// those settings itself when it runs WASM hosts. So does a worker uid of
// root's or the agent's: their folders are never single mode's leftovers.
func wasmCacheSettings(getenv func(string) string, agent uint32) (string, uint32) {
	bad := false
	path := func(k, def string) string {
		raw := strings.TrimSpace(getenv(k))
		if raw == "" {
			raw = def
		}
		if !filepath.IsAbs(raw) {
			bad = true
		}
		return filepath.Clean(raw)
	}
	root := wasmCacheRoot(getenv, path)
	worker, err := envInt(getenv, "SB_WASM_WORKER_UID", defaultWasmWorkerID)
	if bad || root == "" || err != nil || worker <= 0 || worker > math.MaxInt32 || uint32(worker) == agent {
		return "", 0
	}
	return root, uint32(worker)
}

// outermost drops each folder inside another of the list, and repeats.
func outermost(dirs []string) []string {
	slices.Sort(dirs)
	dirs = slices.Compact(dirs)
	var out []string
	for _, d := range dirs {
		if len(out) > 0 && strings.HasPrefix(d, out[len(out)-1]+"/") {
			continue
		}
		out = append(out, d)
	}
	return out
}

// agentIDs is who's uid and primary gid: a user name, or a uid (whose
// primary group is looked up, and is the uid itself when the uid has no
// name here).
func agentIDs(who string) (uint32, uint32, error) {
	who = strings.TrimSpace(who)
	if who == "" {
		return 0, 0, errors.New("agent folders: name the agent's user (--user)")
	}
	var u *user.User
	var err error
	// Ids past MaxInt32 are refused: fchown takes an int, and on a 32-bit
	// build a larger uid_t would wrap into a negative id.
	if n, perr := strconv.ParseUint(who, 10, 64); perr == nil {
		if n > math.MaxInt32 {
			return 0, 0, fmt.Errorf("agent folders: uid %d is past %d", n, math.MaxInt32)
		}
		if u, err = lookupUserID(who); err != nil {
			return uint32(n), uint32(n), nil
		}
	} else if u, err = lookupUserName(who); err != nil {
		return 0, 0, fmt.Errorf("agent folders: user %s: %w", who, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 64)
	if err != nil || uid > math.MaxInt32 {
		return 0, 0, fmt.Errorf("agent folders: user %s has uid %q, not one from 1 to %d", who, u.Uid, math.MaxInt32)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 64)
	if err != nil || gid > math.MaxInt32 {
		return 0, 0, fmt.Errorf("agent folders: user %s has gid %q, not one from 0 to %d", who, u.Gid, math.MaxInt32)
	}
	return uint32(uid), uint32(gid), nil
}

// movedFromUID is whose files the walk moves: root's. Tests, which cannot
// make root's files, set their own uid.
var movedFromUID uint32

// movedFromGID is root's group, whose files get the agent's group.
var movedFromGID uint32

// User lookups, seams for tests.
var (
	lookupUserID   = user.LookupId
	lookupUserName = user.Lookup
)

// GiveToAgent gives the agent every file and folder root owns in f's
// folders. Each folder is reached from / one name at a time with no link
// followed, and every folder above it must be root's and closed to others
// (rootfolder.WalkFolder), so the agent cannot point a walk elsewhere by
// renaming a folder on the way. A folder that is not there is skipped.
func GiveToAgent(f AgentFolders) (AgentFolderResult, error) {
	var res AgentFolderResult
	for _, dir := range f.Dirs {
		fd, err := rootfolder.WalkFolder(dir, false, func(at string, st *unix.Stat_t, last bool) error {
			if last {
				// The folder itself may already be the agent's.
				if st.Mode&unix.S_IFMT != unix.S_IFDIR {
					return fmt.Errorf("%s is not a folder", at)
				}
				return nil
			}
			return rootfolder.CheckFolder(at, uint32(st.Mode), st.Uid, uint32(os.Geteuid()), true)
		})
		if errors.Is(err, unix.ENOENT) {
			res.Missing = append(res.Missing, dir)
			continue
		}
		if err != nil {
			return res, fmt.Errorf("agent folders: %w", err)
		}
		err = giveFolder(fd, dir, f, &res)
		_ = unix.Close(fd)
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

// giveFolder gives the agent the open folder fd (at dir) and what is in it.
// WalkFolder's handle may be O_PATH, which fchown refuses (EBADF), so the
// folder is opened again through it, to read: the same folder, no name
// looked up again.
func giveFolder(fd int, dir string, f AgentFolders, res *AgentFolderResult) error {
	rfd, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("agent folders: open %s: %w", dir, err)
	}
	defer func() { _ = unix.Close(rfd) }()
	var st unix.Stat_t
	if err := unix.Fstat(rfd, &st); err != nil {
		return fmt.Errorf("agent folders: %s: %w", dir, err)
	}
	res.Walked++
	if st.Uid == movedFromUID {
		uid, gid, err := ownerIDs(f.UID, groupFor(st.Gid, f.GID))
		if err == nil {
			err = unix.Fchown(rfd, uid, gid)
		}
		if err != nil {
			return fmt.Errorf("agent folders: chown %s: %w", dir, err)
		}
		res.Changed++
	}
	return walkInto(rfd, dir, uint64(st.Dev), f, res, 0)
}

// ownerIDs is uid and gid as fchown takes them, an int each: at most
// MaxInt32, which agentIDs already holds them to.
func ownerIDs(uid, gid uint32) (int, int, error) {
	if uid > math.MaxInt32 || gid > math.MaxInt32 {
		return 0, 0, fmt.Errorf("owner %d:%d is past %d", uid, gid, math.MaxInt32)
	}
	return int(uid), int(gid), nil
}

// entry is one name in a folder the walk holds open, looked at once.
type entry struct {
	dfd  int    // the folder
	name string // its name there
	fd   int    // a handle on the entry itself, or -1 (agentfolders_other.go)
	st   unix.Stat_t
}

// groupFor is the group a file of root's gets: the agent's for root's
// group, otherwise its own.
func groupFor(gid, agentGID uint32) uint32 {
	if gid == movedFromGID {
		return agentGID
	}
	return gid
}

// walkInto gives the agent what root owns below the open folder fd.
func walkInto(fd int, at string, dev uint64, f AgentFolders, res *AgentFolderResult, depth int) error {
	if depth >= maxAgentFolderDepth {
		return fmt.Errorf("agent folders: %s is more than %d folders deep; not a folder sandboxd made", at, maxAgentFolderDepth)
	}
	names, err := readNames(fd)
	if err != nil {
		return fmt.Errorf("agent folders: list %s: %w", at, err)
	}
	for _, name := range names {
		if err := giveEntry(fd, name, at+"/"+name, dev, f, res, depth); err != nil {
			return err
		}
	}
	return nil
}

// giveEntry gives the agent one entry of the open folder fd, if root owns
// it, and walks into it if it is a folder. Everything is decided and done
// through one handle on the entry (openEntry), never by its name again.
func giveEntry(fd int, name, path string, dev uint64, f AgentFolders, res *AgentFolderResult, depth int) error {
	e, err := openEntry(fd, name)
	if errors.Is(err, unix.ENOENT) {
		return nil // removed while the walk ran
	}
	if err != nil {
		return fmt.Errorf("agent folders: %s: %w", path, err)
	}
	defer e.close()
	res.Walked++
	typ := e.st.Mode & unix.S_IFMT
	if typ == unix.S_IFLNK {
		return nil
	}
	if uint64(e.st.Dev) != dev || e.mountRoot() {
		// A mount: its own root decides.
		res.SkippedMounts++
		return nil
	}
	if typ != unix.S_IFDIR && e.st.Nlink > 1 {
		res.SkippedLinks++
		return nil
	}
	if typ == unix.S_IFDIR && f.singleWasmCache(path, e.st.Uid) {
		forgetWasmCache(e, path, dev, res)
		return nil
	}
	if e.st.Uid == movedFromUID {
		if err := e.chown(f.UID, groupFor(e.st.Gid, f.GID)); err != nil {
			if errors.Is(err, unix.ENOENT) {
				return nil
			}
			return fmt.Errorf("agent folders: chown %s: %w", path, err)
		}
		res.Changed++
	}
	if typ != unix.S_IFDIR {
		return nil
	}
	sub, err := e.openDir(dev)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("agent folders: open %s: %w", path, err)
	}
	if sub < 0 {
		return nil // swapped since it was looked at: the next start walks it
	}
	defer func() { _ = unix.Close(sub) }()
	return walkInto(sub, path, dev, f, res, depth+1)
}

// singleWasmCache reports whether path, a folder uid owns, is a WASM
// compile cache privilege mode single made: a folder where the WASM driver
// puts a cache (owners/<name> or slots/<hash>/cache under the cache root,
// the names rootpolicy.CheckWasmCache takes) that belongs to the worker's
// user. Single gives each cache to the worker's uid. Split's sandboxd makes
// its caches as itself and shares them with the worker's group; it cannot
// do that to the worker's folder (only an owner may change a folder's
// group), and the helper hands a worker only a cache that is the agent's
// (openAgentFolder). Such a cache would stay unused, and every worker
// would compile its module again on each start. Split never makes one:
// the worker cannot write in owners/ or slots/<hash>/.
func (f AgentFolders) singleWasmCache(path string, uid uint32) bool {
	if f.WasmCacheRoot == "" || uid != f.WasmWorkerUID {
		return false
	}
	rel, ok := strings.CutPrefix(path, f.WasmCacheRoot+"/")
	if !ok {
		return false
	}
	if name, ok := strings.CutPrefix(rel, "owners/"); ok {
		return name != "" && !strings.Contains(name, "/") && rootpolicy.CheckWasmCache(name) == nil
	}
	return strings.HasPrefix(rel, "slots/") && rootpolicy.CheckWasmCache(rel) == nil
}

// forgetWasmCache removes a cache single mode left (singleWasmCache):
// what is in it, then the folder. It is only a cache: the worker compiles
// again what it held, once, into the cache split makes. Everything goes
// through the walk's handles: the folder through its entry, each name in
// it relative to the folder that holds it, with no link followed (a link
// is removed, never what it names) and no other file system entered. A
// cache it cannot remove is left as it is and named in CacheErrors; that
// never fails the walk, so sandboxd still starts, and its workers compile
// without that cache, as before.
func forgetWasmCache(e *entry, path string, dev uint64, res *AgentFolderResult) {
	err := func() error {
		sub, err := e.openDir(dev)
		if err != nil {
			return err
		}
		if sub < 0 {
			return errors.New("it changed while the walk looked at it")
		}
		defer func() { _ = unix.Close(sub) }()
		if err := emptyFolder(sub, path, dev, 0); err != nil {
			return err
		}
		return unix.Unlinkat(e.dfd, e.name, unix.AT_REMOVEDIR)
	}()
	if err != nil && !errors.Is(err, unix.ENOENT) {
		res.CacheErrors = append(res.CacheErrors, fmt.Sprintf("%s: %v", path, err))
		return
	}
	res.ForgottenCaches++
}

// emptyFolder removes everything in the open folder fd (at path), deepest
// first, one name at a time relative to fd.
func emptyFolder(fd int, path string, dev uint64, depth int) error {
	if depth >= maxAgentFolderDepth {
		return fmt.Errorf("%s is more than %d folders deep", path, maxAgentFolderDepth)
	}
	names, err := readNames(fd)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := removeEntry(fd, name, path+"/"+name, dev, depth); err != nil {
			return err
		}
	}
	return nil
}

// removeEntry removes one entry of the open folder fd, looked at through a
// handle with no link followed (openEntry): a link, a file or anything
// else that is not a folder is unlinked by name; a folder is opened through
// that handle (the folder looked at), emptied and removed. A folder that is
// the root of a mount, or on another device, stops the removal.
func removeEntry(fd int, name, path string, dev uint64, depth int) error {
	e, err := openEntry(fd, name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer e.close()
	if e.st.Mode&unix.S_IFMT != unix.S_IFDIR {
		if err := unix.Unlinkat(fd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("%s: %w", path, err)
		}
		return nil
	}
	if uint64(e.st.Dev) != dev || e.mountRoot() {
		return fmt.Errorf("%s is another file system", path)
	}
	sub, err := e.openDir(dev)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if sub < 0 {
		return fmt.Errorf("%s changed while it was removed", path)
	}
	err = emptyFolder(sub, path, dev, depth+1)
	_ = unix.Close(sub)
	if err != nil {
		return err
	}
	if err := unix.Unlinkat(fd, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// readNames lists the open folder fd. The listing reads a duplicate of fd,
// so fd itself stays open for the *at calls.
func readNames(fd int) ([]string, error) {
	dup, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	d := os.NewFile(uintptr(dup), ".")
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	return names, nil
}
