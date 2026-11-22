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
// uid 61000; a V8 jail's) keep their owner. It follows no link: each entry
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
	return AgentFolders{Dirs: outermost(dirs), UID: uid, GID: gid}, nil
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
