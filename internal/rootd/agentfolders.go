package rootd

import (
	"errors"
	"fmt"
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
// uid 61000; a V8 jail's) keep their owner. It follows no link, never
// enters another file system (an external storage mount, a tmpfs), and
// leaves a file with more than one name alone: with a second name in a
// folder only root can reach, a chown here would hand that file over too.

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
		{"SB_CLUSTER_CA_DIR", strings.TrimSpace(getenv("SB_CLUSTER_CA_DIR"))},
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
	if n, perr := strconv.ParseUint(who, 10, 32); perr == nil {
		if u, err = lookupUserID(who); err != nil {
			return uint32(n), uint32(n), nil
		}
	} else if u, err = lookupUserName(who); err != nil {
		return 0, 0, fmt.Errorf("agent folders: user %s: %w", who, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("agent folders: user %s has uid %q", who, u.Uid)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("agent folders: user %s has gid %q", who, u.Gid)
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
		if err := unix.Fchown(rfd, int(f.UID), int(groupFor(st.Gid, f.GID))); err != nil {
			return fmt.Errorf("agent folders: chown %s: %w", dir, err)
		}
		res.Changed++
	}
	return walkInto(rfd, dir, uint64(st.Dev), f, res, 0)
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
		path := at + "/" + name
		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue // removed while the walk ran
			}
			return fmt.Errorf("agent folders: %s: %w", path, err)
		}
		res.Walked++
		typ := st.Mode & unix.S_IFMT
		switch {
		case typ == unix.S_IFLNK:
			continue
		case uint64(st.Dev) != dev:
			// Another file system: its own root decides.
			res.SkippedMounts++
			continue
		case typ != unix.S_IFDIR && st.Nlink > 1:
			res.SkippedLinks++
			continue
		}
		if st.Uid == movedFromUID {
			if err := unix.Fchownat(fd, name, int(f.UID), int(groupFor(st.Gid, f.GID)), unix.AT_SYMLINK_NOFOLLOW); err != nil {
				if errors.Is(err, unix.ENOENT) {
					continue
				}
				return fmt.Errorf("agent folders: chown %s: %w", path, err)
			}
			res.Changed++
		}
		if typ != unix.S_IFDIR {
			continue
		}
		sub, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return fmt.Errorf("agent folders: open %s: %w", path, err)
		}
		// The folder opened must be the one just looked at: one the
		// agent swapped in meanwhile is walked on the next start.
		var sst unix.Stat_t
		if err := unix.Fstat(sub, &sst); err != nil || uint64(sst.Dev) != dev || sst.Ino != st.Ino {
			_ = unix.Close(sub)
			continue
		}
		err = walkInto(sub, path, dev, f, res, depth+1)
		_ = unix.Close(sub)
		if err != nil {
			return err
		}
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
