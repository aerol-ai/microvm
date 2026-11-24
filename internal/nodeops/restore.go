package nodeops

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/internal/raftlogdir"
	"github.com/aerol-ai/microvm/internal/rootfolder"
)

// RestoreOptions is one `sandboxd restore`.
type RestoreOptions struct {
	Input string
	// TargetRoot is where the archive's tree lands; "/" (the default) is
	// the node itself.
	TargetRoot string
	// Force is the operator's acknowledgement that this is the node to
	// overwrite.
	Force bool
	// Start starts sandboxd after a restore into / and waits for /health.
	Start         bool
	HealthTimeout time.Duration
	Host          Host
	Out           io.Writer
	// Err gets the warnings the script printed to stderr.
	Err io.Writer

	now  func() time.Time
	euid func() int
	// chown, when set, stands in for every owner change, with the path it
	// would change: an unprivileged test cannot give a file root's owner.
	chown      func(path string, uid, gid int) error
	healthPoll time.Duration
	// liveRoot is the root that is this node itself: "/". Tests point it
	// at a temporary directory.
	liveRoot string
}

// RestoreResult lists what a restore moved aside.
type RestoreResult struct {
	MovedAside []string
	Version    string
}

const restoreStamp = "20060102T150405Z"

// Restore puts a backup archive back. It replaces the database and the Raft
// log, never merges into them: SQLite would replay a leftover state.db-wal
// from the database being replaced onto the restored one, and two Raft logs
// in one directory are not one log. A replacement node that already ran a
// fresh install has both. The server key goes with the database it seals,
// so the node comes back with the archive's key files and none of its own.
// Whatever is replaced is moved aside as <name>.pre-restore-<time>, never
// deleted. Files in the config directory are overwritten in place, as tar
// does.
//
// The whole archive is read and checked before anything on disk changes:
// a truncated or foreign archive is refused with the node untouched. If
// writing fails part way, what was moved aside is moved back.
func Restore(ctx context.Context, o RestoreOptions) (RestoreResult, error) {
	o.defaults()
	var res RestoreResult
	if o.Input == "" {
		return res, usageErr("--input is required")
	}
	if !o.Force {
		return res, usageErr("refusing to restore without --force; stop sandboxd and confirm this is the intended target")
	}
	st, err := os.Stat(o.Input)
	if err != nil || !st.Mode().IsRegular() {
		return res, fmt.Errorf("backup archive not found: %s", o.Input)
	}
	root, err := filepath.Abs(o.TargetRoot)
	if err != nil {
		return res, err
	}
	live := root == o.liveRoot
	if live && o.Host.UnitActive(ctx, sandboxdUnit) {
		return res, fmt.Errorf("sandboxd is running; stop it first (%s): a restore under a running sandboxd mixes two databases", stopHint(o.Host))
	}
	idx, err := scanArchive(o.Input)
	if err != nil {
		return res, fmt.Errorf("%s: %w", o.Input, err)
	}
	// In privilege mode split, on this node or on the one backed up,
	// sandboxd's user owns some of the folders the archive lands in
	// (agentTrees). This node's settings are read before the archive's
	// replace them.
	here, err := ReadNode(filepath.Join(root, filepath.FromSlash(archiveConfig)))
	if err != nil && !errors.Is(err, syscall.ENOTDIR) {
		// A file where the config folder goes has no settings; the
		// restore replaces it.
		return res, err
	}
	backedUp, err := idx.node()
	if err != nil {
		return res, fmt.Errorf("%s: %w", o.Input, err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return res, err
	}

	r := &restorer{o: &o, root: root, stamp: o.now().UTC().Format(restoreStamp),
		split: here.Split || backedUp.Split, agent: agentTrees(here, backedUp)}
	if idx.has(archiveDB) {
		r.setAside(archiveDB, archiveDB+"-wal", archiveDB+"-shm")
	}
	if idx.hasTree(archiveRaft) {
		r.setAside(archiveRaft)
	}
	key := func(name string) string { return archiveLib + "/" + name }
	for _, k := range []string{keyName, ringName, wrappedName} {
		if idx.has(key(k)) {
			r.setAside(key(k))
		}
	}
	if r.err == nil {
		r.err = r.extract(o.Input)
	}
	if r.err != nil {
		r.putBack()
		return res, r.err
	}
	fmt.Fprintf(o.Out, "restored %s into %s\n", o.Input, root)

	// A node file the archive's custody has no use for goes too: sandboxd
	// refuses wrapped custody beside a plaintext key or ring, and a fresh
	// install's own key beside a restored ring or env key is the wrong key.
	if idx.has(key(wrappedName)) {
		r.setAside(key(keyName), key(ringName))
	} else {
		r.setAside(key(wrappedName))
		if !idx.has(key(ringName)) {
			r.setAside(key(ringName))
		}
		if !idx.has(key(keyName)) && exists(r.path(key(keyName))) {
			node, _ := ReadNode(r.path(archiveConfig))
			if idx.has(key(ringName)) || node.EnvKey {
				// The archive's ring or env key is the server key; this
				// one is not.
				r.setAside(key(keyName))
			} else {
				// An archive made before backups carried the key file: the
				// node's own key stays, and opens the restored data only
				// if it is the backed-up node's key (a restore in place).
				fmt.Fprintf(o.Err, "WARNING: the archive carries no server key; sandboxd will use %s, which must be the backed-up node's own key\n", r.path(key(keyName)))
			}
		}
	}
	if r.err != nil {
		return res, r.err
	}
	res.MovedAside = r.moved
	if testHookRestore != nil {
		testHookRestore("keys", r.path(archiveLib))
	}
	// The wrapped key and the ring were written 0600 (restorer.mode): a
	// chmod by name here would follow a link put in their place.
	if p := r.path(key(wrappedName)); exists(p) {
		// Custody "wrapped": sandboxd unwraps this at boot through the key
		// store, which must be reachable. A backup taken before a key
		// version was retired no longer opens once that version is gone.
		fmt.Fprintln(o.Out, "the server key is wrapped: run `sandboxd key verify` with the key store reachable before starting sandboxd")
	}
	if p := r.path(key(ringName)); exists(p) {
		fmt.Fprintf(o.Out, "the server key was rotated: the ring at %s holds it; keep it with SB_CREDENTIAL_KEY_RING_PATH unset or pointing there\n", p)
	}
	if node, err := ReadNode(r.path(archiveConfig)); err == nil && node.RaftWALDir != "" && idx.hasTree(archiveRaft) {
		// An archive holds the log at raft/raft-wal (Backup), and sandboxd
		// will not leave a log there behind for SB_RAFT_WAL_DIR.
		fmt.Fprintf(o.Err, "WARNING: the restored Raft log is in %s; sandboxd refuses to start while SB_RAFT_WAL_DIR=%s is set in %s: remove that line\n",
			r.path(archiveRaft+"/"+raftlogdir.DefaultName), node.RaftWALDir, r.path(archiveConfig))
	}
	if !(o.Start && live) {
		fmt.Fprintln(o.Out, "verify ownership/modes, then start sandboxd")
		return res, nil
	}
	node, err := ReadNode(r.path(archiveConfig))
	if err != nil {
		return res, err
	}
	res.Version, err = startAndWait(ctx, o.Host, o.Out, node.HealthURL, o.HealthTimeout, o.healthPoll)
	return res, err
}

func (o *RestoreOptions) defaults() {
	if o.TargetRoot == "" {
		o.TargetRoot = "/"
	}
	if o.liveRoot == "" {
		o.liveRoot = "/"
	}
	if o.Out == nil {
		o.Out = io.Discard
	}
	if o.Err == nil {
		o.Err = io.Discard
	}
	if o.now == nil {
		o.now = time.Now
	}
	if o.euid == nil {
		o.euid = os.Geteuid
	}
	if o.HealthTimeout <= 0 {
		o.HealthTimeout = 2 * time.Minute
	}
	if o.healthPoll <= 0 {
		o.healthPoll = time.Second
	}
}

// startAndWait starts sandboxd and waits until its /health answers.
func startAndWait(ctx context.Context, h Host, out io.Writer, url string, timeout, poll time.Duration) (string, error) {
	fmt.Fprintln(out, "starting sandboxd")
	if err := h.StartUnit(ctx, sandboxdUnit); err != nil {
		return "", err
	}
	deadline := time.Now().Add(timeout)
	var last error
	for {
		v, err := h.HealthVersion(ctx, url)
		if err == nil {
			fmt.Fprintf(out, "sandboxd is up (%s)\n", v)
			return v, nil
		}
		last = err
		if time.Now().After(deadline) {
			return "", fmt.Errorf("sandboxd did not answer %s within %s (last: %v); see journalctl -u sandboxd", url, timeout, last)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(poll):
		}
	}
}

// archiveIndex is what the first read of an archive found.
type archiveIndex struct {
	names map[string]bool
	// env holds the env files the archive carries (sandboxd.env and
	// cluster.env in the config folder), by name.
	env map[string][]byte
}

// maxEnvBytes bounds an env file read from an archive; sandboxd's are a
// few KiB.
const maxEnvBytes = 1 << 20

// node is the backed-up node's settings, read from the env files the
// archive carries as ReadNode reads them on a node.
func (x *archiveIndex) node() (Node, error) {
	merged := map[string]string{}
	for _, name := range []string{"sandboxd.env", "cluster.env"} {
		raw, ok := x.env[name]
		if !ok {
			continue
		}
		vals, err := nodeupgrade.ParseEnv(raw)
		if err != nil {
			return Node{}, fmt.Errorf("%s/%s: %w", archiveConfig, name, err)
		}
		for k, v := range vals {
			merged[k] = v
		}
	}
	return nodeFromEnv(DefaultConfigDir, merged), nil
}

func (x *archiveIndex) has(name string) bool { return x.names[name] }

// hasTree reports any entry at or below name: an archive that lists Raft
// files without their directory still replaces the Raft log, never merges
// into it.
func (x *archiveIndex) hasTree(name string) bool {
	for n := range x.names {
		if under(n, name) {
			return true
		}
	}
	return false
}

// scanArchive reads the whole archive once, checking every entry, so a bad
// archive is refused before anything changes. Reading to the end of the
// gzip stream checks its CRC.
func scanArchive(file string) (*archiveIndex, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("not a gzipped backup archive: %w", err)
	}
	idx := &archiveIndex{names: map[string]bool{}, env: map[string][]byte{}}
	links := map[string]bool{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read archive: %w", err)
		}
		if h.Typeflag == tar.TypeXGlobalHeader || appleDouble(h.Name) {
			continue
		}
		name, err := entryName(h.Name)
		if err != nil {
			return nil, err
		}
		if err := allowed(name, h); err != nil {
			return nil, err
		}
		// Nothing may be written through a link the archive makes.
		for p := path.Dir(name); p != "."; p = path.Dir(p) {
			if links[p] {
				return nil, fmt.Errorf("%s is below the link %s", name, p)
			}
		}
		if h.Typeflag == tar.TypeSymlink {
			links[name] = true
		}
		if h.Typeflag == tar.TypeLink {
			target, err := entryName(h.Linkname)
			if err != nil || allowed(target, &tar.Header{Typeflag: tar.TypeReg}) != nil || !idx.names[target] {
				return nil, fmt.Errorf("%s links to %q, which is not an earlier file of the backup", name, h.Linkname)
			}
		}
		if path.Dir(name) == archiveConfig && (h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA) { //nolint:staticcheck // old tars
			if base := path.Base(name); base == "sandboxd.env" || base == "cluster.env" {
				raw, err := io.ReadAll(io.LimitReader(tr, maxEnvBytes+1))
				if err != nil {
					return nil, fmt.Errorf("read archive: %w", err)
				}
				if len(raw) > maxEnvBytes {
					return nil, fmt.Errorf("archive entry %s is larger than %d bytes, which an env file never is", name, maxEnvBytes)
				}
				idx.env[base] = raw
			}
		}
		idx.names[name] = true
	}
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return nil, fmt.Errorf("read archive: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return idx, nil
}

// appleDouble is a "._name" entry macOS tar adds for extended attributes,
// when an archive was repacked on a Mac. It is never node data.
func appleDouble(raw string) bool {
	return strings.HasPrefix(path.Base(strings.TrimSuffix(raw, "/")), "._")
}

// entryName is an archive name without "./" and a trailing slash. A name
// that climbs out of the target root is refused.
func entryName(raw string) (string, error) {
	n := strings.TrimPrefix(raw, "./")
	if strings.HasPrefix(n, "/") {
		return "", fmt.Errorf("archive entry %q is an absolute path", raw)
	}
	for _, part := range strings.Split(n, "/") {
		if part == ".." {
			return "", fmt.Errorf("archive entry %q leaves the target root", raw)
		}
	}
	n = path.Clean("/" + n)[1:]
	return n, nil
}

// allowed checks an entry against the backup layout. A backup carries
// nothing else, so anything else means this is not one.
func allowed(name string, h *tar.Header) error {
	isDir := h.Typeflag == tar.TypeDir
	isReg := h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA //nolint:staticcheck // old tars
	switch h.Typeflag {
	case tar.TypeDir, tar.TypeReg, tar.TypeRegA, tar.TypeSymlink, tar.TypeLink: //nolint:staticcheck
	default:
		return fmt.Errorf("archive entry %s has type %q, which a backup never has", name, h.Typeflag)
	}
	switch name {
	case "", "etc", "var", "var/lib", archiveLib:
		if isDir {
			return nil
		}
	case manifestName, archiveDB, archiveLib + "/" + keyName, archiveLib + "/" + ringName, archiveLib + "/" + wrappedName:
		if isReg {
			return nil
		}
	default:
		if under(name, archiveConfig) || under(name, archiveRaft) {
			return nil
		}
		return fmt.Errorf("archive entry %s is not part of a sandboxd backup", name)
	}
	return fmt.Errorf("archive entry %s has the wrong type for a sandboxd backup", name)
}

func under(name, tree string) bool { return name == tree || strings.HasPrefix(name, tree+"/") }

// restorer does the writes of one restore and keeps what to undo.
type restorer struct {
	o     *RestoreOptions
	root  string
	stamp string
	moved []string
	// undo is the moves to reverse, oldest first.
	undo [][2]string
	err  error
	// split is set when this node or the backed-up one runs in privilege
	// mode split; agent is agentTrees.
	split bool
	agent []string
}

func (r *restorer) path(name string) string { return filepath.Join(r.root, filepath.FromSlash(name)) }

// setAside moves each existing name to <name>.pre-restore-<stamp>.
func (r *restorer) setAside(names ...string) {
	for _, name := range names {
		if r.err != nil {
			return
		}
		p := r.path(name)
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		aside := p + ".pre-restore-" + r.stamp
		for i := 1; exists(aside); i++ {
			aside = fmt.Sprintf("%s.pre-restore-%s.%d", p, r.stamp, i)
		}
		if err := os.Rename(p, aside); err != nil {
			r.err = err
			return
		}
		r.undo = append(r.undo, [2]string{p, aside})
		r.moved = append(r.moved, aside)
		fmt.Fprintf(r.o.Out, "moved aside: %s -> %s\n", p, aside)
	}
}

// putBack reverses the moves after a failed write.
func (r *restorer) putBack() {
	for i := len(r.undo) - 1; i >= 0; i-- {
		orig, aside := r.undo[i][0], r.undo[i][1]
		_ = os.RemoveAll(orig)
		if err := os.Rename(aside, orig); err != nil {
			fmt.Fprintf(r.o.Err, "could not put %s back as %s: %v\n", aside, orig, err)
			continue
		}
		fmt.Fprintf(r.o.Out, "put back: %s\n", orig)
	}
}

func (r *restorer) extract(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag == tar.TypeXGlobalHeader || appleDouble(h.Name) {
			continue
		}
		name, err := entryName(h.Name)
		if err != nil {
			return err
		}
		if err := r.entry(name, h, tr); err != nil {
			return fmt.Errorf("restore %s: %w", name, err)
		}
	}
}

// testHookRestore, when set, runs at points where a name the restore works
// on could be swapped: "write" with an entry's path, once the folder that
// holds it is open; "temp" with a regular file's temporary name, once its
// content is written; "keys" with the data folder, after the archive is
// written. Tests swap files there.
var testHookRestore func(stage, path string)

// Every entry below the config folder or the data folder is written
// through the folder that holds it, opened from the top of its tree one
// name at a time with no link followed (openParent), and changed through
// handles and names in that folder, never through a path: a link in the
// way, whenever it is put there, sends no write, mode or owner elsewhere.
// That matters in privilege mode split, where sandboxd's user owns the
// data folder and the certificate folders and can put a link anywhere in
// them; root's restore must not follow one.
func (r *restorer) entry(name string, h *tar.Header, body io.Reader) error {
	dst := r.path(name)
	switch name {
	case manifestName:
		// The archive's description, not a node file.
		return nil
	case "", "etc", "var", "var/lib", archiveLib:
		// Directories the node already has, or the scripts' mkdir -p
		// artefacts: made if missing, their owner and mode left alone.
		return os.MkdirAll(dst, 0o755)
	}
	if name == archiveConfig && h.Typeflag == tar.TypeDir {
		return r.configFolder(dst, h)
	}
	dir, base, err := r.openParent(name)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	if testHookRestore != nil {
		testHookRestore("write", dst)
	}
	switch h.Typeflag {
	case tar.TypeDir:
		return r.folder(dir, base, name, h)
	case tar.TypeSymlink:
		if err := r.clear(dir, base, dst); err != nil {
			return err
		}
		if err := unix.Symlinkat(h.Linkname, dir, base); err != nil {
			return err
		}
		if !r.owner(name) {
			return nil
		}
		if r.o.chown != nil {
			return r.o.chown(dst, h.Uid, h.Gid)
		}
		return unix.Fchownat(dir, base, h.Uid, h.Gid, unix.AT_SYMLINK_NOFOLLOW)
	case tar.TypeLink:
		return r.hardLink(dir, base, name, h)
	}
	return r.file(dir, base, name, h, body)
}

// configFolder is the config folder's own entry, handled as it always
// was: the folder and those above it are root's in both privilege modes,
// and an operator may have linked it to another disk, which stays a link.
func (r *restorer) configFolder(dst string, h *tar.Header) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	mode := fs.FileMode(h.Mode).Perm()
	// Stat, not Lstat: a config directory an operator linked to another
	// disk stays a link.
	if fi, err := os.Stat(dst); err != nil || !fi.IsDir() {
		if err := removeNonDir(dst); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(dst, mode); err != nil {
		return err
	}
	if err := os.Chmod(dst, mode); err != nil {
		return err
	}
	if r.o.euid() != 0 {
		return nil
	}
	if r.o.chown != nil {
		return r.o.chown(dst, h.Uid, h.Gid)
	}
	return os.Lchown(dst, h.Uid, h.Gid)
}

// walkFlags open a folder to work in, following no link.
const walkFlags = rootfolder.FolderFlags

// openParent opens the folder that holds name and returns it with name's
// last element. The top of name's tree (the config folder, or the data
// folder) is opened by its path: it and the folders above it are root's,
// and an operator may have linked it to another disk. Below it each folder
// is opened through the one above, with no link followed, and made there
// if missing (0755, as mkdir -p made them; 0700 in sandboxd's user's
// folders, see mode).
func (r *restorer) openParent(name string) (int, string, error) {
	top := archiveLib
	if under(name, archiveConfig) {
		top = archiveConfig
	}
	if name == top {
		top = path.Dir(name)
	}
	if err := os.MkdirAll(r.path(top), 0o755); err != nil {
		return -1, "", err
	}
	fd, err := unix.Open(r.path(top), walkFlags&^unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, "", fmt.Errorf("open %s: %w", r.path(top), err)
	}
	at := top
	for _, part := range strings.Split(strings.TrimPrefix(path.Dir(name), top), "/") {
		if part == "" {
			continue
		}
		at += "/" + part
		next, err := unix.Openat(fd, part, walkFlags, 0)
		if errors.Is(err, unix.ENOENT) {
			// EEXIST is fine: the open below judges what is there.
			if merr := unix.Mkdirat(fd, part, uint32(r.mode(at, &tar.Header{Typeflag: tar.TypeDir, Mode: 0o755}))); merr != nil && !errors.Is(merr, unix.EEXIST) {
				_ = unix.Close(fd)
				return -1, "", fmt.Errorf("make %s: %w", r.path(at), merr)
			}
			next, err = unix.Openat(fd, part, walkFlags, 0)
		}
		if err != nil {
			var st unix.Stat_t
			if unix.Fstatat(fd, part, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
				err = fmt.Errorf("%s is a link; refusing to write %s through it", r.path(at), name)
			} else {
				err = fmt.Errorf("open %s: %w", r.path(at), err)
			}
			_ = unix.Close(fd)
			return -1, "", err
		}
		_ = unix.Close(fd)
		fd = next
	}
	return fd, path.Base(name), nil
}

// folder makes or keeps the folder base in dir, with the archive's mode
// and, as root, its owner (mode, owner), set through a handle on it.
func (r *restorer) folder(dir int, base, name string, h *tar.Header) error {
	dst := r.path(name)
	mode := r.mode(name, h)
	var st unix.Stat_t
	err := unix.Fstatat(dir, base, &st, unix.AT_SYMLINK_NOFOLLOW)
	switch {
	case errors.Is(err, unix.ENOENT):
	case err != nil:
		return err
	case st.Mode&unix.S_IFMT == unix.S_IFDIR:
	default:
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			// The mode and owner would land on the folder a link points
			// to, wherever that is. A link to anything else, or to
			// nothing, is replaced, as it always was.
			var to unix.Stat_t
			if unix.Fstatat(dir, base, &to, 0) == nil && to.Mode&unix.S_IFMT == unix.S_IFDIR {
				return fmt.Errorf("%s is a link where the backup has a folder; refusing to change the folder it points to: remove the link and restore again", dst)
			}
		}
		if err := unix.Unlinkat(dir, base, 0); err != nil {
			return err
		}
	}
	if err := unix.Mkdirat(dir, base, uint32(mode)); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	fd, err := unix.Openat(dir, base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s without following a link: %w", dst, err)
	}
	f := os.NewFile(uintptr(fd), dst)
	defer f.Close()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	return r.fchown(f, name, h)
}

// file writes a regular file beside its place and renames it over it, so
// a link already there is replaced, never written through. Its mode,
// owner and time are set through the open file.
func (r *restorer) file(dir int, base, name string, h *tar.Header, body io.Reader) error {
	dst := r.path(name)
	var st unix.Stat_t
	if err := unix.Fstatat(dir, base, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR {
		return fmt.Errorf("%s is a directory", dst)
	}
	tmp, err := rootfolder.TmpName(base + ".restore")
	if err != nil {
		return err
	}
	fd, err := unix.Openat(dir, tmp, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(filepath.Dir(dst), tmp))
	renamed := false
	defer func() {
		if !renamed {
			_ = unix.Unlinkat(dir, tmp, 0)
		}
	}()
	_, err = io.Copy(f, body)
	if err == nil && testHookRestore != nil {
		testHookRestore("temp", f.Name())
	}
	if err == nil {
		err = f.Chmod(r.mode(name, h))
	}
	if err == nil {
		err = r.fchown(f, name, h)
	}
	if err == nil {
		tv := unix.NsecToTimeval(h.ModTime.UnixNano())
		err = unix.Futimes(int(f.Fd()), []unix.Timeval{tv, tv})
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := unix.Renameat(dir, tmp, dir, base); err != nil {
		return err
	}
	renamed = true
	return nil
}

// hardLink links base in dir to an earlier file of the archive, reached
// as every entry is (openParent). In sandboxd's user's folders in
// privilege mode split it writes a copy instead: the root helper leaves a
// file with two names root's (handing it over could hand over a file root
// reaches by another name), and sandboxd could not open it.
func (r *restorer) hardLink(dir int, base, name string, h *tar.Header) error {
	target, _ := entryName(h.Linkname)
	tdir, tbase, err := r.openParent(target)
	if err != nil {
		return err
	}
	defer unix.Close(tdir)
	if r.agentOwned(name) {
		fd, err := unix.Openat(tdir, tbase, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open %s without following a link: %w", r.path(target), err)
		}
		src := os.NewFile(uintptr(fd), r.path(target))
		defer src.Close()
		if st, err := src.Stat(); err != nil || !st.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file of the backup", r.path(target))
		}
		return r.file(dir, base, name, h, src)
	}
	if err := r.clear(dir, base, r.path(name)); err != nil {
		return err
	}
	return unix.Linkat(tdir, tbase, dir, base, 0)
}

// clear removes base from dir unless it is a folder, which is refused.
func (r *restorer) clear(dir int, base, dst string) error {
	var st unix.Stat_t
	err := unix.Fstatat(dir, base, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFDIR {
		return fmt.Errorf("%s is a directory", dst)
	}
	if err := unix.Unlinkat(dir, base, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

// mode is the mode an entry gets: the archive's, but for the server-key
// files sandboxd reads alone (0600) and, in privilege mode split, what
// lands in sandboxd's user's folders: there the archive's modes were that
// user's to choose, so group and others get nothing, as sandboxd makes
// its folders (0700).
func (r *restorer) mode(name string, h *tar.Header) fs.FileMode {
	switch name {
	case archiveLib + "/" + wrappedName, archiveLib + "/" + ringName:
		return 0o600
	}
	mode := fs.FileMode(h.Mode).Perm()
	if r.agentOwned(name) {
		mode &= 0o700
	}
	return mode
}

// owner reports whether name gets the archive's owner, as tar gives it
// as root. In privilege mode split what lands in sandboxd's user's
// folders stays root's: the archive's numbers are the backed-up node's,
// whose sandboxd user may have had another uid, one that may be someone
// else's here. `aerolvm-rootd agent-folders`, which runs before every
// sandboxd start, gives root's files there to this node's sandboxd user,
// following no link.
func (r *restorer) owner(name string) bool {
	return r.o.euid() == 0 && !r.agentOwned(name)
}

func (r *restorer) fchown(f *os.File, name string, h *tar.Header) error {
	if !r.owner(name) {
		return nil
	}
	if r.o.chown != nil {
		return r.o.chown(r.path(name), h.Uid, h.Gid)
	}
	return f.Chown(h.Uid, h.Gid)
}

// agentOwned reports whether name is in one of sandboxd's user's folders
// in privilege mode split.
func (r *restorer) agentOwned(name string) bool {
	if !r.split {
		return false
	}
	for _, t := range r.agent {
		if under(name, t) {
			return true
		}
	}
	return false
}

// agentTrees are the archive names of the folders sandboxd's user owns in
// privilege mode split that a restore writes into, from the settings of
// each node given: the data folder (the archive's var/lib/sandboxd) and
// the certificate folders in the config folder, as `aerolvm-rootd
// agent-folders` reads them (internal/rootd). The config folder itself is
// root's, and so are its other folders (secrets, the operator's
// dashboards).
func agentTrees(nodes ...Node) []string {
	trees := []string{archiveLib, archiveConfig + "/tls"}
	for _, n := range nodes {
		for _, dir := range []string{n.ClusterTLSDir, n.ClusterCADir} {
			if !filepath.IsAbs(dir) {
				continue
			}
			if rel, ok := strings.CutPrefix(filepath.Clean(dir), DefaultConfigDir+"/"); ok {
				trees = append(trees, archiveConfig+"/"+filepath.ToSlash(rel))
			}
		}
	}
	return trees
}

func removeNonDir(p string) error {
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("%s is a directory", p)
	}
	return os.Remove(p)
}
