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
	"time"

	"github.com/aerol-ai/microvm/internal/raftlogdir"
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

	now        func() time.Time
	euid       func() int
	lchown     func(path string, uid, gid int) error
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
	if err := os.MkdirAll(root, 0o755); err != nil {
		return res, err
	}

	r := &restorer{o: &o, root: root, stamp: o.now().UTC().Format(restoreStamp)}
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
	if p := r.path(key(wrappedName)); exists(p) {
		// Custody "wrapped": sandboxd unwraps this at boot through the key
		// store, which must be reachable. A backup taken before a key
		// version was retired no longer opens once that version is gone.
		_ = os.Chmod(p, 0o600)
		fmt.Fprintln(o.Out, "the server key is wrapped: run `sandboxd key verify` with the key store reachable before starting sandboxd")
	}
	if p := r.path(key(ringName)); exists(p) {
		_ = os.Chmod(p, 0o600)
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
	if o.lchown == nil {
		o.lchown = os.Lchown
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
type archiveIndex struct{ names map[string]bool }

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
	idx := &archiveIndex{names: map[string]bool{}}
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
	if err := r.noLinkAbove(name); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	mode := fs.FileMode(h.Mode).Perm()
	switch h.Typeflag {
	case tar.TypeDir:
		// Stat, not Lstat: a config directory an operator linked to
		// another disk stays a link.
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
		return r.chown(dst, h)
	case tar.TypeSymlink:
		if err := removeNonDir(dst); err != nil {
			return err
		}
		if err := os.Symlink(h.Linkname, dst); err != nil {
			return err
		}
		return r.chown(dst, h)
	case tar.TypeLink:
		target, _ := entryName(h.Linkname)
		if err := removeNonDir(dst); err != nil {
			return err
		}
		return os.Link(r.path(target), dst)
	}
	// A regular file: written beside its place and renamed over it, so a
	// link already there is replaced, never written through.
	if fi, err := os.Lstat(dst); err == nil && fi.IsDir() {
		return fmt.Errorf("%s is a directory", dst)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".restore-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	_, err = io.Copy(tmp, body)
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = r.chown(tmpName, h)
	}
	if err == nil {
		err = os.Chtimes(tmpName, h.ModTime, h.ModTime)
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
}

// noLinkAbove refuses to write through a link that sits inside the config
// directory or below the state directory on the target. The roots
// themselves may be links (an operator's /var/lib/sandboxd on a data
// disk); a link below them would send the write somewhere else.
func (r *restorer) noLinkAbove(name string) error {
	anchor := archiveLib
	if under(name, archiveConfig) {
		anchor = archiveConfig
	}
	for p := path.Dir(name); p != anchor && p != "." && strings.HasPrefix(p, anchor+"/"); p = path.Dir(p) {
		fi, err := os.Lstat(r.path(p))
		if err == nil && fi.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a link; refusing to write %s through it", r.path(p), name)
		}
	}
	return nil
}

// chown puts the archive's owner back when running as root, as tar does.
func (r *restorer) chown(p string, h *tar.Header) error {
	if r.o.euid() != 0 {
		return nil
	}
	return r.o.lchown(p, h.Uid, h.Gid)
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
