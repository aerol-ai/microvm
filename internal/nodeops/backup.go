package nodeops

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/internal/raftlogdir"
)

// The archive layout. The names are fixed whatever the source paths were,
// as the scripts made them, and restore puts each back at the same place.
const (
	manifestName  = "MANIFEST.txt"
	archiveLib    = "var/lib/sandboxd"
	archiveDB     = archiveLib + "/state.db"
	archiveRaft   = archiveLib + "/raft"
	archiveConfig = "etc/sandboxd"
	keyName       = "credential_encryption.key"
	ringName      = keyName + ".ring"
	wrappedName   = keyName + ".wrapped"
)

// ErrUsage marks a bad command line (exit status 2), as the scripts had.
var ErrUsage = errors.New("usage")

// usageError is an ErrUsage that reads as its message alone.
type usageError string

func (e usageError) Error() string        { return string(e) }
func (e usageError) Is(target error) bool { return target == ErrUsage }

func usageErr(format string, args ...any) error {
	return usageError(fmt.Sprintf(format, args...))
}

// BackupOptions is one `sandboxd backup`. Empty source paths take the
// node's own, read from its env files (ReadNode).
type BackupOptions struct {
	Output     string
	ConfigDir  string
	StateDB    string
	RaftDir    string
	WrappedKey string
	KeyRing    string
	KeyFile    string
	// Stop stops sandboxd for the copy and starts it again afterwards, when
	// it was running. The database copy is consistent either way (VACUUM
	// INTO); the Raft files are only copied at rest with Stop.
	Stop bool
	// Version is the running sandboxd's, for the manifest.
	Version string
	Host    Host
	Out     io.Writer

	now      func() time.Time
	hostname func() (string, error)
}

// BackupResult says what one backup wrote and how long it took.
type BackupResult struct {
	Output string
	Bytes  int64
	// DBBytes and DBTook are the database copy's size and its VACUUM INTO
	// time; zero when the node has no database.
	DBBytes int64
	DBTook  time.Duration
	Took    time.Duration
	Custody string
}

// envKeyLine is a plaintext server key line in an env file; with wrapped
// custody none may leave the node in a backup.
var envKeyLine = regexp.MustCompile(`^[[:space:]]*SB_CREDENTIAL_ENCRYPTION_KEY[[:space:]]*=`)

// source is one thing the archive carries: a file or a tree.
type source struct {
	name string // archive name, without "./"
	path string // what is read
	// content is read from here instead of path when set (the database
	// copy); the header still describes path.
	content string
	tree    bool
	// skip is a file at the top of a tree the archive leaves out.
	skip string
}

// Backup writes the node's database, Raft data, config directory and server
// key to one gzipped tar, mode 0600, replaced in one rename. The database
// is copied with VACUUM INTO, so a backup taken while sandboxd runs is
// consistent and holds the writes still in the WAL.
func Backup(ctx context.Context, o BackupOptions) (res BackupResult, err error) {
	o.defaults()
	start := o.now()
	if o.Output == "" {
		return res, usageErr("--output is required")
	}
	node, err := ReadNode(o.ConfigDir)
	if err != nil {
		return res, err
	}
	o.ConfigDir = node.ConfigDir
	fill(&o.StateDB, node.StateDB)
	fill(&o.RaftDir, node.RaftDir)
	fill(&o.KeyFile, node.KeyFile)
	fill(&o.KeyRing, node.KeyRing)
	fill(&o.WrappedKey, node.WrappedKey)
	out, err := filepath.Abs(o.Output)
	if err != nil {
		return res, err
	}
	// A log SB_RAFT_WAL_DIR put on a disk of its own goes into the archive
	// where it is by default, raft/raft-wal, and the record naming that disk
	// stays out: archive names are fixed (see archiveLib), so a restore lands
	// the default layout. In privilege mode split the record is written by
	// sandboxd's user, so the log's folder comes only from SB_RAFT_WAL_DIR
	// in the env files, and a record naming another is refused
	// (raftlogdir.Trusted).
	walDir, err := raftlogdir.Trusted(o.RaftDir, node.RaftWALDir, node.Split)
	if err != nil {
		return res, err
	}
	for _, dir := range []string{o.RaftDir, walDir, o.ConfigDir} {
		if dir != "" && within(out, dir) {
			return res, usageErr("--output %s is inside %s, which the backup copies", out, dir)
		}
	}

	if o.Stop && o.Host.UnitActive(ctx, sandboxdUnit) {
		fmt.Fprintln(o.Out, "stopping sandboxd for the backup")
		if err = o.Host.StopUnit(ctx, sandboxdUnit); err != nil {
			return res, err
		}
		defer func() {
			// Started again whatever happened: a failed backup must not
			// leave the node down.
			fmt.Fprintln(o.Out, "starting sandboxd again")
			if serr := o.Host.StartUnit(context.WithoutCancel(ctx), sandboxdUnit); serr != nil && err == nil {
				err = serr
			}
		}()
	}

	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return res, err
	}
	work, err := os.MkdirTemp(filepath.Dir(out), ".sandboxd-backup-")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(work)

	host, _ := o.hostname()
	var m manifest
	m.add("created_utc", start.UTC().Format(time.RFC3339))
	m.add("hostname", host)
	m.add("state_db", o.StateDB)
	m.add("raft_dir", o.RaftDir)
	m.add("config_dir", o.ConfigDir)

	var srcs []source
	if exists(o.StateDB) {
		dbCopy := filepath.Join(work, "state.db")
		t0 := o.now()
		vacuum := nodeupgrade.VacuumInto
		if node.Split {
			vacuum = nodeupgrade.VacuumIntoNoFollow
		}
		if err := vacuum(ctx, o.StateDB, dbCopy); err != nil {
			return res, fmt.Errorf("copy %s: %w", o.StateDB, err)
		}
		res.DBTook = o.now().Sub(t0)
		res.DBBytes = fileSize(dbCopy)
		fmt.Fprintf(o.Out, "backed up %s (%s) with VACUUM INTO in %s\n", o.StateDB, humanBytes(res.DBBytes), res.DBTook.Round(time.Millisecond))
		srcs = append(srcs, source{name: archiveDB, path: o.StateDB, content: dbCopy})
		m.add("included", o.StateDB)
	} else {
		m.add("missing", o.StateDB)
	}
	srcs = m.tree(srcs, archiveRaft, o.RaftDir, !node.Split)
	if walDir != "" {
		if n := len(srcs); n > 0 && srcs[n-1].name == archiveRaft {
			srcs[n-1].skip = raftlogdir.LocationFile
		}
		m.add("raft_wal_dir", walDir)
		srcs = m.tree(srcs, archiveRaft+"/"+raftlogdir.DefaultName, walDir, !node.Split)
	}
	srcs = m.tree(srcs, archiveConfig, o.ConfigDir, true)
	if exists(o.RaftDir) && !o.Stop && o.Host.UnitActive(ctx, sandboxdUnit) {
		fmt.Fprintf(o.Out, "note: %s is copied while sandboxd runs; pass --stop for a copy at rest\n", o.RaftDir)
	}

	// Key custody (plans/customer-key-custody.md §3, eng D24). With custody
	// "wrapped" the server key exists only wrapped by the key store: the
	// archive takes the wrapped file and no plaintext key line from the env
	// files, and a restore needs the key store reachable. With custody
	// "file" the database's sealed values open only with this node's key,
	// so a restore onto a fresh machine needs the key file and, after a
	// rotation, the ring. Both are plaintext: the archive is a secret.
	res.Custody = node.Custody
	if res.Custody == "" {
		res.Custody = "file"
	}
	m.add("key_custody", res.Custody)
	wrapped := res.Custody == "wrapped"
	if wrapped {
		srcs = m.file(srcs, archiveLib+"/"+wrappedName, o.WrappedKey, true)
	} else {
		srcs = m.file(srcs, archiveLib+"/"+keyName, o.KeyFile, false)
		srcs = m.file(srcs, archiveLib+"/"+ringName, o.KeyRing, false)
	}
	m.add("sandboxd_version", o.Version)
	if res.DBBytes > 0 {
		m.add("state_db_copy", "vacuum_into")
		m.add("state_db_bytes", fmt.Sprint(res.DBBytes))
		m.add("state_db_copy_ms", fmt.Sprint(res.DBTook.Milliseconds()))
	}

	w := &archiveWriter{now: start, dirs: map[string]bool{}, stripEnvKey: wrapped}
	if node.Split {
		w.agentData = filepath.Dir(o.StateDB)
	}
	n, err := w.write(out, m.bytes(), srcs)
	if err != nil {
		return res, err
	}
	res.Output, res.Bytes, res.Took = out, n, o.now().Sub(start)
	fmt.Fprintf(o.Out, "wrote %s (%s) in %s\n", out, humanBytes(n), res.Took.Round(time.Millisecond))
	return res, nil
}

func (o *BackupOptions) defaults() {
	if o.Out == nil {
		o.Out = io.Discard
	}
	if o.now == nil {
		o.now = time.Now
	}
	if o.hostname == nil {
		o.hostname = os.Hostname
	}
}

func fill(dst *string, def string) {
	if *dst == "" {
		*dst = def
	}
}

// manifest is MANIFEST.txt: key=value lines, in the scripts' order.
type manifest struct{ buf bytes.Buffer }

func (m *manifest) add(k, v string) { fmt.Fprintf(&m.buf, "%s=%s\n", k, v) }
func (m *manifest) bytes() []byte   { return m.buf.Bytes() }

func (m *manifest) tree(srcs []source, name, path string, follow bool) []source {
	if !exists(path) {
		m.add("missing", path)
		return srcs
	}
	m.add("included", path)
	// A tree reached through a symlink (/etc/sandboxd on another disk) is
	// backed up as what it points to; the link alone would restore empty.
	// In privilege mode split only the config folder, root's, is followed:
	// sandboxd's user owns the others' folder and may have left the link.
	if real, err := filepath.EvalSymlinks(path); err == nil && follow {
		path = real
	}
	return append(srcs, source{name: name, path: path, tree: true})
}

// file adds a single file. A key file the node does not have is not worth
// a "missing" line unless the custody needs it (the wrapped file).
func (m *manifest) file(srcs []source, name, path string, required bool) []source {
	if !exists(path) {
		if required {
			m.add("missing", path)
		}
		return srcs
	}
	m.add("included", path)
	return append(srcs, source{name: name, path: path})
}

// archiveWriter streams the sources into a tar.gz.
type archiveWriter struct {
	tw          *tar.Writer
	now         time.Time
	dirs        map[string]bool
	stripEnvKey bool
	// agentData, set in privilege mode split, is sandboxd's data folder:
	// every source is then read through an os.Root (splitSource).
	agentData string
}

func (w *archiveWriter) write(out string, manifest []byte, srcs []source) (int64, error) {
	f, err := os.CreateTemp(filepath.Dir(out), "."+filepath.Base(out)+".tmp-")
	if err != nil {
		return 0, err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return 0, err
	}
	bw := bufio.NewWriterSize(f, 1<<20)
	gz := gzip.NewWriter(bw)
	w.tw = tar.NewWriter(gz)
	err = w.entries(manifest, srcs)
	if err == nil {
		err = w.tw.Close()
	}
	if err == nil {
		err = gz.Close()
	}
	if err == nil {
		err = bw.Flush()
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, out); err != nil {
		return 0, err
	}
	syncDir(filepath.Dir(out))
	return fileSize(out), nil
}

func (w *archiveWriter) entries(manifest []byte, srcs []source) error {
	if err := w.dir(""); err != nil {
		return err
	}
	if err := w.tw.WriteHeader(&tar.Header{Name: "./" + manifestName, Typeflag: tar.TypeReg, Mode: 0o644,
		Size: int64(len(manifest)), ModTime: w.now}); err != nil {
		return err
	}
	if _, err := w.tw.Write(manifest); err != nil {
		return err
	}
	for _, s := range srcs {
		if err := w.parents(s.name); err != nil {
			return err
		}
		if w.agentData != "" {
			if err := w.splitSource(s); err != nil {
				return err
			}
			continue
		}
		if !s.tree {
			if err := w.entry(osView{}, s.name, s.path, s.content); err != nil {
				return err
			}
			continue
		}
		err := filepath.WalkDir(s.path, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// A file Raft removed between the listing and the read.
				if errors.Is(err, fs.ErrNotExist) && path != s.path {
					return nil
				}
				return err
			}
			rel, err := filepath.Rel(s.path, path)
			if err != nil {
				return err
			}
			if s.skip != "" && rel == s.skip {
				return nil
			}
			name := s.name
			if rel != "." {
				name += "/" + filepath.ToSlash(rel)
			}
			return w.entry(osView{}, name, path, "")
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// parents writes the directories above name the archive has not had yet,
// as plain 0755 directories (the scripts made them with mkdir -p).
func (w *archiveWriter) parents(name string) error {
	parts := strings.Split(name, "/")
	for i := 1; i < len(parts); i++ {
		if err := w.dir(strings.Join(parts[:i], "/")); err != nil {
			return err
		}
	}
	return nil
}

func (w *archiveWriter) dir(name string) error {
	if w.dirs[name] {
		return nil
	}
	w.dirs[name] = true
	return w.tw.WriteHeader(&tar.Header{Name: dirName(name), Typeflag: tar.TypeDir, Mode: 0o755, ModTime: w.now})
}

func dirName(name string) string {
	if name == "" {
		return "./"
	}
	return "./" + name + "/"
}

// splitSource writes one source in privilege mode split. sandboxd's user
// owns the data folder and the certificate folders there, and could swap
// any name in them for a link, so each source is read through an os.Root
// opened on the data folder (or on the folder that holds the source, when
// it is elsewhere): Root refuses every path and link that leads out of the
// folder it was opened on, with no race between a look and a read. A link
// is still written as a link, as in single.
func (w *archiveWriter) splitSource(s source) error {
	if s.content != "" {
		// The database copy, made with nofollow; the header only names it.
		return w.entry(lstatView{}, s.name, s.path, s.content)
	}
	anchor := filepath.Dir(s.path)
	switch {
	case within(s.path, w.agentData):
		anchor = w.agentData
	case s.name == archiveConfig:
		// The config folder is root's (its link, if any, was followed).
		anchor = s.path
	}
	top, err := os.OpenRoot(anchor)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer top.Close()
	rel, err := filepath.Rel(anchor, s.path)
	if err != nil {
		return err
	}
	if !s.tree {
		return w.entry(rootView{top}, s.name, rel, "")
	}
	if fi, err := top.Lstat(rel); err != nil || !fi.IsDir() {
		// Gone, or a link: written as what it is, never walked.
		return w.entry(rootView{top}, s.name, rel, "")
	}
	tree, err := top.OpenRoot(rel)
	if err != nil {
		return err
	}
	defer tree.Close()
	return fs.WalkDir(tree.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && path != "." {
				return nil
			}
			return err
		}
		if s.skip != "" && path == filepath.ToSlash(s.skip) {
			return nil
		}
		name := s.name
		if path != "." {
			name += "/" + path
		}
		return w.entry(rootView{tree}, name, path, "")
	})
}

// testHookBeforeOpen, when set, runs between entry's look at a file and
// its open: tests swap the file there.
var testHookBeforeOpen func(name string)

// fileView is how entry reads a path: by name on the host (osView), or
// inside an os.Root (rootView), which keeps every step in its folder.
type fileView interface {
	Lstat(name string) (fs.FileInfo, error)
	Stat(name string) (fs.FileInfo, error)
	Readlink(name string) (string, error)
	Open(name string) (*os.File, error)
}

type osView struct{}

func (osView) Lstat(name string) (fs.FileInfo, error) { return os.Lstat(name) }
func (osView) Stat(name string) (fs.FileInfo, error)  { return os.Stat(name) }
func (osView) Readlink(name string) (string, error)   { return os.Readlink(name) }
func (osView) Open(name string) (*os.File, error)     { return os.Open(name) }

// lstatView is osView whose Stat follows no link.
type lstatView struct{ osView }

func (lstatView) Stat(name string) (fs.FileInfo, error) { return os.Lstat(name) }

type rootView struct{ r *os.Root }

func (v rootView) Lstat(name string) (fs.FileInfo, error) { return v.r.Lstat(name) }
func (v rootView) Stat(name string) (fs.FileInfo, error)  { return v.r.Lstat(name) }
func (v rootView) Readlink(name string) (string, error)   { return v.r.Readlink(name) }
func (v rootView) Open(name string) (*os.File, error)     { return v.r.Open(name) }

// entry writes one path as name, read through v. content, when set, is read
// in place of path (the database copy); the header keeps path's owner, mode
// and time.
func (w *archiveWriter) entry(v fileView, name, path, content string) error {
	stat := v.Lstat
	if content != "" {
		// The database copy stands in for path, whatever path is.
		stat = v.Stat
	}
	fi, err := stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	link := ""
	switch {
	case fi.Mode().IsDir(), fi.Mode().IsRegular():
	case fi.Mode()&fs.ModeSymlink != 0:
		if link, err = v.Readlink(path); err != nil {
			return err
		}
	default:
		// A socket or a device has no place in a backup; tar cannot carry
		// a socket at all.
		return nil
	}
	hdr, err := tar.FileInfoHeader(fi, link)
	if err != nil {
		return err
	}
	// Numeric owners only: a restore puts back the IDs, as tar does as root.
	hdr.Uname, hdr.Gname = "", ""
	if fi.IsDir() {
		hdr.Name = dirName(name)
		w.dirs[name] = true
		return w.tw.WriteHeader(hdr)
	}
	hdr.Name = "./" + name
	if !fi.Mode().IsRegular() {
		return w.tw.WriteHeader(hdr)
	}
	open, src := v.Open, path
	if content != "" {
		open, src = os.Open, content
	} else if testHookBeforeOpen != nil {
		testHookBeforeOpen(name)
	}
	f, err := open(src)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && content == "" {
			return nil
		}
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	// In privilege mode split the file read must be the one looked at.
	// os.Root keeps a swap between the two inside the folder, but a swap
	// for a link to another file there would put that file in the archive
	// under this one's name.
	if w.agentData != "" && content == "" && !os.SameFile(fi, st) {
		return fmt.Errorf("%s changed between the backup's look at it and its read; run the backup again", name)
	}
	hdr.Size = st.Size()
	var body io.Reader = f
	if w.stripEnvKey && isTopLevelEnv(name) {
		raw, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		clean := stripEnvKeyLines(raw)
		hdr.Size = int64(len(clean))
		body = bytes.NewReader(clean)
	}
	if err := w.tw.WriteHeader(hdr); err != nil {
		return err
	}
	n, err := io.CopyN(w.tw, body, hdr.Size)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%s shrank from %d to %d bytes while it was copied; run the backup with --stop", path, hdr.Size, n)
		}
		return err
	}
	return nil
}

// isTopLevelEnv is an env file directly in the config directory, the ones
// the script scrubbed (etc/sandboxd/*.env).
func isTopLevelEnv(name string) bool {
	rest, ok := strings.CutPrefix(name, archiveConfig+"/")
	return ok && !strings.Contains(rest, "/") && strings.HasSuffix(rest, ".env")
}

func stripEnvKeyLines(raw []byte) []byte {
	var out bytes.Buffer
	for _, line := range bytes.SplitAfter(raw, []byte("\n")) {
		if envKeyLine.Match(line) {
			continue
		}
		out.Write(line)
	}
	return out.Bytes()
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// within reports whether path is dir or below it.
func within(path, dir string) bool {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(abs, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
