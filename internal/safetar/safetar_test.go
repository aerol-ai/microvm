package safetar

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// entry is one archive member for archive().
type entry struct {
	name     string
	typeflag byte
	body     string
	link     string
	mode     int64
}

func file(name, body string) entry {
	return entry{name: name, typeflag: tar.TypeReg, body: body, mode: 0o644}
}
func dir(name string) entry { return entry{name: name, typeflag: tar.TypeDir, mode: 0o755} }
func symlink(name, target string) entry {
	return entry{name: name, typeflag: tar.TypeSymlink, link: target}
}

func archive(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Linkname: e.link, Mode: e.mode, ModTime: time.Unix(1700000000, 0)}
		if e.typeflag == tar.TypeXGlobalHeader {
			hdr = &tar.Header{Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": "global"}}
		}
		if e.typeflag == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.body != "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(data)
	_ = zw.Close()
	return buf.Bytes()
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// sandbox is a target folder and an "outside" folder next to it holding a
// file an escape would overwrite.
type sandbox struct {
	dest, outside, victim string
}

func newSandbox(t *testing.T) sandbox {
	t.Helper()
	base := t.TempDir()
	s := sandbox{dest: filepath.Join(base, "dest"), outside: filepath.Join(base, "outside")}
	for _, d := range []string{s.dest, s.outside} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s.victim = filepath.Join(s.outside, "victim")
	if err := os.WriteFile(s.victim, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s sandbox) assertOutsideUntouched(t *testing.T) {
	t.Helper()
	if got := read(t, s.victim); got != "untouched" {
		t.Fatalf("the file outside the folder was changed: %q", got)
	}
	entries, err := os.ReadDir(s.outside)
	if err != nil || len(entries) != 1 {
		t.Fatalf("the outside folder gained files: %v %v", entries, err)
	}
	parent, _ := os.ReadDir(filepath.Dir(s.dest))
	if len(parent) != 2 {
		t.Fatalf("files appeared next to the folder: %v", parent)
	}
}

func TestExtractWritesFilesFoldersAndLinks(t *testing.T) {
	data := archive(t,
		dir("./"),
		dir("src"),
		file("src/main.go", "package main"),
		entry{name: "bin/run.sh", typeflag: tar.TypeReg, body: "#!/bin/sh", mode: 0o4755},
		symlink("src/current", "main.go"),
		symlink("latest", "src"),
		file("latest/through-link.txt", "inside"),
		entry{name: "ro", typeflag: tar.TypeDir, mode: 0o555},
		file("ro/kept.txt", "a read-only folder still gets its contents"),
		entry{name: "pax_global_header", typeflag: tar.TypeXGlobalHeader},
	)
	for _, compressed := range []bool{false, true} {
		dest := filepath.Join(t.TempDir(), "d")
		if err := os.Mkdir(dest, 0o700); err != nil {
			t.Fatal(err)
		}
		payload := data
		if compressed {
			payload = gzipped(t, data)
		}
		res, err := Extract(bytes.NewReader(payload), dest, Limits{MaxEntries: 100, MaxBytes: 1 << 20})
		if err != nil {
			t.Fatalf("gzip=%v: %v", compressed, err)
		}
		if res.Entries != 8 {
			t.Fatalf("entries = %d, want 8", res.Entries)
		}
		if got := read(t, filepath.Join(dest, "src", "through-link.txt")); got != "inside" {
			t.Fatalf("file through an inside symlink = %q", got)
		}
		if target, err := os.Readlink(filepath.Join(dest, "src", "current")); err != nil || target != "main.go" {
			t.Fatalf("symlink = %q, %v", target, err)
		}
		info, err := os.Stat(filepath.Join(dest, "bin", "run.sh"))
		if err != nil || info.Mode() != 0o755 {
			t.Fatalf("file mode = %v (%v), want 0755 with setuid dropped", info.Mode(), err)
		}
		if info, err := os.Stat(filepath.Join(dest, "ro")); err != nil || info.Mode().Perm() != 0o555 {
			t.Fatalf("folder mode = %v, %v", info.Mode(), err)
		}
		_ = os.Chmod(filepath.Join(dest, "ro"), 0o755)
		if info, err := os.Stat(dest); err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("the target folder's own mode changed: %v", info.Mode())
		}
		if mtime := info.ModTime(); !mtime.Equal(time.Unix(1700000000, 0)) {
			t.Fatalf("file mtime = %v, want the archive's", mtime)
		}
		left, _ := filepath.Glob(filepath.Join(dest, "*", ".tar-*"))
		if len(left) != 0 {
			t.Fatalf("temp files left: %v", left)
		}
	}
}

// Each hostile archive is refused with ErrUnsafe and writes nothing outside
// the folder.
func TestExtractRefusesHostileArchives(t *testing.T) {
	cases := []struct {
		name    string
		entries []entry
		// prepare runs against the fresh target before extraction.
		prepare func(t *testing.T, s sandbox)
		bad     string
	}{
		{name: "dot-dot", entries: []entry{file("../victim-sibling", "x")}, bad: "../victim-sibling"},
		{name: "dot-dot inside the path", entries: []entry{file("a/../../outside/victim", "x")}, bad: "a/../../outside/victim"},
		{name: "dot-dot that stays inside", entries: []entry{file("a/../b", "x")}, bad: "a/../b"},
		{name: "absolute path", entries: []entry{file("/etc/passwd", "x")}, bad: "/etc/passwd"},
		{name: "symlink to an absolute path", entries: []entry{symlink("etc", "/etc")}, bad: "etc"},
		{name: "symlink out by dot-dot", entries: []entry{symlink("up", "../outside")}, bad: "up"},
		{
			// Each link looks harmless by its name: l1 points at the folder
			// itself, and l2's target "../outside" read from "d/l1" stays
			// inside lexically. Followed, l2 is at the folder's top and
			// leaves it. Only resolving the link (os.Root) sees that.
			name:    "two-step symlink chain",
			entries: []entry{dir("d"), symlink("d/l1", ".."), symlink("d/l1/l2", "../outside"), file("d/l1/l2/victim", "x")},
			bad:     "d/l1/l2",
		},
		{
			name:    "symlink then a file through it",
			entries: []entry{symlink("s", "../outside"), file("s/victim", "x")},
			bad:     "s",
		},
		{
			// A symlink that was already in the folder, pointing outside: a
			// file "through" it must not land outside.
			name: "file through a pre-existing outside symlink",
			prepare: func(t *testing.T, s sandbox) {
				if err := os.Symlink(s.outside, filepath.Join(s.dest, "evil")); err != nil {
					t.Fatal(err)
				}
			},
			entries: []entry{file("evil/victim", "x")},
			bad:     "evil/victim",
		},
		{name: "hard link", entries: []entry{file("a", "x"), {name: "b", typeflag: tar.TypeLink, link: "a"}}, bad: "b"},
		{name: "hard link to outside", entries: []entry{{name: "h", typeflag: tar.TypeLink, link: "../outside/victim"}}, bad: "h"},
		{name: "character device", entries: []entry{{name: "null", typeflag: tar.TypeChar}}, bad: "null"},
		{name: "block device", entries: []entry{{name: "sda", typeflag: tar.TypeBlock}}, bad: "sda"},
		{name: "fifo", entries: []entry{{name: "pipe", typeflag: tar.TypeFifo}}, bad: "pipe"},
		{name: "unknown type", entries: []entry{{name: "odd", typeflag: 'Z'}}, bad: "odd"},
		{name: "empty symlink target", entries: []entry{symlink("nothing", "")}, bad: "nothing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newSandbox(t)
			if tc.prepare != nil {
				tc.prepare(t, s)
			}
			_, err := Extract(bytes.NewReader(archive(t, tc.entries...)), s.dest, Limits{})
			var entryErr *EntryError
			if !errors.As(err, &entryErr) || entryErr.Entry != tc.bad {
				t.Fatalf("err = %v, want a refusal naming %q", err, tc.bad)
			}
			if !errors.Is(err, ErrUnsafe) {
				t.Fatalf("err = %v, want ErrUnsafe", err)
			}
			s.assertOutsideUntouched(t)
		})
	}
}

// A hard link already inside the folder, to a file outside it (pnpm's
// node_modules has many): an archive entry with that name gets a new file,
// and the outside file keeps its content.
func TestExtractDoesNotWriteThroughPreExistingHardLink(t *testing.T) {
	s := newSandbox(t)
	inside := filepath.Join(s.dest, "linked")
	if err := os.Link(s.victim, inside); err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(bytes.NewReader(archive(t, file("linked", "new content"))), s.dest, Limits{}); err != nil {
		t.Fatal(err)
	}
	if got := read(t, inside); got != "new content" {
		t.Fatalf("inside = %q", got)
	}
	s.assertOutsideUntouched(t)
	var a, b syscall.Stat_t
	_ = syscall.Stat(inside, &a)
	_ = syscall.Stat(s.victim, &b)
	if a.Ino == b.Ino {
		t.Fatal("the entry was written into the shared inode")
	}
}

func TestExtractReplacesFilesAndLinks(t *testing.T) {
	s := newSandbox(t)
	if err := os.WriteFile(filepath.Join(s.dest, "f"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A symlink in the folder to a file outside: an entry of that name
	// replaces the link, never writes the file it names.
	if err := os.Symlink(s.victim, filepath.Join(s.dest, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(s.dest, "full"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.dest, "full", "x"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Extract(bytes.NewReader(archive(t, file("f", "new"), file("link", "replaced"), symlink("f2", "f"))), s.dest, Limits{})
	if err != nil || res.Entries != 3 {
		t.Fatalf("extract = %+v, %v", res, err)
	}
	if read(t, filepath.Join(s.dest, "f")) != "new" || read(t, filepath.Join(s.dest, "link")) != "replaced" {
		t.Fatal("entries did not replace what was there")
	}
	if info, _ := os.Lstat(filepath.Join(s.dest, "link")); info.Mode()&fs.ModeSymlink != 0 {
		t.Fatal("link still a symlink")
	}
	s.assertOutsideUntouched(t)
	// A file entry cannot replace a folder, and a symlink entry cannot
	// replace a folder with contents.
	for _, e := range []entry{file("full", "x"), symlink("full", "f")} {
		if _, err := Extract(bytes.NewReader(archive(t, e)), s.dest, Limits{}); err == nil {
			t.Fatalf("%s %q replaced a folder", string(e.typeflag), e.name)
		}
	}
}

func TestExtractLimits(t *testing.T) {
	s := newSandbox(t)
	_, err := Extract(bytes.NewReader(archive(t, file("a", "1"), file("b", "2"), file("c", "3"))), s.dest, Limits{MaxEntries: 2})
	var entryErr *EntryError
	if !errors.Is(err, ErrTooLarge) || !errors.As(err, &entryErr) || entryErr.Entry != "c" || entryErr.Written != 2 {
		t.Fatalf("too many entries = %v", err)
	}
	s = newSandbox(t)
	_, err = Extract(bytes.NewReader(archive(t, file("a", "12345"), file("b", "123456"))), s.dest, Limits{MaxBytes: 10})
	if !errors.Is(err, ErrTooLarge) || !errors.As(err, &entryErr) || entryErr.Entry != "b" || entryErr.Written != 1 {
		t.Fatalf("too many bytes = %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.dest, "b")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("the entry over the byte cap was written")
	}
	// A gzip bomb is capped on what it expands to, not what it sends.
	s = newSandbox(t)
	bomb := gzipped(t, archive(t, file("zeros", strings.Repeat("\x00", 1<<20))))
	if _, err := Extract(bytes.NewReader(bomb), s.dest, Limits{MaxBytes: 1 << 10}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("gzip bomb = %v", err)
	}
}

// Owner decision P1: a failure part way keeps what was written, like tar -x,
// and the error names the failing entry and the count written.
func TestExtractFailurePartWayKeepsWhatWasWritten(t *testing.T) {
	s := newSandbox(t)
	_, err := Extract(bytes.NewReader(archive(t, file("one", "1"), dir("two"), file("../three", "3"), file("four", "4"))), s.dest, Limits{})
	var entryErr *EntryError
	if !errors.As(err, &entryErr) || entryErr.Entry != "../three" || entryErr.Written != 2 {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), `"../three"`) || !strings.Contains(err.Error(), "2 entries written") {
		t.Fatalf("message %q does not name the entry and the count", err.Error())
	}
	if read(t, filepath.Join(s.dest, "one")) != "1" {
		t.Fatal("an entry written before the failure was removed")
	}
	if _, err := os.Stat(filepath.Join(s.dest, "four")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("an entry after the failure was written")
	}
}

func TestExtractCorruptArchives(t *testing.T) {
	good := archive(t, file("a", strings.Repeat("x", 2000)))
	cases := map[string][]byte{
		"truncated in a file": good[:1024],
		"not a tar":           []byte(strings.Repeat("not a tar archive ", 64)),
		"bad gzip":            {0x1f, 0x8b, 0x00, 0x01, 0x02},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			s := newSandbox(t)
			_, err := Extract(bytes.NewReader(data), s.dest, Limits{})
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("err = %v, want ErrCorrupt", err)
			}
			left, _ := filepath.Glob(filepath.Join(s.dest, ".tar-*"))
			if len(left) != 0 {
				t.Fatalf("temp files left: %v", left)
			}
		})
	}
	if _, err := Extract(bytes.NewReader(good), filepath.Join(t.TempDir(), "missing"), Limits{}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing folder = %v", err)
	}
}

func TestEntryErrorMessages(t *testing.T) {
	e := &EntryError{Written: 3, Err: ErrCorrupt}
	if !strings.Contains(e.Error(), "3 entries written") || strings.Contains(e.Error(), "entry \"") {
		t.Fatalf("message = %q", e.Error())
	}
	if _, err := entryName(""); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("empty name = %v", err)
	}
	if name, err := entryName("./a//b/"); err != nil || name != filepath.Join("a", "b") {
		t.Fatalf("entryName = %q, %v", name, err)
	}
}

// A link that is dangling or harmless when it is made can lead out of the
// folder once later entries are in: a link it goes through is made after
// it, or a folder on its path is replaced by a link. Extract checks every
// link again at the end, refuses the archive and removes the link.
func TestExtractRechecksLinksAtTheEnd(t *testing.T) {
	cases := []struct {
		name    string
		entries []entry
	}{
		{
			name:    "the link it goes through comes later",
			entries: []entry{symlink("a", "s/c/.."), dir("s"), symlink("s/c", "..")},
		},
		{
			name:    "a folder on its path becomes a link",
			entries: []entry{dir("s"), dir("s/c"), symlink("a", "s/c/.."), symlink("s/c", "..")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newSandbox(t)
			_, err := Extract(bytes.NewReader(archive(t, tc.entries...)), s.dest, Limits{})
			var entryErr *EntryError
			if !errors.As(err, &entryErr) || entryErr.Entry != "a" || !errors.Is(err, ErrUnsafe) {
				t.Fatalf("err = %v, want ErrUnsafe naming %q", err, "a")
			}
			if _, err := os.Lstat(filepath.Join(s.dest, "a")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the link out of the folder was left on disk: %v", err)
			}
			s.assertOutsideUntouched(t)
		})
	}
	// A link that stays dangling is fine, as tar allows it.
	s := newSandbox(t)
	if _, err := Extract(bytes.NewReader(archive(t, symlink("later", "not-there"))), s.dest, Limits{}); err != nil {
		t.Fatalf("a dangling link inside the folder: %v", err)
	}
}
