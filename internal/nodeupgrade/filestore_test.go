package nodeupgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sumOf(b string) string {
	h := sha256.Sum256([]byte(b))
	return hex.EncodeToString(h[:])
}

func TestFileStorePutHasOpen(t *testing.T) {
	s := FileStore{Dir: filepath.Join(t.TempDir(), "files")}
	body := "sandboxd bytes"
	sum := sumOf(body)
	if s.Has(sum) {
		t.Fatal("empty store has the file")
	}
	created, n, err := s.Put(sum, strings.NewReader(body))
	if err != nil || !created || n != int64(len(body)) {
		t.Fatalf("Put = %v %d %v", created, n, err)
	}
	if !s.Has(sum) {
		t.Fatal("Has after Put = false")
	}
	// A repeated upload is a no-op and does not read the body.
	created, n, err = s.Put(sum, iotestErrReader{})
	if err != nil || created || n != int64(len(body)) {
		t.Fatalf("second Put = %v %d %v", created, n, err)
	}
	f, err := s.Open(sum)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(f)
	f.Close()
	if string(got) != body {
		t.Fatalf("Open read %q", got)
	}
	fi, _ := os.Stat(s.Dir)
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("store dir mode %v", fi.Mode().Perm())
	}
}

type iotestErrReader struct{}

func (iotestErrReader) Read([]byte) (int, error) { return 0, errors.New("must not be read") }

func TestFileStoreRefusals(t *testing.T) {
	s := FileStore{Dir: t.TempDir(), MaxBytes: 8}
	for _, bad := range []string{"", "../etc/passwd", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		if _, err := s.Path(bad); !errors.Is(err, ErrBadHash) {
			t.Errorf("Path(%q) err = %v", bad, err)
		}
		if _, _, err := s.Put(bad, strings.NewReader("x")); !errors.Is(err, ErrBadHash) {
			t.Errorf("Put(%q) err = %v", bad, err)
		}
		if _, err := s.Open(bad); !errors.Is(err, ErrBadHash) {
			t.Errorf("Open(%q) err = %v", bad, err)
		}
		if s.Has(bad) {
			t.Errorf("Has(%q) = true", bad)
		}
	}
	// Wrong body for the name: refused, nothing kept.
	if _, _, err := s.Put(sumOf("right"), strings.NewReader("wrong")); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("mismatch err = %v", err)
	}
	// Over the cap: refused, nothing kept.
	big := "123456789"
	if _, _, err := s.Put(sumOf(big), strings.NewReader(big)); err == nil || !strings.Contains(err.Error(), "larger than 8") {
		t.Fatalf("cap err = %v", err)
	}
	entries, _ := os.ReadDir(s.Dir)
	if len(entries) != 0 {
		t.Fatalf("refused puts left files: %v", entries)
	}
	// A read error mid-body leaves nothing either.
	if _, _, err := s.Put(sumOf("x"), iotestErrReader{}); err == nil {
		t.Fatal("read error not returned")
	}
	if entries, _ := os.ReadDir(s.Dir); len(entries) != 0 {
		t.Fatalf("failed put left files: %v", entries)
	}
	// A store dir that cannot be made.
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, nil, 0o600)
	if _, _, err := (FileStore{Dir: filepath.Join(file, "sub")}).Put(sumOf("a"), strings.NewReader("a")); err == nil {
		t.Fatal("put under a file succeeded")
	}
}

// J14: a store that takes uploads caps their total, like the cluster
// leader does: a body that would go past it, or any body once it is full,
// is refused with ErrStoreFull and nothing is kept. A file already there
// still answers without reading the body.
func TestFileStoreTotalCap(t *testing.T) {
	s := FileStore{Dir: t.TempDir(), MaxBytes: 8, MaxTotalBytes: 10}
	if created, _, err := s.Put(sumOf("123456"), strings.NewReader("123456")); err != nil || !created {
		t.Fatalf("first put = %v %v", created, err)
	}
	// 6 + 6 > 10: cut while it streams, though under the per-file cap.
	if _, _, err := s.Put(sumOf("abcdef"), strings.NewReader("abcdef")); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("put past the total = %v", err)
	}
	if created, _, err := s.Put(sumOf("abcd"), strings.NewReader("abcd")); err != nil || !created {
		t.Fatalf("put that fits exactly = %v %v", created, err)
	}
	if _, _, err := s.Put(sumOf("z"), strings.NewReader("z")); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("put into a full store = %v", err)
	}
	if created, n, err := s.Put(sumOf("abcd"), iotestErrReader{}); err != nil || created || n != 4 {
		t.Fatalf("repeat put into a full store = %v %d %v", created, n, err)
	}
	// The per-file cap still wins when it is the smaller one.
	roomy := FileStore{Dir: t.TempDir(), MaxBytes: 4, MaxTotalBytes: 100}
	if _, _, err := roomy.Put(sumOf("123456"), strings.NewReader("123456")); errors.Is(err, ErrStoreFull) || err == nil {
		t.Fatalf("per-file cap = %v", err)
	}
	entries, _ := os.ReadDir(s.Dir)
	if len(entries) != 2 {
		t.Fatalf("refused puts left files: %v", entries)
	}
	if (FileStore{Dir: filepath.Join(t.TempDir(), "missing")}).storedBytes() != 0 {
		t.Fatal("a missing store holds bytes")
	}
}

func TestFileStoreMaterialize(t *testing.T) {
	s := FileStore{Dir: t.TempDir()}
	a, b := "sandboxd", "toolboxd"
	for _, x := range []string{a, b} {
		if _, _, err := s.Put(sumOf(x), strings.NewReader(x)); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(t.TempDir(), "op")
	files := map[string]string{"sandboxd_linux_amd64": sumOf(a), "toolboxd_linux_amd64": sumOf(b)}
	if err := s.Materialize(dir, files); err != nil {
		t.Fatal(err)
	}
	// Again over existing names: still fine.
	if err := s.Materialize(dir, files); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "toolboxd_linux_amd64"))
	if string(got) != b {
		t.Fatalf("materialized %q", got)
	}
	for _, bad := range []map[string]string{
		{"../x": sumOf(a)},
		{"..": sumOf(a)},
		{"": sumOf(a)},
		{"sandboxd": "nothex"},
		{"sandboxd": sumOf("missing")},
	} {
		if err := s.Materialize(dir, bad); err == nil {
			t.Errorf("Materialize(%v) succeeded", bad)
		}
	}
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, nil, 0o600)
	if err := s.Materialize(filepath.Join(file, "sub"), files); err == nil {
		t.Fatal("materialize under a file succeeded")
	}
}

// The copy fallback (no hard link across file systems) checks the hash, so
// a store file changed on disk is never handed to the upgrader.
func TestFileStoreMaterializeCopyChecksTheHash(t *testing.T) {
	s := FileStore{Dir: t.TempDir()}
	sum := sumOf("good")
	if _, _, err := s.Put(sum, strings.NewReader("good")); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// A directory where the link would go makes os.Link fail and the
	// copy path run; a directory also can't be opened for writing, so
	// the copy fails too and the error surfaces.
	if err := os.Mkdir(filepath.Join(dir, "sandboxd"), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "sandboxd", "keep"), nil, 0o600)
	if err := s.Materialize(dir, map[string]string{"sandboxd": sum}); err == nil {
		t.Fatal("materialize over a non-empty dir succeeded")
	}
	// Tamper with the stored file, then force the copy path by making
	// the source unlinkable: a symlinked store dir on the same fs still
	// links, so instead check through streamToFileMax directly.
	p, _ := s.Path(sum)
	os.WriteFile(p, []byte("evil"), 0o600)
	in, _ := os.Open(p)
	_, got, err := streamToFileMax(in, filepath.Join(t.TempDir(), "x"), 0o600, 1<<20)
	in.Close()
	if err != nil || got == sum {
		t.Fatalf("tampered file hashed as its name: %v", err)
	}
}

func TestFileStorePrune(t *testing.T) {
	s := FileStore{Dir: t.TempDir()}
	now := time.Now()
	old, fresh, kept := sumOf("old"), sumOf("fresh"), sumOf("kept")
	for _, x := range []string{"old", "fresh", "kept"} {
		if _, _, err := s.Put(sumOf(x), strings.NewReader(x)); err != nil {
			t.Fatal(err)
		}
	}
	past := now.Add(-2 * time.Hour)
	for _, x := range []string{old, kept} {
		p, _ := s.Path(x)
		os.Chtimes(p, past, past)
	}
	tmp := filepath.Join(s.Dir, ".put-123")
	os.WriteFile(tmp, nil, 0o600)
	os.Chtimes(tmp, past, past)
	os.Mkdir(filepath.Join(s.Dir, "subdir"), 0o700)
	n, err := s.Prune(now, time.Hour, map[string]bool{kept: true})
	if err != nil || n != 2 {
		t.Fatalf("Prune = %d %v", n, err)
	}
	if s.Has(old) || !s.Has(fresh) || !s.Has(kept) {
		t.Fatalf("after prune: old=%v fresh=%v kept=%v", s.Has(old), s.Has(fresh), s.Has(kept))
	}
	if n, err := (FileStore{Dir: filepath.Join(t.TempDir(), "none")}).Prune(now, time.Hour, nil); n != 0 || err != nil {
		t.Fatalf("missing dir prune = %d %v", n, err)
	}
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, nil, 0o600)
	if _, err := (FileStore{Dir: file}).Prune(now, time.Hour, nil); err == nil {
		t.Fatal("prune of a file succeeded")
	}
	if FileStoreDir("/var/lib/sandboxd/upgrade") != "/var/lib/sandboxd/upgrade/files" {
		t.Fatal(FileStoreDir("/var/lib/sandboxd/upgrade"))
	}
}
