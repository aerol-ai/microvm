package firecracker

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// diskUseChecked says whether a test may assert how much disk a copy uses.
// Only on Linux, where Firecracker runs: ext4, xfs, btrfs and tmpfs keep
// every zero block a writer skips as a hole. macOS's APFS decides for
// itself: it fills a gap under about 16 MiB with real zero blocks, and a
// write into a hole made by truncate allocates the whole file.
var diskUseChecked = runtime.GOOS == "linux"

// allocated is how much of the disk path really uses, as opposed to its size.
func allocated(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no block counts on this platform")
	}
	return int64(st.Blocks) * 512
}

func fileDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// sparseDisk writes a file shaped like a VM disk: size bytes, mostly holes,
// with a little data at these offsets (some not block-aligned) and one MiB
// of zeros written out as real blocks. It skips the test on a filesystem
// that keeps no holes, where sparseness cannot be measured.
func sparseDisk(t *testing.T, path string, size int64, data map[int64]string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if allocated(t, path) >= size/2 {
		t.Skip("this filesystem keeps no holes")
	}
	if _, err := f.WriteAt(make([]byte, 1<<20), 8<<20); err != nil {
		t.Fatal(err)
	}
	for off, s := range data {
		if _, err := f.WriteAt([]byte(s), off); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
}

// The regression: Stop and Start copy a 10 GiB rootfs that holds a few
// hundred MiB. A plain copy wrote every zero, so each copy took the full
// size on the host. The copy must hold the same bytes and use no more disk
// than the data needs, even where the source wrote its zeros out.
func TestCopyFileKeepsTheCopySparse(t *testing.T) {
	const size = 64 << 20
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "rootfs.ext4"), filepath.Join(dir, "copy.ext4")
	sparseDisk(t, src, size, map[int64]string{
		0:            "ext4 superblock",
		5000:         "not block-aligned",
		40<<20 + 123: "a file the guest wrote",
		size - 4:     "tail",
	})
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}

	if fileDigest(t, dst) != fileDigest(t, src) {
		t.Fatal("the copy's bytes differ from the source's")
	}
	si, _ := os.Stat(src)
	di, _ := os.Stat(dst)
	if di.Size() != size || di.Mode().Perm() != si.Mode().Perm() {
		t.Fatalf("copy size %d mode %v, want %d %v", di.Size(), di.Mode().Perm(), int64(size), si.Mode().Perm())
	}
	// Four blocks hold data. The source also has a MiB of written zeros,
	// which the copy leaves as a hole.
	if got, srcUse := allocated(t, dst), allocated(t, src); diskUseChecked && (got > 256<<10 || got >= srcUse) {
		t.Fatalf("the copy uses %d bytes of disk (source %d) for a %d-byte file with four blocks of data", got, srcUse, int64(size))
	}
}

// Where the filesystem cannot list holes, the whole file is one range and
// the zero-block check alone must keep the copy sparse and correct.
func TestCopySparseWithoutHoleListing(t *testing.T) {
	const size = 16 << 20
	dir := t.TempDir()
	srcPath, dstPath := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
	sparseDisk(t, srcPath, size, map[int64]string{12345: "data", 9 << 20: "more"})
	src, err := os.Open(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := copySparse(dst, src, []byteRange{{0, size}}, size); err != nil {
		t.Fatalf("copySparse: %v", err)
	}
	if err := dst.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
	if fileDigest(t, dstPath) != fileDigest(t, srcPath) {
		t.Fatal("the copy's bytes differ from the source's")
	}
	if got := allocated(t, dstPath); diskUseChecked && got > 256<<10 {
		t.Fatalf("the copy uses %d bytes of disk for two blocks of data", got)
	}
}

func TestDataRanges(t *testing.T) {
	const size = 32 << 20
	dir := t.TempDir()
	path := filepath.Join(dir, "disk")
	offsets := map[int64]string{100: "a", 20 << 20: "b", size - 1: "c"}
	sparseDisk(t, path, size, offsets)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ranges := dataRanges(f, size)

	var covered, last int64
	for _, r := range ranges {
		if r.start < last || r.end <= r.start || r.end > size {
			t.Fatalf("ranges are not in order and inside the file: %v", ranges)
		}
		covered += r.end - r.start
		last = r.end
	}
	for off := range offsets {
		in := false
		for _, r := range ranges {
			in = in || (off >= r.start && off < r.end)
		}
		if !in {
			t.Errorf("data at %d is in no range: %v", off, ranges)
		}
	}
	// The holes between are skipped without being read, where the
	// filesystem lists them (Linux and macOS filesystems all do).
	if covered >= size {
		t.Logf("this filesystem lists no holes; dataRanges read the whole file")
	}

	t.Run("a file that is all hole has nothing to read", func(t *testing.T) {
		hole := filepath.Join(dir, "hole")
		if err := os.WriteFile(hole, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(hole, size); err != nil {
			t.Fatal(err)
		}
		hf, err := os.Open(hole)
		if err != nil {
			t.Fatal(err)
		}
		defer hf.Close()
		var n int64
		for _, r := range dataRanges(hf, size) {
			n += r.end - r.start
		}
		if n == size {
			t.Skip("this filesystem lists no holes")
		}
		if n != 0 {
			t.Fatalf("an all-hole file has %d bytes of data ranges", n)
		}
	})
	t.Run("a file that cannot seek is read whole", func(t *testing.T) {
		cf, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		cf.Close()
		if got := dataRanges(cf, size); len(got) != 1 || got[0] != (byteRange{0, size}) {
			t.Fatalf("dataRanges of a closed file = %v, want the whole file", got)
		}
	})
}

// recordingDest is a copyFileDest that remembers each write.
type recordingDest struct {
	writes []byteRange
	err    error
}

func (r *recordingDest) WriteAt(p []byte, off int64) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	r.writes = append(r.writes, byteRange{off, off + int64(len(p))})
	return len(p), nil
}
func (r *recordingDest) Truncate(int64) error { return nil }
func (r *recordingDest) Sync() error          { return nil }
func (r *recordingDest) Close() error         { return nil }

func TestWriteDataBlocksWritesOnlyDataBlocks(t *testing.T) {
	const b = sparseBlockSize
	block := func(fill byte) []byte { return bytes.Repeat([]byte{fill}, b) }
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	zero, data := block(0), block('x')
	cases := []struct {
		name  string
		chunk []byte
		want  []byteRange // relative to an offset of 1 MiB
	}{
		{"all zeros: no write", cat(zero, zero, zero), nil},
		{"one data block among zeros", cat(zero, data, zero), []byteRange{{b, 2 * b}}},
		{"adjacent data blocks: one write", cat(data, data, zero), []byteRange{{0, 2 * b}}},
		{"data, zero, data: two writes", cat(data, zero, data), []byteRange{{0, b}, {2 * b, 3 * b}}},
		{"one non-zero byte makes its block data", cat(zero, append(make([]byte, b-1), 1)), []byteRange{{b, 2 * b}}},
		{"a short last block with data", cat(zero, []byte("tail")), []byteRange{{b, b + 4}}},
		{"a short last block of zeros", cat(data, make([]byte, 10)), []byteRange{{0, b}}},
	}
	const off = 1 << 20
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst := &recordingDest{}
			if err := writeDataBlocks(dst, tc.chunk, off); err != nil {
				t.Fatal(err)
			}
			var got []byteRange
			for _, w := range dst.writes {
				got = append(got, byteRange{w.start - off, w.end - off})
			}
			if len(got) != len(tc.want) {
				t.Fatalf("writes %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("writes %v, want %v", got, tc.want)
				}
			}
		})
	}
	t.Run("a failed write is returned", func(t *testing.T) {
		err := writeDataBlocks(&recordingDest{err: io.ErrShortWrite}, cat(data, zero), off)
		if !errors.Is(err, io.ErrShortWrite) || !strings.Contains(err.Error(), "write at ") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a failed write of the last run is returned", func(t *testing.T) {
		err := writeDataBlocks(&recordingDest{err: io.ErrShortWrite}, cat(zero, data), off)
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestCopySparseFailsOnAShortRead(t *testing.T) {
	err := copySparse(&recordingDest{}, strings.NewReader("short"), []byteRange{{0, 100}}, 100)
	if !errors.Is(err, io.ErrUnexpectedEOF) || !strings.Contains(err.Error(), "read at 0") {
		t.Fatalf("err = %v, want an unexpected EOF at 0", err)
	}
}

// A template create links the template's rootfs into the jail, and copies it
// when it cannot link (the templates folder on another filesystem). That
// copy must keep the holes too.
func TestLinkOrCopyRootfsCopyIsSparse(t *testing.T) {
	const size = 32 << 20
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "template.ext4"), filepath.Join(dir, "rootfs.ext4")
	sparseDisk(t, src, size, map[int64]string{0: "superblock", 30 << 20: "a file"})
	orig := linkRootfsFn
	t.Cleanup(func() { linkRootfsFn = orig })
	linkRootfsFn = func(string, string) error { return syscall.EXDEV }

	if err := linkOrCopyRootfs(src, dst); err != nil {
		t.Fatalf("linkOrCopyRootfs: %v", err)
	}
	if fileDigest(t, dst) != fileDigest(t, src) {
		t.Fatal("the copy's bytes differ from the template's")
	}
	if fi, _ := os.Stat(dst); fi.Size() != size || fi.Mode().Perm() != 0o600 {
		t.Fatalf("copy size %d mode %v, want %d 0600", fi.Size(), fi.Mode().Perm(), int64(size))
	}
	if got := allocated(t, dst); diskUseChecked && got > 256<<10 {
		t.Fatalf("the copy uses %d bytes of disk for two blocks of data", got)
	}
}

// The copy goes by the size it read first. A file that is longer by the
// time its ranges are listed (written to after the stat) must not give
// ranges past that size, or the copy would not match what was stat'ed.
func TestDataRangesStopAtTheGivenSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, 12<<20); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte("data past the size"), 8<<20); err != nil {
		t.Fatal(err)
	}
	// 4 MiB ends before the data, 8 MiB + 10 inside its block, 10 MiB after it.
	for _, size := range []int64{4 << 20, 8<<20 + 10, 10 << 20} {
		for _, r := range dataRanges(f, size) {
			if r.start < 0 || r.end > size || r.end <= r.start {
				t.Fatalf("dataRanges(size %d) gave %v, outside [0, %d)", size, r, size)
			}
		}
	}
}
