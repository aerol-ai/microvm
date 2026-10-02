package containerd

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"
)

func tarWith(t *testing.T, build func(*tar.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	build(tw)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A build-context tar with too many entries is rejected (inode-exhaustion bound).
func TestExtractTarRejectsTooManyEntries(t *testing.T) {
	old := maxContextEntries
	maxContextEntries = 3
	t.Cleanup(func() { maxContextEntries = old })

	data := tarWith(t, func(tw *tar.Writer) {
		for i := 0; i < 5; i++ {
			name := "f" + string(rune('0'+i))
			_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
			_, _ = tw.Write([]byte("x"))
		}
	})
	if err := extractTar(data, t.TempDir()); err == nil || !strings.Contains(err.Error(), "too many entries") {
		t.Fatalf("extractTar = %v, want too-many-entries rejection", err)
	}
}

// A build-context tar whose extracted bytes exceed the ceiling is rejected.
func TestExtractTarRejectsTotalBytes(t *testing.T) {
	old := maxContextTotalBytes
	maxContextTotalBytes = 16
	t.Cleanup(func() { maxContextTotalBytes = old })

	big := bytes.Repeat([]byte("A"), 64)
	data := tarWith(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "big.bin", Mode: 0o644, Size: int64(len(big)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(big)
	})
	if err := extractTar(data, t.TempDir()); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("extractTar = %v, want total-bytes rejection", err)
	}
}

// A normal small context still extracts under the (default) bounds.
func TestExtractTarWithinBounds(t *testing.T) {
	data := tarWith(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "ok.txt", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("hello"))
	})
	if err := extractTar(data, t.TempDir()); err != nil {
		t.Fatalf("extractTar(normal) = %v, want nil", err)
	}
}
