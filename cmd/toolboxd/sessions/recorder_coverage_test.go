package sessions

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecorderDefaultColsRowsAndOpenError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "defaults.cast")
	rec, err := newRecorder(path, 0, -1, "title")
	if err != nil {
		t.Fatalf("newRecorder defaults: %v", err)
	}
	_ = rec.Close()

	readonly := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(readonly, 0o555); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(readonly, 0o755) })
	if _, err := newRecorder(filepath.Join(readonly, "blocked.cast"), 80, 24, "x"); err == nil {
		if os.Geteuid() == 0 {
			t.Skip("root can create files in mode 0555 directories")
		}
		t.Fatal("expected open failure in read-only dir")
	}
}
