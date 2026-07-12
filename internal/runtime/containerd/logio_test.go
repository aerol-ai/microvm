package containerd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCappedWriterBoundsFileSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "task.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := &cappedWriter{f: f, cap: 64}
	// Write well past the cap. Every Write must report the full length so the
	// FIFO copy goroutine keeps draining (a short write would stall the task).
	chunk := []byte(strings.Repeat("x", 100))
	for range 5 {
		n, werr := w.Write(chunk)
		if werr != nil {
			t.Fatalf("write: %v", werr)
		}
		if n != len(chunk) {
			t.Fatalf("Write reported %d, want full %d (short write blocks the task FIFO)", n, len(chunk))
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// File holds the cap plus a bounded one-time truncation marker, never the
	// full 500 bytes written.
	if info.Size() > 64+128 {
		t.Fatalf("log file size = %d, expected bounded near cap 64", info.Size())
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "log truncated") {
		t.Fatalf("expected truncation marker in capped log, got %q", body)
	}
}

func TestTaskLogIOCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sb.log")
	creator, closeLog, err := taskLogIO(path)
	if err != nil {
		t.Fatalf("taskLogIO: %v", err)
	}
	defer closeLog()
	if creator == nil {
		t.Fatal("nil cio.Creator")
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("log file not created: %v", statErr)
	}
}
