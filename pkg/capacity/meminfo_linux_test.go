//go:build linux

package capacity

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeMeminfoFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "meminfo")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadMeminfoFieldLinux(t *testing.T) {
	orig := meminfoPath
	t.Cleanup(func() { meminfoPath = orig })

	t.Run("happy_path", func(t *testing.T) {
		meminfoPath = writeMeminfoFixture(t, "MemTotal:       2097152 kB\nMemAvailable:   1048576 kB\n")
		got, err := readMeminfoField("MemAvailable")
		if err != nil || got != 1024 {
			t.Fatalf("MemAvailable = %d, %v; want 1024", got, err)
		}
		total, err := totalMemoryMB()
		if err != nil || total != 2048 {
			t.Fatalf("MemTotal = %d, %v; want 2048", total, err)
		}
	})

	t.Run("missing_field", func(t *testing.T) {
		meminfoPath = writeMeminfoFixture(t, "MemTotal: 1024 kB\n")
		if _, err := readMemAvailableMB(); err == nil {
			t.Fatal("expected missing MemAvailable error")
		}
	})

	t.Run("malformed_line", func(t *testing.T) {
		meminfoPath = writeMeminfoFixture(t, "MemAvailable:\n")
		if _, err := readMeminfoField("MemAvailable"); err == nil {
			t.Fatal("expected malformed line error")
		}
	})

	t.Run("non_numeric", func(t *testing.T) {
		meminfoPath = writeMeminfoFixture(t, "MemAvailable: notanumber kB\n")
		if _, err := readMeminfoField("MemAvailable"); err == nil {
			t.Fatal("expected parse error")
		}
	})

	t.Run("open_error", func(t *testing.T) {
		meminfoPath = filepath.Join(t.TempDir(), "missing")
		if _, err := readMeminfoField("MemAvailable"); err == nil {
			t.Fatal("expected open error")
		}
	})
}

func TestProcMeminfoProbeCacheLinux(t *testing.T) {
	orig := meminfoPath
	t.Cleanup(func() { meminfoPath = orig })

	dir := t.TempDir()
	path := filepath.Join(dir, "meminfo")
	if err := os.WriteFile(path, []byte("MemAvailable: 2048000 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	meminfoPath = path

	p := &procMeminfoProbe{ttl: time.Hour}
	first, err := p.FreeMB()
	if err != nil || first <= 0 {
		t.Fatalf("FreeMB = %d, %v", first, err)
	}
	// Overwrite fixture; cached value must stick within TTL.
	if err := os.WriteFile(path, []byte("MemAvailable: 1024 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := p.FreeMB()
	if err != nil || second != first {
		t.Fatalf("cached FreeMB = %d, %v; want %d", second, err, first)
	}

	p2 := NewProcMeminfoProbe()
	if _, ok := p2.(*procMeminfoProbe); !ok {
		t.Fatalf("NewProcMeminfoProbe type = %T", p2)
	}
	if _, err := p2.FreeMB(); err != nil {
		t.Fatalf("live FreeMB: %v", err)
	}

	meminfoPath = filepath.Join(t.TempDir(), "missing")
	p3 := &procMeminfoProbe{ttl: time.Millisecond}
	if _, err := p3.FreeMB(); err == nil {
		t.Fatal("expected FreeMB open error")
	}
}

func TestDetectHostLinux(t *testing.T) {
	info, err := DetectHost()
	if err != nil {
		t.Fatalf("DetectHost: %v", err)
	}
	if info.CPUCores <= 0 || info.MemoryTotalMB <= 0 {
		t.Fatalf("DetectHost = %+v, want positive CPU/memory", info)
	}
}
