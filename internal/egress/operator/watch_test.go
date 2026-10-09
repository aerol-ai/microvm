package operator

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWatcherInvalidReloadLogsAndBootErrorClears: a broken edit is logged
// with the file's path, and once a good file has loaded the boot error no
// longer refuses creates, even though the first load failed.
func TestWatcherInvalidReloadLogsAndBootErrorClears(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress-policy.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nnope: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	w := NewWatcher(path, slog.New(slog.NewTextHandler(&logs, nil)), nil)
	if w.BootError() == nil || !strings.Contains(logs.String(), "egress operator file invalid") || !strings.Contains(logs.String(), path) {
		t.Fatalf("boot error %v, log %q", w.BootError(), logs.String())
	}
	if err := os.WriteFile(path, []byte("version: 1\ndefault_policy: {mode: block_all}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := w.BootError(); err != nil {
		t.Fatalf("a good file loaded since boot: %v", err)
	}
}
