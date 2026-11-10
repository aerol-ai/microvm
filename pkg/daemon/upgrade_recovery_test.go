package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/nodeupgrade"
)

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func stubRecovery(t *testing.T, fn func(context.Context, string, nodeupgrade.Host, io.Writer) ([]nodeupgrade.RecoverResult, error)) {
	t.Helper()
	orig := recoverUpgrades
	t.Cleanup(func() { recoverUpgrades = orig })
	recoverUpgrades = fn
}

func TestRecoverInterruptedUpgrade(t *testing.T) {
	cfg := config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	cases := []struct {
		name    string
		results []nodeupgrade.RecoverResult
		err     error
		wantErr string
		wantLog string
	}{
		{name: "nothing to do"},
		{name: "recovery cannot run", err: errors.New("permission denied"), wantLog: "could not check for an interrupted upgrade"},
		{name: "completed", results: []nodeupgrade.RecoverResult{{Op: "op-1", Result: nodeupgrade.ResultCompletedAtBoot}}, wantLog: "op=op-1"},
		{name: "reverted with a problem", results: []nodeupgrade.RecoverResult{{Op: "op-2", Result: nodeupgrade.ResultRevertedAtBoot, Err: errors.New("caddy down")}},
			wantLog: "caddy down"},
		{name: "reverted the sandboxd binary", results: []nodeupgrade.RecoverResult{{Op: "op-3", Result: nodeupgrade.ResultRevertedAtBoot, RevertedSandboxd: true}},
			wantErr: "exiting so systemd starts the previous binary"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs.Reset()
			stubRecovery(t, func(_ context.Context, dir string, _ nodeupgrade.Host, out io.Writer) ([]nodeupgrade.RecoverResult, error) {
				if dir != filepath.Join(filepath.Dir(cfg.DBPath), "upgrade") {
					t.Fatalf("state dir = %s", dir)
				}
				_, _ = io.WriteString(out, "line one\npartial")
				return tc.results, tc.err
			})
			err := recoverInterruptedUpgrade(context.Background(), cfg, logger)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(logs.String(), tc.wantLog) {
				t.Fatalf("logs have no %q:\n%s", tc.wantLog, logs.String())
			}
			if !strings.Contains(logs.String(), "line one") || !strings.Contains(logs.String(), "partial") {
				t.Fatalf("progress lines were not logged:\n%s", logs.String())
			}
		})
	}
}

// A sandboxd booting after an upgrader died with the sandboxd binary
// swapped but toolboxd not: Run puts the binary back and exits before it
// opens the store, so systemd starts the previous binary.
func TestRunRevertsAHalfSwappedUpgradeBeforeTheStore(t *testing.T) {
	paths := setBaseRunEnv(t)
	dir := t.TempDir()
	sandboxd, toolboxd := filepath.Join(dir, "sandboxd"), filepath.Join(dir, "toolboxd")
	write := func(p, s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(sandboxd, "new sandboxd")
	write(sandboxd+".prev", "old sandboxd")
	write(toolboxd, "old toolboxd")
	stateDir := nodeupgrade.StateDirFor(paths.dbPath)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	st := nodeupgrade.State{Format: 1, Op: "op-half", Version: "v0.6.12", Phase: nodeupgrade.PhaseSwapping, StartedAt: time.Now(),
		Files: []nodeupgrade.FileState{
			{Role: "toolboxd", Path: toolboxd, SHA256: sha("new toolboxd"), PrevSHA256: sha("old toolboxd"), Changed: true},
			{Role: "sandboxd", Path: sandboxd, SHA256: sha("new sandboxd"), PrevSHA256: sha("old sandboxd"), Changed: true},
		}}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "op-half.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	err = runWithAutoCancel(t, 5*time.Second, nil)
	if err == nil || !strings.Contains(err.Error(), "op-half") {
		t.Fatalf("Run = %v, want it to stop for the reverted binary", err)
	}
	if b, _ := os.ReadFile(sandboxd); string(b) != "old sandboxd" {
		t.Fatalf("sandboxd = %q, want the previous binary back", b)
	}
	if _, err := os.Stat(paths.dbPath); !os.IsNotExist(err) {
		t.Fatalf("the store was opened before recovery finished: %v", err)
	}
	got, err := nodeupgrade.LoadState(stateDir, "op-half")
	if err != nil || got.Phase != nodeupgrade.PhaseFailed {
		t.Fatalf("record = %+v, %v", got, err)
	}
}

// A normal boot writes the store-opened marker beside the database once
// the store is open and migrated; a marker that cannot be written is only
// logged.
func TestRunMarksTheStoreOpened(t *testing.T) {
	paths := setBaseRunEnv(t)
	if err := runWithAutoCancel(t, 150*time.Millisecond, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	raw, err := os.ReadFile(nodeupgrade.StoreOpenedMarkerPath(paths.dbPath))
	if err != nil {
		t.Fatalf("no store-opened marker: %v", err)
	}
	if !strings.Contains(string(raw), `"version"`) {
		t.Fatalf("marker = %s", raw)
	}

	var logs bytes.Buffer
	orig := writeStoreOpened
	t.Cleanup(func() { writeStoreOpened = orig })
	writeStoreOpened = func(string, string) error { return errors.New("read-only file system") }
	markStoreOpened(config.Config{DBPath: paths.dbPath}, slog.New(slog.NewTextHandler(&logs, nil)))
	if !strings.Contains(logs.String(), "read-only file system") {
		t.Fatalf("logs: %s", logs.String())
	}
	if _, ok := newUpgradeRecoveryHost().(*nodeupgrade.SystemHost); !ok {
		t.Fatal("boot recovery does not use the systemd host")
	}
}
