package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// Workers spill while the daemon is down and every spilled line carries a
// capability the previous process minted. The drain at the next boot has to
// verify those with the same key, so an auto-minted key must survive a
// restart of the daemon on the same data directory.
func TestAuditIngestSigningKeyPersistsAcrossRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	first := &Service{cfg: config.Config{EgressAttributionEnabled: true, DBPath: dbPath}}
	key, err := first.auditIngestSigningKey()
	if err != nil || len(key) != 64 {
		t.Fatalf("minted key = %q err=%v, want 64 hex characters", key, err)
	}
	if again, err := first.auditIngestSigningKey(); err != nil || again != key {
		t.Fatalf("same process re-resolved a different key: %q vs %q err=%v", again, key, err)
	}
	keyPath := filepath.Join(filepath.Dir(dbPath), auditIngestKeyFile)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key not persisted beside the state DB: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("persisted key mode = %o, want 0600", info.Mode().Perm())
	}
	if entries, _ := filepath.Glob(filepath.Join(filepath.Dir(dbPath), auditIngestKeyFile+".tmp-*")); len(entries) != 0 {
		t.Fatalf("temp files left behind: %v", entries)
	}

	capability, err := auditlog.MintEgressCapability(key, "sb", "inc", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// "Restart": a new Service on the same data directory, before any ingest
	// server starts (the sink drains spill at boot, ahead of it).
	second := &Service{cfg: config.Config{EgressAttributionEnabled: true, DBPath: dbPath}}
	restarted, err := second.auditIngestSigningKey()
	if err != nil || restarted != key {
		t.Fatalf("restarted key = %q err=%v, want the persisted %q", restarted, err, key)
	}
	if sb, inc, err := auditlog.ParseAndVerifyEgressCapability(restarted, capability, time.Now()); err != nil || sb != "sb" || inc != "inc" {
		t.Fatalf("capability minted before restart does not verify after it: %v", err)
	}
	// The ingest server started later uses the very same key.
	if err := second.StartAuditIngestServer(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(second.StopAuditIngestServer)
	if second.auditIngestToken() != key {
		t.Fatal("ingest server minted its own key instead of the persisted one")
	}
}

func TestAuditIngestSigningKeyPrecedenceAndDisabledMode(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	// An operator-provided token wins and nothing is persisted.
	configured := &Service{cfg: config.Config{EgressAttributionEnabled: true, DBPath: dbPath, AuditIngestToken: " operator-token "}}
	if key, err := configured.auditIngestSigningKey(); err != nil || key != "operator-token" {
		t.Fatalf("configured key = %q err=%v", key, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dbPath), auditIngestKeyFile)); !os.IsNotExist(err) {
		t.Fatalf("configured token must not be persisted: %v", err)
	}
	// Attribution disabled and no token: nothing mints, nothing verifies.
	disabled := &Service{cfg: config.Config{DBPath: dbPath}}
	if key, err := disabled.auditIngestSigningKey(); err != nil || key != "" {
		t.Fatalf("disabled key = %q err=%v, want empty", key, err)
	}
	// No data directory: process-local key, as before persistence existed.
	local := &Service{cfg: config.Config{EgressAttributionEnabled: true}}
	key, err := local.auditIngestSigningKey()
	if err != nil || len(key) != 64 {
		t.Fatalf("process-local key = %q err=%v", key, err)
	}
	if again, _ := local.auditIngestSigningKey(); again != key {
		t.Fatal("process-local key must be cached")
	}
	// A corrupt (empty) key file is replaced, not trusted.
	corrupt := filepath.Join(t.TempDir(), "state.db")
	if err := os.WriteFile(filepath.Join(filepath.Dir(corrupt), auditIngestKeyFile), []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	replaced := &Service{cfg: config.Config{EgressAttributionEnabled: true, DBPath: corrupt}}
	if key, err := replaced.auditIngestSigningKey(); err != nil || len(key) != 64 {
		t.Fatalf("key after empty file = %q err=%v", key, err)
	}
	if nilKey, err := (*Service)(nil).auditIngestSigningKey(); err != nil || nilKey != "" {
		t.Fatalf("nil service key = %q err=%v", nilKey, err)
	}
	// A key path that cannot be read as a file (here: a directory) is an
	// error, not "no key yet": silently minting a fresh key would orphan every
	// capability the previous process handed out.
	unreadable := filepath.Join(t.TempDir(), "state.db")
	if err := os.Mkdir(filepath.Join(filepath.Dir(unreadable), auditIngestKeyFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if key, err := (&Service{cfg: config.Config{EgressAttributionEnabled: true, DBPath: unreadable}}).auditIngestSigningKey(); err == nil || key != "" {
		t.Fatalf("directory at key path = %q err=%v, want read error", key, err)
	}
	// A data directory the daemon cannot write to fails the mint instead of
	// handing out a key that will not survive the process.
	if os.Geteuid() != 0 {
		readOnly := filepath.Join(t.TempDir(), "ro")
		if err := os.Mkdir(readOnly, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(readOnly, 0o700) })
		if key, err := (&Service{cfg: config.Config{EgressAttributionEnabled: true, DBPath: filepath.Join(readOnly, "state.db")}}).auditIngestSigningKey(); err == nil || key != "" {
			t.Fatalf("read-only data dir = %q err=%v, want persist error", key, err)
		}
	}
}
