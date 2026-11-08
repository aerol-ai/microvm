package service

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/internal/version"
)

func TestNodeUpgradesController(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, remote := range []bool{true, false} {
		db := filepath.Join(t.TempDir(), "state.db")
		svc := New(config.Config{DBPath: db, RemoteUpgrade: remote}, logger, nil, nil, nil, nil, nil, nil, nil)
		// The audit writer runs beside the database; stop it before the
		// temp dir is removed, or a late write races the cleanup.
		t.Cleanup(svc.CloseSecretAuditSink)
		if svc.RemoteUpgradeEnabled() != remote {
			t.Fatalf("RemoteUpgradeEnabled = %v, want %v", svc.RemoteUpgradeEnabled(), remote)
		}
		l := svc.NodeUpgrades()
		if l.StateDir != nodeupgrade.StateDirFor(db) || l.RunningVersion != version.Version || l.Binary == nil || l.Host == nil {
			t.Fatalf("controller = %+v", l)
		}
		if svc.NodeUpgrades() != l {
			t.Fatal("a second call built a second controller")
		}
	}
	// A controller attached first is the one used.
	svc := New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	t.Cleanup(svc.CloseSecretAuditSink)
	mine := &nodeupgrade.Local{StateDir: "/x"}
	svc.AttachNodeUpgrades(mine)
	if svc.NodeUpgrades() != mine {
		t.Fatal("attached controller ignored")
	}
}
