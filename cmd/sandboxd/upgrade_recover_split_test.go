package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
)

// In privilege mode split, sandboxd's user owns its data folder. An
// upgrade folder inside it (SB_UPGRADE_STATE_DIR unset) is one that user
// can write, and `sandboxd upgrade recover` runs as root: it refuses that
// folder, as the upgrade does, and touches nothing (hardening, M1 PR 10
// review).
func TestRunUpgradeRecoverRefusesTheAgentsFolder(t *testing.T) {
	n := newCLINode(t)
	n.paths.Split = true // StateDir is <data folder>/upgrade
	hash := func(s string) string {
		h := sha256.Sum256([]byte(s))
		return hex.EncodeToString(h[:])
	}
	// A record asking recovery to put a *.prev back over the installed
	// sandboxd.
	if err := os.WriteFile(n.paths.Sandboxd+".prev", []byte("older sandboxd\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	st := nodeupgrade.State{Format: 1, Op: "planted", Version: "v9.9.9", Phase: nodeupgrade.PhaseSwapping, StartedAt: time.Now(),
		Files: []nodeupgrade.FileState{{Role: "sandboxd", Path: n.paths.Sandboxd, SHA256: hash("old sandboxd\n"),
			PrevSHA256: hash("older sandboxd\n"), Changed: true}}}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(n.paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(n.paths.StateDir, "planted.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := runUpgradeCLI([]string{"recover"}, &out, &out); code != 1 || !strings.Contains(out.String(), "SB_UPGRADE_STATE_DIR") {
		t.Fatalf("code %d: %s", code, out.String())
	}
	if b, _ := os.ReadFile(n.paths.Sandboxd); string(b) != "old sandboxd\n" {
		t.Fatalf("recovery acted on the agent's folder: sandboxd is now %q", b)
	}
}
