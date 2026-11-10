package scripts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// The embedded copy is install.sh itself, so its hash is the one
// release.json publishes for the release (cmd/releasemeta hashes the same
// file).
func TestInstallShIsTheScript(t *testing.T) {
	disk, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(disk, InstallSh) {
		t.Fatal("the embedded install.sh differs from scripts/install.sh")
	}
	sum := sha256.Sum256(disk)
	if InstallShSHA256() != hex.EncodeToString(sum[:]) {
		t.Fatalf("InstallShSHA256 = %s", InstallShSHA256())
	}
	// host apply relies on these.
	for _, want := range []string{"\t\t--config-only)\n", "\nNODE_SETTINGS=(\n"} {
		if !bytes.Contains(InstallSh, []byte(want)) {
			t.Errorf("install.sh has no %q", want)
		}
	}
}
