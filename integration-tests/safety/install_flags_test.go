package safety

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// --no-start leaves sandboxd for cluster-join.sh to start; a --local
// install never joins a cluster, so the pair is refused before install.sh
// touches the machine.
func TestInstallRefusesNoStartWithLocal(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script, "--local", "--no-start")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "--no-start is for a node cluster-join.sh will start") {
		t.Fatalf("install.sh --local --no-start = %v:\n%s", err, out)
	}
}
