package docker

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestCoverage95AOCRPullAuthEdgePaths(t *testing.T) {
	dir := coverageReadyDir(t)
	emptyPAT := filepath.Join(dir, "empty")
	if err := os.WriteFile(emptyPAT, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Client{logger: slog.Default()}
	c.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai", "aocr.aerol.ai"}, "cluster-1", emptyPAT)
	if got := c.resolveAOCRPullAuth("aocr.aerol.ai/cluster/cluster-1/templates/x:latest"); got != nil {
		t.Fatalf("empty PAT should resolve to nil auth, got %+v", got)
	}

	c.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai"}, "cluster-1", filepath.Join(dir, "missing"))
	if got := c.resolveAOCRPullAuth("aocr.aerol.ai/cluster/cluster-1/templates/x:latest"); got != nil {
		t.Fatalf("missing PAT should resolve to nil auth, got %+v", got)
	}
	if c.aocrPullAuth == nil {
		t.Fatal("expected configured auth object")
	}
}
