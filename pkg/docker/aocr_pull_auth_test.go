package docker

import (
	"os"
	"path/filepath"
	"testing"
)

// writePAT writes a PAT file under a temp dir and returns its path.
func writePAT(t *testing.T, token string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "cluster-pat")
	if err := os.WriteFile(p, []byte(token), 0o600); err != nil {
		t.Fatalf("write pat: %v", err)
	}
	return p
}

func TestResolveAOCRPullAuth_NilWhenUnconfigured(t *testing.T) {
	c := &Client{}
	if got := c.resolveAOCRPullAuth("aocr.aerol.ai/cluster/c1/templates/py311:latest"); got != nil {
		t.Fatalf("expected nil auth when unconfigured, got %+v", got)
	}
}

func TestResolveAOCRPullAuth_TemplatesAndSnapshots(t *testing.T) {
	patPath := writePAT(t, "tok-123\n") // trailing newline must be trimmed
	c := &Client{}
	c.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai", ""}, "prod-aerolvm-us-east-1", patPath)

	for _, ref := range []string{
		"aocr.aerol.ai/cluster/prod-aerolvm-us-east-1/templates/py311:latest",
		"aocr.aerol.ai/cluster/prod-aerolvm-us-east-1/snapshots/py-ready:latest",
	} {
		got := c.resolveAOCRPullAuth(ref)
		if got == nil {
			t.Fatalf("expected auth for %q, got nil", ref)
		}
		if got.Server != "aocr.aerol.ai" {
			t.Errorf("ref %q: Server = %q, want aocr.aerol.ai", ref, got.Server)
		}
		if got.Username != "prod-aerolvm-us-east-1" {
			t.Errorf("ref %q: Username = %q, want cluster id", ref, got.Username)
		}
		if got.Password != "tok-123" {
			t.Errorf("ref %q: Password = %q, want trimmed token", ref, got.Password)
		}
	}
}

func TestResolveAOCRPullAuth_ScopingRules(t *testing.T) {
	patPath := writePAT(t, "tok")
	c := &Client{}
	c.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai"}, "c1", patPath)

	cases := []struct {
		name string
		ref  string
		want bool
	}{
		{"other host cluster path", "ghcr.io/cluster/c1/templates/py311:latest", false},
		{"configured host non-cluster repo", "aocr.aerol.ai/acme/my-image:latest", false},
		{"configured host mirror namespace", "aocr.aerol.ai/mirror/aocr/ghcr/foo:latest", false},
		{"docker hub short ref (no host)", "ubuntu:22.04", false},
		{"cluster prefix collision", "aocr.aerol.ai/clusterfoo/bar:latest", false},
		{"configured host cluster path", "aocr.aerol.ai/cluster/c1/templates/py311:latest", true},
		{"transport prefix stripped", "docker://aocr.aerol.ai/cluster/c1/snapshots/s:latest", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := c.resolveAOCRPullAuth(tc.ref) != nil
			if got != tc.want {
				t.Fatalf("resolveAOCRPullAuth(%q) matched=%v, want %v", tc.ref, got, tc.want)
			}
		})
	}
}

func TestResolveAOCRPullAuth_PATReadFreshEachCall(t *testing.T) {
	patPath := writePAT(t, "first")
	c := &Client{}
	c.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai"}, "c1", patPath)

	ref := "aocr.aerol.ai/cluster/c1/templates/py311:latest"
	if got := c.resolveAOCRPullAuth(ref); got == nil || got.Password != "first" {
		t.Fatalf("first resolve: got %+v, want password=first", got)
	}
	// Rotate the PAT on disk; the next resolve must reflect it without any
	// restart or reconfigure — the rotation contract.
	if err := os.WriteFile(patPath, []byte("second"), 0o600); err != nil {
		t.Fatalf("rotate pat: %v", err)
	}
	if got := c.resolveAOCRPullAuth(ref); got == nil || got.Password != "second" {
		t.Fatalf("after rotation: got %+v, want password=second", got)
	}
}

func TestResolveAOCRPullAuth_NilWhenPATMissing(t *testing.T) {
	c := &Client{}
	c.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai"}, "c1", filepath.Join(t.TempDir(), "does-not-exist"))
	if got := c.resolveAOCRPullAuth("aocr.aerol.ai/cluster/c1/templates/py311:latest"); got != nil {
		t.Fatalf("expected nil auth when PAT file missing, got %+v", got)
	}
}

func TestConfigureAOCRPullAuth_NoOpWhenIncomplete(t *testing.T) {
	patPath := writePAT(t, "tok")
	cases := []struct {
		name      string
		hosts     []string
		clusterID string
		patPath   string
	}{
		{"empty cluster id", []string{"aocr.aerol.ai"}, "", patPath},
		{"empty pat path", []string{"aocr.aerol.ai"}, "c1", ""},
		{"no non-empty hosts", []string{"", "  "}, "c1", patPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{}
			c.ConfigureAOCRPullAuth(tc.hosts, tc.clusterID, tc.patPath)
			if c.aocrPullAuth != nil {
				t.Fatalf("expected aocrPullAuth to stay nil for incomplete config")
			}
		})
	}
}
