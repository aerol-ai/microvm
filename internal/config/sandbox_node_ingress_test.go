package config

import "testing"

// C24: an ingress node opens 80 and 443 to its sandboxes unless
// SB_SANDBOX_NODE_INGRESS=false keeps them closed (a pod behind a Service).
func TestSandboxNodeIngressConfig(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "tok")
	t.Setenv("SB_PUBLIC_HOST", "127.0.0.1")
	t.Setenv("SB_DB_PATH", t.TempDir()+"/db.sqlite")
	t.Setenv("SB_CONTAINER_RUNTIME", "docker")
	t.Setenv("SB_TOOLBOX_BINARY_PATH", t.TempDir()+"/toolboxd")
	for value, closed := range map[string]bool{"": false, "true": false, "false": true} {
		t.Setenv("SB_SANDBOX_NODE_INGRESS", value)
		cfg, err := Load()
		if err != nil || cfg.SandboxNodeIngressClosed != closed {
			t.Fatalf("%q: closed=%v %v, want %v", value, cfg.SandboxNodeIngressClosed, err, closed)
		}
	}
}
