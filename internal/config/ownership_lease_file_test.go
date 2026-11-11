package config

import "testing"

// T3: the ownership lease is written to a file only when one is named.
func TestOwnershipLeaseFileConfig(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "tok")
	t.Setenv("SB_PUBLIC_HOST", "127.0.0.1")
	t.Setenv("SB_DB_PATH", t.TempDir()+"/db.sqlite")
	t.Setenv("SB_CONTAINER_RUNTIME", "docker")
	t.Setenv("SB_TOOLBOX_BINARY_PATH", t.TempDir()+"/toolboxd")
	for value, want := range map[string]string{"": "", " /run/aerolvm/ownership-lease ": "/run/aerolvm/ownership-lease"} {
		t.Setenv("SB_OWNERSHIP_LEASE_FILE", value)
		cfg, err := Load()
		if err != nil || cfg.OwnershipLeaseFile != want {
			t.Fatalf("%q: %q %v, want %q", value, cfg.OwnershipLeaseFile, err, want)
		}
	}
}
