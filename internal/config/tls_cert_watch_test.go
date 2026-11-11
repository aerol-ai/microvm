package config

import "testing"

// C25: the certificate Caddy loads from a file is watched only when named.
func TestTLSCertWatchFileConfig(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "tok")
	t.Setenv("SB_PUBLIC_HOST", "127.0.0.1")
	t.Setenv("SB_DB_PATH", t.TempDir()+"/db.sqlite")
	t.Setenv("SB_CONTAINER_RUNTIME", "docker")
	t.Setenv("SB_TOOLBOX_BINARY_PATH", t.TempDir()+"/toolboxd")
	for value, want := range map[string]string{"": "", " /etc/aerolvm/tls/tls.crt ": "/etc/aerolvm/tls/tls.crt"} {
		t.Setenv("SB_TLS_CERT_WATCH_FILE", value)
		cfg, err := Load()
		if err != nil || cfg.TLSCertWatchFile != want {
			t.Fatalf("%q: %q %v, want %q", value, cfg.TLSCertWatchFile, err, want)
		}
	}
}
