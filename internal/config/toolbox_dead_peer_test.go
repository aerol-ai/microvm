package config

import (
	"strings"
	"testing"
	"time"
)

func TestToolboxDeadPeerTimeout(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "tok")
	t.Setenv("SB_PUBLIC_HOST", "127.0.0.1")
	t.Setenv("SB_DB_PATH", t.TempDir()+"/db.sqlite")
	t.Setenv("SB_CONTAINER_RUNTIME", "docker")
	t.Setenv("SB_TOOLBOX_BINARY_PATH", t.TempDir()+"/toolboxd")

	for _, tc := range []struct {
		name, env string
		want      time.Duration
		err       bool
	}{
		{name: "default", want: 30 * time.Second},
		{name: "off", env: "0", want: 0},
		{name: "longer", env: "2m", want: 2 * time.Minute},
		{name: "minimum", env: "6s", want: 6 * time.Second},
		{name: "unparsable_keeps_default", env: "soon", want: 30 * time.Second},
		{name: "below_minimum", env: "5s", err: true},
		{name: "negative", env: "-1s", err: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env != "" {
				t.Setenv("SB_TOOLBOX_DEAD_PEER_TIMEOUT", tc.env)
			}
			cfg, err := Load()
			if tc.err {
				if err == nil || !strings.Contains(err.Error(), "SB_TOOLBOX_DEAD_PEER_TIMEOUT must be 0 (off) or at least 6s") {
					t.Fatalf("Load() error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ToolboxDeadPeerTimeout != tc.want {
				t.Fatalf("ToolboxDeadPeerTimeout = %v, want %v", cfg.ToolboxDeadPeerTimeout, tc.want)
			}
		})
	}
}
