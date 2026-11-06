package config

import (
	"strings"
	"testing"
	"time"
)

// TestDefaultLifecycleEnv: SB_DEFAULT_DESTROY_IF_IDLE_FOR and SB_MAX_AGE are
// off by default, read as Go durations, and refused outside 0..30 days (plan
// L4).
func TestDefaultLifecycleEnv(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "token")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DefaultDestroyIfIdleFor != 0 || cfg.MaxAge != 0 {
		t.Fatalf("defaults on by default: %s %s", cfg.DefaultDestroyIfIdleFor, cfg.MaxAge)
	}

	t.Setenv("SB_DEFAULT_DESTROY_IF_IDLE_FOR", "2h")
	t.Setenv("SB_MAX_AGE", "168h")
	if cfg, err = Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DefaultDestroyIfIdleFor != 2*time.Hour || cfg.MaxAge != 168*time.Hour {
		t.Fatalf("read %s %s", cfg.DefaultDestroyIfIdleFor, cfg.MaxAge)
	}

	for _, tc := range []struct{ key, value string }{
		{"SB_DEFAULT_DESTROY_IF_IDLE_FOR", "-1m"},
		{"SB_MAX_AGE", "721h"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("Load = %v, want a refusal naming %s", err, tc.key)
			}
		})
	}
}
