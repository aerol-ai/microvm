package config

import (
	"strings"
	"testing"
)

// Exercises the validation branches of Load that the happy-path tests skip.
// Each case sets the minimum env to reach one error return.

func TestLoad_HappyPathMinimal(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "operator-pat")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PATToken != "operator-pat" {
		t.Fatalf("PATToken = %q", cfg.PATToken)
	}
	// Defaults should be populated.
	if cfg.APIPort == 0 || cfg.DBPath == "" {
		t.Fatalf("expected defaults populated, got %+v", cfg)
	}
}

func TestLoad_MissingPATToken(t *testing.T) {
	// Ensure no inherited token.
	t.Setenv("SB_PAT_TOKEN", "")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "SB_PAT_TOKEN is required") {
		t.Fatalf("err = %v, want SB_PAT_TOKEN required", err)
	}
}

func TestLoad_ValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "otel metrics interval",
			env:  map[string]string{"SB_OTEL_METRICS_ENABLED": "true", "SB_OTEL_METRICS_INTERVAL": "0s"},
			want: "SB_OTEL_METRICS_INTERVAL",
		},
		{
			name: "otel traces sample ratio",
			env:  map[string]string{"SB_OTEL_TRACES_ENABLED": "true", "SB_OTEL_TRACES_SAMPLE_RATIO": "2"},
			want: "SB_OTEL_TRACES_SAMPLE_RATIO",
		},
		{
			name: "image pull max concurrent negative",
			env:  map[string]string{"SB_IMAGE_PULL_MAX_CONCURRENT": "-1"},
			want: "SB_IMAGE_PULL_MAX_CONCURRENT",
		},
		{
			name: "auto import without hooks url",
			env:  map[string]string{"SB_AUTO_IMPORT_ENABLED": "true"},
			want: "SB_AUTO_IMPORT_HOOKS_URL",
		},
		{
			name: "snapshot push without cluster id",
			env:  map[string]string{"SB_SNAPSHOT_PUSH_ENABLED": "true"},
			want: "SB_AUTO_IMPORT_CLUSTER_ID",
		},
		{
			name: "toolbox mount path relative",
			env:  map[string]string{"SB_TOOLBOX_MOUNT_PATH": "relative/path"},
			want: "SB_TOOLBOX_MOUNT_PATH",
		},
		{
			name: "invalid runtime",
			env:  map[string]string{"SB_CONTAINER_RUNTIME": "bogus"},
			want: "invalid SB_CONTAINER_RUNTIME",
		},
		{
			name: "firecracker as host default rejected",
			env:  map[string]string{"SB_CONTAINER_RUNTIME": "firecracker"},
			want: "not allowed as the host default",
		},
		{
			name: "enable firecracker with bad tap pool size",
			env:  map[string]string{"SB_ENABLE_FIRECRACKER": "true", "SB_FIRECRACKER_TAP_POOL_SIZE": "0"},
			want: "SB_FIRECRACKER_TAP_POOL_SIZE must be > 0",
		},
		{
			name: "auto import bad retention suffix",
			env: map[string]string{
				"SB_AUTO_IMPORT_ENABLED":          "true",
				"SB_AUTO_IMPORT_HOOKS_URL":        "https://hooks.example.com",
				"SB_AUTO_IMPORT_CLUSTER_ID":       "cluster-1",
				"SB_AUTO_IMPORT_CLUSTER_PAT_PATH": "/tmp/pat",
				"SB_AUTO_IMPORT_RETENTION_SUFFIX": "nodashes",
			},
			want: "SB_AUTO_IMPORT_RETENTION_SUFFIX must start with",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_PAT_TOKEN", "operator-pat")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestLoad_OTELEndpointEnablesExporters(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "operator-pat")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.OTELMetricsEnabled || !cfg.OTELTracesEnabled {
		t.Fatalf("expected OTEL exporters enabled by generic endpoint, got metrics=%v traces=%v",
			cfg.OTELMetricsEnabled, cfg.OTELTracesEnabled)
	}
}
