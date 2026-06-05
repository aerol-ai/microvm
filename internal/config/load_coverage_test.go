package config

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
			name: "image pull failure backoff negative",
			env:  map[string]string{"SB_IMAGE_PULL_FAILURE_BACKOFF": "-1s"},
			want: "SB_IMAGE_PULL_FAILURE_BACKOFF must be >= 0",
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
		{
			name: "invalid l4 port range",
			env:  map[string]string{"SB_L4_PORT_RANGE_START": "999", "SB_L4_PORT_RANGE_END": "1000"},
			want: "invalid SB_L4_PORT_RANGE_START/END",
		},
		{
			name: "node role without cluster",
			env:  map[string]string{"SB_NODE_ROLE": "worker"},
			want: "requires SB_ENABLE_CLUSTER=true",
		},
		{
			name: "cluster bootstrap requires server role",
			env: map[string]string{
				"SB_ENABLE_CLUSTER":               "true",
				"SB_CLUSTER_BOOTSTRAP":            "true",
				"SB_CLUSTER_INSECURE_GOSSIP":      "true",
				"SB_CLUSTER_INSECURE_CREDENTIALS": "true",
				"SB_NODE_ROLE":                    "worker,ingress",
			},
			want: "may bootstrap a cluster",
		},
		{
			name: "cluster negative auto voters",
			env: map[string]string{
				"SB_ENABLE_CLUSTER":               "true",
				"SB_CLUSTER_BOOTSTRAP":            "true",
				"SB_CLUSTER_INSECURE_GOSSIP":      "true",
				"SB_CLUSTER_INSECURE_CREDENTIALS": "true",
				"SB_CLUSTER_MAX_AUTO_VOTERS":      "-1",
			},
			want: "SB_CLUSTER_MAX_AUTO_VOTERS must be >= 0",
		},
		{
			name: "cluster negative pending per worker",
			env: map[string]string{
				"SB_ENABLE_CLUSTER":                        "true",
				"SB_CLUSTER_BOOTSTRAP":                     "true",
				"SB_CLUSTER_INSECURE_GOSSIP":               "true",
				"SB_CLUSTER_INSECURE_CREDENTIALS":          "true",
				"SB_CLUSTER_CREATE_MAX_PENDING_PER_WORKER": "-1",
			},
			want: "SB_CLUSTER_CREATE_MAX_PENDING_PER_WORKER must be >= 0",
		},
		{
			name: "auto import reconcile interval must be positive",
			env: map[string]string{
				"SB_AUTO_IMPORT_ENABLED":            "true",
				"SB_AUTO_IMPORT_HOOKS_URL":          "https://hooks.example.com",
				"SB_AUTO_IMPORT_CLUSTER_ID":         "cluster-1",
				"SB_AUTO_IMPORT_CLUSTER_PAT_PATH":   "/tmp/pat",
				"SB_AUTO_IMPORT_RECONCILE_INTERVAL": "0s",
			},
			want: "SB_AUTO_IMPORT_RECONCILE_INTERVAL must be > 0",
		},
		{
			name: "snapshot push reconcile interval must be positive",
			env: map[string]string{
				"SB_SNAPSHOT_PUSH_ENABLED":            "true",
				"SB_AUTO_IMPORT_CLUSTER_ID":           "cluster-1",
				"SB_AUTO_IMPORT_CLUSTER_PAT_PATH":     "/tmp/pat",
				"SB_SNAPSHOT_PUSH_RECONCILE_INTERVAL": "0s",
			},
			want: "SB_SNAPSHOT_PUSH_RECONCILE_INTERVAL must be > 0",
		},
		{
			name: "snapshot push max inflight must be positive",
			env: map[string]string{
				"SB_SNAPSHOT_PUSH_ENABLED":        "true",
				"SB_AUTO_IMPORT_CLUSTER_ID":       "cluster-1",
				"SB_AUTO_IMPORT_CLUSTER_PAT_PATH": "/tmp/pat",
				"SB_SNAPSHOT_PUSH_MAX_IN_FLIGHT":  "0",
			},
			want: "SB_SNAPSHOT_PUSH_MAX_IN_FLIGHT must be > 0",
		},
		{
			name: "fleet contract refresh must be positive",
			env: map[string]string{
				"SB_FLEET_ENABLED":          "true",
				"SB_FLEET_ENDPOINT":         "https://fleet.aerol.ai",
				"SB_FLEET_TOKEN":            "token",
				"SB_FLEET_CONTRACT_REFRESH": "0s",
			},
			want: "SB_FLEET_CONTRACT_REFRESH must be > 0",
		},
		{
			name: "serverless direct bypass requires positive netstats poll",
			env: map[string]string{
				"SB_HTTP_WAKE_DIRECT_BYPASS_ENABLED": "true",
				"SB_NETSTATS_POLL_INTERVAL":          "0s",
			},
			want: "SB_NETSTATS_POLL_INTERVAL must be > 0",
		},
		{
			name: "serverless direct bypass requires positive reconcile interval",
			env: map[string]string{
				"SB_L4_WAKE_DIRECT_BYPASS_ENABLED": "true",
				"SB_RECONCILE_INTERVAL":            "0s",
			},
			want: "SB_RECONCILE_INTERVAL must be > 0",
		},
		{
			name: "serverless l4 pending per sandbox must be positive",
			env:  map[string]string{"SB_L4_WAKE_MAX_PENDING_PER_SANDBOX": "0"},
			want: "SB_L4_WAKE_MAX_PENDING_PER_SANDBOX must be > 0",
		},
		{
			name: "serverless l4 pending global must be positive",
			env:  map[string]string{"SB_L4_WAKE_MAX_PENDING_GLOBAL": "0"},
			want: "SB_L4_WAKE_MAX_PENDING_GLOBAL must be > 0",
		},
		{
			name: "serverless l4 active per sandbox must be positive",
			env:  map[string]string{"SB_L4_WAKE_MAX_ACTIVE_PER_SANDBOX": "0"},
			want: "SB_L4_WAKE_MAX_ACTIVE_PER_SANDBOX must be > 0",
		},
		{
			name: "serverless l4 active global must be positive",
			env:  map[string]string{"SB_L4_WAKE_MAX_ACTIVE_GLOBAL": "0"},
			want: "SB_L4_WAKE_MAX_ACTIVE_GLOBAL must be > 0",
		},
		{
			name: "serverless http pending per sandbox must be positive",
			env:  map[string]string{"SB_HTTP_WAKE_MAX_PENDING_PER_SANDBOX": "0"},
			want: "SB_HTTP_WAKE_MAX_PENDING_PER_SANDBOX must be > 0",
		},
		{
			name: "serverless http pending global must be positive",
			env:  map[string]string{"SB_HTTP_WAKE_MAX_PENDING_GLOBAL": "0"},
			want: "SB_HTTP_WAKE_MAX_PENDING_GLOBAL must be > 0",
		},
		{
			name: "serverless http global buffer must be positive",
			env:  map[string]string{"SB_HTTP_WAKE_MAX_BUFFER_GLOBAL": "0"},
			want: "SB_HTTP_WAKE_MAX_BUFFER_GLOBAL must be > 0",
		},
		{
			name: "serverless wake start concurrency must be positive",
			env:  map[string]string{"SB_WAKE_START_CONCURRENCY": "0"},
			want: "SB_WAKE_START_CONCURRENCY must be > 0",
		},
		{
			name: "custom domains require domain",
			env: map[string]string{
				"SB_ENABLE_CUSTOM_DOMAINS": "true",
				"SB_DOMAIN":                "",
			},
			want: "SB_DOMAIN must be set when SB_ENABLE_CUSTOM_DOMAINS=true",
		},
		{
			name: "custom domains max per sandbox must be positive",
			env: map[string]string{
				"SB_ENABLE_CUSTOM_DOMAINS":          "true",
				"SB_DOMAIN":                         "example.test",
				"SB_CUSTOM_DOMAINS_MAX_PER_SANDBOX": "0",
			},
			want: "SB_CUSTOM_DOMAINS_MAX_PER_SANDBOX must be > 0",
		},
		{
			name: "custom domains tls burst must be positive",
			env: map[string]string{
				"SB_ENABLE_CUSTOM_DOMAINS": "true",
				"SB_DOMAIN":                "example.test",
				"SB_TLS_ON_DEMAND_BURST":   "0",
			},
			want: "SB_TLS_ON_DEMAND_BURST must be > 0",
		},
		{
			name: "custom domains tls interval must be positive",
			env: map[string]string{
				"SB_ENABLE_CUSTOM_DOMAINS":  "true",
				"SB_DOMAIN":                 "example.test",
				"SB_TLS_ON_DEMAND_INTERVAL": "0s",
			},
			want: "SB_TLS_ON_DEMAND_INTERVAL must be > 0",
		},
		{
			name: "custom domains require positive budget fraction",
			env: map[string]string{
				"SB_ENABLE_CUSTOM_DOMAINS":       "true",
				"SB_DOMAIN":                      "example.test",
				"SB_ACME_DAEMON_BUDGET_FRACTION": "1",
			},
			want: "SB_ACME_DAEMON_BUDGET_FRACTION must be in (0, 1)",
		},
		{
			name: "custom domains require positive budget capacity",
			env: map[string]string{
				"SB_ENABLE_CUSTOM_DOMAINS":       "true",
				"SB_DOMAIN":                      "example.test",
				"SB_ACME_DAEMON_BUDGET_CAPACITY": "0",
			},
			want: "SB_ACME_DAEMON_BUDGET_CAPACITY must be > 0",
		},
		{
			name: "custom domains require positive budget window",
			env: map[string]string{
				"SB_ENABLE_CUSTOM_DOMAINS":     "true",
				"SB_DOMAIN":                    "example.test",
				"SB_ACME_DAEMON_BUDGET_WINDOW": "0s",
			},
			want: "SB_ACME_DAEMON_BUDGET_WINDOW must be > 0",
		},
		{
			name: "firecracker requires non negative jailer ids",
			env: map[string]string{
				"SB_ENABLE_FIRECRACKER": "true",
				"SB_JAILER_UID":         "-1",
			},
			want: "SB_JAILER_UID/SB_JAILER_GID must be >= 0",
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

func TestConfigHelperCoverage(t *testing.T) {
	t.Run("canonical_node_role", func(t *testing.T) {
		if got := canonicalNodeRole(nil); got != "" {
			t.Fatalf("canonicalNodeRole(nil) = %q, want empty", got)
		}
		if got := canonicalNodeRole([]string{NodeRoleWorker}); got != NodeRoleWorker {
			t.Fatalf("canonicalNodeRole(single) = %q", got)
		}
		if got := canonicalNodeRole([]string{NodeRoleIngress, NodeRoleWorker}); got != "ingress,worker" {
			t.Fatalf("canonicalNodeRole(multi) = %q", got)
		}
	})

	t.Run("roles_accessors", func(t *testing.T) {
		cfg := Config{NodeRole: "worker,ingress"}
		roles := cfg.Roles()
		if len(roles) != 2 || roles[0] != NodeRoleIngress || roles[1] != NodeRoleWorker {
			t.Fatalf("Roles() = %+v", roles)
		}
		cfg.NodeRole = "bogus"
		if got := cfg.Roles(); len(got) != 3 || got[0] != NodeRoleServer || got[1] != NodeRoleWorker || got[2] != NodeRoleIngress {
			t.Fatalf("Roles() fallback = %+v, want mixed expansion", got)
		}
	})

	t.Run("float_and_whitelist_parsers", func(t *testing.T) {
		t.Setenv("CFG_FLOAT", "1.25")
		if got := getEnvFloat("CFG_FLOAT", 0.5); got != 1.25 {
			t.Fatalf("getEnvFloat() = %v, want 1.25", got)
		}
		t.Setenv("CFG_FLOAT", "broken")
		if got := getEnvFloat("CFG_FLOAT", 0.5); got != 0.5 {
			t.Fatalf("getEnvFloat() fallback = %v, want 0.5", got)
		}
		got := parseImageGCWhitelist(" alpine:3.20 , , ghcr.io/acme/api ")
		if len(got) != 2 || got[0] != "alpine:3.20" || got[1] != "ghcr.io/acme/api" {
			t.Fatalf("parseImageGCWhitelist() = %+v", got)
		}
	})

	t.Run("loopback_and_advertise_host_helpers", func(t *testing.T) {
		if err := requireLoopbackAddr("X", "localhost:1234"); err != nil {
			t.Fatalf("requireLoopbackAddr(localhost) error = %v", err)
		}
		if err := requireLoopbackAddr("X", "[::1]:1234"); err != nil {
			t.Fatalf("requireLoopbackAddr(::1) error = %v", err)
		}
		if err := requireLoopbackAddr("X", ":1234"); err == nil || !strings.Contains(err.Error(), "wildcard") {
			t.Fatalf("requireLoopbackAddr(wildcard) err = %v", err)
		}
		if err := requireLoopbackAddr("X", "example.com:1234"); err == nil || !strings.Contains(err.Error(), "loopback IP") {
			t.Fatalf("requireLoopbackAddr(hostname) err = %v", err)
		}
		cases := map[string]string{
			"":                         "",
			"https://node.example:443": "node.example",
			"127.0.0.1:8443":           "127.0.0.1",
			"[::1]:8443":               "::1",
			"plain-host":               "plain-host",
			"example.com:8080":         "example.com",
		}
		for in, want := range cases {
			if got := normalizeAdvertiseHost(in); got != want {
				t.Fatalf("normalizeAdvertiseHost(%q) = %q, want %q", in, got, want)
			}
		}
	})

	t.Run("load_branch_envs", func(t *testing.T) {
		t.Setenv("SB_PAT_TOKEN", "operator-pat")
		t.Setenv("SB_ENABLE_CLUSTER", "true")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
		t.Setenv("SB_CLUSTER_INSECURE_GOSSIP", "true")
		t.Setenv("SB_CLUSTER_INSECURE_CREDENTIALS", "true")
		t.Setenv("SB_NODE_ROLE", "server,worker")
		t.Setenv("SB_DATA_PLANE_ADVERTISE_HOST", (&url.URL{Scheme: "https", Host: "edge.example:443"}).String())
		t.Setenv("SB_IDLE_TIMEOUT_MIN", "17")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.NodeRole != "server,worker" {
			t.Fatalf("NodeRole = %q, want server,worker", cfg.NodeRole)
		}
		if cfg.DataPlaneAdvertiseHost != "edge.example" {
			t.Fatalf("DataPlaneAdvertiseHost = %q, want edge.example", cfg.DataPlaneAdvertiseHost)
		}
		if cfg.IdleTimeout() != 17*time.Minute {
			t.Fatalf("IdleTimeout() = %v, want 17m", cfg.IdleTimeout())
		}
	})
}

func TestLoad_ComprehensiveEnabledConfig(t *testing.T) {
	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "credential_encryption.key")
	if err := os.WriteFile(keyPath, []byte("shared-key"), 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}

	t.Setenv("SB_PAT_TOKEN", "operator-pat")
	t.Setenv("SB_ENABLE_CLUSTER", "true")
	t.Setenv("SB_NODE_ROLE", "server,worker")
	t.Setenv("SB_BOOTSTRAP_PEERS", "https://peer-a:7000,https://peer-b:7000")
	t.Setenv("SB_GOSSIP_SECRET_KEY", "gossip-secret")
	t.Setenv("SB_CREDENTIAL_ENCRYPTION_KEY_PATH", keyPath)
	t.Setenv("SB_API_ADVERTISE_URL", "http://api.example.test:21212")
	t.Setenv("SB_CLUSTER_INTERNAL_ADVERTISE", "https://cluster.example.test:7002")
	t.Setenv("SB_ENABLE_CUSTOM_DOMAINS", "true")
	t.Setenv("SB_DOMAIN", "example.test")
	t.Setenv("SB_CUSTOM_DOMAINS_MAX_PER_SANDBOX", "3")
	t.Setenv("SB_TLS_ON_DEMAND_BURST", "10")
	t.Setenv("SB_TLS_ON_DEMAND_INTERVAL", "2m")
	t.Setenv("SB_ACME_DAEMON_BUDGET_FRACTION", "0.5")
	t.Setenv("SB_ACME_DAEMON_BUDGET_CAPACITY", "50")
	t.Setenv("SB_ACME_DAEMON_BUDGET_WINDOW", "1h")
	t.Setenv("SB_AUTO_IMPORT_ENABLED", "true")
	t.Setenv("SB_AUTO_IMPORT_HOOKS_URL", "https://hooks.example.test")
	t.Setenv("SB_AUTO_IMPORT_CLUSTER_ID", "cluster-1")
	t.Setenv("SB_AUTO_IMPORT_CLUSTER_PAT_PATH", "/tmp/cluster.pat")
	t.Setenv("SB_AUTO_IMPORT_RECONCILE_INTERVAL", "1m")
	t.Setenv("SB_AUTO_IMPORT_REQUEST_TIMEOUT", "10s")
	t.Setenv("SB_AUTO_IMPORT_MAX_IN_FLIGHT", "2")
	t.Setenv("SB_SNAPSHOT_PUSH_ENABLED", "true")
	t.Setenv("SB_SNAPSHOT_PUSH_RECONCILE_INTERVAL", "2m")
	t.Setenv("SB_SNAPSHOT_PUSH_MAX_IN_FLIGHT", "3")
	t.Setenv("SB_FLEET_ENABLED", "true")
	t.Setenv("SB_FLEET_ENDPOINT", "https://fleet.example.test")
	t.Setenv("SB_FLEET_TOKEN", "fleet-token")
	t.Setenv("SB_FLEET_CONTRACT_REFRESH", "2m")
	t.Setenv("SB_ENABLE_FIRECRACKER", "true")
	t.Setenv("SB_FIRECRACKER_USE_JAILER", "false")
	t.Setenv("SB_FIRECRACKER_VMM_POOL_ENABLED", "true")
	t.Setenv("SB_FIRECRACKER_VMM_POOL_DEPTH_DEFAULT", "2")
	t.Setenv("SB_FIRECRACKER_VMM_POOL_GC_INTERVAL", "3m")
	t.Setenv("SB_FIRECRACKER_VMM_POOL_GC_TTL", "10m")
	t.Setenv("SB_FIRECRACKER_VMM_POOL_REFILL_INTERVAL", "5s")
	t.Setenv("SB_FIRECRACKER_RSS_SAMPLER_INTERVAL", "2s")
	t.Setenv("SB_FIRECRACKER_RSS_WATERMARK_RATIO", "0.25")
	t.Setenv("SB_OTEL_METRICS_ENDPOINT", "http://collector:4318")
	t.Setenv("SB_OTEL_TRACES_ENDPOINT", "http://collector:4318")
	t.Setenv("SB_OTEL_TRACES_SAMPLE_RATIO", "0.25")
	t.Setenv("SB_IMAGE_BUILD_CONTEXT_ENABLED", "true")
	t.Setenv("SB_IMAGE_BUILD_TIMEOUT", "12m")
	t.Setenv("SB_IMAGE_BUILD_GC_INTERVAL", "6m")
	t.Setenv("SB_IMAGE_BUILD_GC_TTL", "48h")
	t.Setenv("SB_IMAGE_GC_WHITELIST", "alpine:3.20, ghcr.io/acme/base")
	t.Setenv("SB_HOST_RUNTIMES", "docker, firecracker")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.EnableCluster || !cfg.EnableCustomDomains || !cfg.AutoImportEnabled || !cfg.SnapshotPushEnabled || !cfg.FleetControlPlaneEnabled || !cfg.EnableFirecracker {
		t.Fatalf("expected enabled features in cfg, got %+v", cfg)
	}
	if cfg.DataPlaneAdvertiseHost != "api.example.test" {
		t.Fatalf("DataPlaneAdvertiseHost = %q, want api.example.test", cfg.DataPlaneAdvertiseHost)
	}
	if cfg.NodeRole != "server,worker" {
		t.Fatalf("NodeRole = %q, want server,worker", cfg.NodeRole)
	}
	if cfg.CredentialEncryptionKeyPath != keyPath {
		t.Fatalf("CredentialEncryptionKeyPath = %q, want %q", cfg.CredentialEncryptionKeyPath, keyPath)
	}
	if cfg.FleetControlPlaneEndpoint != "https://fleet.example.test" {
		t.Fatalf("FleetControlPlaneEndpoint = %q", cfg.FleetControlPlaneEndpoint)
	}
	if !cfg.OTELMetricsEnabled || !cfg.OTELTracesEnabled {
		t.Fatalf("expected OTEL enabled, got metrics=%v traces=%v", cfg.OTELMetricsEnabled, cfg.OTELTracesEnabled)
	}
	if len(cfg.ImageGCWhitelist) != 2 || len(cfg.HostSupportedRuntimes) != 2 {
		t.Fatalf("unexpected list parsing: whitelist=%v runtimes=%v", cfg.ImageGCWhitelist, cfg.HostSupportedRuntimes)
	}
}
