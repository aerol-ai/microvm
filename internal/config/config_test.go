package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadCases(t *testing.T) {
	// 6 cases
	clearEnv := func(t *testing.T) {
		t.Helper()
		keys := []string{
			"SB_PAT_TOKEN",
			"SB_API_HOST",
			"SB_API_PORT",
			"SB_DOMAIN",
			"SB_PUBLIC_HOST",
			"SB_CADDY_ADMIN_URL",
			"SB_CADDY_SERVER_ID",
			"SB_DB_PATH",
			"SB_DOCKER_NETWORK",
			"SB_TOOLBOX_BINARY_PATH",
			"SB_TOOLBOX_MOUNT_PATH",
			"SB_TOOLBOX_PORT",
			"SB_IDLE_TIMEOUT_MIN",
			"SB_CONTAINER_PRIVILEGED",
			"SB_RESOURCE_LIMITS_DISABLED",
			"SB_CONTAINER_RUNTIME",
			"SB_AUTO_RECONCILE",
			"SB_ENABLE_CADDY",
			"SB_ENABLE_NETWORK_RULES",
			"SB_LOG_LEVEL",
			"SB_SHUTDOWN_TIMEOUT",
			"SB_HTTP_CLIENT_TIMEOUT",
			"SB_OTEL_METRICS_ENABLED",
			"SB_OTEL_METRICS_ENDPOINT",
			"SB_OTEL_METRICS_INTERVAL",
			"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
			"OTEL_EXPORTER_OTLP_ENDPOINT",
			"OTEL_SERVICE_NAME",
			"SB_CLUSTER_MAX_AUTO_VOTERS",
			"SB_CLUSTER_CREATE_MAX_PENDING_PER_WORKER",
			"SB_IMAGE_PULL_MAX_CONCURRENT",
			"SB_IMAGE_PULL_FAILURE_BACKOFF",
			"SB_DATA_PLANE_ADVERTISE_HOST",
			"SB_NODE_ROLE",
			"SB_ENABLE_CLUSTER",
			"SB_CLUSTER_BOOTSTRAP",
		}
		for _, key := range keys {
			t.Setenv(key, "")
		}
	}

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "missing_pat_token_errors",
			run: func(t *testing.T) {
				clearEnv(t)
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "SB_PAT_TOKEN") {
					t.Fatalf("expected SB_PAT_TOKEN error, got %v", err)
				}
			},
		},
		{
			name: "defaults_with_required_env",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				cfg, err := Load()
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if cfg.PATToken != "token" {
					t.Fatalf("expected PATToken to be set, got %+v", cfg)
				}
				if cfg.APIHost != "0.0.0.0" || cfg.APIPort != 21212 {
					t.Fatalf("unexpected listen defaults: %+v", cfg)
				}
				if cfg.PublicHost != "127.0.0.1" || cfg.DockerNetwork != "bridge" {
					t.Fatalf("unexpected host/network defaults: %+v", cfg)
				}
				if cfg.ToolboxMountPath != "/usr/local/bin/toolboxd" || cfg.ToolboxPort != 2280 {
					t.Fatalf("unexpected toolbox defaults: %+v", cfg)
				}
				if !strings.HasSuffix(cfg.ToolboxBinaryPath, string(filepath.Separator)+"toolboxd") {
					t.Fatalf("unexpected toolbox binary path: %s", cfg.ToolboxBinaryPath)
				}
				if cfg.Runtime != "docker" {
					t.Fatalf("expected default Runtime=docker, got %q", cfg.Runtime)
				}
				if cfg.ClusterMaxAutoVoters != 5 {
					t.Fatalf("expected default ClusterMaxAutoVoters=5, got %d", cfg.ClusterMaxAutoVoters)
				}
				if cfg.ClusterCreateMaxPendingPerWorker != 32 {
					t.Fatalf("expected default ClusterCreateMaxPendingPerWorker=32, got %d", cfg.ClusterCreateMaxPendingPerWorker)
				}
				if cfg.OTELMetricsEnabled || cfg.OTELMetricsEndpoint != "" || cfg.OTELMetricsInterval != 30*time.Second || cfg.OTELServiceName != "sandboxd" {
					t.Fatalf("unexpected otel defaults: %+v", cfg)
				}
				if cfg.ImagePullMaxConcurrent != 4 || cfg.ImagePullFailureBackoff != 30*time.Second {
					t.Fatalf("unexpected image pull defaults: %+v", cfg)
				}
				if cfg.NodeRole != NodeRoleMixed {
					t.Fatalf("expected default NodeRole=%q, got %q", NodeRoleMixed, cfg.NodeRole)
				}
				if !cfg.IsServer() || !cfg.IsWorker() || !cfg.IsIngress() {
					t.Fatalf("expected mixed default to return true for all role predicates: %+v", cfg)
				}
			},
		},
		{
			name: "accepts_gvisor_runtime",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_CONTAINER_RUNTIME", "gvisor")
				cfg, err := Load()
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if cfg.Runtime != "gvisor" {
					t.Fatalf("expected Runtime=gvisor, got %q", cfg.Runtime)
				}
			},
		},
		{
			name: "rejects_unknown_runtime",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_CONTAINER_RUNTIME", "firecracker")
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "SB_CONTAINER_RUNTIME") {
					t.Fatalf("expected SB_CONTAINER_RUNTIME error, got %v", err)
				}
			},
		},
		{
			name: "normalizes_domain_and_public_host",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_DOMAIN", "https://sandbox.example.com")
				t.Setenv("SB_PUBLIC_HOST", " http://203.0.113.10 ")
				cfg, err := Load()
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if cfg.Domain != "sandbox.example.com" || cfg.PublicHost != "203.0.113.10" {
					t.Fatalf("unexpected normalized hosts: domain=%q public=%q", cfg.Domain, cfg.PublicHost)
				}
			},
		},
		{
			name: "rejects_relative_toolbox_mount_path",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_TOOLBOX_MOUNT_PATH", "toolboxd")
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "absolute path") {
					t.Fatalf("expected absolute path error, got %v", err)
				}
			},
		},
		{
			name: "parses_overrides",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_API_HOST", "127.0.0.1")
				t.Setenv("SB_API_PORT", "9001")
				t.Setenv("SB_DB_PATH", "/tmp/test.db")
				t.Setenv("SB_DOCKER_NETWORK", "runner-bridge")
				t.Setenv("SB_TOOLBOX_PORT", "41100")
				t.Setenv("SB_IDLE_TIMEOUT_MIN", "15")
				t.Setenv("SB_CONTAINER_PRIVILEGED", "true")
				t.Setenv("SB_RESOURCE_LIMITS_DISABLED", "true")
				t.Setenv("SB_AUTO_RECONCILE", "false")
				t.Setenv("SB_ENABLE_CADDY", "false")
				t.Setenv("SB_ENABLE_NETWORK_RULES", "false")
				t.Setenv("SB_CLUSTER_MAX_AUTO_VOTERS", "3")
				t.Setenv("SB_LOG_LEVEL", "DEBUG")
				t.Setenv("SB_SHUTDOWN_TIMEOUT", "25s")
				t.Setenv("SB_HTTP_CLIENT_TIMEOUT", "12s")
				t.Setenv("SB_OTEL_METRICS_ENDPOINT", "http://otel.example.test:4318/v1/metrics")
				t.Setenv("SB_OTEL_METRICS_INTERVAL", "45s")
				t.Setenv("OTEL_SERVICE_NAME", "sandboxd-prod")
				t.Setenv("SB_IMAGE_PULL_MAX_CONCURRENT", "8")
				t.Setenv("SB_IMAGE_PULL_FAILURE_BACKOFF", "2m")
				cfg, err := Load()
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if cfg.APIHost != "127.0.0.1" || cfg.APIPort != 9001 || cfg.DBPath != "/tmp/test.db" {
					t.Fatalf("unexpected override values: %+v", cfg)
				}
				if cfg.ToolboxPort != 41100 || cfg.IdleTimeoutMinutes != 15 {
					t.Fatalf("unexpected toolbox/idle values: %+v", cfg)
				}
				if !cfg.ContainerPrivileged || !cfg.ResourceLimitsOff {
					t.Fatalf("expected privileged/resource overrides: %+v", cfg)
				}
				if cfg.AutoReconcile || cfg.EnableCaddy || cfg.EnableNetworkRules {
					t.Fatalf("expected disabled bool overrides: %+v", cfg)
				}
				if cfg.ClusterMaxAutoVoters != 3 {
					t.Fatalf("expected ClusterMaxAutoVoters=3, got %d", cfg.ClusterMaxAutoVoters)
				}
				if cfg.LogLevel != "debug" || cfg.ShutdownTimeout != 25*time.Second || cfg.HTTPClientTimeout != 12*time.Second {
					t.Fatalf("unexpected log/duration overrides: %+v", cfg)
				}
				if !cfg.OTELMetricsEnabled || cfg.OTELMetricsEndpoint != "http://otel.example.test:4318/v1/metrics" || cfg.OTELMetricsInterval != 45*time.Second || cfg.OTELServiceName != "sandboxd-prod" {
					t.Fatalf("unexpected otel overrides: %+v", cfg)
				}
				if cfg.ImagePullMaxConcurrent != 8 || cfg.ImagePullFailureBackoff != 2*time.Minute {
					t.Fatalf("unexpected image pull overrides: %+v", cfg)
				}
			},
		},
		{
			name: "falls_back_on_invalid_values",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_API_PORT", "bad")
				t.Setenv("SB_TOOLBOX_PORT", "bad")
				t.Setenv("SB_IDLE_TIMEOUT_MIN", "bad")
				t.Setenv("SB_CONTAINER_PRIVILEGED", "bad")
				t.Setenv("SB_SHUTDOWN_TIMEOUT", "bad")
				cfg, err := Load()
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if cfg.APIPort != 21212 || cfg.ToolboxPort != 2280 || cfg.IdleTimeoutMinutes != 0 {
					t.Fatalf("expected numeric fallbacks, got %+v", cfg)
				}
				if cfg.ContainerPrivileged {
					t.Fatalf("expected invalid bool to fall back to false")
				}
				if cfg.ShutdownTimeout != 10*time.Second {
					t.Fatalf("expected invalid duration fallback, got %s", cfg.ShutdownTimeout)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

func TestClusterCredentialKeyValidation(t *testing.T) {
	// The cluster-mode credential-key check is the safety net for the silent
	// per-node lazy-key divergence that breaks failover for sealed registry
	// and mount creds. Cover the four matrix corners.
	setClusterDefaults := func(t *testing.T, keyPath string) {
		t.Helper()
		t.Setenv("SB_PAT_TOKEN", "token")
		t.Setenv("SB_ENABLE_CLUSTER", "true")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
		t.Setenv("SB_GOSSIP_SECRET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") // 32-byte base64
		t.Setenv("SB_CREDENTIAL_ENCRYPTION_KEY_PATH", keyPath)
		// Clear vars the test toggles per-case so previous cases don't leak.
		t.Setenv("SB_CREDENTIAL_ENCRYPTION_KEY", "")
		t.Setenv("SB_CLUSTER_INSECURE_CREDENTIALS", "")
		t.Setenv("SB_API_ADVERTISE_URL", "")
		t.Setenv("SB_DATA_PLANE_ADVERTISE_HOST", "")
	}

	t.Run("refuses_when_no_env_and_no_file", func(t *testing.T) {
		dir := t.TempDir()
		setClusterDefaults(t, filepath.Join(dir, "cred.key"))
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "SB_CREDENTIAL_ENCRYPTION_KEY") {
			t.Fatalf("expected SB_CREDENTIAL_ENCRYPTION_KEY error, got %v", err)
		}
	})

	t.Run("accepts_when_env_set", func(t *testing.T) {
		dir := t.TempDir()
		setClusterDefaults(t, filepath.Join(dir, "cred.key"))
		t.Setenv("SB_CREDENTIAL_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		if _, err := Load(); err != nil {
			t.Fatalf("Load() error = %v", err)
		}
	})

	t.Run("accepts_when_key_file_present", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "cred.key")
		if err := os.WriteFile(keyPath, []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), 0o600); err != nil {
			t.Fatalf("seed key file: %v", err)
		}
		setClusterDefaults(t, keyPath)
		if _, err := Load(); err != nil {
			t.Fatalf("Load() error = %v", err)
		}
	})

	t.Run("accepts_when_opt_out_set", func(t *testing.T) {
		dir := t.TempDir()
		setClusterDefaults(t, filepath.Join(dir, "cred.key"))
		t.Setenv("SB_CLUSTER_INSECURE_CREDENTIALS", "true")
		if _, err := Load(); err != nil {
			t.Fatalf("Load() error = %v", err)
		}
	})

	t.Run("derives_data_plane_host_from_api_advertise_url", func(t *testing.T) {
		dir := t.TempDir()
		setClusterDefaults(t, filepath.Join(dir, "cred.key"))
		t.Setenv("SB_CREDENTIAL_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		t.Setenv("SB_API_ADVERTISE_URL", "http://10.0.0.5:21212")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.DataPlaneAdvertiseHost != "10.0.0.5" {
			t.Fatalf("DataPlaneAdvertiseHost = %q", cfg.DataPlaneAdvertiseHost)
		}
	})

	t.Run("accepts_explicit_data_plane_host", func(t *testing.T) {
		dir := t.TempDir()
		setClusterDefaults(t, filepath.Join(dir, "cred.key"))
		t.Setenv("SB_CREDENTIAL_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		t.Setenv("SB_API_ADVERTISE_URL", "http://shared-api.internal:21212")
		t.Setenv("SB_DATA_PLANE_ADVERTISE_HOST", "10.0.0.7")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.DataPlaneAdvertiseHost != "10.0.0.7" {
			t.Fatalf("DataPlaneAdvertiseHost = %q", cfg.DataPlaneAdvertiseHost)
		}
	})
}

func TestNodeRoleCases(t *testing.T) {
	// Helper: a known-good cluster-mode env so role-specific cases don't
	// trip the credential/gossip/peer invariants. Each subtest tweaks only
	// what it's testing.
	setClusterDefaults := func(t *testing.T) {
		t.Helper()
		t.Setenv("SB_PAT_TOKEN", "token")
		t.Setenv("SB_ENABLE_CLUSTER", "true")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
		t.Setenv("SB_GOSSIP_SECRET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		t.Setenv("SB_CREDENTIAL_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		t.Setenv("SB_API_ADVERTISE_URL", "http://10.0.0.5:21212")
		t.Setenv("SB_NODE_ROLE", "")
	}

	t.Run("default_is_mixed_in_single_node_mode", func(t *testing.T) {
		t.Setenv("SB_PAT_TOKEN", "token")
		t.Setenv("SB_ENABLE_CLUSTER", "")
		t.Setenv("SB_NODE_ROLE", "")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.NodeRole != NodeRoleMixed {
			t.Fatalf("NodeRole = %q, want %q", cfg.NodeRole, NodeRoleMixed)
		}
	})

	t.Run("accepts_each_known_role", func(t *testing.T) {
		for _, role := range []string{NodeRoleServer, NodeRoleWorker, NodeRoleIngress, NodeRoleMixed} {
			t.Run(role, func(t *testing.T) {
				setClusterDefaults(t)
				t.Setenv("SB_NODE_ROLE", role)
				// Worker/ingress can't bootstrap; flip to a peer join for those.
				if role == NodeRoleWorker || role == NodeRoleIngress {
					t.Setenv("SB_CLUSTER_BOOTSTRAP", "false")
					t.Setenv("SB_BOOTSTRAP_PEERS", "10.0.0.1:7000")
				}
				cfg, err := Load()
				if err != nil {
					t.Fatalf("role=%q Load() error = %v", role, err)
				}
				if cfg.NodeRole != role {
					t.Fatalf("role=%q parsed as %q", role, cfg.NodeRole)
				}
			})
		}
	})

	t.Run("rejects_unknown_role", func(t *testing.T) {
		setClusterDefaults(t)
		t.Setenv("SB_NODE_ROLE", "controller")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "SB_NODE_ROLE") {
			t.Fatalf("expected SB_NODE_ROLE error, got %v", err)
		}
	})

	t.Run("lowercases_input", func(t *testing.T) {
		setClusterDefaults(t)
		t.Setenv("SB_NODE_ROLE", "Worker")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "false")
		t.Setenv("SB_BOOTSTRAP_PEERS", "10.0.0.1:7000")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.NodeRole != NodeRoleWorker {
			t.Fatalf("expected lowercase normalization, got %q", cfg.NodeRole)
		}
	})

	t.Run("non_default_role_requires_cluster_mode", func(t *testing.T) {
		t.Setenv("SB_PAT_TOKEN", "token")
		t.Setenv("SB_ENABLE_CLUSTER", "")
		t.Setenv("SB_NODE_ROLE", "worker")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "SB_ENABLE_CLUSTER") {
			t.Fatalf("expected SB_ENABLE_CLUSTER requirement error, got %v", err)
		}
	})

	t.Run("worker_cannot_bootstrap", func(t *testing.T) {
		setClusterDefaults(t)
		t.Setenv("SB_NODE_ROLE", "worker")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "SB_CLUSTER_BOOTSTRAP") {
			t.Fatalf("expected bootstrap-incompatible error, got %v", err)
		}
	})

	t.Run("ingress_cannot_bootstrap", func(t *testing.T) {
		setClusterDefaults(t)
		t.Setenv("SB_NODE_ROLE", "ingress")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "SB_CLUSTER_BOOTSTRAP") {
			t.Fatalf("expected bootstrap-incompatible error, got %v", err)
		}
	})

	t.Run("ingress_advertise_host_default_falls_back_to_public_host", func(t *testing.T) {
		c := Config{PublicHost: "203.0.113.10"}
		if got := c.EffectivePublicHost(); got != "203.0.113.10" {
			t.Fatalf("EffectivePublicHost fallback = %q, want PublicHost", got)
		}
	})

	t.Run("ingress_advertise_host_overrides_public_host", func(t *testing.T) {
		c := Config{PublicHost: "10.0.0.5", IngressAdvertiseHost: "ingress.example.com"}
		if got := c.EffectivePublicHost(); got != "ingress.example.com" {
			t.Fatalf("EffectivePublicHost override = %q, want ingress.example.com", got)
		}
	})

	t.Run("ingress_advertise_host_is_normalized_from_env", func(t *testing.T) {
		setClusterDefaults(t)
		t.Setenv("SB_INGRESS_ADVERTISE_HOST", "https://ingress.example.com:443")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.IngressAdvertiseHost != "ingress.example.com" {
			t.Fatalf("IngressAdvertiseHost = %q, want host-only normalization", cfg.IngressAdvertiseHost)
		}
	})

	t.Run("helpers_match_role", func(t *testing.T) {
		cases := []struct {
			role                            string
			wantServer, wantWorker, wantIng bool
		}{
			// Legacy single-role truth table — bit-for-bit unchanged.
			{NodeRoleMixed, true, true, true},
			{NodeRoleServer, true, false, false},
			{NodeRoleWorker, false, true, false},
			{NodeRoleIngress, false, false, true},
			// Hybrid combinations — caller may have already canonicalised via
			// Load() or may be constructing the Config{} by hand in tests.
			// Both forms must work, so include unsorted inputs too.
			{"worker,ingress", false, true, true},
			{"ingress,worker", false, true, true},
			{"server,worker", true, true, false},
			{"server,ingress", true, false, true},
			{"server,worker,ingress", true, true, true},
			// An empty NodeRole on a hand-built Config{} should degrade to
			// mixed (every gate on) rather than silently turning all the
			// startup work off.
			{"", true, true, true},
		}
		for _, tc := range cases {
			c := Config{NodeRole: tc.role}
			if c.IsServer() != tc.wantServer || c.IsWorker() != tc.wantWorker || c.IsIngress() != tc.wantIng {
				t.Fatalf("role=%q: IsServer=%v IsWorker=%v IsIngress=%v (want %v %v %v)",
					tc.role, c.IsServer(), c.IsWorker(), c.IsIngress(),
					tc.wantServer, tc.wantWorker, tc.wantIng)
			}
		}
	})

	t.Run("accepts_hybrid_worker_ingress", func(t *testing.T) {
		setClusterDefaults(t)
		t.Setenv("SB_NODE_ROLE", "worker,ingress")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "false")
		t.Setenv("SB_BOOTSTRAP_PEERS", "10.0.0.1:7000")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		// Canonical form is sorted, so "worker,ingress" becomes "ingress,worker".
		if cfg.NodeRole != "ingress,worker" {
			t.Fatalf("NodeRole = %q, want %q", cfg.NodeRole, "ingress,worker")
		}
		if cfg.IsServer() || !cfg.IsWorker() || !cfg.IsIngress() {
			t.Fatalf("IsServer=%v IsWorker=%v IsIngress=%v (want false/true/true)",
				cfg.IsServer(), cfg.IsWorker(), cfg.IsIngress())
		}
	})

	t.Run("accepts_hybrid_server_worker", func(t *testing.T) {
		setClusterDefaults(t)
		t.Setenv("SB_NODE_ROLE", "server,worker")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.NodeRole != "server,worker" {
			t.Fatalf("NodeRole = %q, want %q", cfg.NodeRole, "server,worker")
		}
		if !cfg.IsServer() || !cfg.IsWorker() || cfg.IsIngress() {
			t.Fatalf("IsServer=%v IsWorker=%v IsIngress=%v (want true/true/false)",
				cfg.IsServer(), cfg.IsWorker(), cfg.IsIngress())
		}
	})

	t.Run("accepts_hybrid_server_ingress", func(t *testing.T) {
		setClusterDefaults(t)
		t.Setenv("SB_NODE_ROLE", "server,ingress")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.NodeRole != "ingress,server" {
			t.Fatalf("NodeRole = %q, want %q", cfg.NodeRole, "ingress,server")
		}
		if !cfg.IsServer() || cfg.IsWorker() || !cfg.IsIngress() {
			t.Fatalf("IsServer=%v IsWorker=%v IsIngress=%v (want true/false/true)",
				cfg.IsServer(), cfg.IsWorker(), cfg.IsIngress())
		}
	})

	t.Run("hybrid_dedupes_and_normalises_case", func(t *testing.T) {
		setClusterDefaults(t)
		// Mixed case + duplicate + extra whitespace: all should collapse to
		// the canonical sorted form.
		t.Setenv("SB_NODE_ROLE", "Worker,WORKER,ingress")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "false")
		t.Setenv("SB_BOOTSTRAP_PEERS", "10.0.0.1:7000")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.NodeRole != "ingress,worker" {
			t.Fatalf("NodeRole = %q, want %q", cfg.NodeRole, "ingress,worker")
		}
	})

	t.Run("hybrid_trims_whitespace", func(t *testing.T) {
		setClusterDefaults(t)
		t.Setenv("SB_NODE_ROLE", "  worker , ingress  ")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "false")
		t.Setenv("SB_BOOTSTRAP_PEERS", "10.0.0.1:7000")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.NodeRole != "ingress,worker" {
			t.Fatalf("NodeRole = %q, want %q", cfg.NodeRole, "ingress,worker")
		}
	})

	t.Run("rejects_mixed_combined_with_other", func(t *testing.T) {
		setClusterDefaults(t)
		t.Setenv("SB_NODE_ROLE", "mixed,worker")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), NodeRoleMixed) {
			t.Fatalf("expected error mentioning %q, got %v", NodeRoleMixed, err)
		}
	})

	t.Run("rejects_hybrid_with_unknown_token", func(t *testing.T) {
		setClusterDefaults(t)
		t.Setenv("SB_NODE_ROLE", "worker,controller")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "controller") {
			t.Fatalf("expected error naming bad token %q, got %v", "controller", err)
		}
	})

	t.Run("rejects_empty_token", func(t *testing.T) {
		setClusterDefaults(t)
		t.Setenv("SB_NODE_ROLE", "worker,,ingress")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "empty token") {
			t.Fatalf("expected empty-token error, got %v", err)
		}
	})

	t.Run("hybrid_without_server_cannot_bootstrap", func(t *testing.T) {
		setClusterDefaults(t)
		t.Setenv("SB_NODE_ROLE", "worker,ingress")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "SB_CLUSTER_BOOTSTRAP") {
			t.Fatalf("expected bootstrap-incompatible error, got %v", err)
		}
	})

	t.Run("hybrid_with_server_can_bootstrap", func(t *testing.T) {
		setClusterDefaults(t)
		t.Setenv("SB_NODE_ROLE", "server,worker")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if !cfg.ClusterBootstrap {
			t.Fatalf("expected ClusterBootstrap=true")
		}
	})

	t.Run("hybrid_requires_cluster_mode", func(t *testing.T) {
		t.Setenv("SB_PAT_TOKEN", "token")
		t.Setenv("SB_ENABLE_CLUSTER", "")
		t.Setenv("SB_NODE_ROLE", "worker,ingress")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "SB_ENABLE_CLUSTER") {
			t.Fatalf("expected SB_ENABLE_CLUSTER requirement error, got %v", err)
		}
	})
}

func TestConfigMethodCases(t *testing.T) {
	// 5 cases
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "listen_addr_uses_host_and_port",
			run: func(t *testing.T) {
				cfg := Config{APIHost: "127.0.0.1", APIPort: 9090}
				if got := cfg.ListenAddr(); got != "127.0.0.1:9090" {
					t.Fatalf("ListenAddr() = %q", got)
				}
			},
		},
		{
			name: "domain_mode_true_when_domain_present",
			run: func(t *testing.T) {
				if !(Config{Domain: "sandbox.example.com"}).DomainMode() {
					t.Fatalf("expected DomainMode() to be true")
				}
			},
		},
		{
			name: "domain_mode_false_when_domain_missing",
			run: func(t *testing.T) {
				if (Config{}).DomainMode() {
					t.Fatalf("expected DomainMode() to be false")
				}
			},
		},
		{
			name: "idle_timeout_zero_when_disabled",
			run: func(t *testing.T) {
				if got := (Config{IdleTimeoutMinutes: 0}).IdleTimeout(); got != 0 {
					t.Fatalf("IdleTimeout() = %s", got)
				}
			},
		},
		{
			name: "idle_timeout_uses_minutes",
			run: func(t *testing.T) {
				if got := (Config{IdleTimeoutMinutes: 3}).IdleTimeout(); got != 3*time.Minute {
					t.Fatalf("IdleTimeout() = %s", got)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

func TestEnvHelperCases(t *testing.T) {
	// 5 cases
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "get_env_uses_fallback",
			run: func(t *testing.T) {
				t.Setenv("TEST_ENV_VALUE", "")
				if got := getEnv("TEST_ENV_VALUE", "fallback"); got != "fallback" {
					t.Fatalf("getEnv() = %q", got)
				}
			},
		},
		{
			name: "get_env_trims_value",
			run: func(t *testing.T) {
				t.Setenv("TEST_ENV_VALUE", " value ")
				if got := getEnv("TEST_ENV_VALUE", "fallback"); got != "value" {
					t.Fatalf("getEnv() = %q", got)
				}
			},
		},
		{
			name: "get_env_int_parses_valid_value",
			run: func(t *testing.T) {
				t.Setenv("TEST_ENV_INT", "42")
				if got := getEnvInt("TEST_ENV_INT", 7); got != 42 {
					t.Fatalf("getEnvInt() = %d", got)
				}
			},
		},
		{
			name: "get_env_int_falls_back_on_invalid",
			run: func(t *testing.T) {
				t.Setenv("TEST_ENV_INT", "oops")
				if got := getEnvInt("TEST_ENV_INT", 7); got != 7 {
					t.Fatalf("getEnvInt() = %d", got)
				}
			},
		},
		{
			name: "get_env_bool_parses_valid_value",
			run: func(t *testing.T) {
				t.Setenv("TEST_ENV_BOOL", "true")
				if got := getEnvBool("TEST_ENV_BOOL", false); !got {
					t.Fatalf("getEnvBool() = %v", got)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

func TestDurationAndNormalizeCases(t *testing.T) {
	// 2 cases
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "get_env_duration_parses_valid_value",
			run: func(t *testing.T) {
				t.Setenv("TEST_ENV_DURATION", "30s")
				if got := getEnvDuration("TEST_ENV_DURATION", time.Second); got != 30*time.Second {
					t.Fatalf("getEnvDuration() = %s", got)
				}
			},
		},
		{
			name: "normalize_host_strips_scheme_and_trailing_whitespace",
			run: func(t *testing.T) {
				if got := normalizeHost("https://sandbox.example.com "); got != "sandbox.example.com" {
					t.Fatalf("normalizeHost() = %q", got)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}
