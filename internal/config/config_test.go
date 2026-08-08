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
			"SB_OTEL_TRACES_ENABLED",
			"SB_OTEL_TRACES_ENDPOINT",
			"SB_OTEL_TRACES_SAMPLE_RATIO",
			"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
			"OTEL_EXPORTER_OTLP_ENDPOINT",
			"OTEL_SERVICE_NAME",
			"SB_CLUSTER_MAX_AUTO_VOTERS",
			"SB_CLUSTER_CREATE_MAX_PENDING_PER_WORKER",
			"SB_IMAGE_PULL_MAX_CONCURRENT",
			"SB_IMAGE_PULL_FAILURE_BACKOFF",
			"SB_DATA_PLANE_ADVERTISE_HOST",
			"SB_CLUSTER_SHARD_AWARE_INGRESS",
			"SB_NODE_ROLE",
			"SB_ENABLE_CLUSTER",
			"SB_CLUSTER_BOOTSTRAP",
			"SB_ENABLE_SERVERLESS",
			"SB_INTERNAL_INGRESS_ADDR",
			"SB_INTERNAL_L4_WAKE_ADDR",
			"SB_INTERNAL_L4_WAKE_DIR",
			"SB_L4_WAKE_MAX_PENDING_PER_SANDBOX",
			"SB_L4_WAKE_MAX_PENDING_GLOBAL",
			"SB_L4_WAKE_MAX_ACTIVE_PER_SANDBOX",
			"SB_L4_WAKE_MAX_ACTIVE_GLOBAL",
			"SB_HTTP_WAKE_MAX_BUFFER",
			"SB_HTTP_WAKE_DIRECT_BYPASS_ENABLED",
			"SB_L4_WAKE_DIRECT_BYPASS_ENABLED",
			"SB_NETSTATS_POLL_INTERVAL",
			"SB_RECONCILE_INTERVAL",
			"SB_ENABLE_CUSTOM_DOMAINS",
			"SB_CUSTOM_DOMAINS_MAX_PER_SANDBOX",
			"SB_TLS_ON_DEMAND_BURST",
			"SB_TLS_ON_DEMAND_INTERVAL",
			"SB_ACME_DAEMON_BUDGET_FRACTION",
			"SB_ACME_DAEMON_BUDGET_WINDOW",
			"SB_ACME_DAEMON_BUDGET_CAPACITY",
			"SB_FIRECRACKER_SNAPSHOT_VERIFY_MODE",
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
				if cfg.OTELMetricsEnabled || cfg.OTELMetricsEndpoint != "" || cfg.OTELMetricsInterval != 30*time.Second || cfg.OTELTracesEnabled || cfg.OTELTracesEndpoint != "" || cfg.OTELTracesSampleRatio != 0.05 || cfg.OTELServiceName != "sandboxd" {
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
				// SB_ENABLE_SERVERLESS defaults on so the wake path is
				// armed out of the box; operators flip it off explicitly.
				if !cfg.EnableServerless {
					t.Fatalf("expected EnableServerless to default to true, got false")
				}
				if cfg.InternalIngressAddr != "127.0.0.1:21213" {
					t.Fatalf("expected default InternalIngressAddr=127.0.0.1:21213, got %q", cfg.InternalIngressAddr)
				}
				if cfg.InternalL4WakeAddr != "127.0.0.1:21214" {
					t.Fatalf("expected default InternalL4WakeAddr=127.0.0.1:21214, got %q", cfg.InternalL4WakeAddr)
				}
				if cfg.InternalL4WakeDir != "/run/sandboxd/l4wake" {
					t.Fatalf("expected default InternalL4WakeDir=/run/sandboxd/l4wake, got %q", cfg.InternalL4WakeDir)
				}
				if cfg.L4WakeMaxPendingPerSandbox != 256 {
					t.Fatalf("expected default L4WakeMaxPendingPerSandbox=256, got %d", cfg.L4WakeMaxPendingPerSandbox)
				}
				if cfg.L4WakeMaxPendingGlobal != 4096 {
					t.Fatalf("expected default L4WakeMaxPendingGlobal=4096, got %d", cfg.L4WakeMaxPendingGlobal)
				}
				if cfg.L4WakeMaxActivePerSandbox != 4096 {
					t.Fatalf("expected default L4WakeMaxActivePerSandbox=4096, got %d", cfg.L4WakeMaxActivePerSandbox)
				}
				if cfg.L4WakeMaxActiveGlobal != 65536 {
					t.Fatalf("expected default L4WakeMaxActiveGlobal=65536, got %d", cfg.L4WakeMaxActiveGlobal)
				}
				if cfg.HTTPWakeMaxBuffer != 8*1024*1024 {
					t.Fatalf("expected default HTTPWakeMaxBuffer=8MiB, got %d", cfg.HTTPWakeMaxBuffer)
				}
				if cfg.FirecrackerSnapshotVerifyMode != "once" {
					t.Fatalf("expected default FirecrackerSnapshotVerifyMode=once, got %q", cfg.FirecrackerSnapshotVerifyMode)
				}
				if !cfg.WasmPoolEnabled {
					t.Fatalf("expected default WasmPoolEnabled=true, got false")
				}
				if cfg.WasmPoolDepthDefault != 2 {
					t.Fatalf("expected default WasmPoolDepthDefault=2, got %d", cfg.WasmPoolDepthDefault)
				}
			},
		},
		{
			name: "enable_serverless_override",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_SERVERLESS", "true")
				cfg, err := Load()
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if !cfg.EnableServerless {
					t.Fatalf("expected EnableServerless=true, got false")
				}
			},
		},
		{
			name: "serverless_ingress_overrides",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_SERVERLESS", "true")
				t.Setenv("SB_INTERNAL_INGRESS_ADDR", "127.0.0.1:33333")
				t.Setenv("SB_INTERNAL_L4_WAKE_ADDR", "127.0.0.1:33334")
				t.Setenv("SB_INTERNAL_L4_WAKE_DIR", "/tmp/sandboxd-l4wake-test")
				t.Setenv("SB_L4_WAKE_MAX_PENDING_PER_SANDBOX", "17")
				t.Setenv("SB_L4_WAKE_MAX_PENDING_GLOBAL", "170")
				t.Setenv("SB_L4_WAKE_MAX_ACTIVE_PER_SANDBOX", "1700")
				t.Setenv("SB_L4_WAKE_MAX_ACTIVE_GLOBAL", "17000")
				t.Setenv("SB_HTTP_WAKE_MAX_BUFFER", "16777216")
				cfg, err := Load()
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if cfg.InternalIngressAddr != "127.0.0.1:33333" {
					t.Fatalf("expected InternalIngressAddr override, got %q", cfg.InternalIngressAddr)
				}
				if cfg.InternalL4WakeAddr != "127.0.0.1:33334" {
					t.Fatalf("expected InternalL4WakeAddr override, got %q", cfg.InternalL4WakeAddr)
				}
				if cfg.InternalL4WakeDir != "/tmp/sandboxd-l4wake-test" {
					t.Fatalf("expected InternalL4WakeDir override, got %q", cfg.InternalL4WakeDir)
				}
				if cfg.L4WakeMaxPendingPerSandbox != 17 {
					t.Fatalf("expected L4WakeMaxPendingPerSandbox override, got %d", cfg.L4WakeMaxPendingPerSandbox)
				}
				if cfg.L4WakeMaxPendingGlobal != 170 {
					t.Fatalf("expected L4WakeMaxPendingGlobal override, got %d", cfg.L4WakeMaxPendingGlobal)
				}
				if cfg.L4WakeMaxActivePerSandbox != 1700 {
					t.Fatalf("expected L4WakeMaxActivePerSandbox override, got %d", cfg.L4WakeMaxActivePerSandbox)
				}
				if cfg.L4WakeMaxActiveGlobal != 17000 {
					t.Fatalf("expected L4WakeMaxActiveGlobal override, got %d", cfg.L4WakeMaxActiveGlobal)
				}
				if cfg.HTTPWakeMaxBuffer != 16*1024*1024 {
					t.Fatalf("expected HTTPWakeMaxBuffer override, got %d", cfg.HTTPWakeMaxBuffer)
				}
			},
		},
		{
			name: "serverless_rejects_zero_buffer",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_SERVERLESS", "true")
				t.Setenv("SB_HTTP_WAKE_MAX_BUFFER", "0")
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "SB_HTTP_WAKE_MAX_BUFFER") {
					t.Fatalf("expected SB_HTTP_WAKE_MAX_BUFFER error, got %v", err)
				}
			},
		},
		{
			// The wake ingress proxies carry no auth and trust that Caddy
			// on localhost is their only client. Overriding the listen
			// address to a routable interface would silently publish an
			// unauthenticated endpoint that can wake any sandbox by ID;
			// boot must refuse rather than start in that state.
			name: "serverless_rejects_non_loopback_ingress_addr",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_SERVERLESS", "true")
				t.Setenv("SB_INTERNAL_INGRESS_ADDR", "0.0.0.0:21213")
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "SB_INTERNAL_INGRESS_ADDR") {
					t.Fatalf("expected SB_INTERNAL_INGRESS_ADDR loopback error, got %v", err)
				}
			},
		},
		{
			name: "serverless_rejects_non_loopback_l4_wake_addr",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_SERVERLESS", "true")
				t.Setenv("SB_INTERNAL_L4_WAKE_ADDR", "192.168.1.10:21214")
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "SB_INTERNAL_L4_WAKE_ADDR") {
					t.Fatalf("expected SB_INTERNAL_L4_WAKE_ADDR loopback error, got %v", err)
				}
			},
		},
		{
			// "localhost" and ::1 are both legitimate loopback bindings;
			// the validator must accept them so operators aren't forced
			// into a specific spelling.
			name: "serverless_accepts_localhost_and_ipv6_loopback",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_SERVERLESS", "true")
				t.Setenv("SB_INTERNAL_INGRESS_ADDR", "localhost:21213")
				t.Setenv("SB_INTERNAL_L4_WAKE_ADDR", "[::1]:21214")
				if _, err := Load(); err != nil {
					t.Fatalf("Load() error = %v", err)
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
			name: "rejects_unknown_wasm_module_digest_mode",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_WASM", "true")
				t.Setenv("SB_WASM_MODULE_DIGEST_MODE", "sometimes")
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "SB_WASM_MODULE_DIGEST_MODE") {
					t.Fatalf("expected wasm digest mode error, got %v", err)
				}
			},
		},
		{
			// SB_ENABLE_ISOLATE alone must load: every isolate knob has a
			// usable default so a single env var opts a host in
			// (plans/isolate-runtime.md Phase 1).
			name: "isolate_enable_loads_with_defaults",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_ISOLATE", "true")
				cfg, err := Load()
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if !cfg.EnableIsolate {
					t.Fatal("expected EnableIsolate=true")
				}
				if cfg.IsolateWorkerdPath != "/usr/local/bin/workerd" {
					t.Fatalf("IsolateWorkerdPath = %q", cfg.IsolateWorkerdPath)
				}
				if cfg.IsolateRunDir != "/run/sandboxd/isolate" {
					t.Fatalf("IsolateRunDir = %q", cfg.IsolateRunDir)
				}
				if cfg.IsolateGroupGranularity != IsolateGroupPerTenant {
					t.Fatalf("IsolateGroupGranularity = %q, want %q", cfg.IsolateGroupGranularity, IsolateGroupPerTenant)
				}
				if !cfg.IsolateUseJail {
					t.Fatal("expected IsolateUseJail=true by default (unjailed workerd is dev-only)")
				}
				if cfg.IsolateJailUID != 1000 || cfg.IsolateJailGID != 1000 {
					t.Fatalf("jail uid/gid = %d/%d, want 1000/1000", cfg.IsolateJailUID, cfg.IsolateJailGID)
				}
				if cfg.IsolateJitless {
					t.Fatal("expected IsolateJitless=false by default")
				}
			},
		},
		{
			// The host default runtime cannot be "isolate" — same rule as
			// firecracker/wasm: select it per-sandbox via the API.
			name: "rejects_isolate_as_host_default_runtime",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_CONTAINER_RUNTIME", "isolate")
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "SB_ENABLE_ISOLATE") {
					t.Fatalf("expected isolate host-default rejection, got %v", err)
				}
			},
		},
		{
			name: "rejects_unknown_isolate_group_granularity",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_ISOLATE", "true")
				t.Setenv("SB_ISOLATE_GROUP_GRANULARITY", "per-planet")
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "SB_ISOLATE_GROUP_GRANULARITY") {
					t.Fatalf("expected granularity error, got %v", err)
				}
			},
		},
		{
			name: "accepts_per_sandbox_isolate_granularity",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_ISOLATE", "true")
				t.Setenv("SB_ISOLATE_GROUP_GRANULARITY", "per-sandbox")
				cfg, err := Load()
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if cfg.IsolateGroupGranularity != IsolateGroupPerSandbox {
					t.Fatalf("IsolateGroupGranularity = %q", cfg.IsolateGroupGranularity)
				}
			},
		},
		{
			name: "isolate_workerd_path_override",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_ISOLATE", "true")
				t.Setenv("SB_ISOLATE_WORKERD_PATH", "/opt/workerd/bin/workerd")
				cfg, err := Load()
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if cfg.IsolateWorkerdPath != "/opt/workerd/bin/workerd" {
					t.Fatalf("IsolateWorkerdPath = %q", cfg.IsolateWorkerdPath)
				}
			},
		},
		{
			// A jailed-but-root workerd defeats the point of the jail; uid/gid
			// 0 is a misconfiguration, not a privilege drop.
			name: "rejects_root_isolate_jail_uid",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_ISOLATE", "true")
				t.Setenv("SB_ISOLATE_JAIL_UID", "0")
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "non-root") {
					t.Fatalf("expected non-root jail uid error, got %v", err)
				}
			},
		},
		{
			name: "isolate_jail_disabled_skips_jail_validation",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_ISOLATE", "true")
				t.Setenv("SB_ISOLATE_USE_JAIL", "false")
				t.Setenv("SB_ISOLATE_JAIL_CHROOT_BASE", "")
				if _, err := Load(); err != nil {
					t.Fatalf("Load() error = %v", err)
				}
			},
		},
		{
			name: "rejects_unknown_firecracker_snapshot_verify_mode",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_FIRECRACKER_SNAPSHOT_VERIFY_MODE", "sometimes")
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "SB_FIRECRACKER_SNAPSHOT_VERIFY_MODE") {
					t.Fatalf("expected snapshot verify mode error, got %v", err)
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
				t.Setenv("SB_OTEL_TRACES_ENDPOINT", "http://otel.example.test:4318/v1/traces")
				t.Setenv("SB_OTEL_TRACES_SAMPLE_RATIO", "0.25")
				t.Setenv("OTEL_SERVICE_NAME", "sandboxd-prod")
				t.Setenv("SB_IMAGE_PULL_MAX_CONCURRENT", "8")
				t.Setenv("SB_IMAGE_PULL_FAILURE_BACKOFF", "2m")
				t.Setenv("SB_FIRECRACKER_SNAPSHOT_VERIFY_MODE", "ALWAYS")
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
				if !cfg.OTELMetricsEnabled || cfg.OTELMetricsEndpoint != "http://otel.example.test:4318/v1/metrics" || cfg.OTELMetricsInterval != 45*time.Second || !cfg.OTELTracesEnabled || cfg.OTELTracesEndpoint != "http://otel.example.test:4318/v1/traces" || cfg.OTELTracesSampleRatio != 0.25 || cfg.OTELServiceName != "sandboxd-prod" {
					t.Fatalf("unexpected otel overrides: %+v", cfg)
				}
				if cfg.ImagePullMaxConcurrent != 8 || cfg.ImagePullFailureBackoff != 2*time.Minute {
					t.Fatalf("unexpected image pull overrides: %+v", cfg)
				}
				if cfg.FirecrackerSnapshotVerifyMode != "always" {
					t.Fatalf("expected FirecrackerSnapshotVerifyMode=always, got %q", cfg.FirecrackerSnapshotVerifyMode)
				}
			},
		},
		{
			name: "generic_otel_endpoint_enables_exporters_without_endpoint_override",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel.example.test:4318")
				cfg, err := Load()
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if !cfg.OTELMetricsEnabled || cfg.OTELMetricsEndpoint != "" || !cfg.OTELTracesEnabled || cfg.OTELTracesEndpoint != "" {
					t.Fatalf("unexpected generic otel config: %+v", cfg)
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
		{
			name: "rejects_invalid_otel_trace_sample_ratio",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_OTEL_TRACES_ENABLED", "true")
				t.Setenv("SB_OTEL_TRACES_SAMPLE_RATIO", "1.25")
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "SB_OTEL_TRACES_SAMPLE_RATIO") {
					t.Fatalf("expected trace sample ratio error, got %v", err)
				}
			},
		},
		{
			name: "direct_bypass_requires_netstats_poll_interval",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_HTTP_WAKE_DIRECT_BYPASS_ENABLED", "true")
				t.Setenv("SB_NETSTATS_POLL_INTERVAL", "0")
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "SB_NETSTATS_POLL_INTERVAL") {
					t.Fatalf("expected netstats poll interval error, got %v", err)
				}
			},
		},
		{
			name: "direct_bypass_requires_reconcile_interval",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_L4_WAKE_DIRECT_BYPASS_ENABLED", "true")
				t.Setenv("SB_RECONCILE_INTERVAL", "0")
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "SB_RECONCILE_INTERVAL") {
					t.Fatalf("expected reconcile interval error, got %v", err)
				}
			},
		},
		{
			name: "custom_domains_default_off",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				cfg, err := Load()
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if cfg.EnableCustomDomains {
					t.Fatalf("expected EnableCustomDomains default false, got true")
				}
				// Even with the gate off, the caps and TLS budget defaults
				// should be populated so downstream code can read them
				// without a feature-flag branch.
				if cfg.CustomDomainsMaxPerSandbox != 25 {
					t.Fatalf("expected default CustomDomainsMaxPerSandbox=25, got %d", cfg.CustomDomainsMaxPerSandbox)
				}
				if cfg.TLSOnDemandBurst != 5 {
					t.Fatalf("expected default TLSOnDemandBurst=5, got %d", cfg.TLSOnDemandBurst)
				}
				if cfg.TLSOnDemandInterval != time.Minute {
					t.Fatalf("expected default TLSOnDemandInterval=1m, got %s", cfg.TLSOnDemandInterval)
				}
			},
		},
		{
			name: "custom_domains_requires_domain",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_CUSTOM_DOMAINS", "true")
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "SB_DOMAIN") {
					t.Fatalf("expected SB_DOMAIN required error, got %v", err)
				}
			},
		},
		{
			name: "custom_domains_enabled_with_domain",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_CUSTOM_DOMAINS", "true")
				t.Setenv("SB_DOMAIN", "aerol.cloud")
				t.Setenv("SB_CUSTOM_DOMAINS_MAX_PER_SANDBOX", "10")
				t.Setenv("SB_TLS_ON_DEMAND_BURST", "3")
				t.Setenv("SB_TLS_ON_DEMAND_INTERVAL", "30s")
				cfg, err := Load()
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if !cfg.EnableCustomDomains {
					t.Fatalf("expected EnableCustomDomains=true")
				}
				if cfg.CustomDomainsMaxPerSandbox != 10 {
					t.Fatalf("expected CustomDomainsMaxPerSandbox=10, got %d", cfg.CustomDomainsMaxPerSandbox)
				}
				if cfg.TLSOnDemandBurst != 3 {
					t.Fatalf("expected TLSOnDemandBurst=3, got %d", cfg.TLSOnDemandBurst)
				}
				if cfg.TLSOnDemandInterval != 30*time.Second {
					t.Fatalf("expected TLSOnDemandInterval=30s, got %s", cfg.TLSOnDemandInterval)
				}
			},
		},
		{
			name: "custom_domains_rejects_zero_max_per_sandbox",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_CUSTOM_DOMAINS", "true")
				t.Setenv("SB_DOMAIN", "aerol.cloud")
				t.Setenv("SB_CUSTOM_DOMAINS_MAX_PER_SANDBOX", "0")
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "SB_CUSTOM_DOMAINS_MAX_PER_SANDBOX") {
					t.Fatalf("expected SB_CUSTOM_DOMAINS_MAX_PER_SANDBOX error, got %v", err)
				}
			},
		},
		{
			name: "custom_domains_rejects_zero_tls_burst",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_CUSTOM_DOMAINS", "true")
				t.Setenv("SB_DOMAIN", "aerol.cloud")
				t.Setenv("SB_TLS_ON_DEMAND_BURST", "0")
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "SB_TLS_ON_DEMAND_BURST") {
					t.Fatalf("expected SB_TLS_ON_DEMAND_BURST error, got %v", err)
				}
			},
		},
		{
			name: "custom_domains_rejects_zero_tls_interval",
			run: func(t *testing.T) {
				clearEnv(t)
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_ENABLE_CUSTOM_DOMAINS", "true")
				t.Setenv("SB_DOMAIN", "aerol.cloud")
				t.Setenv("SB_TLS_ON_DEMAND_INTERVAL", "0")
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), "SB_TLS_ON_DEMAND_INTERVAL") {
					t.Fatalf("expected SB_TLS_ON_DEMAND_INTERVAL error, got %v", err)
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

	t.Run("secret_provider_defaults_local", func(t *testing.T) {
		dir := t.TempDir()
		setClusterDefaults(t, filepath.Join(dir, "cred.key"))
		t.Setenv("SB_CREDENTIAL_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		t.Setenv("SB_SECRET_PROVIDER", "")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.SecretProvider != "local" {
			t.Fatalf("SecretProvider = %q, want local", cfg.SecretProvider)
		}
		if cfg.SecretAuditRetentionDays != 30 {
			t.Fatalf("SecretAuditRetentionDays = %d, want 30", cfg.SecretAuditRetentionDays)
		}
		if !cfg.EgressAttributionEnabled {
			t.Fatal("EgressAttributionEnabled default = false, want true")
		}
		if cfg.AuditRateLimitIdentity != 10 || cfg.AuditRateLimitOperator != 50 || cfg.AuditRateLimitNode != 50 {
			t.Fatalf("audit rate defaults = %v/%v/%v", cfg.AuditRateLimitIdentity, cfg.AuditRateLimitOperator, cfg.AuditRateLimitNode)
		}
	})

	t.Run("secret_provider_awskms_requires_key", func(t *testing.T) {
		dir := t.TempDir()
		setClusterDefaults(t, filepath.Join(dir, "cred.key"))
		t.Setenv("SB_CREDENTIAL_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		t.Setenv("SB_SECRET_PROVIDER", "awskms")
		t.Setenv("SB_SECRET_AWS_KMS_KEY_ID", "")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "SB_SECRET_AWS_KMS_KEY_ID") {
			t.Fatalf("expected AWS KMS key error, got %v", err)
		}
	})

	t.Run("secret_provider_vault_not_implemented", func(t *testing.T) {
		dir := t.TempDir()
		setClusterDefaults(t, filepath.Join(dir, "cred.key"))
		t.Setenv("SB_CREDENTIAL_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		t.Setenv("SB_SECRET_PROVIDER", "vault")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "not implemented") {
			t.Fatalf("expected vault not-implemented error, got %v", err)
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

	t.Run("cluster_shard_aware_ingress_opt_in_loads", func(t *testing.T) {
		setClusterDefaults(t)
		t.Setenv("SB_CLUSTER_SHARD_AWARE_INGRESS", "true")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if !cfg.ClusterShardAwareIngress {
			t.Fatal("ClusterShardAwareIngress = false, want true")
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
		// Fix 3: CreateSandboxTimeout getter.
		{
			name: "create_sandbox_timeout_zero_disables",
			run: func(t *testing.T) {
				if got := (Config{CreateSandboxTimeoutSeconds: 0}).CreateSandboxTimeout(); got != 0 {
					t.Fatalf("CreateSandboxTimeout() = %s, want 0 (disabled)", got)
				}
			},
		},
		{
			name: "create_sandbox_timeout_negative_disables",
			run: func(t *testing.T) {
				if got := (Config{CreateSandboxTimeoutSeconds: -1}).CreateSandboxTimeout(); got != 0 {
					t.Fatalf("CreateSandboxTimeout() = %s, want 0 (negative treated as disabled)", got)
				}
			},
		},
		{
			name: "create_sandbox_timeout_uses_seconds",
			run: func(t *testing.T) {
				want := 600 * time.Second
				if got := (Config{CreateSandboxTimeoutSeconds: 600}).CreateSandboxTimeout(); got != want {
					t.Fatalf("CreateSandboxTimeout() = %s, want %s", got, want)
				}
			},
		},
		{
			name: "create_sandbox_timeout_default_is_ten_minutes",
			run: func(t *testing.T) {
				t.Setenv("SB_PAT_TOKEN", "token")
				t.Setenv("SB_CREATE_TIMEOUT_SEC", "")
				cfg, err := Load()
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if cfg.CreateSandboxTimeout() != 600*time.Second {
					t.Fatalf("default CreateSandboxTimeout = %s, want 600s", cfg.CreateSandboxTimeout())
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

func TestParseMirrorUpstreams(t *testing.T) {
	cases := []struct {
		name, raw string
		want      []MirrorUpstreamMapping
	}{
		{"empty input returns empty slice", "", []MirrorUpstreamMapping{}},
		{"single pair", "ghcr.io=ghcr", []MirrorUpstreamMapping{{"ghcr.io", "ghcr"}}},
		{
			"default day-1 four upstreams",
			"ghcr.io=ghcr,gcr.io=gcr,quay.io=quay,registry.k8s.io=k8s",
			[]MirrorUpstreamMapping{
				{"ghcr.io", "ghcr"}, {"gcr.io", "gcr"}, {"quay.io", "quay"}, {"registry.k8s.io", "k8s"},
			},
		},
		{"whitespace tolerated", "  ghcr.io = ghcr , gcr.io = gcr  ", []MirrorUpstreamMapping{{"ghcr.io", "ghcr"}, {"gcr.io", "gcr"}}},
		{"malformed entries skipped silently", "ghcr.io=ghcr,bogus,quay.io=quay,=,no_value=,=no_host", []MirrorUpstreamMapping{{"ghcr.io", "ghcr"}, {"quay.io", "quay"}}},
		{"only commas and spaces returns empty", " , , , ", []MirrorUpstreamMapping{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseMirrorUpstreams(c.raw)
			if len(got) != len(c.want) {
				t.Fatalf("len = %d, want %d (%+v)", len(got), len(c.want), got)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("entry %d = %+v, want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}
