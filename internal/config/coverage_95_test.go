package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Helpers / Load branches that sit below the 95% bar. Table-driven where the
// existing load_coverage_test.go style already fits; direct calls for the
// pure parsers that Load only exercises via the empty-default path.

func TestGetEnvInt64Coverage(t *testing.T) {
	cases := []struct {
		name string
		val  string
		want int64
	}{
		{"empty_falls_back", "", 42},
		{"whitespace_falls_back", "  ", 42},
		{"invalid_falls_back", "nope", 42},
		{"valid_parsed", "9223372036854775807", 9223372036854775807},
		{"negative_parsed", "-7", -7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_COV_INT64", tc.val)
			if got := getEnvInt64("SB_COV_INT64", 42); got != tc.want {
				t.Fatalf("getEnvInt64(%q) = %d, want %d", tc.val, got, tc.want)
			}
		})
	}
}

func TestParseWasmStandardModulesCoverage(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{"empty", "", map[string]string{}},
		{"blank_entries_skipped", " , , ", map[string]string{}},
		// Malformed entries must not poison a valid neighbor — silent skip.
		{"malformed_skipped", "noequals,=missingalias,alias=,OK=mod.wasm,UPPER=X.wasm", map[string]string{
			"ok":    "mod.wasm",
			"upper": "X.wasm",
		}},
		{"trims_and_lowercases", "  Echo = hello.wasm  ", map[string]string{"echo": "hello.wasm"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseWasmStandardModules(tc.raw)
			if len(got) != len(tc.want) {
				t.Fatalf("parseWasmStandardModules(%q) = %#v, want %#v", tc.raw, got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Fatalf("alias %q = %q, want %q (full=%#v)", k, got[k], v, got)
				}
			}
		})
	}
}

func TestDockerReadySocketDirDefaultBase(t *testing.T) {
	// Empty MountsCredentialsRuntimeDir must fall back to /run/sandboxd —
	// the non-empty path is already covered in docker_ready_socket_test.go.
	cfg := Config{}
	if got := cfg.DockerReadySocketDir(); got != "/run/sandboxd/docker/ready" {
		t.Fatalf("DockerReadySocketDir() = %q", got)
	}
}

func TestRequireLoopbackAddrMalformed(t *testing.T) {
	err := requireLoopbackAddr("SB_INTERNAL_INGRESS_ADDR", "not-host-port")
	if err == nil || !strings.Contains(err.Error(), "must be host:port") {
		t.Fatalf("err = %v, want host:port parse failure", err)
	}
}

func TestNormalizeAdvertiseHostBracketedMissingClose(t *testing.T) {
	// SplitHostPort rejects "[foo:bar" (missing ']'); the LastIndex fallback
	// still peels a single-colon host so advertise-host derivation stays useful.
	if got := normalizeAdvertiseHost("[foo:bar"); got != "foo" {
		t.Fatalf("normalizeAdvertiseHost([foo:bar) = %q, want foo", got)
	}
}

func TestGetEnvClearSentinel(t *testing.T) {
	t.Setenv("SB_COV_CLEAR", envClearSentinel)
	if got := getEnv("SB_COV_CLEAR", "/fallback"); got != "" {
		t.Fatalf("getEnv(sentinel) = %q, want empty", got)
	}
}

func TestLoad_Coverage95ValidationBranches(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "platform_volumes_missing_bucket",
			env: map[string]string{
				"SB_PLATFORM_VOLUMES_ENABLED": "true",
			},
			want: "SB_PLATFORM_VOLUMES_S3_BUCKET",
		},
		{
			name: "db_path_clear_sentinel",
			env: map[string]string{
				"SB_DB_PATH": envClearSentinel,
			},
			want: "SB_DB_PATH is required",
		},
		{
			name: "auto_import_missing_cluster_id",
			env: map[string]string{
				"SB_AUTO_IMPORT_ENABLED":   "true",
				"SB_AUTO_IMPORT_HOOKS_URL": "https://hooks.example.com",
			},
			want: "SB_AUTO_IMPORT_CLUSTER_ID",
		},
		{
			name: "auto_import_missing_pat_path",
			env: map[string]string{
				"SB_AUTO_IMPORT_ENABLED":    "true",
				"SB_AUTO_IMPORT_HOOKS_URL":  "https://hooks.example.com",
				"SB_AUTO_IMPORT_CLUSTER_ID": "cluster-1",
			},
			want: "SB_AUTO_IMPORT_CLUSTER_PAT_PATH",
		},
		{
			name: "snapshot_push_missing_pat_path",
			env: map[string]string{
				"SB_SNAPSHOT_PUSH_ENABLED":  "true",
				"SB_AUTO_IMPORT_CLUSTER_ID": "cluster-1",
			},
			want: "SB_AUTO_IMPORT_CLUSTER_PAT_PATH",
		},
		{
			name: "snapshot_push_bad_tag_suffix",
			env: map[string]string{
				"SB_SNAPSHOT_PUSH_ENABLED":        "true",
				"SB_AUTO_IMPORT_CLUSTER_ID":       "cluster-1",
				"SB_AUTO_IMPORT_CLUSTER_PAT_PATH": "/tmp/pat",
				"SB_SNAPSHOT_PUSH_TAG_SUFFIX":     "not-a-suffix",
			},
			want: "SB_SNAPSHOT_PUSH_TAG_SUFFIX",
		},
		{
			name: "docker_readiness_poll_initial_non_positive",
			env: map[string]string{
				"SB_DOCKER_READINESS_POLL_INITIAL": "0s",
			},
			want: "SB_DOCKER_READINESS_POLL_INITIAL must be > 0",
		},
		{
			name: "docker_readiness_poll_max_below_initial",
			env: map[string]string{
				"SB_DOCKER_READINESS_POLL_INITIAL": "100ms",
				"SB_DOCKER_READINESS_POLL_MAX":     "50ms",
			},
			want: "SB_DOCKER_READINESS_POLL_MAX must be >=",
		},
		{
			// normalizeHost("http://") strips the scheme and leaves ""; with
			// an empty domain that trips the public-host required check.
			name: "public_host_normalized_empty",
			env: map[string]string{
				"SB_DOMAIN":      "",
				"SB_PUBLIC_HOST": "http://",
			},
			want: "SB_PUBLIC_HOST is required when SB_DOMAIN is empty",
		},
		{
			name: "wasm_rejected_as_host_default",
			env: map[string]string{
				"SB_CONTAINER_RUNTIME": "wasm",
			},
			want: "not allowed as the host default",
		},
		{
			name: "l4_tls_listen_without_fallback",
			env: map[string]string{
				"SB_L4_TLS_LISTEN":   ":443",
				"SB_L4_TLS_FALLBACK": envClearSentinel,
			},
			want: "SB_L4_TLS_FALLBACK must be set",
		},
		{
			name: "wasm_max_instances_negative",
			env: map[string]string{
				"SB_ENABLE_WASM":        "true",
				"SB_WASM_MAX_INSTANCES": "-1",
			},
			want: "SB_WASM_MAX_INSTANCES must be >= 0",
		},
		{
			name: "wasm_default_memory_negative",
			env: map[string]string{
				"SB_ENABLE_WASM":            "true",
				"SB_WASM_DEFAULT_MEMORY_MB": "-1",
			},
			want: "SB_WASM_DEFAULT_MEMORY_MB must be >= 0",
		},
		{
			name: "wasm_checkpoint_max_parallel_negative",
			env: map[string]string{
				"SB_ENABLE_WASM":                  "true",
				"SB_WASM_CHECKPOINT_MAX_PARALLEL": "-1",
			},
			want: "SB_WASM_CHECKPOINT_MAX_PARALLEL must be >= 0",
		},
		{
			name: "wasm_pool_depth_negative",
			env: map[string]string{
				"SB_ENABLE_WASM":             "true",
				"SB_WASM_POOL_ENABLED":       "false",
				"SB_WASM_POOL_DEPTH_DEFAULT": "-1",
			},
			want: "SB_WASM_POOL_DEPTH_DEFAULT must be >= 0",
		},
		{
			name: "wasm_pool_enabled_requires_positive_depth",
			env: map[string]string{
				"SB_ENABLE_WASM":             "true",
				"SB_WASM_POOL_ENABLED":       "true",
				"SB_WASM_POOL_DEPTH_DEFAULT": "0",
			},
			want: "SB_WASM_POOL_DEPTH_DEFAULT must be > 0 when SB_WASM_POOL_ENABLED=true",
		},
		{
			name: "wasm_engine_unknown",
			env: map[string]string{
				"SB_ENABLE_WASM": "true",
				"SB_WASM_ENGINE": "lucet",
			},
			want: "SB_WASM_ENGINE=",
		},
		{
			name: "isolate_jail_uid_negative",
			env: map[string]string{
				"SB_ENABLE_ISOLATE":   "true",
				"SB_ISOLATE_JAIL_UID": "-1",
			},
			want: "SB_ISOLATE_JAIL_UID/SB_ISOLATE_JAIL_GID must be >= 0",
		},
		{
			name: "isolate_pool_enabled_requires_positive_depth",
			env: map[string]string{
				"SB_ENABLE_ISOLATE":             "true",
				"SB_ISOLATE_POOL_ENABLED":       "true",
				"SB_ISOLATE_POOL_DEPTH_DEFAULT": "0",
			},
			want: "SB_ISOLATE_POOL_DEPTH_DEFAULT must be > 0 when SB_ISOLATE_POOL_ENABLED=true",
		},
		{
			name: "firecracker_binary_cleared",
			env: map[string]string{
				"SB_ENABLE_FIRECRACKER": "true",
				"SB_FIRECRACKER_BINARY": envClearSentinel,
			},
			want: "SB_FIRECRACKER_BINARY is required",
		},
		{
			name: "firecracker_jailer_binary_cleared",
			env: map[string]string{
				"SB_ENABLE_FIRECRACKER": "true",
				"SB_JAILER_BINARY":      envClearSentinel,
			},
			want: "SB_JAILER_BINARY is required",
		},
		{
			name: "firecracker_kernel_cleared",
			env: map[string]string{
				"SB_ENABLE_FIRECRACKER": "true",
				"SB_FIRECRACKER_KERNEL": envClearSentinel,
			},
			want: "SB_FIRECRACKER_KERNEL is required",
		},
		{
			name: "firecracker_run_dir_cleared",
			env: map[string]string{
				"SB_ENABLE_FIRECRACKER":  "true",
				"SB_FIRECRACKER_RUN_DIR": envClearSentinel,
			},
			want: "SB_FIRECRACKER_RUN_DIR is required",
		},
		{
			name: "firecracker_templates_dir_cleared",
			env: map[string]string{
				"SB_ENABLE_FIRECRACKER":        "true",
				"SB_FIRECRACKER_TEMPLATES_DIR": envClearSentinel,
			},
			want: "SB_FIRECRACKER_TEMPLATES_DIR is required",
		},
		{
			name: "firecracker_jailer_chroot_cleared",
			env: map[string]string{
				"SB_ENABLE_FIRECRACKER":     "true",
				"SB_FIRECRACKER_USE_JAILER": "true",
				"SB_JAILER_CHROOT_BASE":     envClearSentinel,
			},
			want: "SB_JAILER_CHROOT_BASE is required",
		},
		{
			name: "firecracker_tap_cidr_cleared",
			env: map[string]string{
				"SB_ENABLE_FIRECRACKER":        "true",
				"SB_FIRECRACKER_TAP_BASE_CIDR": envClearSentinel,
			},
			want: "SB_FIRECRACKER_TAP_BASE_CIDR is required",
		},
		{
			name: "firecracker_skopeo_cleared",
			env: map[string]string{
				"SB_ENABLE_FIRECRACKER":     "true",
				"SB_FIRECRACKER_SKOPEO_BIN": envClearSentinel,
			},
			want: "SB_FIRECRACKER_SKOPEO_BIN is required",
		},
		{
			name: "firecracker_umoci_cleared",
			env: map[string]string{
				"SB_ENABLE_FIRECRACKER":    "true",
				"SB_FIRECRACKER_UMOCI_BIN": envClearSentinel,
			},
			want: "SB_FIRECRACKER_UMOCI_BIN is required",
		},
		{
			name: "firecracker_mkfs_cleared",
			env: map[string]string{
				"SB_ENABLE_FIRECRACKER":   "true",
				"SB_FIRECRACKER_MKFS_BIN": envClearSentinel,
			},
			want: "SB_FIRECRACKER_MKFS_BIN is required",
		},
		{
			name: "wasm_run_dir_cleared",
			env: map[string]string{
				"SB_ENABLE_WASM":  "true",
				"SB_WASM_RUN_DIR": envClearSentinel,
			},
			want: "SB_WASM_RUN_DIR is required",
		},
		{
			name: "wasm_modules_dir_cleared",
			env: map[string]string{
				"SB_ENABLE_WASM":      "true",
				"SB_WASM_MODULES_DIR": envClearSentinel,
			},
			want: "SB_WASM_MODULES_DIR is required",
		},
		{
			name: "isolate_workerd_path_cleared",
			env: map[string]string{
				"SB_ENABLE_ISOLATE":       "true",
				"SB_ISOLATE_WORKERD_PATH": envClearSentinel,
			},
			want: "SB_ISOLATE_WORKERD_PATH is required",
		},
		{
			name: "isolate_run_dir_cleared",
			env: map[string]string{
				"SB_ENABLE_ISOLATE":  "true",
				"SB_ISOLATE_RUN_DIR": envClearSentinel,
			},
			want: "SB_ISOLATE_RUN_DIR is required",
		},
		{
			name: "isolate_jail_chroot_cleared",
			env: map[string]string{
				"SB_ENABLE_ISOLATE":           "true",
				"SB_ISOLATE_USE_JAIL":         "true",
				"SB_ISOLATE_JAIL_CHROOT_BASE": envClearSentinel,
			},
			want: "SB_ISOLATE_JAIL_CHROOT_BASE is required",
		},
		{
			name: "containerd_socket_cleared",
			env: map[string]string{
				"SB_CONTAINER_ENGINE":  "containerd",
				"SB_CONTAINERD_SOCKET": envClearSentinel,
			},
			want: "SB_CONTAINERD_SOCKET is required",
		},
		{
			name: "containerd_namespace_cleared",
			env: map[string]string{
				"SB_CONTAINER_ENGINE":     "containerd",
				"SB_CONTAINERD_NAMESPACE": envClearSentinel,
			},
			want: "SB_CONTAINERD_NAMESPACE is required",
		},
		{
			name: "serverless_ingress_addr_cleared",
			env: map[string]string{
				"SB_ENABLE_SERVERLESS":     "true",
				"SB_INTERNAL_INGRESS_ADDR": envClearSentinel,
			},
			want: "SB_INTERNAL_INGRESS_ADDR must be set",
		},
		{
			name: "serverless_l4_wake_addr_cleared",
			env: map[string]string{
				"SB_ENABLE_SERVERLESS":     "true",
				"SB_INTERNAL_L4_WAKE_ADDR": envClearSentinel,
			},
			want: "SB_INTERNAL_L4_WAKE_ADDR must be set",
		},
		{
			name: "serverless_l4_wake_dir_cleared",
			env: map[string]string{
				"SB_ENABLE_SERVERLESS":    "true",
				"SB_INTERNAL_L4_WAKE_DIR": envClearSentinel,
			},
			want: "SB_INTERNAL_L4_WAKE_DIR must be set",
		},
		{
			name: "cluster_bootstrap_peers_required",
			env: map[string]string{
				"SB_ENABLE_CLUSTER":               "true",
				"SB_CLUSTER_BOOTSTRAP":            "false",
				"SB_CLUSTER_INSECURE_GOSSIP":      "true",
				"SB_CLUSTER_INSECURE_CREDENTIALS": "true",
				"SB_API_ADVERTISE_URL":            "http://10.0.0.5:21212",
			},
			want: "SB_BOOTSTRAP_PEERS is required",
		},
		{
			name: "cluster_gossip_secret_required",
			env: map[string]string{
				"SB_ENABLE_CLUSTER":               "true",
				"SB_CLUSTER_BOOTSTRAP":            "true",
				"SB_CLUSTER_INSECURE_CREDENTIALS": "true",
				"SB_API_ADVERTISE_URL":            "http://10.0.0.5:21212",
			},
			want: "SB_GOSSIP_SECRET_KEY is required",
		},
		{
			// ":" SplitHostPort-succeeds with an empty host, so advertise-host
			// derivation collapses to "" and must refuse boot rather than
			// publish a blank peer address.
			name: "cluster_data_plane_host_underivable",
			env: map[string]string{
				"SB_ENABLE_CLUSTER":               "true",
				"SB_CLUSTER_BOOTSTRAP":            "true",
				"SB_CLUSTER_INSECURE_GOSSIP":      "true",
				"SB_CLUSTER_INSECURE_CREDENTIALS": "true",
				"SB_API_ADVERTISE_URL":            ":",
			},
			want: "SB_DATA_PLANE_ADVERTISE_HOST could not be derived",
		},
		{
			name: "wasm_standard_modules_and_cache_max_bytes_load",
			env: map[string]string{
				"SB_WASM_STANDARD_MODULES": "echo=echo.wasm,time=time.wasm",
				"SB_WASM_CACHE_MAX_BYTES":  "1048576",
			},
			want: "", // success path — asserted below
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_PAT_TOKEN", "operator-pat")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			cfg, err := Load()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Load() error = %v", err)
				}
				if cfg.WasmCacheMaxBytes != 1048576 {
					t.Fatalf("WasmCacheMaxBytes = %d, want 1048576", cfg.WasmCacheMaxBytes)
				}
				if cfg.WasmStandardModules["echo"] != "echo.wasm" || cfg.WasmStandardModules["time"] != "time.wasm" {
					t.Fatalf("WasmStandardModules = %#v", cfg.WasmStandardModules)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestLoad_CredentialKeyStatNonExistError(t *testing.T) {
	// Point the key path inside a mode-000 directory so Stat fails with
	// permission denied (not IsNotExist) — the only way to reach that arm
	// without inventing a fake filesystem.
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	if err := os.Mkdir(blocked, 0o000); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) })

	t.Setenv("SB_PAT_TOKEN", "operator-pat")
	t.Setenv("SB_ENABLE_CLUSTER", "true")
	t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
	t.Setenv("SB_CLUSTER_INSECURE_GOSSIP", "true")
	t.Setenv("SB_API_ADVERTISE_URL", "http://10.0.0.5:21212")
	t.Setenv("SB_CREDENTIAL_ENCRYPTION_KEY", "")
	t.Setenv("SB_CLUSTER_INSECURE_CREDENTIALS", "")
	t.Setenv("SB_CREDENTIAL_ENCRYPTION_KEY_PATH", filepath.Join(blocked, "cred.key"))

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "stat ") {
		t.Fatalf("err = %v, want stat failure", err)
	}
}
