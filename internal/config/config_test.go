package config

import (
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
				t.Setenv("SB_LOG_LEVEL", "DEBUG")
				t.Setenv("SB_SHUTDOWN_TIMEOUT", "25s")
				t.Setenv("SB_HTTP_CLIENT_TIMEOUT", "12s")
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
				if cfg.LogLevel != "debug" || cfg.ShutdownTimeout != 25*time.Second || cfg.HTTPClientTimeout != 12*time.Second {
					t.Fatalf("unexpected log/duration overrides: %+v", cfg)
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
