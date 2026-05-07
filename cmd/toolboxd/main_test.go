package main

import "testing"

func TestResolveSandboxIDCases(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		hostname string
		want     string
	}{
		{name: "env_value_wins", envValue: "manual-id", hostname: "host-id", want: "manual-id"},
		{name: "hostname_fallback", envValue: "", hostname: "7f3c2a1b9d4e", want: "7f3c2a1b9d4e"},
		{name: "blank_returns_empty", envValue: "", hostname: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveSandboxID(tc.envValue, tc.hostname); got != tc.want {
				t.Fatalf("resolveSandboxID(%q, %q) = %q, want %q", tc.envValue, tc.hostname, got, tc.want)
			}
		})
	}
}

func TestNormalizeSandboxPathCases(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		sandboxID string
		want      string
	}{
		{name: "exact_prefix_root", path: "/7f3c2a1b9d4e", sandboxID: "7f3c2a1b9d4e", want: "/"},
		{name: "exact_prefix_subpath", path: "/7f3c2a1b9d4e/process/execute", sandboxID: "7f3c2a1b9d4e", want: "/process/execute"},
		{name: "heuristic_root_strip", path: "/7f3c2a1b9d4e/", sandboxID: "", want: "/"},
		{name: "heuristic_proxy_strip", path: "/7f3c2a1b9d4e/proxy/3000", sandboxID: "", want: "/proxy/3000"},
		{name: "direct_toolbox_path_kept", path: "/process/execute", sandboxID: "", want: "/process/execute"},
		{name: "direct_proxy_path_kept", path: "/proxy/3000", sandboxID: "", want: "/proxy/3000"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeSandboxPath(tc.path, tc.sandboxID); got != tc.want {
				t.Fatalf("normalizeSandboxPath(%q, %q) = %q, want %q", tc.path, tc.sandboxID, got, tc.want)
			}
		})
	}
}
