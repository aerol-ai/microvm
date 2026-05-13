package main

import "testing"

func TestNormalizeSandboxIDCases(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     string
	}{
		{name: "uses_trimmed_hostname", hostname: " 7f3c2a1b9d4e ", want: "7f3c2a1b9d4e"},
		{name: "blank_returns_empty", hostname: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeSandboxID(tc.hostname); got != tc.want {
				t.Fatalf("normalizeSandboxID(%q) = %q, want %q", tc.hostname, got, tc.want)
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
		{name: "heuristic_files_strip", path: "/7f3c2a1b9d4e/files", sandboxID: "", want: "/files"},
		{name: "heuristic_git_strip", path: "/7f3c2a1b9d4e/git/status", sandboxID: "", want: "/git/status"},
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
