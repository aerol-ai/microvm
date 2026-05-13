package main

import "testing"

func TestGitCloneURLAndAuthEnvUsesSanitizedURL(t *testing.T) {
	cloneURL, env := gitCloneURLAndAuthEnv("https://example.com/org/repo.git", "user", "pass")
	if cloneURL != "https://example.com/org/repo.git" {
		t.Fatalf("cloneURL = %q", cloneURL)
	}
	if len(env) != 3 {
		t.Fatalf("env length = %d, want 3", len(env))
	}
	if env[0] != "GIT_CONFIG_COUNT=1" || env[1] != "GIT_CONFIG_KEY_0=http.extraHeader" {
		t.Fatalf("unexpected git config env: %+v", env)
	}
	if env[2] != "GIT_CONFIG_VALUE_0=Authorization: Basic dXNlcjpwYXNz" {
		t.Fatalf("unexpected auth header env: %q", env[2])
	}
}

func TestGitCloneURLAndAuthEnvExtractsEmbeddedCredentials(t *testing.T) {
	cloneURL, env := gitCloneURLAndAuthEnv("https://user:pass@example.com/org/repo.git", "", "")
	if cloneURL != "https://example.com/org/repo.git" {
		t.Fatalf("cloneURL = %q", cloneURL)
	}
	if len(env) != 3 || env[2] != "GIT_CONFIG_VALUE_0=Authorization: Basic dXNlcjpwYXNz" {
		t.Fatalf("unexpected env: %+v", env)
	}
}

func TestGitCloneURLAndAuthEnvLeavesSSHURLAlone(t *testing.T) {
	rawURL := "git@github.com:aerol-ai/microvm.git"
	cloneURL, env := gitCloneURLAndAuthEnv(rawURL, "user", "pass")
	if cloneURL != rawURL {
		t.Fatalf("cloneURL = %q, want %q", cloneURL, rawURL)
	}
	if len(env) != 0 {
		t.Fatalf("env = %+v, want empty", env)
	}
}
