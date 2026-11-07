package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestGetSandboxOutputUnchanged is the compatibility contract for `get` once
// it also takes a kind (plans/kubectl-style-cluster-ops.md §3.3): a word
// that is not a kind is a sandbox, and `aerolvm get <sandbox>` prints, with
// and without --json, exactly what it printed before kinds existed, with the
// same exit codes. The golden files were recorded from the CLI before the
// change.
func TestGetSandboxOutputUnchanged(t *testing.T) {
	h := newHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box", Image: "python:3.12", Runtime: "docker", PublicURL: "https://box.example.com"})
	h.fake.AddSandbox(models.Sandbox{Name: "plain"})
	for _, tc := range []struct {
		args   []string
		code   int
		golden string
	}{
		{[]string{"get", "box"}, exitOK, "get-sandbox"},
		{[]string{"get", "plain"}, exitOK, "get-sandbox-plain"},
		{[]string{"get", "box", "--json"}, exitOK, "get-sandbox-json"},
		{[]string{"get", "--json", "box"}, exitOK, "get-sandbox-json"},
		{[]string{"get", "missing"}, exitError, "get-missing"},
		{[]string{"get", "missing", "--json"}, exitError, "get-missing-json"},
		{[]string{"get"}, exitUsage, "get-no-args"},
		{[]string{"get", "a", "b"}, exitUsage, "get-two-args"},
		{[]string{"get", "--nope", "box"}, exitUsage, "get-bad-flag"},
	} {
		code := h.run(tc.args...)
		if code != tc.code {
			t.Fatalf("%v = exit %d, want %d (stderr %q)", tc.args, code, tc.code, h.stderr.String())
		}
		got := fmt.Sprintf("exit %d\n--- stdout\n%s--- stderr\n%s", code, h.stdout.String(), h.stderr.String())
		checkGoldenIn(t, "compat", tc.golden+".golden", got)
	}
}

// checkGoldenIn is checkGolden for a testdata directory of its own.
func checkGoldenIn(t *testing.T, dir, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", dir, name)
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update): %v", err)
	}
	if string(want) != got {
		t.Fatalf("%s changed; review and run with -update:\n--- got\n%s--- want\n%s", name, got, want)
	}
}
