package main

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// execDuration matches the one measured field in the old output: exec
// reports its own wall time, 0 ms on a quiet machine and 1 ms or more under
// load. The compare pins it to 0, so only the shape is the contract.
var execDuration = regexp.MustCompile(`"duration_ms": [0-9]+`)

// TestOldVerbsUnchanged is the Phase 4 promise in
// plans/kubectl-style-cluster-ops.md §10: once get, describe and delete take
// sandboxes, snapshots and tokens, every verb and flag that worked before
// still parses and prints exactly what it printed, with the same exit code.
// The golden files under testdata/compat/old were recorded from the CLI at
// d48b0093, before Phase 4 touched it. Only usage that already worked (or
// already failed in a way a script may check) is here; help text and the
// overview grow with new verbs and are not part of the contract. One old
// error turned into a feature on purpose and is left out: `exec -it <sb>`
// with no command opens a shell now (it used to say "no command given").
func TestOldVerbsUnchanged(t *testing.T) {
	h := newHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box", Image: "python:3.12", Runtime: "docker", Tags: map[string]string{"app": "web"}})
	h.fake.AddSandbox(models.Sandbox{Name: "db", Image: "postgres:17", Runtime: "docker", Tags: map[string]string{"app": "db"}})
	h.fake.AddSandbox(models.Sandbox{Name: "nodes", Runtime: "docker"})
	for _, tc := range []struct {
		args   []string
		golden string
	}{
		{[]string{"list"}, "list"},
		{[]string{"list", "--json"}, "list-json"},
		{[]string{"list", "--tag", "app=web"}, "list-tag"},
		{[]string{"list", "--limit", "1", "--json"}, "list-limit-json"},
		{[]string{"list", "extra"}, "list-extra"},
		{[]string{"create", "--name", "box"}, "create-existing"},
		{[]string{"create", "--name", "box", "--json"}, "create-existing-json"},
		{[]string{"create", "positional"}, "create-positional"},
		{[]string{"get", "box", "--json"}, "get-box-json"},
		{[]string{"get", "box", "-o", "json"}, "get-box-o-json"},
		{[]string{"exec", "box", "--", "echo", "hi"}, "exec-echo"},
		{[]string{"exec", "box", "--json", "--", "echo hi"}, "exec-echo-json"},
		{[]string{"exec", "box"}, "exec-no-command"},
		{[]string{"exec", "-it", "box", "--", "echo", "hi"}, "exec-it-no-tty"},
		{[]string{"shell", "box"}, "shell-no-tty"},
		{[]string{"snapshot", "box", "snap-1"}, "snapshot"},
		{[]string{"snapshot", "box", "snap-1", "--json"}, "snapshot-json"},
		{[]string{"stop", "box"}, "stop"},
		{[]string{"start", "box", "--json"}, "start-json"},
		{[]string{"expose", "box", "8080"}, "expose"},
		{[]string{"destroy", "missing"}, "destroy-missing"},
		{[]string{"destroy", "missing", "--json"}, "destroy-missing-json"},
		{[]string{"destroy", "db"}, "destroy-db"},
		{[]string{"destroy", "box", "--json"}, "destroy-box-json"},
		{[]string{"describe"}, "describe-no-args"},
		{[]string{"delete"}, "delete-no-args"},
		{[]string{"cordon"}, "cordon-no-args"},
	} {
		code := h.run(tc.args...)
		got := fmt.Sprintf("exit %d\n--- stdout\n%s--- stderr\n%s", code, h.stdout.String(), h.stderr.String())
		got = execDuration.ReplaceAllString(got, `"duration_ms": 0`)
		checkGoldenIn(t, "compat/old", tc.golden+".golden", got)
	}
}

// TestOldTokenVerbsUnchanged is TestOldVerbsUnchanged for `aerolvm token`,
// which `get tokens` and `delete token` now share code with.
func TestOldTokenVerbsUnchanged(t *testing.T) {
	f, srv := newFakeTokenAPI(t)
	created := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	f.tokens["tok_aaaaaaaaaaaa"] = models.APIToken{ID: "tok_aaaaaaaaaaaa", Name: "ci", Role: "runner", Team: "ml",
		CreatedBy: "operator", CreatedAt: created, ExpiresAt: created.Add(90 * 24 * time.Hour)}
	h := newHarness(t)
	h.env["SB_API_URL"] = srv.URL
	for _, tc := range []struct {
		args   []string
		golden string
	}{
		{[]string{"token", "list"}, "token-list"},
		{[]string{"token", "list", "--json"}, "token-list-json"},
		{[]string{"token", "revoke", "tok_aaaaaaaaaaaa"}, "token-revoke"},
		{[]string{"token", "revoke", "tok_aaaaaaaaaaaa", "--json"}, "token-revoke-json"},
		{[]string{"token", "list"}, "token-list-empty"},
		{[]string{"token", "list", "--json"}, "token-list-empty-json"},
	} {
		code := h.run(tc.args...)
		got := strings.ReplaceAll(fmt.Sprintf("exit %d\n--- stdout\n%s--- stderr\n%s", code, h.stdout.String(), h.stderr.String()), srv.URL, "URL")
		checkGoldenIn(t, "compat/old", tc.golden+".golden", got)
	}
}
