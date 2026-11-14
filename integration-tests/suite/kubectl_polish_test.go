//go:build integration

package suite

// kubectl grammar for sandboxes, snapshots and tokens, Phase 4
// (plans/kubectl-style-cluster-ops.md §3.3, §9; UC-670..676). Every case runs
// the built aerolvm binary against the live server, and runs its stable
// forms a second time through a copy named kubectl-aerolvm (how `kubectl
// aerolvm` runs it as a Krew plugin), which must answer the same.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/models"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

var (
	pluginOnce sync.Once
	pluginPath string
	pluginErr  error
)

// kubectlPluginBinary is the built aerolvm, copied under the name kubectl
// runs a plugin by.
func kubectlPluginBinary(t *testing.T) string {
	t.Helper()
	src := aerolvmBinary(t)
	pluginOnce.Do(func() {
		dir, err := os.MkdirTemp("", "kubectl-aerolvm-itest-")
		if err != nil {
			pluginErr = err
			return
		}
		pluginPath = filepath.Join(dir, "kubectl-aerolvm")
		in, err := os.Open(src)
		if err != nil {
			pluginErr = err
			return
		}
		defer in.Close()
		out, err := os.OpenFile(pluginPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			pluginErr = err
			return
		}
		if _, err := io.Copy(out, in); err != nil {
			pluginErr = err
		}
		if err := out.Close(); err != nil && pluginErr == nil {
			pluginErr = err
		}
	})
	if pluginErr != nil {
		t.Fatal(pluginErr)
	}
	return pluginPath
}

// both runs aerolvm and then kubectl-aerolvm with the same arguments and
// requires the same exit code, stdout and stderr. Use it only for forms whose
// output does not move between two reads (-o name, errors, tables with no
// AGE column).
func both(t *testing.T, env []string, args ...string) cliResult {
	t.Helper()
	a := runCLI(t, env, nil, args...)
	plugin := kubectlPluginBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	k := runBinaryIn(ctx, t, plugin, env, args...)
	if a != k {
		t.Fatalf("aerolvm %v and kubectl-aerolvm %v differ:\naerolvm: exit %d\n%s%s\nkubectl-aerolvm: exit %d\n%s%s",
			args, args, a.code, a.stdout, a.stderr, k.code, k.stdout, k.stderr)
	}
	return a
}

// runBinaryIn runs bin with exactly env, without a terminal.
func runBinaryIn(ctx context.Context, t *testing.T, bin string, env []string, args ...string) cliResult {
	t.Helper()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := cliResult{stdout: stdout.String(), stderr: stderr.String()}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		res.code = exit.ExitCode()
	case err != nil:
		t.Fatalf("%s %v: %v", filepath.Base(bin), args, err)
	}
	return res
}

// mustBoth is both, failing unless the command exits 0.
func mustBoth(t *testing.T, env []string, args ...string) cliResult {
	t.Helper()
	r := both(t, env, args...)
	if r.code != 0 {
		t.Fatalf("aerolvm %v = %d\nstdout: %s\nstderr: %s", args, r.code, r.stdout, r.stderr)
	}
	return r
}

// lines is stdout split into its non-empty lines, sorted.
func lines(out string) []string {
	var l []string
	for _, s := range strings.Split(out, "\n") {
		if s = strings.TrimSpace(s); s != "" {
			l = append(l, s)
		}
	}
	slices.Sort(l)
	return l
}

// polishFleet makes three tagged sandboxes for one case: a (app=web), b
// (app=db) and c (app=web, tier=front), all with run=<unique>, so a
// selector on run= sees only this case's sandboxes.
func polishFleet(t *testing.T) (run string, names [3]string, ids [3]string) {
	t.Helper()
	c := client(t)
	run = strings.ToLower(harness.UniqueName(sc, t))
	tags := []map[string]string{
		{"kops4": run, "app": "web"},
		{"kops4": run, "app": "db"},
		{"kops4": run, "app": "web", "tier": "front"},
	}
	for i, suffix := range []string{"a", "b", "c"} {
		names[i] = run + "-" + suffix
		sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: names[i], Tags: tags[i]})
		waitRunning(t, sb)
		ids[i] = sb.ID
	}
	return run, names, ids
}

// UC-670 — aerolvm get sandboxes: the table, -o wide, -o name, -o json and
// -o yaml show the sandboxes the API has, and `get sb <name> --json` is the
// same object as the old `get <name> --json`.
func TestKubectlGetSandboxes(t *testing.T) {
	harness.Require(t, sc, "UC-670")
	env := tokenEnv(t)
	run, names, ids := polishFleet(t)

	sel := "kops4=" + run
	if got := lines(mustBoth(t, env, "get", "sb", "-l", sel, "-o", "name").stdout); !slices.Equal(got, []string{"sandbox/" + names[0], "sandbox/" + names[1], "sandbox/" + names[2]}) {
		t.Fatalf("get sb -l %s -o name = %v", sel, got)
	}
	table := mustCLI(t, env, "get", "sandboxes", "-l", sel).stdout
	wide := mustCLI(t, env, "get", "sb", "-l", sel, "-o", "wide").stdout
	if !strings.HasPrefix(table, "NAME") || !strings.Contains(wide, "IMAGE") || !strings.Contains(wide, harness.DefaultImage) {
		t.Fatalf("tables:\n%s\n%s", table, wide)
	}
	for i := range names {
		if !strings.Contains(table, names[i]) || !strings.Contains(table, ids[i]) || !strings.Contains(table, "started") {
			t.Fatalf("get sb is missing %s (%s):\n%s", names[i], ids[i], table)
		}
	}
	// The whole fleet, unfiltered, includes this case's sandboxes too.
	if all := mustCLI(t, env, "get", "sb", "-o", "name").stdout; !strings.Contains(all, "sandbox/"+names[1]+"\n") {
		t.Fatalf("get sb -o name (every page) is missing %s", names[1])
	}

	var list struct {
		Sandboxes []models.Sandbox `json:"sandboxes"`
	}
	mustCLI(t, env, "get", "sb", "-l", sel, "-o", "json").json(t, &list)
	var got []string
	for _, sb := range list.Sandboxes {
		got = append(got, sb.ID)
	}
	slices.Sort(got)
	want := append([]string(nil), ids[:]...)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("get sb -o json = %v, want %v", got, want)
	}

	var one map[string]any
	if err := yaml.Unmarshal([]byte(mustCLI(t, env, "get", "sb", names[0], "-o", "yaml").stdout), &one); err != nil {
		t.Fatalf("get sb -o yaml is not YAML: %v", err)
	}
	if one["id"] != ids[0] || one["name"] != names[0] {
		t.Fatalf("get sb %s -o yaml = %v", names[0], one)
	}

	var oldForm, newForm models.Sandbox
	mustCLI(t, env, "get", names[0], "--json").json(t, &oldForm)
	mustCLI(t, env, "get", "sb", names[0], "--json").json(t, &newForm)
	if oldForm.ID != ids[0] || newForm.ID != oldForm.ID || newForm.Name != oldForm.Name || newForm.Image != oldForm.Image || newForm.Status != oldForm.Status {
		t.Fatalf("get sb --json %+v differs from the old get --json %+v", newForm, oldForm)
	}
	t.Logf("UC-670 PASS: get sb table/wide/name/json/yaml list %d sandboxes; kubectl-aerolvm matched", len(ids))
}

// UC-671 — aerolvm get sb -l: k=v is filtered by sandboxd, k!=v, k and !k
// by the CLI, and a set-based selector is refused with exit 2.
func TestKubectlGetSandboxesSelector(t *testing.T) {
	harness.Require(t, sc, "UC-671")
	env := tokenEnv(t)
	run, names, _ := polishFleet(t)
	for _, tc := range []struct {
		sel  string
		want []string
	}{
		{"kops4=" + run + ",app=web", []string{names[0], names[2]}},
		{"kops4==" + run + ",app!=web", []string{names[1]}},
		{"kops4=" + run + ",tier", []string{names[2]}},
		{"kops4=" + run + ",!tier", []string{names[0], names[1]}},
		{"kops4=" + run + ",app=nothing", nil},
	} {
		var want []string
		for _, n := range tc.want {
			want = append(want, "sandbox/"+n)
		}
		if got := lines(mustBoth(t, env, "get", "sb", "-l", tc.sel, "-o", "name").stdout); !slices.Equal(got, want) {
			t.Fatalf("get sb -l %s = %v, want %v", tc.sel, got, want)
		}
	}
	if r := both(t, env, "get", "sb", "-l", "app in (web,db)"); r.code != 2 || !strings.Contains(r.stderr, "set-based") {
		t.Fatalf("set-based selector = %d %q", r.code, r.stderr)
	}
	t.Log("UC-671 PASS: -l k=v, k==v, k!=v, k and !k select the right sandboxes; set-based refused")
}

// UC-672 — aerolvm describe sb shows the sandbox's ID, status and tags, and
// a word that is not a kind is still a sandbox: `describe <name>` and the
// old `get <name>` both work.
func TestKubectlDescribeSandbox(t *testing.T) {
	harness.Require(t, sc, "UC-672")
	env := tokenEnv(t)
	_, names, ids := polishFleet(t)
	out := mustCLI(t, env, "describe", "sb", names[2]).stdout
	for _, want := range []string{"Name:", names[2], "ID:", ids[2], "Status:", "started", "app=web,", "tier=front", "Network:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("describe sb %s is missing %q:\n%s", names[2], want, out)
		}
	}
	if fallback := mustCLI(t, env, "describe", names[2]).stdout; !strings.Contains(fallback, ids[2]) {
		t.Fatalf("describe %s (no kind) = %q", names[2], fallback)
	}
	if old := mustCLI(t, env, "get", names[2]).stdout; !strings.Contains(old, "id") || !strings.Contains(old, ids[2]) || !strings.Contains(old, "status") {
		t.Fatalf("old get %s = %q", names[2], old)
	}
	var obj models.Sandbox
	mustCLI(t, env, "describe", "sandbox", names[2], "-o", "json").json(t, &obj)
	if obj.ID != ids[2] || obj.Tags["tier"] != "front" {
		t.Fatalf("describe -o json = %+v", obj)
	}
	if r := both(t, env, "describe", "sb", "ghost-"+names[0]); r.code != 1 || !strings.Contains(r.stderr, "not found") {
		t.Fatalf("describe a missing sandbox = %d %q", r.code, r.stderr)
	}
	t.Log("UC-672 PASS: describe sb, describe <name> and the old get <name> all reach the sandbox")
}

// UC-673 — aerolvm delete sb destroys the sandbox (the API answers 404
// after), a repeat delete exits 0, and delete with a word that is not a kind
// is refused before anything is destroyed.
func TestKubectlDeleteSandbox(t *testing.T) {
	harness.Require(t, sc, "UC-673")
	env := tokenEnv(t)
	c := client(t)
	_, names, ids := polishFleet(t)
	if r := both(t, env, "delete", "sbx", names[0]); r.code != 2 || !strings.Contains(r.stderr, `unknown kind "sbx"`) {
		t.Fatalf("delete with an unknown kind = %d %q", r.code, r.stderr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := c.SDK().Get(ctx, ids[0]); err != nil {
		t.Fatalf("the refused delete touched %s: %v", names[0], err)
	}
	if r := mustCLI(t, env, "delete", "sb", names[1]); r.stdout != "sandbox \""+names[1]+"\" deleted\n" {
		t.Fatalf("delete sb = %q", r.stdout)
	}
	deadline := time.Now().Add(time.Minute)
	for {
		_, err := c.SDK().Get(ctx, ids[1])
		if errors.Is(err, microvm.ErrNotFound) || (err != nil && strings.Contains(strings.ToLower(err.Error()), "not found")) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandbox %s still answers after delete sb: %v", ids[1], err)
		}
		time.Sleep(2 * time.Second)
	}
	if r := mustBoth(t, env, "delete", "sandboxes", names[1]); !strings.Contains(r.stderr, "already gone") {
		t.Fatalf("repeat delete = %q %q", r.stdout, r.stderr)
	}
	var res []map[string]any
	mustCLI(t, env, "delete", "sb", names[2], "ghost-"+names[2], "--json").json(t, &res)
	if len(res) != 2 || res[0]["id"] != ids[2] || res[1]["already_gone"] != true {
		t.Fatalf("delete sb --json = %v", res)
	}
	t.Log("UC-673 PASS: delete sb destroys, repeats exit 0, a typo'd kind destroys nothing")
}

// UC-674 — aerolvm get/describe/delete snapshots, on a snapshot the old
// `aerolvm snapshot` verb made.
func TestKubectlSnapshots(t *testing.T) {
	harness.Require(t, sc, "UC-674")
	env := tokenEnv(t)
	c := client(t)
	name := strings.ToLower(harness.UniqueName(sc, t))
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: name})
	waitRunning(t, sb)
	snap := name + "-snap"
	if r := mustCLI(t, env, "snapshot", name, snap); strings.TrimSpace(r.stdout) != snap {
		t.Fatalf("snapshot = %q", r.stdout)
	}
	t.Cleanup(func() { runCLI(t, env, nil, "delete", "snap", snap) })

	// On a cluster GET /v1/snapshots lists only the answering server's own
	// store (pkg/api/v1 listSnapshots is not forwarded; TODOS.md "The
	// snapshot list is node-local on a cluster"), so a snapshot on a worker
	// is missing from it. The list checks run on a single node; the by-name
	// verbs below are forwarded to the owner and run everywhere.
	if !sc.Has(harness.CapCluster) {
		if got := mustBoth(t, env, "get", "snapshots", "-o", "name").stdout; !strings.Contains(got, "snapshot/"+snap+"\n") {
			t.Fatalf("get snapshots -o name is missing %s:\n%s", snap, got)
		}
		if table := mustCLI(t, env, "get", "snap").stdout; !strings.Contains(table, snap) || !strings.Contains(table, sb.ID) {
			t.Fatalf("get snap:\n%s", table)
		}
	}
	var obj models.SandboxSnapshot
	mustCLI(t, env, "get", "snap", snap, "-o", "json").json(t, &obj)
	if obj.Name != snap || obj.SourceSandboxID != sb.ID {
		t.Fatalf("get snap -o json = %+v", obj)
	}
	if d := mustCLI(t, env, "describe", "snapshot", snap).stdout; !strings.Contains(d, "Source sandbox:") || !strings.Contains(d, sb.ID) {
		t.Fatalf("describe snapshot:\n%s", d)
	}
	if r := mustBoth(t, env, "delete", "snap", snap); r.stdout != "snapshot \""+snap+"\" deleted\n" {
		t.Fatalf("delete snap = %q", r.stdout)
	}
	if r := both(t, env, "get", "snapshot", snap); r.code != 1 || !strings.Contains(r.stderr, "not found") {
		t.Fatalf("get a deleted snapshot = %d %q", r.code, r.stderr)
	}
	mustBoth(t, env, "delete", "snapshots", snap)
	t.Log("UC-674 PASS: get/describe/delete snapshots on a snapshot the old verb made")
}

// UC-675 — aerolvm get/describe/delete tokens on a token `aerolvm token
// create` made; delete is a revoke, and a name is never enough to delete.
func TestKubectlTokens(t *testing.T) {
	harness.Require(t, sc, "UC-675")
	env := tokenEnv(t)
	tokName := harness.TokenName("kops4")
	var created models.CreatedAPIToken
	mustCLI(t, env, "token", "create", "--name", tokName, "--role", "viewer", "--team", "kops4", "--expires-in", "1d", "--json").json(t, &created)
	if created.ID == "" {
		t.Fatal("token create returned no id")
	}
	t.Cleanup(func() { runCLI(t, env, nil, "delete", "token", created.ID) })

	if got := mustBoth(t, env, "get", "tokens", "-o", "name").stdout; !strings.Contains(got, "token/"+created.ID+"\n") {
		t.Fatalf("get tokens -o name is missing %s:\n%s", created.ID, got)
	}
	if table := mustBoth(t, env, "get", "tok", created.ID).stdout; !strings.Contains(table, tokName) || !strings.Contains(table, "viewer") {
		t.Fatalf("get tok %s:\n%s", created.ID, table)
	}
	var obj models.APIToken
	mustCLI(t, env, "get", "tokens", created.ID, "-o", "json").json(t, &obj)
	if obj.ID != created.ID || obj.Role != "viewer" || obj.Team != "kops4" {
		t.Fatalf("get tokens -o json = %+v", obj)
	}
	if d := mustCLI(t, env, "describe", "token", tokName).stdout; !strings.Contains(d, created.ID) || !strings.Contains(d, "team kops4") {
		t.Fatalf("describe token by name:\n%s", d)
	}
	if r := both(t, env, "delete", "token", tokName); r.code != 2 {
		t.Fatalf("delete token by name = %d %q, want a usage error", r.code, r.stderr)
	}
	if r := mustCLI(t, env, "delete", "token", created.ID); r.stdout != "token \""+created.ID+"\" deleted\n" {
		t.Fatalf("delete token = %q", r.stdout)
	}
	deadline := time.Now().Add(time.Minute)
	for {
		r := runCLI(t, env, nil, "get", "tokens", created.ID)
		if r.code == 1 && strings.Contains(r.stderr, "not found") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("token %s is still listed after delete: %d %q %q", created.ID, r.code, r.stdout, r.stderr)
		}
		time.Sleep(2 * time.Second)
	}
	mustBoth(t, env, "delete", "tokens", created.ID)
	t.Log("UC-675 PASS: get/describe/delete tokens; delete revokes; a name never deletes")
}

// UC-676 — aerolvm api-resources lists the four kinds and their short names,
// asking no server, and top nodes shows each node's reservations from
// /v1/capacity. On a cluster the ingress and the servers have no budget and
// show "-", and rows sort by name, so the checks look for a node that has one
// rather than at the first row.
func TestKubectlAPIResourcesAndTop(t *testing.T) {
	harness.Require(t, sc, "UC-676")
	env := tokenEnv(t)
	res := mustBoth(t, env, "api-resources", "-o", "wide").stdout
	for _, want := range []string{"nodes", "sandboxes", "sb", "snapshots", "snap", "tokens", "tok", "jointokens", "jt", "get,describe,delete"} {
		if !strings.Contains(res, want) {
			t.Fatalf("api-resources is missing %q:\n%s", want, res)
		}
	}
	// api-resources needs no login.
	// The names come sorted, so check membership, not the first line
	// (jointokens sorts before nodes).
	if r := both(t, cliEnv("XDG_CONFIG_HOME="+t.TempDir()), "api-resources", "-o", "name"); r.code != 0 ||
		!slices.Contains(lines(r.stdout), "nodes") || !slices.Contains(lines(r.stdout), "jointokens") {
		t.Fatalf("api-resources with no login = %d %q %q", r.code, r.stdout, r.stderr)
	}
	top := mustCLI(t, env, "top", "nodes").stdout
	rows := strings.Split(strings.TrimSpace(top), "\n")
	if len(rows) < 2 || !strings.HasPrefix(rows[0], "NAME") || !strings.Contains(rows[0], "CPU%") ||
		!slices.ContainsFunc(rows[1:], func(r string) bool { return strings.Contains(r, "%") }) {
		t.Fatalf("top nodes:\n%s", top)
	}
	var usage struct {
		Nodes []struct {
			Known     bool    `json:"known"`
			CPUBudget float64 `json:"cpu_budget"`
		} `json:"nodes"`
	}
	mustCLI(t, env, "top", "nodes", "-o", "json").json(t, &usage)
	known := 0
	for _, n := range usage.Nodes {
		if n.Known && n.CPUBudget > 0 {
			known++
		}
	}
	if known == 0 {
		t.Fatalf("top nodes -o json has no node with a budget: %+v", usage)
	}
	t.Logf("UC-676 PASS: api-resources (no login needed) and top nodes:\n%s", top)
}
