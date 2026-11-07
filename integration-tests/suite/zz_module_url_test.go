//go:build integration

package suite

// Terraform used by URL, Phase 5 (plans/kubectl-style-cluster-ops.md §7, §9
// Phase 5 row). The cluster-module-url scenario provisions through a root
// of its own, whose module block fetches Terraform/ by git URL (run.sh
// prepare_module_root): no checkout of scripts/ or setup/ is behind it, and
// the join is left to the module's default, one line per node. The last
// case grows the cluster by one machine, so the file sorts late ("zz_").

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// moduleURLTargets loads the targets and splits off the blank machines
// (Terraform nodes[].blank): plain Ubuntu, not members until a case joins
// them.
func moduleURLTargets(t *testing.T) (members, blank []harness.IntegrationNode) {
	t.Helper()
	targets := joinTokenTargets(t)
	for _, n := range targets.Nodes {
		out, err := joinNodeSSH(t, n, `grep -c "blank node: nothing installed" /var/log/aerolvm-bootstrap.log || true`)
		if err != nil {
			t.Fatalf("%s: %v: %s", n.Name, err, out)
		}
		if f := strings.Fields(out); len(f) > 0 && f[len(f)-1] != "0" {
			blank = append(blank, n)
		} else {
			members = append(members, n)
		}
	}
	return members, blank
}

// getNodesStatus parses `aerolvm get nodes` and returns each node's STATUS
// by name.
func getNodesStatus(t *testing.T) map[string]string {
	t.Helper()
	table := mustCLI(t, tokenEnv(t), "get", "nodes").stdout
	status := map[string]string{}
	for i, line := range strings.Split(strings.TrimSpace(table), "\n") {
		f := strings.Fields(line)
		if i == 0 {
			if len(f) < 3 || f[0] != "NAME" || f[2] != "STATUS" {
				t.Fatalf("get nodes header = %q", line)
			}
			continue
		}
		if len(f) >= 3 {
			status[f[0]] = f[2]
		}
	}
	return status
}

// UC-683 — the cluster came from the module fetched by URL: the scenario's
// root holds only Terraform files, its module source is a git:: URL, and
// Terraform's module manifest says it fetched the module from that URL into
// its own data folder. Every member joined with one line (the module's
// default): the seed ran install.sh init and each other node install.sh
// join, with nothing of the old two-pass join on disk.
func TestModuleURLClusterCameFromTheModuleByURL(t *testing.T) {
	harness.Require(t, sc, "UC-683")
	dataDir := filepath.Join("..", ".tf", sc.Name)
	root := filepath.Join(dataDir, "root")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read the scenario's root %s: %v", root, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !(strings.HasSuffix(name, ".tf") || name == ".terraform.lock.hcl") {
			t.Fatalf("the module-url root holds %q; it should hold only Terraform files", name)
		}
	}
	mainTF, err := os.ReadFile(filepath.Join(root, "main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mainTF), `source = "git::`) || !strings.Contains(string(mainTF), "//Terraform?ref=") {
		t.Fatalf("the root's module block does not fetch Terraform/ by git URL:\n%s", mainTF)
	}
	raw, err := os.ReadFile(filepath.Join(dataDir, "modules", "modules.json"))
	if err != nil {
		t.Fatalf("no module manifest: %v", err)
	}
	var manifest struct {
		Modules []struct{ Key, Source, Dir string } `json:"Modules"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("module manifest: %v", err)
	}
	fetched := ""
	for _, m := range manifest.Modules {
		if m.Key == "aerolvm" {
			if !strings.HasPrefix(m.Source, "git::") || !strings.HasSuffix(filepath.ToSlash(m.Dir), "modules/aerolvm/Terraform") {
				t.Fatalf("module aerolvm came from %q into %q, want a git:: URL into the data folder", m.Source, m.Dir)
			}
			fetched = m.Source
		}
	}
	if fetched == "" {
		t.Fatalf("the module manifest has no aerolvm module: %s", raw)
	}

	members, _ := moduleURLTargets(t)
	for _, n := range members {
		marker := "joined the cluster with sandboxd join"
		if n.Seed {
			marker = "seed started the cluster with sandboxd init"
		}
		out, err := joinNodeSSH(t, n, `sudo bash -c 'grep -c "`+marker+`" /var/log/aerolvm-bootstrap.log; `+
			`ls /tmp/cluster-join.sh /tmp/cluster-init.sh /tmp/aerolvm-tls-bundle.tar.gz 2>/dev/null | wc -l'`)
		if err != nil {
			t.Fatalf("%s: %v: %s", n.Name, err, out)
		}
		f := strings.Fields(out)
		if len(f) < 2 || f[len(f)-2] == "0" || f[len(f)-1] != "0" {
			t.Fatalf("%s did not join with one line (bootstrap marker count, old files): %q", n.Name, out)
		}
	}
	t.Logf("UC-683: module from %s; %d members joined with one line", fetched, len(members))
}

// UC-684 — `aerolvm get nodes` lists every member, and every one is Ready.
func TestModuleURLGetNodesAllReady(t *testing.T) {
	harness.Require(t, sc, "UC-684")
	members, _ := moduleURLTargets(t)
	c := client(t)
	status := getNodesStatus(t)
	for _, n := range members {
		id := heteroNodeID(t, c, joinTokenTargets(t), n.Name)
		s, ok := status[id]
		if !ok {
			t.Fatalf("get nodes does not list %s (%s): %v", n.Name, id, status)
		}
		if !strings.HasPrefix(s, "Ready") {
			t.Fatalf("%s (%s) is %s, want Ready", n.Name, id, s)
		}
	}
	if len(status) != len(members) {
		t.Fatalf("get nodes lists %d nodes, the scenario has %d members: %v", len(status), len(members), status)
	}
	t.Logf("UC-684: %d nodes Ready: %v", len(status), status)
}

// UC-685 — a sandbox runs on the cluster and answers exec.
func TestModuleURLSandboxAnswersExec(t *testing.T) {
	harness.Require(t, sc, "UC-685")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := sb.ExecCommand(ctx, "echo module-url-ok")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.Contains(res.Stdout, "module-url-ok") {
		t.Fatalf("exec stdout = %q", res.Stdout)
	}
	owner, _ := c.OwnerNodeID(ctx, sb.ID)
	t.Logf("UC-685: sandbox %s on %s answered exec", sb.ID, owner)
}

// UC-686 — the module made one join token per role and the seed registered
// them: reusable worker and ingress tokens that never expire, and a
// reusable server token that ends within 24 hours.
func TestModuleURLTokenPerRole(t *testing.T) {
	harness.Require(t, sc, "UC-686")
	tokens := listJoinTokens(t)
	seen := map[string]bool{}
	for _, tok := range tokens {
		if !tok.Reusable {
			continue
		}
		switch tok.Role {
		case "worker", "ingress":
			if tok.ExpiresAt == nil {
				seen[tok.Role] = true
			}
		case "server":
			if tok.ExpiresAt != nil && time.Until(*tok.ExpiresAt) <= 24*time.Hour+time.Minute {
				seen[tok.Role] = true
			}
		}
	}
	for _, role := range []string{"server", "worker", "ingress"} {
		if !seen[role] {
			t.Fatalf("no reusable %s token with the module's lifetime in %+v", role, tokens)
		}
	}
	t.Logf("UC-686: the module's three tokens are registered (%d tokens in all)", len(tokens))
}

// UC-687 — the line `aerolvm join-command` prints, run on a blank machine
// (plain Ubuntu, nothing installed), makes it one more worker: it joins
// under its host name, and `aerolvm get nodes` lists it Ready.
func TestModuleURLJoinCommandAddsAWorker(t *testing.T) {
	harness.Require(t, sc, "UC-687")
	members, blank := moduleURLTargets(t)
	if len(blank) == 0 {
		t.Skip("the scenario has no blank machine to join")
	}
	spare := blank[0]
	harness.RequireNodeSSH(t, spare)
	installer, artifacts := artifactArgs(t)
	line := mustCLI(t, tokenEnv(t), "join-command")
	_, args := joinLineArgs(t, line.stdout)
	if !strings.Contains(line.stdout, "--ca-cert-hash sha256:") {
		t.Fatalf("join-command printed %q", line.stdout)
	}
	// The printed words run unchanged. Only the installer is this build's (a
	// dev build is not on the release CDN), so its URL and the flags that
	// point it at this build's files go in front of them.
	quoted := make([]string, 0, len(artifacts)+len(args))
	for _, a := range append(append([]string{}, artifacts...), args...) {
		quoted = append(quoted, shellQuote(a))
	}
	hostname, _ := joinNodeSSH(t, spare, "hostname -s")
	hostname = strings.TrimSpace(hostname)
	out, code := runOnNode(t, spare, fmt.Sprintf("curl -fsSL %s | sudo bash -s -- %s", shellQuote(installer), strings.Join(quoted, " ")))
	if code != 0 || !strings.Contains(out, "joined the cluster as a worker node") {
		t.Fatalf("the join-command line on blank %s = %d\n%s", spare.Name, code, out)
	}
	waitMember(t, hostname, true)
	deadline := time.Now().Add(2 * time.Minute)
	for {
		status := getNodesStatus(t)
		if strings.HasPrefix(status[hostname], "Ready") {
			if len(status) != len(members)+1 {
				t.Fatalf("get nodes lists %d nodes after the join, want %d: %v", len(status), len(members)+1, status)
			}
			t.Logf("UC-687: %s joined as %s and is %s; %d nodes", spare.Name, hostname, status[hostname], len(status))
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s is %q in get nodes 2m after the join: %v", hostname, status[hostname], status)
		}
		time.Sleep(5 * time.Second)
	}
	for _, m := range listNodeViews(t, client(t)) {
		if m.NodeID == hostname && (m.Role != "worker" || m.Voter) {
			t.Fatalf("%s joined as %+v, want a worker that is not a voter", hostname, m)
		}
	}
}
