//go:build integration

package suite

// One-line joins, Phase 2b (plans/kubectl-style-cluster-ops.md §4, §4.2,
// §7, §9 Phase 2 row). The cluster-join-token scenario builds every node
// from blank Ubuntu with the one-line installer and Terraform's token per
// role (Terraform one_line_join): no S3 hand-off, no CSR loop, no scp.
// UC-620 proves that is how each node got in, UC-623 that certs renew by
// themselves with 10-minute certs (SB_CLUSTER_NODE_CERT_TTL=10m). The
// disruptive cases (refused tokens, a deleted worker joining again,
// join-command as typed) are in zz_join_token_test.go.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// joinTokenTargets loads the targets and skips unless the scenario joined
// its nodes with tokens.
func joinTokenTargets(t *testing.T) *harness.IntegrationTargets {
	t.Helper()
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	return targets
}

// expectedJoinRole is the role a node's cert names (DNS:role:<role>), from
// its Terraform role.
func expectedJoinRole(role string) string {
	parts := strings.Split(strings.ReplaceAll(role, " ", ""), ",")
	has := func(p string) bool {
		for _, x := range parts {
			if x == p {
				return true
			}
		}
		return false
	}
	switch {
	case role == "mixed" || has("server"):
		return "server"
	case has("worker"):
		return "worker"
	}
	return "ingress"
}

// nodeSSH runs script on node as the ubuntu user.
func joinNodeSSH(t *testing.T, node harness.IntegrationNode, script string) (string, error) {
	t.Helper()
	target, ok := harness.SSHTarget(node)
	if !ok {
		t.Fatalf("node %s has no SSH address", node.Name)
	}
	return harness.SSHRun(t, target, script)
}

// certFacts reads a node's cert: serial, life and SANs.
type certFacts struct {
	serial    string
	notBefore time.Time
	notAfter  time.Time
	sans      string
}

func readNodeCert(t *testing.T, node harness.IntegrationNode) (certFacts, error) {
	t.Helper()
	out, err := joinNodeSSH(t, node, `sudo bash -c 'set -a; . /etc/sandboxd/sandboxd.env 2>/dev/null; . /etc/sandboxd/cluster.env; set +a; `+
		`c="${SB_CLUSTER_TLS_DIR:-/etc/sandboxd/tls}/node.crt"; openssl x509 -in "$c" -noout -serial -startdate -enddate; `+
		`echo "SANS=$(openssl x509 -in "$c" -noout -ext subjectAltName | tr -d "\n ")"'`)
	if err != nil {
		return certFacts{}, fmt.Errorf("%s: %v: %s", node.Name, err, out)
	}
	var f certFacts
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "serial="):
			f.serial = strings.TrimPrefix(line, "serial=")
		case strings.HasPrefix(line, "notBefore="):
			f.notBefore, _ = time.Parse("Jan _2 15:04:05 2006 MST", strings.TrimPrefix(line, "notBefore="))
		case strings.HasPrefix(line, "notAfter="):
			f.notAfter, _ = time.Parse("Jan _2 15:04:05 2006 MST", strings.TrimPrefix(line, "notAfter="))
		case strings.HasPrefix(line, "SANS="):
			f.sans = strings.TrimPrefix(line, "SANS=")
		}
	}
	if f.serial == "" || f.notAfter.IsZero() {
		return f, fmt.Errorf("%s: unreadable cert: %s", node.Name, out)
	}
	return f, nil
}

// joinTokenView is one token in `aerolvm get jointokens -o json`.
type joinTokenView struct {
	ID        string     `json:"id"`
	Role      string     `json:"role"`
	ExpiresAt *time.Time `json:"expires_at"`
	Reusable  bool       `json:"reusable"`
	Expired   bool       `json:"expired"`
	UsedBy    []struct {
		NodeID string `json:"node_id"`
	} `json:"used_by"`
}

func listJoinTokens(t *testing.T) []joinTokenView {
	t.Helper()
	r := mustCLI(t, tokenEnv(t), "get", "jointokens", "-o", "json")
	var out struct {
		Tokens []joinTokenView `json:"tokens"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil {
		// One token prints bare; this cluster has at least three.
		t.Fatalf("get jointokens -o json: %v\n%s", err, r.stdout)
	}
	return out.Tokens
}

// UC-620 — every node joined with a token through the one-line installer:
// its bootstrap ran install.sh init (seed) or install.sh join, its
// cluster.env is the one sandboxd init/join wrote, its cert names the
// token's role, nothing of the old two-pass join ran, and each of
// Terraform's three per-role tokens lists exactly the nodes of its role.
func TestJoinTokenEveryNodeJoinedWithAToken(t *testing.T) {
	harness.Require(t, sc, "UC-620")
	targets := joinTokenTargets(t)
	c := client(t)
	members := listNodeViews(t, c)
	if want := os.Getenv("AEROL_EXPECTED_MEMBERS"); want != "" && fmt.Sprint(len(members)) != want {
		t.Fatalf("%d members, want %s", len(members), want)
	}
	byRole := map[string][]string{}
	for _, n := range targets.Nodes {
		role := expectedJoinRole(n.Role)
		id := heteroNodeID(t, c, targets, n.Name)
		byRole[role] = append(byRole[role], id)
		marker := "joined the cluster with sandboxd join"
		if n.Seed {
			marker = "seed started the cluster with sandboxd init"
		}
		out, err := joinNodeSSH(t, n, `sudo bash -c 'grep -c "`+marker+`" /var/log/aerolvm-bootstrap.log; `+
			`grep -c "Managed by sandboxd init / sandboxd join" /etc/sandboxd/cluster.env; `+
			`ls /tmp/cluster-join.sh /tmp/cluster-init.sh /tmp/aerolvm-tls-bundle.tar.gz 2>/dev/null | wc -l'`)
		if err != nil {
			t.Fatalf("%s: %v: %s", n.Name, err, out)
		}
		fields := strings.Fields(out)
		if len(fields) < 3 || fields[len(fields)-3] == "0" || fields[len(fields)-2] == "0" || fields[len(fields)-1] != "0" {
			t.Fatalf("%s did not join with the one-line installer (bootstrap marker, cluster.env header, old files): %q", n.Name, out)
		}
		cert, err := readNodeCert(t, n)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(cert.sans, "DNS:role:"+role) || !strings.Contains(cert.sans, "DNS:node:"+id) {
			t.Fatalf("%s cert SANs %q, want role:%s and node:%s", n.Name, cert.sans, role, id)
		}
		t.Logf("%s (%s): joined by token, cert names role %s, life %s", n.Name, id, role, cert.notAfter.Sub(cert.notBefore))
	}
	// The servers are all voters; no other role is.
	for _, m := range members {
		if !m.Alive {
			t.Fatalf("member %s is not alive", m.NodeID)
		}
		if m.Voter != containsString(byRole["server"], m.NodeID) {
			t.Fatalf("member %s (%s) voter=%t", m.NodeID, m.Role, m.Voter)
		}
	}
	// Terraform's tokens: worker and ingress never expire and are reusable;
	// the server one expires; each lists the nodes of its role.
	tokens := listJoinTokens(t)
	for _, role := range []string{"server", "worker", "ingress"} {
		want := byRole[role]
		if role == "server" {
			want = withoutString(want, heteroNodeID(t, c, targets, seedName(targets)))
		}
		found := false
		for _, tok := range tokens {
			var used []string
			for _, u := range tok.UsedBy {
				used = append(used, u.NodeID)
			}
			if tok.Role != role || !tok.Reusable || len(used) == 0 {
				continue
			}
			found = true
			for _, id := range want {
				if !containsString(used, id) {
					t.Fatalf("%s token %s was used by %v, not by %s", role, tok.ID, used, id)
				}
			}
			if (role == "server") != (tok.ExpiresAt != nil) {
				t.Fatalf("%s token %s expires at %v", role, tok.ID, tok.ExpiresAt)
			}
		}
		if !found && len(want) > 0 {
			t.Fatalf("no reusable %s token used by %v in %+v", role, want, tokens)
		}
	}
}

func seedName(targets *harness.IntegrationTargets) string {
	for _, n := range targets.Nodes {
		if n.Seed {
			return n.Name
		}
	}
	return ""
}

// UC-623 — node certs renew themselves (D6, §4.2): with
// SB_CLUSTER_NODE_CERT_TTL=10m every cert lives about 15 minutes (10m plus
// the 5m backdate), and within 15 minutes a server's and a worker's cert
// are replaced by new ones for the same node and role, with no restart; the
// cluster keeps placing sandboxes on the worker afterwards.
func TestJoinTokenCertsRenewThemselves(t *testing.T) {
	harness.Require(t, sc, "UC-623")
	targets := joinTokenTargets(t)
	c := client(t)
	var watch []harness.IntegrationNode
	for _, role := range []string{"server", "worker"} {
		for _, n := range targets.Nodes {
			if !n.Seed && expectedJoinRole(n.Role) == role {
				watch = append(watch, n)
				break
			}
		}
	}
	if len(watch) != 2 {
		t.Skipf("needs a joined server and worker, have %d", len(watch))
	}
	before := map[string]certFacts{}
	pids := map[string]string{}
	for _, n := range watch {
		f, err := readNodeCert(t, n)
		if err != nil {
			t.Fatal(err)
		}
		if life := f.notAfter.Sub(f.notBefore); life > 16*time.Minute {
			t.Fatalf("%s cert lives %s; SB_CLUSTER_NODE_CERT_TTL=10m should make it about 15m", n.Name, life)
		}
		before[n.Name] = f
		pid, _ := joinNodeSSH(t, n, "systemctl show -p MainPID --value sandboxd")
		pids[n.Name] = strings.TrimSpace(pid)
	}
	deadline := time.Now().Add(15 * time.Minute)
	renewed := map[string]bool{}
	for len(renewed) < len(watch) && time.Now().Before(deadline) {
		time.Sleep(30 * time.Second)
		for _, n := range watch {
			if renewed[n.Name] {
				continue
			}
			f, err := readNodeCert(t, n)
			if err != nil {
				t.Logf("read %s: %v", n.Name, err)
				continue
			}
			if f.serial != before[n.Name].serial && f.notAfter.After(before[n.Name].notAfter) {
				if f.sans != before[n.Name].sans {
					t.Fatalf("%s renewed cert names %q, was %q", n.Name, f.sans, before[n.Name].sans)
				}
				renewed[n.Name] = true
				t.Logf("%s renewed: serial %s -> %s, not after %s -> %s", n.Name, before[n.Name].serial, f.serial,
					before[n.Name].notAfter.Format(time.RFC3339), f.notAfter.Format(time.RFC3339))
			}
		}
	}
	for _, n := range watch {
		if !renewed[n.Name] {
			t.Fatalf("%s's cert was not renewed within 15 minutes", n.Name)
		}
		pid, _ := joinNodeSSH(t, n, "systemctl show -p MainPID --value sandboxd")
		if strings.TrimSpace(pid) != pids[n.Name] {
			t.Fatalf("%s's sandboxd restarted to renew (PID %s -> %s)", n.Name, pids[n.Name], strings.TrimSpace(pid))
		}
	}
	// The renewed certs carry the cluster's internal calls: every member
	// stays alive and a sandbox still lands and answers.
	for _, m := range listNodeViews(t, c) {
		if !m.Alive {
			t.Fatalf("member %s went down after renewal", m.NodeID)
		}
	}
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	owner, err := c.OwnerNodeID(ctx, sb.ID)
	if err != nil || owner == "" {
		t.Fatalf("sandbox %s after renewal has no owner (%v)", sb.ID, err)
	}
	t.Logf("sandbox %s placed on %s after renewal", sb.ID, owner)
}

// artifactArgs are the installer flags that point the one-line installer at
// this build (run.sh presigns them into .tf/<scenario>/artifacts.tfvars),
// and the installer's own URL. A release install needs none of them.
func artifactArgs(t *testing.T) (installer string, flags []string) {
	t.Helper()
	path := filepath.Join("..", ".tf", sc.Name, "artifacts.tfvars")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no %s (a local build is needed to install this build by hand): %v", path, err)
	}
	re := regexp.MustCompile(`(?m)^\s*([a-z_]+)\s*=\s*"([^"]*)"`)
	vals := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		vals[m[1]] = m[2]
	}
	installer = vals["install_script_url"]
	if installer == "" || vals["sandboxd_url"] == "" {
		t.Skipf("%s has no install_script_url or sandboxd_url", path)
	}
	flags = []string{"--sandboxd-url", vals["sandboxd_url"], "--toolboxd-url", vals["toolboxd_url"], "--checksums-url", vals["checksums_url"]}
	if v := vals["caddy_binary_url"]; v != "" {
		flags = append(flags, "--caddy-binary-url", v)
	}
	return installer, flags
}
