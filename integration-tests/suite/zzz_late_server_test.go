//go:build integration

package suite

// UC-694 — a server added after the module's join token stopped working,
// kubeadm's way (`kubeadm token create` on a control-plane node, then join
// with the new token): here `sudo sandboxd join-command` on a server, since
// the cluster makes a server token only when a server asks. The module's server token lasts 24 hours, so a server that
// Terraform adds later gets a fresh token through node_join_tokens, which
// only changes which token that node's user data carries. This case runs
// that very user data: a joined server's rendered bootstrap, on the blank
// spare-server, with only the node name and the token swapped. It sorts
// last (zzz_) because it adds a server member, which stays until
// teardown: a live server cannot be deleted ("raft member is still alive").

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

var (
	bootstrapTokenLine = regexp.MustCompile(`(?m)^JOIN_TOKEN='([a-z0-9]{6}\.[a-z0-9]{32})'$`)
	bootstrapNodeID    = regexp.MustCompile(`--node-id '([^']+)'`)
)

func TestJoinTokenLateServerJoinsWithAFreshToken(t *testing.T) {
	harness.Require(t, sc, "UC-694")
	targets := allIntegrationTargets(t)
	var donor, spare harness.IntegrationNode
	for _, n := range targets.Nodes {
		switch {
		case n.Name == "spare-server" && n.Blank:
			spare = n
		case !n.Blank && !n.Seed && expectedJoinRole(n.Role) == "server" && donor.Name == "":
			donor = n
		}
	}
	if spare.Name == "" || donor.Name == "" {
		t.Fatalf("needs the blank spare-server and a joined server (spare %q, donor %q)", spare.Name, donor.Name)
	}
	harness.RequireNodeSSH(t, spare)

	// The donor's rendered bootstrap: what the module put in a joining
	// server's user data.
	script := sshRoot(t, donor, "cat /var/lib/cloud/instance/scripts/part-001 2>/dev/null || zcat -f /var/lib/cloud/instance/user-data.txt")
	start := strings.Index(script, "wait_for_join_port() {")
	end := strings.Index(script, "\nwait_for_join_port || exit 1")
	if start < 0 || end <= start || bootstrapTokenLine.FindString(script) == "" {
		t.Fatalf("%s's bootstrap has no wait_for_join_port or JOIN_TOKEN line", donor.Name)
	}
	wait := script[start:end]
	m := bootstrapNodeID.FindStringSubmatch(script)
	if m == nil || !strings.HasSuffix(m[1], donor.Name) {
		t.Fatalf("%s's bootstrap names no --node-id ending in %s", donor.Name, donor.Name)
	}
	donorID := m[1]
	spareID := strings.TrimSuffix(donorID, donor.Name) + spare.Name

	// 1. A token the join port refuses (a server token that has expired)
	// stops the wait after the grace, naming the fix, instead of waiting
	// out seed_wait_max_seconds.
	expired := newServerJoinToken(t, donor, "1m")
	time.Sleep(75 * time.Second)
	target, _ := harness.SSHTarget(spare)
	probe := "JOIN_TOKEN='" + expired + "'\n" + wait + "\nJOIN_REFUSED_GRACE=20 JOIN_POLL_SECONDS=2 wait_for_join_port; echo \"WAIT_EXIT=$?\"\n"
	began := time.Now()
	out, _ := harness.SSHRunStdin(t, target, "bash -s", probe)
	if !strings.Contains(out, "WAIT_EXIT=1") || !strings.Contains(out, "refused this node's join token") ||
		!strings.Contains(out, "sudo sandboxd join-command --role server --ttl 2h --json") || !strings.Contains(out, "node_join_tokens[") {
		t.Fatalf("an expired token did not stop the wait with the fix:\n%s", out)
	}
	if took := time.Since(began); took > 3*time.Minute {
		t.Fatalf("the refused wait took %s", took)
	}
	if strings.Contains(out, expired) {
		t.Fatalf("the wait printed the token:\n%s", out)
	}

	// 2. The same bootstrap with a fresh token, the user data that
	// node_join_tokens gives a late server, joins the spare as a server.
	fresh := newServerJoinToken(t, donor, "2h")
	late := strings.ReplaceAll(script, donorID, spareID)
	late = bootstrapTokenLine.ReplaceAllLiteralString(late, "JOIN_TOKEN='"+fresh+"'")
	if out, err := harness.SSHRunStdin(t, target, "sudo install -m 0700 /dev/stdin /root/late-server.sh", late); err != nil {
		t.Fatalf("writing the late server's bootstrap: %v\n%s", err, out)
	}
	// The redirect runs as root too: /var/log is not the ssh user's to write.
	out, code := runOnNode(t, spare, "sudo bash -c 'bash /root/late-server.sh >/var/log/aerolvm-late-server.log 2>&1'")
	if code != 0 {
		tail, _ := joinNodeSSH(t, spare, "sudo tail -n 40 /var/log/aerolvm-late-server.log")
		t.Fatalf("the late server's bootstrap = %d\n%s\n%s", code, out, tail)
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		var role string
		for _, n := range listNodeViews(t, client(t)) {
			if n.NodeID == spareID && n.Alive {
				role = n.Role
			}
		}
		if strings.Contains(role, "server") {
			t.Logf("UC-694 PASS: an expired token stopped the wait with the fix; %s joined as %s with a fresh token through the module's bootstrap", spareID, role)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s is not a live server member (role %q)", spareID, role)
		}
		time.Sleep(5 * time.Second)
	}
}

// newServerJoinToken makes a server join token the way an operator gets one
// for node_join_tokens: `sudo sandboxd join-command --role server --json` on
// a server (only a server's own request gets a server token).
func newServerJoinToken(t *testing.T, server harness.IntegrationNode, ttl string) string {
	t.Helper()
	target, _ := harness.SSHTarget(server)
	out, err := harness.SSHRun(t, target, "sudo sandboxd join-command --role server --ttl "+ttl+" --json 2>/dev/null")
	var got struct {
		Token string `json:"token"`
	}
	if start := strings.Index(out, "{"); start >= 0 {
		_ = json.Unmarshal([]byte(out[start:]), &got)
	}
	if err != nil || !regexp.MustCompile(`^[a-z0-9]{6}\.[a-z0-9]{32}$`).MatchString(got.Token) {
		t.Fatalf("sandboxd join-command on %s gave no token (err %v)", server.Name, err)
	}
	return got.Token
}
