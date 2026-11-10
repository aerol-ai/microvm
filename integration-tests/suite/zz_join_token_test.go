//go:build integration

package suite

// Join tokens refused, a deleted worker joining again, and `aerolvm
// join-command` used as typed (plans/kubectl-style-cluster-ops.md §4, §5,
// §9 Phase 2 row). Disruptive: it deletes a worker twice, so the file sorts
// after the other cases ("zz_"). The worker ends the run joined again under
// its host name, a member like any other.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// joinProbe posts one join from a node, the way a new machine does: a fresh
// P-256 key and CSR, the given token and node ID, this cluster's build. The
// node is a live member, so the join server's dial-back to it succeeds and
// the answer is about the token alone. Prints "STATUS <code>" and the body.
const joinProbe = `
import json, ssl, subprocess, sys, tempfile, urllib.error, urllib.request
url, token, node_id, version = sys.argv[1:5]
d = tempfile.mkdtemp()
subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", d + "/k.pem"], check=True)
subprocess.run(["openssl", "req", "-new", "-key", d + "/k.pem", "-subj", "/CN=" + node_id, "-out", d + "/c.csr"], check=True)
body = json.dumps({"token": token, "node_id": node_id, "csr": open(d + "/c.csr").read(), "version": version}).encode()
req = urllib.request.Request(url + "/v1/join", data=body, headers={"Content-Type": "application/json"})
try:
    r = urllib.request.urlopen(req, context=ssl._create_unverified_context(), timeout=90)
    print("STATUS", r.status)
    print(r.read().decode()[:300])
except urllib.error.HTTPError as e:
    print("STATUS", e.code)
    print(e.read().decode()[:600])
`

var joinProbeStatus = regexp.MustCompile(`STATUS (\d+)`)

// probeJoin runs joinProbe on node and returns the status and body.
func probeJoin(t *testing.T, node harness.IntegrationNode, joinURL, token, nodeID string) (int, string) {
	t.Helper()
	target, _ := harness.SSHTarget(node)
	script := fmt.Sprintf(`v="$(/usr/local/bin/sandboxd version -o json | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')"; python3 - %s %s %s "$v"`,
		shellQuote(joinURL), shellQuote(token), shellQuote(nodeID))
	out, err := harness.SSHRunStdin(t, target, script, joinProbe)
	m := joinProbeStatus.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("join probe from %s: %v\n%s", node.Name, err, out)
	}
	var code int
	fmt.Sscanf(m[1], "%d", &code)
	return code, out
}

// clusterInfoStatus asks the join port for cluster-info of a token id.
func clusterInfoStatus(t *testing.T, node harness.IntegrationNode, joinURL, tokenID string) string {
	t.Helper()
	out, _ := joinNodeSSH(t, node, fmt.Sprintf(`curl -sk -o /dev/null -w '%%{http_code}' %s`, shellQuote(joinURL+"/v1/join/cluster-info?token_id="+tokenID)))
	return strings.TrimSpace(out)
}

// joinLineArgs is what follows "bash -s -- " in a printed join command: the
// installer options a cluster with a domain adds (--domain and the DNS
// options), then join and its flags.
func joinLineArgs(t *testing.T, line string) (installer string, args []string) {
	t.Helper()
	line = strings.TrimSpace(line)
	m := regexp.MustCompile(`^curl -fsSL (\S+) \| sudo bash -s -- ((?:\S+ )*?join .+)$`).FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("join-command printed %q, not `curl -fsSL <installer> | sudo bash -s -- [options] join ...`", line)
	}
	return m[1], strings.Fields(m[2])
}

// dnsTokenWord is how a printed join command reads the DNS API token: the
// shell on the new machine expands it, so the secret is not in the line.
const dnsTokenWord = `"$CLOUDFLARE_API_TOKEN"`

// runJoinLine runs a printed join command's words on node as typed, through
// installer: every word quoted except dnsTokenWord, which the remote shell
// expands. The token itself is read on member from its Caddy settings and
// sent on stdin, so it is in no command line and no log.
func runJoinLine(t *testing.T, node, member harness.IntegrationNode, installer string, words []string) (string, int) {
	t.Helper()
	quoted := make([]string, 0, len(words))
	stdin := ""
	for _, w := range words {
		if w != dnsTokenWord {
			quoted = append(quoted, shellQuote(w))
			continue
		}
		quoted = append(quoted, w)
		if stdin == "" {
			tok, err := joinNodeSSH(t, member, `sudo sed -n 's/^SB_DNS_API_TOKEN=//p' /etc/default/caddy`)
			if tok = strings.TrimSpace(tok); err != nil || tok == "" {
				t.Fatalf("the join command reads CLOUDFLARE_API_TOKEN, and %s has no DNS API token to set it from: %v", member.Name, err)
			}
			stdin = tok + "\n"
		}
	}
	target, ok := harness.SSHTarget(node)
	if !ok {
		t.Fatalf("node %s has no SSH address", node.Name)
	}
	script := fmt.Sprintf(`IFS= read -r CLOUDFLARE_API_TOKEN || true; export CLOUDFLARE_API_TOKEN; curl -fsSL %s | sudo bash -s -- %s; echo "EXIT=$?"`,
		shellQuote(installer), strings.Join(quoted, " "))
	out, _ := harness.SSHRunStdin(t, target, script, stdin)
	code := -1
	if i := strings.LastIndex(out, "EXIT="); i >= 0 {
		fmt.Sscanf(out[i+len("EXIT="):], "%d", &code)
	}
	return out, code
}

func tokenOf(t *testing.T, args []string) string {
	t.Helper()
	for i, a := range args {
		if a == "--token" && i+1 < len(args) {
			return args[i+1]
		}
	}
	t.Fatalf("no --token in %v", args)
	return ""
}

// runOnNode runs a root command on node and returns its output and exit
// status (the last line of the output carries it).
func runOnNode(t *testing.T, node harness.IntegrationNode, cmd string) (string, int) {
	t.Helper()
	out, _ := joinNodeSSH(t, node, cmd+`; echo "EXIT=$?"`)
	code := -1
	if i := strings.LastIndex(out, "EXIT="); i >= 0 {
		fmt.Sscanf(out[i+len("EXIT="):], "%d", &code)
	}
	return out, code
}

func memberIDs(t *testing.T) []string {
	t.Helper()
	var ids []string
	for _, m := range listNodeViews(t, client(t)) {
		if m.Alive {
			ids = append(ids, m.NodeID)
		}
	}
	return ids
}

func waitMember(t *testing.T, id string, want bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if containsString(memberIDs(t), id) == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("member %s present=%t after 3m, want %t (members %v)", id, !want, want, memberIDs(t))
		}
		time.Sleep(5 * time.Second)
	}
}

// UC-621 — wrong, reused and revoked tokens are refused: cluster-info for an
// unknown token id is 403; a join with a token the cluster never made is 403
// token_invalid; a single-use token that joined one key is 403 token_used
// for another; a revoked token's cluster-info is 403; join-command refuses
// --ttl 0 for servers before calling, and warns for a never-expiring worker
// token. UC-622 — a deleted worker can't come back with its old key (403
// key_revoked, with `sandboxd reset` named as the fix); after
// `sandboxd reset --yes` a fresh join (new key, token) brings the same node
// ID back. UC-625 — running that join again changes nothing: the server
// answers replay and sandboxd keeps its PID. UC-624 — `aerolvm join-command`
// prints a line that, run as typed on a reset machine, makes it a member.
func TestJoinTokenRefusalsAndAFreshJoin(t *testing.T) {
	harness.Require(t, sc, "UC-622", "UC-621", "UC-624", "UC-625")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this deletes a worker")
	}
	targets := joinTokenTargets(t)
	c := client(t)
	workers := requireWorkers(t, c, 2)
	victim := pickDeletableWorker(t, targets)
	harness.RequireNodeSSH(t, victim)
	victimID := heteroNodeID(t, c, targets, victim.Name)
	if !containsString(workers, victimID) {
		t.Skipf("%s (%s) is not an alive worker member: %v", victim.Name, victimID, workers)
	}
	var other harness.IntegrationNode
	for _, n := range targets.Nodes {
		if n.Name != victim.Name && expectedJoinRole(n.Role) == "worker" {
			other = n
		}
	}
	if other.Name == "" {
		t.Skip("needs a second worker to send the probes from")
	}
	seed := pickServer(t, targets)
	joinURL := "https://" + seed.PrivateIP + ":7003"
	installer, artifacts := artifactArgs(t)
	env := tokenEnv(t)

	// --- UC-621: tokens that must not work. ---
	if code, out := probeJoin(t, other, joinURL, "zzzzzz.00000000000000000000000000000000", "uc621-wrong"); code != 403 || !strings.Contains(out, "token_invalid") {
		t.Fatalf("UC-621: a join with a made-up token = %d\n%s", code, out)
	}
	if got := clusterInfoStatus(t, other, joinURL, "zzzzzz"); got != "403" {
		t.Fatalf("UC-621: cluster-info for an unknown token id = %s, want 403", got)
	}
	if r := runCLI(t, env, nil, "join-command", "--role", "server", "--ttl", "0"); r.code != 2 || !strings.Contains(r.stderr, "only for worker and ingress") {
		t.Fatalf("UC-621: join-command --role server --ttl 0 = %d %s", r.code, r.stderr)
	}
	never := mustCLI(t, env, "join-command", "--role", "worker", "--ttl", "0", "--reusable")
	if !strings.Contains(never.stderr, "never expires") {
		t.Fatalf("UC-621: a never-expiring worker token printed no warning: %s", never.stderr)
	}
	_, neverArgs := joinLineArgs(t, never.stdout)
	neverID, _, _ := strings.Cut(tokenOf(t, neverArgs), ".")
	if got := clusterInfoStatus(t, other, joinURL, neverID); got != "200" {
		t.Fatalf("UC-621: cluster-info for a live token = %s, want 200", got)
	}
	mustCLI(t, env, "delete", "jointoken", neverID)
	if got := clusterInfoStatus(t, other, joinURL, neverID); got != "403" {
		t.Fatalf("UC-621: cluster-info for a revoked token = %s, want 403", got)
	}

	// --- UC-622: delete the worker; its old key is refused. ---
	t.Cleanup(func() {
		// Whatever happened, try to leave the machine a member.
		runOnNode(t, victim, "systemctl is-active --quiet sandboxd || sudo systemctl start sandboxd")
	})
	mustCLI(t, env, "delete", "node", victimID, "--force")
	waitMember(t, victimID, false)
	first := mustCLI(t, env, "join-command", "--role", "worker")
	_, firstArgs := joinLineArgs(t, first.stdout)
	t1 := tokenOf(t, firstArgs)
	out, code := runOnNode(t, victim, fmt.Sprintf("sudo sandboxd join %s --token %s --node-id %s",
		shellQuote(joinURL), shellQuote(t1), shellQuote(victimID)))
	if code == 0 || !strings.Contains(out, "key_revoked") || !strings.Contains(out, "sandboxd reset --yes") {
		t.Fatalf("UC-622: the deleted worker's old key joined (exit %d):\n%s", code, out)
	}
	out, code = runOnNode(t, victim, "sudo sandboxd reset --yes")
	if code != 0 {
		t.Fatalf("UC-622: sandboxd reset --yes = %d\n%s", code, out)
	}
	out, code = runOnNode(t, victim, fmt.Sprintf("sudo sandboxd join %s --token %s --node-id %s --role worker",
		shellQuote(joinURL), shellQuote(t1), shellQuote(victimID)))
	if code != 0 || !strings.Contains(out, "joined the cluster as a worker node") {
		t.Fatalf("UC-622: a fresh join of %s = %d\n%s", victimID, code, out)
	}
	waitMember(t, victimID, true)

	// --- UC-625: the same join again is a replay; sandboxd keeps running. ---
	pid, _ := joinNodeSSH(t, victim, "systemctl show -p MainPID --value sandboxd")
	out, code = runOnNode(t, victim, fmt.Sprintf("sudo sandboxd join %s --token %s --node-id %s --role worker",
		shellQuote(joinURL), shellQuote(t1), shellQuote(victimID)))
	if code != 0 || !strings.Contains(out, "already joined; nothing changed") || !strings.Contains(out, "sandboxd keeps running") {
		t.Fatalf("UC-625: re-running the join = %d\n%s", code, out)
	}
	if after, _ := joinNodeSSH(t, victim, "systemctl show -p MainPID --value sandboxd"); strings.TrimSpace(after) != strings.TrimSpace(pid) {
		t.Fatalf("UC-625: the re-run restarted sandboxd (PID %s -> %s)", strings.TrimSpace(pid), strings.TrimSpace(after))
	}

	// --- UC-621: the single-use token now belongs to that key. ---
	if code, out := probeJoin(t, other, joinURL, t1, "uc621-second"); code != 403 || !strings.Contains(out, "token_used") {
		t.Fatalf("UC-621: a used single-use token for another key = %d\n%s", code, out)
	}

	// --- UC-624: join-command's line, run as typed on a reset machine. ---
	mustCLI(t, env, "delete", "node", victimID, "--force")
	waitMember(t, victimID, false)
	if out, code := runOnNode(t, victim, "sudo sandboxd reset --yes"); code != 0 {
		t.Fatalf("UC-624: sandboxd reset --yes = %d\n%s", code, out)
	}
	line := mustCLI(t, env, "join-command")
	printedInstaller, args := joinLineArgs(t, line.stdout)
	if printedInstaller != "https://aerolvm.aerol.ai" || !strings.Contains(line.stdout, "--ca-cert-hash sha256:") {
		t.Fatalf("UC-624: join-command printed %q", line.stdout)
	}
	// The printed words run unchanged, after the Cloudflare token the line
	// asks for is set. Only the installer is this build's (a dev build is not
	// on the release CDN), so its URL and the flags that point it at this
	// build's files go in front of them.
	hostname, _ := joinNodeSSH(t, victim, "hostname -s")
	hostname = strings.TrimSpace(hostname)
	out, code = runJoinLine(t, victim, pickServer(t, targets), installer, append(append([]string{}, artifacts...), args...))
	if code != 0 || !strings.Contains(out, "joined the cluster as a worker node") {
		t.Fatalf("UC-624: the join-command line as typed = %d\n%s", code, out)
	}
	waitMember(t, hostname, true)
	// The machine is a worker again, under its host name: the default node ID.
	var joined nodeView
	for _, m := range listNodeViews(t, c) {
		if m.NodeID == hostname {
			joined = m
		}
	}
	if joined.Role != "worker" || joined.Voter {
		t.Fatalf("UC-624: %s joined as %+v", hostname, joined)
	}
	raw, _ := json.Marshal(joined)
	t.Logf("UC-624: %s joined as typed: %s", hostname, raw)
}
