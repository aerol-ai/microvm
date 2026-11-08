//go:build integration

package suite

// Worker and ingress nodes without the operator PAT
// (plans/kubectl-style-cluster-ops.md §8). A one-line join gives a worker or
// ingress node the PAT's SHA-256 instead of the PAT, and it calls its peers
// with its node cert alone. These cases read every node's files, ask the join
// service for a worker's and an ingress's answer, walk the old path from a
// worker token to the CA key and see each step refused, and drive a worker's
// own API. Run them on cluster-rollout-join (or cluster-join-token) with
// AEROL_TEST_RUN='TestPATFree'. They change nothing a later case reads,
// except one throwaway node ID per role that UC-691 admits and deletes.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// patFreeTargets loads the targets, skipping when the run has none.
func patFreeTargets(t *testing.T) *harness.IntegrationTargets {
	t.Helper()
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	return targets
}

// operatorPAT is the operator token the scenario was built with.
func operatorPAT(t *testing.T) string {
	t.Helper()
	pat := strings.TrimSpace(sc.OperatorPAT)
	if pat == "" {
		pat = strings.TrimSpace(sc.PAT)
	}
	if pat == "" {
		t.Fatal("the scenario has no operator PAT")
	}
	return pat
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// nodeOfRole returns the first SSH-reachable node whose join role is role.
func nodeOfRole(t *testing.T, targets *harness.IntegrationTargets, role string) harness.IntegrationNode {
	t.Helper()
	for _, n := range targets.Nodes {
		if expectedJoinRole(n.Role) == role {
			if _, ok := harness.SSHTarget(n); ok {
				return n
			}
		}
	}
	t.Skipf("no SSH-reachable %s node (the case needs a role-separated scenario)", role)
	return harness.IntegrationNode{}
}

// patFacts is what a node's env files say about the PAT, as hashes only.
type patFacts struct {
	own  string // SHA-256 of the node's SB_PAT_TOKEN
	list string // SB_PAT_TOKEN_SHA256
	hits string // files that hold the operator PAT
}

var patFactLine = regexp.MustCompile(`(?m)^(OWN|LIST|HITS)=(.*)$`)

// readPATFacts reads node's SB_PAT_TOKEN (as its hash), SB_PAT_TOKEN_SHA256,
// and the files that hold the operator PAT. The PAT goes in on stdin, so it
// never lands in the node's argv or sudo log.
func readPATFacts(t *testing.T, node harness.IntegrationNode, pat string) patFacts {
	t.Helper()
	target, _ := harness.SSHTarget(node)
	script := `pat="$(cat)"; ` +
		`sudo bash -c 'set -a; . /etc/sandboxd/sandboxd.env; [ -f /etc/sandboxd/cluster.env ] && . /etc/sandboxd/cluster.env; set +a; ` +
		`printf "OWN=%s\n" "$(printf %s "$SB_PAT_TOKEN" | sha256sum | cut -d" " -f1)"; printf "LIST=%s\n" "${SB_PAT_TOKEN_SHA256:-}"'; ` +
		`hits=""; ` +
		`for f in $(sudo find /etc/sandboxd -type f 2>/dev/null) /var/log/aerolvm-bootstrap.log /var/log/cloud-init-output.log; do ` +
		`sudo grep -qF -- "$pat" "$f" 2>/dev/null && hits="$hits $f"; done; ` +
		`for f in /var/lib/cloud/instance/user-data.txt /var/lib/cloud/instance/user-data.txt.i; do ` +
		`sudo zcat -f "$f" 2>/dev/null | grep -qF -- "$pat" && hits="$hits $f"; done; ` +
		`echo "HITS=$hits"`
	out, err := harness.SSHRunStdin(t, target, script, pat)
	if err != nil {
		t.Fatalf("read PAT facts on %s: %v\n%s", node.Name, err, out)
	}
	var f patFacts
	for _, m := range patFactLine.FindAllStringSubmatch(out, -1) {
		switch m[1] {
		case "OWN":
			f.own = strings.TrimSpace(m[2])
		case "LIST":
			f.list = strings.TrimSpace(m[2])
		case "HITS":
			f.hits = strings.TrimSpace(m[2])
		}
	}
	if f.own == "" {
		t.Fatalf("no PAT facts from %s:\n%s", node.Name, out)
	}
	return f
}

// UC-690 — worker and ingress nodes hold no operator PAT, only its hash;
// every server holds the PAT.
func TestPATFreeNodesHoldNoPAT(t *testing.T) {
	harness.Require(t, sc, "UC-690")
	targets := patFreeTargets(t)
	pat := operatorPAT(t)
	want := sha256Hex(pat)
	roles := map[string]int{}
	for _, n := range targets.Nodes {
		if _, ok := harness.SSHTarget(n); !ok {
			continue
		}
		role := expectedJoinRole(n.Role)
		f := readPATFacts(t, n, pat)
		switch role {
		case "server":
			if f.own != want || f.list != "" {
				t.Errorf("server %s: holds the PAT %v, PAT hash list %q; want the PAT and no list", n.Name, f.own == want, f.list)
			}
		default:
			if f.own == want {
				t.Errorf("%s %s: its SB_PAT_TOKEN is the operator PAT", role, n.Name)
			}
			if !containsString(strings.Split(f.list, ","), want) {
				t.Errorf("%s %s: SB_PAT_TOKEN_SHA256 = %q, want the PAT's hash %s", role, n.Name, f.list, want)
			}
			if f.hits != "" {
				t.Errorf("%s %s: the operator PAT is in %s", role, n.Name, f.hits)
			}
		}
		roles[role]++
	}
	if roles["worker"] == 0 || roles["ingress"] == 0 || roles["server"] == 0 {
		t.Fatalf("checked roles %v: the case needs servers, workers and an ingress node", roles)
	}
}

// joinAnswerProbe posts one join like a new machine and prints what the
// answer says about the PAT, never the PAT, the CA key or the cert itself.
const joinAnswerProbe = `
import json, ssl, subprocess, sys, tempfile, urllib.error, urllib.request
url, token, node_id, version = sys.argv[1:5]
d = tempfile.mkdtemp()
subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", d + "/k.pem"], check=True)
subprocess.run(["openssl", "req", "-new", "-key", d + "/k.pem", "-subj", "/CN=" + node_id, "-out", d + "/c.csr"], check=True)
body = json.dumps({"token": token, "node_id": node_id, "csr": open(d + "/c.csr").read(), "version": version}).encode()
req = urllib.request.Request(url + "/v1/join", data=body, headers={"Content-Type": "application/json"})
try:
    r = urllib.request.urlopen(req, context=ssl._create_unverified_context(), timeout=90)
    a = json.loads(r.read().decode())
    print("STATUS", r.status)
    print("SUMMARY " + json.dumps({"role": a.get("role", ""), "pat_token": bool(a.get("pat_token")), "ca_key": bool(a.get("ca_key")),
        "pat_sha256": a.get("pat_sha256") or [], "scope": a.get("operator_volume_scope", "")}))
except urllib.error.HTTPError as e:
    print("STATUS", e.code)
    print(e.read().decode()[:600])
`

type joinAnswerSummary struct {
	Role      string   `json:"role"`
	PATToken  bool     `json:"pat_token"`
	CAKey     bool     `json:"ca_key"`
	PATSHA256 []string `json:"pat_sha256"`
	Scope     string   `json:"scope"`
}

// UC-691 — a worker's and an ingress's join answer carry the PAT's hash,
// never the PAT or the CA key.
func TestPATFreeJoinAnswer(t *testing.T) {
	harness.Require(t, sc, "UC-691")
	targets := patFreeTargets(t)
	want := sha256Hex(operatorPAT(t))
	from := nodeOfRole(t, targets, "worker")
	seed := pickServer(t, targets)
	joinURL := "https://" + seed.PrivateIP + ":7003"
	env := tokenEnv(t)
	for _, role := range []string{"worker", "ingress"} {
		t.Run(role, func(t *testing.T) {
			line := mustCLI(t, env, "join-command", "--role", role)
			_, args := joinLineArgs(t, line.stdout)
			token := tokenOf(t, args)
			id, _, _ := strings.Cut(token, ".")
			nodeID := fmt.Sprintf("uc691-%s-%d", role, time.Now().Unix())
			t.Cleanup(func() {
				runCLI(t, env, nil, "delete", "node", nodeID, "--force")
				runCLI(t, env, nil, "delete", "jointoken", id)
			})
			target, _ := harness.SSHTarget(from)
			script := fmt.Sprintf(`v="$(/usr/local/bin/sandboxd version -o json | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')"; python3 - %s %s %s "$v"`,
				shellQuote(joinURL), shellQuote(token), shellQuote(nodeID))
			out, err := harness.SSHRunStdin(t, target, script, joinAnswerProbe)
			m := regexp.MustCompile(`(?m)^SUMMARY (.*)$`).FindStringSubmatch(out)
			if m == nil || !strings.Contains(out, "STATUS 200") {
				t.Fatalf("join probe for a %s token from %s: %v\n%s", role, from.Name, err, out)
			}
			var got joinAnswerSummary
			if err := json.Unmarshal([]byte(m[1]), &got); err != nil {
				t.Fatalf("summary %q: %v", m[1], err)
			}
			if got.Role != role || got.PATToken || got.CAKey || !containsString(got.PATSHA256, want) || !strings.HasPrefix(got.Scope, "op-") {
				t.Fatalf("%s join answer = %+v, want role %s, no PAT, no CA key, the PAT's hash %s and an op- scope", role, got, role, want)
			}
		})
	}
}

// peerCallFrom has node call server's internal mTLS listener with its OWN
// certificate and, when withOwnToken, its own SB_PAT_TOKEN as the bearer.
// It returns the status and the body.
func peerCallFrom(t *testing.T, node, server harness.IntegrationNode, method, path, body string, withOwnToken bool) (int, string) {
	t.Helper()
	target, _ := harness.SSHTarget(node)
	auth := ""
	if withOwnToken {
		auth = `-H "Authorization: Bearer $SB_PAT_TOKEN" `
	}
	data := ""
	if body != "" {
		data = `-H "Content-Type: application/json" --data ` + shellQuote(body) + ` `
	}
	script := `sudo bash -c ` + shellQuote(`set -a; . /etc/sandboxd/sandboxd.env 2>/dev/null || true; . /etc/sandboxd/cluster.env; set +a; `+
		`base="${SB_CLUSTER_INTERNAL_ADVERTISE%/}"; hostport="${base#https://}"; port="${hostport##*:}"; `+
		`curl -sS -o /tmp/aerolvm-uc692.body -w "\nPROBE_CODE=%{http_code}\n" --max-time 20 -X `+method+` `+
		`--resolve "aerolvm-cluster-node:$port:`+server.PrivateIP+`" `+auth+data+
		`--cert "$SB_CLUSTER_TLS_DIR/node.crt" --key "$SB_CLUSTER_TLS_DIR/node.key" --cacert "$SB_CLUSTER_TLS_DIR/ca.crt" `+
		`"https://aerolvm-cluster-node:$port`+path+`"; echo PROBE_BODY_START; head -c 2000 /tmp/aerolvm-uc692.body; echo; echo PROBE_BODY_END`)
	out, err := harness.SSHRun(t, target, script)
	code := 0
	if i := strings.LastIndex(out, "PROBE_CODE="); i >= 0 {
		fmt.Sscanf(out[i+len("PROBE_CODE="):], "%d", &code)
	}
	if code == 0 {
		t.Fatalf("peer call from %s: %v\n%s", node.Name, err, out)
	}
	resp := ""
	if s, e := strings.Index(out, "PROBE_BODY_START"), strings.Index(out, "PROBE_BODY_END"); s >= 0 && e > s {
		resp = strings.TrimSpace(out[s+len("PROBE_BODY_START") : e])
	}
	return code, resp
}

// ownToken reads node's own SB_PAT_TOKEN, for the cases that try it off
// the node. It is a throwaway secret of a test machine; never logged.
func ownToken(t *testing.T, node harness.IntegrationNode) string {
	t.Helper()
	out := sshRoot(t, node, `awk -F= '$1 == "SB_PAT_TOKEN" { print substr($0, length($1) + 2) }' /etc/sandboxd/sandboxd.env`)
	tok := strings.TrimSpace(out)
	if tok == "" {
		t.Fatalf("%s has no SB_PAT_TOKEN", node.Name)
	}
	return tok
}

// whoamiWith calls GET /v1/whoami at base with bearer and returns the status.
func whoamiWith(t *testing.T, base, bearer string) (int, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/v1/whoami", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := harness.HTTPClient(30 * time.Second).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// UC-692 — every step from a worker token to the CA key is refused: the
// worker's cert (what a leaked worker token buys) is a live peer but gets
// no server token, no CA key and no adopt, and its own token is no use off
// the worker.
func TestPATFreeWorkerCannotReachTheCAKey(t *testing.T) {
	harness.Require(t, sc, "UC-692")
	targets := patFreeTargets(t)
	worker := nodeOfRole(t, targets, "worker")
	seed := pickServer(t, targets)

	// Control: the worker's cert alone is a live peer, the way its sandboxd
	// calls. A refusal below is then about the power asked for.
	if code, body := peerCallFrom(t, worker, seed, http.MethodGet, "/v1/cluster/internal/drained-nodes", "", false); code != http.StatusOK {
		t.Fatalf("control: the worker's cert alone on %s = %d %s", seed.Name, code, body)
	}
	for _, step := range []struct {
		name, method, path, body string
		withOwnToken             bool
		want                     int
		says                     string
	}{
		{"a server join token by cert", http.MethodPost, "/v1/cluster/join-tokens", `{"role":"server","ttl":"1h"}`, false, http.StatusForbidden, "not an admitted server"},
		{"the CA key by cert", http.MethodPost, "/v1/cluster/internal/ca-key", `{}`, false, http.StatusForbidden, ""},
		{"adopt by cert", http.MethodPost, "/v1/cluster/adopt", `{}`, false, http.StatusForbidden, "not an admitted server"},
		{"a server join token with the worker's own token", http.MethodPost, "/v1/cluster/join-tokens", `{"role":"server","ttl":"1h"}`, true, http.StatusUnauthorized, ""},
	} {
		code, body := peerCallFrom(t, worker, seed, step.method, step.path, step.body, step.withOwnToken)
		if code != step.want || !strings.Contains(body, step.says) {
			t.Errorf("%s from %s = %d %s, want %d %q", step.name, worker.Name, code, body, step.want, step.says)
		}
		if strings.Contains(body, "BEGIN") || strings.Contains(body, `"token"`) {
			t.Errorf("%s from %s leaked a key or a token: %s", step.name, worker.Name, body)
		}
	}

	// The worker's own token: refused by the load balancer, by the worker's
	// own public API and by a server; accepted on the worker's loopback.
	own := ownToken(t, worker)
	if code, err := whoamiWith(t, sc.BaseURL, own); err != nil || code != http.StatusUnauthorized {
		t.Errorf("the worker's own token at the API domain = %d %v, want 401", code, err)
	}
	if worker.PublicIP != "" {
		if code, err := whoamiWith(t, "http://"+worker.PublicIP+":21212", own); err != nil || code != http.StatusUnauthorized {
			t.Errorf("the worker's own token on its public API = %d %v, want 401", code, err)
		}
	}
	server := sshRoot(t, worker, `. /etc/sandboxd/sandboxd.env; curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $SB_PAT_TOKEN" http://`+seed.PrivateIP+`:21212/v1/whoami`)
	if strings.TrimSpace(server) != "401" {
		t.Errorf("the worker's own token at %s's API = %s, want 401", seed.Name, server)
	}
	local := sshRoot(t, worker, `. /etc/sandboxd/sandboxd.env; curl -s -H "Authorization: Bearer $SB_PAT_TOKEN" http://127.0.0.1:21212/v1/whoami`)
	if !strings.Contains(local, `"kind":"operator"`) {
		t.Errorf("the worker's own token on its loopback = %s, want the operator", local)
	}
}

// UC-693 — a worker's own API serves sandbox calls with the operator PAT,
// creating and forwarding; its own token on loopback reaches a sandbox
// another node owns.
func TestPATFreeWorkerAPIServesSandboxes(t *testing.T) {
	harness.Require(t, sc, "UC-693")
	targets := patFreeTargets(t)
	worker := nodeOfRole(t, targets, "worker")
	if worker.PublicIP == "" {
		t.Skipf("%s has no public IP for its API", worker.Name)
	}
	viaWorker := *sc
	viaWorker.BaseURL = "http://" + worker.PublicIP + ":21212"
	viaWorker.PAT = operatorPAT(t)
	wc := harness.NewClient(t, &viaWorker)
	lb := client(t)

	// Create through the worker's API and run exec in it.
	sb := wc.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	res, err := sb.Exec(ctx, sdktypes.ExecRequest{Command: "echo uc693-worker-api"})
	if err != nil || !strings.Contains(res.Stdout, "uc693-worker-api") {
		t.Fatalf("exec through %s's API = %+v %v", worker.Name, res, err)
	}

	// A sandbox the load balancer placed: read it and run exec in it
	// through the worker, from whichever node owns it.
	other := lb.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t) + "-lb"})
	owner, err := lb.OwnerNodeID(ctx, other.ID)
	if err != nil {
		t.Fatalf("owner of %s: %v", other.ID, err)
	}
	got, err := wc.SDK().Get(ctx, other.ID)
	if err != nil || got.ID != other.ID {
		t.Fatalf("get %s (owned by %s) through %s = %v", other.ID, owner, worker.Name, err)
	}
	res, err = got.Exec(ctx, sdktypes.ExecRequest{Command: "echo uc693-forwarded"})
	if err != nil || !strings.Contains(res.Stdout, "uc693-forwarded") {
		t.Fatalf("exec in %s (owned by %s) through %s = %+v %v", other.ID, owner, worker.Name, res, err)
	}

	// The worker's own token, on its loopback, reads that sandbox: when
	// another node owns it, the forward goes as the worker.
	out := sshRoot(t, worker, `. /etc/sandboxd/sandboxd.env; curl -s -w "\nCODE=%{http_code}" -H "Authorization: Bearer $SB_PAT_TOKEN" http://127.0.0.1:21212/v1/sandboxes/`+other.ID)
	if !strings.Contains(out, "CODE=200") || !strings.Contains(out, other.ID) {
		t.Fatalf("the worker's own token on loopback, sandbox %s owned by %s:\n%s", other.ID, owner, out)
	}
}
