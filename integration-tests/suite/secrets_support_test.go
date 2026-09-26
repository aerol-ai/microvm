//go:build integration

package suite

// Shared helpers for the secrets / audit / enterprise use cases (groups A-M).
// Kept in their own file so the group files stay assertions.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// pickSSHNodeHolding returns an SSH-reachable node whose cluster node id is in
// holders. Group A/B probe the peer that is supposed to hold a copy, which is
// not necessarily the seed.
func pickSSHNodeHolding(t *testing.T, c *harness.Client, targets *harness.IntegrationTargets, holders []string) (harness.IntegrationNode, bool) {
	t.Helper()
	for _, node := range targets.Nodes {
		if _, ok := harness.SSHTarget(node); !ok {
			continue
		}
		if slices.Contains(holders, heteroNodeID(t, c, targets, node.Name)) {
			return node, true
		}
	}
	return harness.IntegrationNode{}, false
}

// seedFirstNodeNames lists the SSH-reachable node names. Used to size
// expectations against the fleet the scenario actually provisioned rather than
// against a number baked into a test.
func seedFirstNodeNames(targets *harness.IntegrationTargets) []string {
	var out []string
	for _, n := range targets.Nodes {
		if _, ok := harness.SSHTarget(n); ok {
			out = append(out, n.Name)
		}
	}
	return out
}

// internalListenerPort extracts the port sandboxd listens on for peer traffic,
// read from the node's own cluster env rather than assumed.
const internalListenerPortScript = `sudo bash -c 'set -a; . /etc/sandboxd/cluster.env; set +a; ` +
	`echo "${SB_CLUSTER_INTERNAL_LISTEN##*:}"'`

// blockInternalListenerEverywhere makes every node's peer listener refuse new
// connections, leaving the public API reachable. Returns an idempotent restore.
//
// REJECT, not DROP: a refused connection fails fast, so the create path
// reports a fan-out failure instead of sitting on a TCP timeout until the
// test's own deadline — which would make the case fail for the wrong reason
// and take four minutes to do it.
func blockInternalListenerEverywhere(t *testing.T, targets *harness.IntegrationTargets) func() {
	t.Helper()
	type blocked struct {
		node harness.IntegrationNode
		port string
	}
	var applied []blocked

	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		for _, b := range applied {
			target, _ := harness.SSHTarget(b.node)
			// Delete, then CONFIRM the rule is gone. `iptables -D` removes one
			// matching rule and reports success even when the state afterwards
			// is not what we want; a REJECT left on the peer port breaks every
			// later cluster case in the run, and the report would blame
			// whichever one ran next.
			script := "sudo iptables -D INPUT -p tcp --dport " + b.port + " -j REJECT 2>/dev/null; " +
				"if sudo iptables -S INPUT | grep -q -- '--dport " + b.port + " -j REJECT'; then echo STILLBLOCKED; else echo CLEARED; fi"
			out, err := harness.SSHRun(t, target, script)
			if err != nil || !strings.Contains(out, "CLEARED") {
				t.Errorf("RESTORE FAILED on %s: the peer listener is still blocked on port %s and the rest of this run is suspect: %v\n%s",
					b.node.Name, b.port, err, strings.TrimSpace(out))
			}
		}
	}
	t.Cleanup(restore)

	for _, node := range targets.Nodes {
		target, ok := harness.SSHTarget(node)
		if !ok {
			continue
		}
		port, err := harness.SSHRun(t, target, internalListenerPortScript)
		port = strings.TrimSpace(port)
		if err != nil || port == "" {
			t.Fatalf("read the internal listener port on %s: %v (%q)", node.Name, err, port)
		}
		if out, err := harness.SSHRun(t, target, "sudo iptables -I INPUT 1 -p tcp --dport "+port+" -j REJECT"); err != nil {
			t.Fatalf("block the peer listener on %s: %v\n%s", node.Name, err, out)
		}
		applied = append(applied, blocked{node: node, port: port})
	}
	if len(applied) == 0 {
		t.Fatal("no node's peer listener could be blocked; the case would pass having injected no fault")
	}
	return restore
}

// assertNoSandboxNamed fails if any sandbox with this name survives. A
// retracted create must leave nothing that later reads as a healthy sandbox.
func assertNoSandboxNamed(t *testing.T, c *harness.Client, name string) {
	t.Helper()
	// One retry: the retraction is allowed to be a moment behind the error.
	deadline := time.Now().Add(90 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		list, err := c.SDK().List(ctx)
		cancel()
		if err != nil {
			t.Fatalf("list sandboxes: %v", err)
		}
		found := false
		for _, sb := range list {
			if sb.Name == name {
				found = true
				break
			}
		}
		if !found {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandbox %q survived a retracted create: an orphan row that looks healthy but can never fail over", name)
		}
		time.Sleep(5 * time.Second)
	}
}

// withoutString returns xs minus one value.
func withoutString(xs []string, drop string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if x != drop {
			out = append(out, x)
		}
	}
	return out
}

// withoutAll returns xs minus everything in drop.
func withoutAll(xs, drop []string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if !slices.Contains(drop, x) {
			out = append(out, x)
		}
	}
	return out
}

// clusterNodeIDs lists every gossiped member id.
func clusterNodeIDs(t *testing.T, c *harness.Client) []string {
	t.Helper()
	members := fetchMembers(t, c)
	out := make([]string, 0, len(members.Members))
	for _, m := range members.Members {
		out = append(out, m.NodeID)
	}
	return out
}

// nodeForClusterID maps a cluster node id back to the provisioned EC2 node, so
// a case can kill the machine behind an owner it resolved from the placement.
// This is what keeps group B off the hetero-only worker-x/y/z topology.
func nodeForClusterID(t *testing.T, c *harness.Client, targets *harness.IntegrationTargets, nodeID string) (harness.IntegrationNode, bool) {
	t.Helper()
	for _, n := range targets.Nodes {
		if nodeIDFromPrivateIP(n.PrivateIP) == nodeID || n.Name == nodeID {
			return n, true
		}
	}
	// Fall back to the gossiped member list, whose NodeName carries the
	// terraform name as a suffix.
	for _, m := range fetchMembers(t, c).Members {
		if m.NodeID != nodeID {
			continue
		}
		for _, n := range targets.Nodes {
			if m.NodeName == n.Name || strings.HasSuffix(m.NodeName, "-"+n.Name) {
				return n, true
			}
		}
	}
	return harness.IntegrationNode{}, false
}

// awaitNewOwner blocks until the placement names an owner other than previous.
func awaitNewOwner(t *testing.T, c *harness.Client, sandboxID, previous string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if owner := resolvePlacementOwner(t, c, sandboxID); owner != "" && owner != previous {
			t.Logf("sandbox %s reassigned from %s to %s", sandboxID, previous, owner)
			return owner
		}
		time.Sleep(10 * time.Second)
	}
	t.Fatalf("sandbox %s was never reassigned away from %s within %s", sandboxID, previous, timeout)
	return ""
}

// execEnvValue reads one environment variable from INSIDE the sandbox.
//
// This is the difference between "the sandbox is running" and "its credentials
// work". A sandbox that boots with an empty environment satisfies the former.
// Retried, because a freshly recreated sandbox's exec surface comes up a
// moment after the placement does.
func execEnvValue(t *testing.T, c *harness.Client, sandboxID, key string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		sb, err := c.SDK().Get(ctx, sandboxID)
		if err == nil {
			// printf, not echo: echo of an unset variable and echo of an empty
			// one are indistinguishable, and "" is the answer that matters.
			res, execErr := sb.Exec(ctx, sdktypes.ExecRequest{Command: "printf %s \"${" + key + "}\""})
			if execErr == nil {
				cancel()
				return strings.TrimSpace(res.Stdout)
			}
			last = execErr.Error()
		} else {
			last = err.Error()
		}
		cancel()
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("could not read %s from inside sandbox %s within %s (last: %s)", key, sandboxID, timeout, last)
	return ""
}

// sandboxStatusAndEnv reads the status and the sealed env in one place.
func sandboxStatusAndEnv(t *testing.T, c *harness.Client, sandboxID string) (string, map[string]string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var v struct {
		Status string            `json:"status"`
		Env    map[string]string `json:"env"`
	}
	if err := c.GetJSON(ctx, "/v1/sandboxes/"+sandboxID+"?include_env=true", &v); err != nil {
		t.Fatalf("read sandbox %s: %v", sandboxID, err)
	}
	return v.Status, v.Env
}

// sandboxIDByName finds a sandbox by name, or "" if it does not exist yet.
func sandboxIDByName(t *testing.T, c *harness.Client, name string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	list, err := c.SDK().List(ctx)
	if err != nil {
		return ""
	}
	for _, sb := range list {
		if sb.Name == name {
			return sb.ID
		}
	}
	return ""
}

// advertisedRuntimesForFailover lists the runtimes this scenario can actually
// fail a sandbox over on. Sealing is runtime-agnostic but the RESTORE path is
// not — PR #432 found a durable-WASM recreate that lost the sealed env
// entirely because the store rows carry no env — so UC-118 runs per runtime
// rather than trusting one.
func advertisedRuntimesForFailover(s *harness.Scenario) []string {
	var out []string
	for _, pair := range []struct {
		cap harness.Capability
		rt  string
	}{
		{harness.CapDocker, "docker"},
		{harness.CapContainerdEngine, "containerd"},
		{harness.CapWasm, "wasm"},
	} {
		if s.Has(pair.cap) {
			out = append(out, pair.rt)
		}
	}
	return out
}

// pickBounceableNode returns an SSH-reachable node that is not the current
// owner of the sandbox under test. Bouncing the owner would confound a
// membership experiment with a failover one.
func pickBounceableNode(t *testing.T, c *harness.Client, targets *harness.IntegrationTargets, ownerNodeID string) (harness.IntegrationNode, bool) {
	t.Helper()
	for _, n := range targets.Nodes {
		if _, ok := harness.SSHTarget(n); !ok {
			continue
		}
		if heteroNodeID(t, c, targets, n.Name) != ownerNodeID {
			return n, true
		}
	}
	return harness.IntegrationNode{}, false
}

// tailLines returns the last n lines, for putting a node's refusal into a
// failure message without dumping a whole journal into the report.
func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// The store path and the sealed-env column are read from the node's own
// config rather than hardcoded. The first draft of this file guessed
// "sandboxd.db" and "sealed_env"; the real names are state.db (install.sh
// writes SB_DB_PATH=/var/lib/sandboxd/state.db) and sealed_blob
// (store.go:149). Both guesses would have made UC-129 and UC-130 skip
// silently — a green matrix with two unrun cases, which is worse than a red
// one.
const sealedEnvColumn = "sealed_blob"

// storeDBExpr resolves SB_DB_PATH from the node's env files, falling back to
// the installer default.
const storeDBExpr = `db="${SB_DB_PATH:-/var/lib/sandboxd/state.db}"`

// sqliteSourceEnv loads the daemon's env so SB_DB_PATH is in scope.
const sqliteSourceEnv = `set -a; . /etc/sandboxd/sandboxd.env 2>/dev/null || true; . /etc/sandboxd/cluster.env 2>/dev/null || true; set +a; `

// sqliteDumpScript dumps the sandbox and env tables as text. `.dump` rather
// than a SELECT so a plaintext column added later is included without this
// script having to know its name — the point is to prove the secret is
// nowhere, not to check one column.
const sqliteDumpScript = `sudo bash -c '` + sqliteSourceEnv + storeDBExpr + `; ` +
	`command -v sqlite3 >/dev/null || exit 3; ` +
	`sqlite3 "file:$db?mode=ro" ".dump sandboxes" ".dump sandbox_env" 2>/dev/null'`

// corruptSealedEnvScript flips the sealed env blob for one sandbox. Prints
// NOROW when there is nothing to corrupt, so the caller can skip rather than
// assert against a change it never made.
func corruptSealedEnvScript(sandboxID string) string {
	q := func(sql string) string { return `"` + sql + `"` }
	return `sudo bash -c '` + sqliteSourceEnv + storeDBExpr + `; ` +
		`command -v sqlite3 >/dev/null || exit 3; ` +
		`n=$(sqlite3 "$db" ` + q(`SELECT COUNT(*) FROM sandbox_env WHERE sandbox_id = '"'"'`+sandboxID+`'"'"';`) + `); ` +
		`[ "$n" = "1" ] || { echo NOROW; exit 0; }; ` +
		`sqlite3 "$db" ` + q(`UPDATE sandbox_env SET `+sealedEnvColumn+` = randomblob(length(`+sealedEnvColumn+`)) WHERE sandbox_id = '"'"'`+sandboxID+`'"'"';`) + ` && echo CORRUPTED'`
}

// assertNoEnvKey fails if a response body carries an "env" object with
// anything in it. Distinct from the plaintext sweep: this catches a response
// that exposes the KEYS (which are themselves informative — AWS_SECRET_KEY
// tells an attacker what to go after) even when the values are redacted.
func assertNoEnvKey(t *testing.T, what string, body json.RawMessage) {
	t.Helper()
	var v struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return // not an object with an env field; nothing to assert
	}
	if len(v.Env) > 0 {
		t.Fatalf("%s returned %d env keys without include_env: even the key names are information a default read must not give up", what, len(v.Env))
	}
}

// redactedKeys lists only the keys of an env map, for failure messages that
// must not print the values they are complaining about.
func redactedKeys(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k := range env {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// containsString is slices.Contains, named for readability at the call sites
// where the haystack is a coverage list.
func containsString(xs []string, want string) bool { return slices.Contains(xs, want) }

// sameEventIDs compares two histories by event id. Order is not asserted —
// the fan-out merge is free to interleave — but the SET must match, which is
// what "the same history" means.
func sameEventIDs(a, b []auditlog.Event) bool {
	ids := func(evs []auditlog.Event) map[string]bool {
		m := make(map[string]bool, len(evs))
		for _, ev := range evs {
			if ev.EventID != "" {
				m[ev.EventID] = true
			}
		}
		return m
	}
	am, bm := ids(a), ids(b)
	if len(am) != len(bm) {
		return false
	}
	for id := range am {
		if !bm[id] {
			return false
		}
	}
	return true
}

// auditLogPath is where the node keeps its hash-chained evidence.
// The audit directory is the DB's directory: internal/service derives it with
// secretAuditDataDir(cfg.DBPath). There is no SB_SECRET_AUDIT_DIR — an early
// draft assumed one, which would have pointed every script below at a path
// that does not exist and turned four cases into silent skips.
const auditLogScript = sqliteSourceEnv +
	`db="${SB_DB_PATH:-/var/lib/sandboxd/state.db}"; dir=$(dirname "$db"); log="$dir/secrets.jsonl"; `

// tamperMiddleAuditLineScript edits a line in the MIDDLE of the chain and
// keeps a pristine copy alongside.
//
// The middle matters. A tail edit is indistinguishable from a torn write
// after a crash — which the product deliberately tolerates and records as a
// gap — so tampering with the tail would assert nothing about tamper
// detection.
const tamperMiddleAuditLineScript = `sudo bash -c '` + auditLogScript +
	`n=$(wc -l < "$log" 2>/dev/null || echo 0); ` +
	`[ "$n" -ge 4 ] || { echo TOOSHORT; exit 0; }; ` +
	`cp -a "$log" "$log.itest-backup"; ` +
	`mid=$(( n / 2 )); ` +
	`awk -v m="$mid" '"'"'NR==m { sub(/"reason":"/, "\"reason\":\"tampered-"); } { print }'"'"' "$log.itest-backup" > "$log.tmp" && ` +
	`cat "$log.tmp" > "$log" && rm -f "$log.tmp" && echo TAMPERED'`

// restoreTamperedAuditLogScript puts the pristine copy back. Writing through
// the existing inode (cat >, not mv) because the daemon holds the file open:
// a rename would leave it appending to an unlinked inode.
const restoreTamperedAuditLogScript = `sudo bash -c '` + auditLogScript +
	`[ -f "$log.itest-backup" ] || { echo NOBACKUP; exit 0; }; ` +
	`cat "$log.itest-backup" > "$log" && rm -f "$log.itest-backup" && echo RESTORED'`

// missingEventIDs returns the ids present in before but absent from after.
func missingEventIDs(before, after []auditlog.Event) []string {
	have := make(map[string]bool, len(after))
	for _, ev := range after {
		if ev.EventID != "" {
			have[ev.EventID] = true
		}
	}
	var missing []string
	for _, ev := range before {
		if ev.EventID != "" && !have[ev.EventID] {
			missing = append(missing, ev.EventID)
		}
	}
	return missing
}

func firstN(xs []string, n int) []string {
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}

// pickNonSeedNode prefers a joiner. Refusing the seed's boot on a cluster
// costs the rendezvous every joiner needs to rejoin, which turns one red case
// into a split cluster.
func pickNonSeedNode(targets *harness.IntegrationTargets) (harness.IntegrationNode, bool) {
	if targets == nil {
		return harness.IntegrationNode{}, false
	}
	for _, n := range targets.Nodes {
		if n.Seed {
			continue
		}
		if _, ok := harness.SSHTarget(n); ok {
			return n, true
		}
	}
	return harness.IntegrationNode{}, false
}

// witnessReceiptScript reports whether a witness receipt is on disk. The
// receipt is the proof that survives a restart; a witness that ships heads
// but persists nothing loses the evidence the moment the node reboots.
const witnessReceiptScript = `sudo bash -c '` + auditLogScript +
	`if [ -s "$dir/witness_receipts.jsonl" ] || [ -s "$dir/witness_tip.json" ]; then echo FOUND; else echo MISSING; fi'`

// auditIngestBindScript prints the address the ingest listener is bound to,
// or NONE when it is not configured.
const auditIngestBindScript = `sudo bash -c '` + sqliteSourceEnv +
	`p="${SB_AUDIT_INGEST_PORT:-0}"; ` +
	`[ "$p" != "0" ] || { echo NONE; exit 0; }; ` +
	`ss -ltn 2>/dev/null | awk -v p=":$p" '"'"'$4 ~ p"$" { print $4; found=1 } END { if (!found) print "NONE" }'"'"' | head -1'`

// auditIngestUntokenedScript POSTs an event with no token and prints the
// status. Run on the node because the listener is (and must be) loopback.
const auditIngestUntokenedScript = `sudo bash -c '` + sqliteSourceEnv +
	`p="${SB_AUDIT_INGEST_PORT:-0}"; ` +
	`[ "$p" != "0" ] || { echo NONE; exit 0; }; ` +
	`curl -sS -o /dev/null -w "%{http_code}" --max-time 20 -X POST ` +
	`-H "Content-Type: application/json" --data "{\\"kind\\":\\"egress\\",\\"sandbox_id\\":\\"itest-forged\\"}" ` +
	`"http://127.0.0.1:$p/audit/events"'`

// envOr reads an environment variable with a default.
func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// assertChainedJSONL checks that an exported stream is one JSON object per
// line, each carrying the chain links, and that none of it contains the
// secret. An export that ships unchained records is an export whose contents
// cannot be shown to be complete.
func assertChainedJSONL(t *testing.T, what, body, secret string) {
	t.Helper()
	harness.AssertNoPlaintext(t, what, body, secret)

	lines := 0
	chained := 0
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lines++
		var ev auditlog.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("%s: line %d is not one JSON object per line: %v", what, lines, err)
		}
		if ev.EventHash != "" && ev.PrevHash != "" {
			chained++
		}
	}
	if lines == 0 {
		t.Fatalf("%s contained no records", what)
	}
	if chained == 0 {
		t.Fatalf("%s delivered %d records and NONE carried chain links; the export cannot be shown to be complete", what, lines)
	}
}

// assertExpvarEquals reads /v1/metrics and asserts a gauge's value. The gauge
// is what an operator alerts on: a subsystem that works while reporting
// unhealthy is a page that fires forever, and one that fails while reporting
// healthy is a page that never fires.
func assertExpvarEquals(t *testing.T, c *harness.Client, name string, want int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	body, err := c.GetText(ctx, "/v1/metrics")
	if err != nil {
		t.Fatalf("read /v1/metrics: %v", err)
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, name) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[len(fields)-1] == strconv.Itoa(want) {
			return
		}
		t.Fatalf("%s = %s, want %d", name, fields[len(fields)-1], want)
	}
	t.Fatalf("%s is not exported by /v1/metrics at all; there is nothing for an operator to alert on", name)
}

// clusterTLSEnv makes SB_CLUSTER_TLS_DIR and SB_CLUSTER_INTERNAL_ADVERTISE
// available to a remote script.
const clusterTLSEnv = `set -a; . /etc/sandboxd/cluster.env 2>/dev/null || true; set +a; ` +
	`tls="${SB_CLUSTER_TLS_DIR:-/etc/sandboxd/tls}"; base="${SB_CLUSTER_INTERNAL_ADVERTISE%/}"; `

// nodeCertSANsScript prints the subjectAltName line of the node certificate.
const nodeCertSANsScript = `sudo bash -c '` + clusterTLSEnv +
	`command -v openssl >/dev/null || { echo NOOPENSSL; exit 0; }; ` +
	`openssl x509 -in "$tls/node.crt" -noout -text | grep -A1 "Subject Alternative Name" | tail -1'`

// caKeyPresenceScript reports whether the CA signing key is on this node.
const caKeyPresenceScript = `sudo bash -c '` + clusterTLSEnv +
	`if [ -f "$tls/ca.key" ]; then echo PRESENT; else echo ABSENT; fi'`

// plaintextInternalProbeScript speaks http (not https) to the internal port.
const plaintextInternalProbeScript = `sudo bash -c '` + clusterTLSEnv +
	`hostport="${base#https://}"; hostport="${hostport#http://}"; ` +
	`curl -sS -o /dev/null -w "%{http_code}" --max-time 15 "http://$hostport/v1/cluster/internal/secrets/probe" 2>/dev/null || echo 000'`

// forgedCertProbeScript mints a self-signed certificate carrying a valid
// node:<id> SAN and offers it to the peer listener.
//
// A valid SAN on an untrusted issuer is the interesting forgery: it separates
// "does the server check the name?" from "does the server check WHO SIGNED
// the name?". Only the second is a real identity check.
func forgedCertProbeScript(nodeID string) string {
	return `sudo bash -c '` + clusterTLSEnv +
		`command -v openssl >/dev/null || { echo NOOPENSSL; exit 3; }; ` +
		`d=$(mktemp -d); trap "rm -rf $d" EXIT; ` +
		`openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=forged" ` +
		`-addext "subjectAltName=DNS:node:` + nodeID + `" ` +
		`-keyout "$d/f.key" -out "$d/f.crt" >/dev/null 2>&1 || { echo MINTFAIL; exit 3; }; ` +
		`curl -sS -o /dev/null -w "%{http_code}" --max-time 15 ` +
		`--cert "$d/f.crt" --key "$d/f.key" --cacert "$tls/ca.crt" ` +
		`-I "$base/v1/cluster/internal/secrets/probe" 2>/dev/null || echo 000'`
}

// lastField returns the last whitespace-separated token, which is where curl
// leaves its -w output after any diagnostics.
func lastField(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// plantDecoyCAKeyScript puts a file named ca.key in the daemon's TLS
// directory. It never has to be a real key — the enterprise gate is a stat().
const plantDecoyCAKeyScript = `sudo bash -c '` + clusterTLSEnv +
	`[ -d "$tls" ] || { echo NOTLSDIR; exit 3; }; ` +
	`[ -f "$tls/ca.key" ] && { echo ALREADYPRESENT; exit 0; }; ` +
	`printf "%s\n" "itest decoy - not a key" > "$tls/ca.key" && chmod 0600 "$tls/ca.key" && echo PLANTED'`

const removeDecoyCAKeyScript = `sudo bash -c '` + clusterTLSEnv +
	`if grep -q "itest decoy" "$tls/ca.key" 2>/dev/null; then rm -f "$tls/ca.key" && echo REMOVED; else echo "NOTOURS"; fi'`

// assertNodeBackInService is UC-159 applied per row: after a deliberately
// refused boot, the node must be up AND back in the cluster before the next
// row runs. Asserting it only once at the end would not identify the row that
// left the fleet degraded — and every row after that one would fail for a
// reason that has nothing to do with what it tests.
func assertNodeBackInService(t *testing.T, c *harness.Client, targets *harness.IntegrationTargets, node harness.IntegrationNode) {
	t.Helper()
	target, ok := harness.SSHTarget(node)
	if !ok {
		t.Fatalf("node %s has no SSH address", node.Name)
	}
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		out, _ := harness.SSHRun(t, target, "sudo systemctl is-active sandboxd || true")
		if strings.TrimSpace(out) == "active" {
			break
		}
		time.Sleep(5 * time.Second)
	}
	out, _ := harness.SSHRun(t, target, "sudo systemctl is-active sandboxd || true")
	if strings.TrimSpace(out) != "active" {
		t.Fatalf("node %s is still down after the gate row restored its configuration; every later row would assert against a degraded fleet", node.Name)
	}

	// Up is not the same as rejoined. A node that is running but out of the
	// member list is exactly the 2+1 split this suite has produced before.
	if !sc.Has(harness.CapCluster) {
		return
	}
	nodeID := heteroNodeID(t, c, targets, node.Name)
	rejoinDeadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(rejoinDeadline) {
		if containsString(clusterNodeIDs(t, c), nodeID) {
			return
		}
		time.Sleep(10 * time.Second)
	}
	t.Fatalf("node %s (%s) is running but has not rejoined the cluster; the fleet is split and every later case is suspect", node.Name, nodeID)
}

// workerdJailProbeScript reports the four jail properties at once.
//
// One script, one process: probing them in four SSH round trips could
// describe four different workerd processes if the group restarts in
// between, and "uid from one process, seccomp from another" is not evidence
// that any single process is jailed.
const workerdJailProbeScript = `sudo bash -c '
pid=$(pgrep -n workerd 2>/dev/null || true)
if [ -z "$pid" ]; then echo "FOUND=0"; exit 0; fi
echo "FOUND=1"
echo "UID=$(awk "/^Uid:/ {print \$2}" /proc/$pid/status 2>/dev/null)"
echo "SECCOMP=$(awk "/^Seccomp:/ {print \$2}" /proc/$pid/status 2>/dev/null)"
echo "NONEWPRIVS=$(awk "/^NoNewPrivs:/ {print \$2}" /proc/$pid/status 2>/dev/null)"
echo "ROOT=$(readlink /proc/$pid/root 2>/dev/null)"
cg=$(awk -F: "{print \$3}" /proc/$pid/cgroup 2>/dev/null | head -1)
echo "PIDSMAX=$(cat /sys/fs/cgroup$cg/pids.max 2>/dev/null)"
'`

// parseKV turns KEY=VALUE lines into a map.
func parseKV(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		m[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return m
}

// getWithHeaders issues an authenticated GET and returns the body AND the
// response headers. UC-168's honesty property lives in a header, which
// Client.GetJSON discards.
func getWithHeaders(ctx context.Context, c *harness.Client, path string) (string, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL()+path, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Authorization", "Bearer "+sc.PAT)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return string(b), resp.Header, fmt.Errorf("GET %s: status %d", path, resp.StatusCode)
	}
	return string(b), resp.Header, nil
}

// deleteSandboxRowScript removes a sandbox row from the store, leaving the
// runtime's in-memory group behind. That is what an orphan IS — a killed
// process is not an orphan, it is a dead process.
func deleteSandboxRowScript(sandboxID string) string {
	return `sudo bash -c '` + sqliteSourceEnv + storeDBExpr + `; ` +
		`command -v sqlite3 >/dev/null || exit 3; ` +
		`n=$(sqlite3 "$db" "SELECT COUNT(*) FROM sandboxes WHERE id='"'"'` + sandboxID + `'"'"';"); ` +
		`[ "$n" = "1" ] || { echo NOROW; exit 0; }; ` +
		`sqlite3 "$db" "DELETE FROM sandboxes WHERE id='"'"'` + sandboxID + `'"'"';" && echo DELETED'`
}

// leakForm is one encoding of the canary and the name to report it under.
type leakForm struct {
	name    string
	encoded string
}

// leakForms mirrors harness.FindPlaintextLeak's table. It is spelled out here
// rather than derived because the sweep greps on a REMOTE host: the encodings
// have to travel into a shell command, not into a Go strings.Contains.
func leakForms(secret string) []leakForm {
	return []leakForm{
		{"raw", secret},
		{"base64-std", base64.StdEncoding.EncodeToString([]byte(secret))},
		{"base64-raw", base64.RawStdEncoding.EncodeToString([]byte(secret))},
		{"hex", hex.EncodeToString([]byte(secret))},
		{"url-query", url.QueryEscape(secret)},
	}
}

// leakGrepScript looks for one encoded form everywhere a secret could come
// to rest: the daemon's data dir (store, audit JSONL, Raft log), the system
// logs, and the journal.
//
// Every hit is prefixed with a literal HIT: marker and the Go side counts
// ONLY those. Anything else the pipeline emits — ssh banners, a grep
// diagnostic about an unreadable path, sudo chatter — is then structurally
// incapable of being read as a leaked secret. The first two live runs both
// reported the canary as found in all five encodings with an empty location
// list, which is what "the output was non-empty" gets you.
func leakGrepScript(needle string) string {
	q := shellSingleQuoteForSuite(needle)
	return `sudo bash -c '` + sqliteSourceEnv + storeDBExpr + `; dir=$(dirname "$db"); ` +
		`{ grep -rlaF ` + q + ` "$dir" /var/log 2>/dev/null; ` +
		`journalctl -u sandboxd --no-pager 2>/dev/null | grep -aF ` + q + ` | head -3; ` +
		`} | sed -e "/^$/d" -e "s/^/HIT:/" | head -20; echo SWEEPDONE'`
}

// shellSingleQuoteForSuite wraps s for a single-quoted word nested inside the
// outer `sudo bash -c '...'`.
func shellSingleQuoteForSuite(s string) string {
	return `'"'"'` + strings.ReplaceAll(s, "'", `'"'"'`) + `'"'"'`
}

// createSecretSandbox creates a sandbox carrying sealed env, using the HA
// path only where HA is possible.
//
// CreateHASandbox waits for failover_ready, which a single-node deployment
// can never report — the server omits the field entirely (policy=recreate
// needs a peer to be ready ON). A CapSecrets-only use case that reached for
// the HA helper would therefore burn its whole timeout and fail on S1 for a
// reason unrelated to what it tests. UC-169's leak sweep is exactly that
// shape: it wants a sandbox with sealed material, and it is just as valid on
// one node as on three.
func createSecretSandbox(t *testing.T, c *harness.Client, env map[string]string) *microvm.Sandbox {
	t.Helper()
	if sc.Has(harness.CapCluster) {
		return harness.CreateHASandbox(t, c, harness.HASandboxSpec{Env: env})
	}
	return c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		Env:  env,
	})
}

// isTransientGatewayErr reports whether an API error is the edge failing to
// reach the daemon rather than the daemon answering. A 502/503/504 is
// neither a pass nor the failure a case is asserting, so cases retry past it
// instead of recording a verdict the daemon never gave.
func isTransientGatewayErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, code := range []string{"status 502", "status 503", "status 504"} {
		if strings.Contains(msg, code) {
			return true
		}
	}
	return false
}

// countGapMarkers counts overflow gap markers in a history.
//
// They carry no sandbox_id, so a marker any other case created on the same
// node appears here too. Cases that care about gaps must baseline and
// compare rather than assert on presence.
func countGapMarkers(events []auditlog.Event) int {
	n := 0
	for _, ev := range events {
		if ev.Kind == "gap" || ev.Result == "gap" {
			n++
		}
	}
	return n
}
