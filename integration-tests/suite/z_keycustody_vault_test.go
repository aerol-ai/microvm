//go:build integration

package suite

// Customer key custody on Vault (plans/customer-key-custody.md Phase 6),
// UC-297..306, UC-313 and UC-314, on cluster-3-mixed-secrets-vault. Disruptive: the cases
// restart, revoke and fail over nodes, so the z_ prefix keeps them after the
// rest of the suite. They run in order: UC-297 switches the local cluster
// to Vault and UC-298 wraps the server key; every later case brings the
// cluster to that state itself if it runs alone.

import (
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func kcVaultWrapped(t *testing.T, targets *harness.IntegrationTargets) harness.IntegrationNode {
	t.Helper()
	return kcEnsureWrapped(t, targets, kcEnsureVault)
}

// UC-297 — a running local cluster moves to Vault the two-step way, and a
// sandbox sealed before the switch keeps working through it.
func TestKeyCustodySwitchLocalToVault(t *testing.T) {
	harness.Require(t, sc, "UC-297")
	targets := kcTargets(t)
	nodes := kcNodes(targets)
	if kcMarked(t, nodes[0], "provider-switched") {
		t.Skip("this cluster already seals with Vault (an earlier run switched it); the switch needs a local cluster")
	}
	c := client(t)
	secret := secretValue(t, "297")
	sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{Env: map[string]string{"UC297_TOKEN": secret}})
	waitRunning(t, sb)

	kcSwitchToVault(t, targets, func(step int) {
		if step != 1 {
			return
		}
		// Step 1: every node has the Vault settings but still seals
		// locally. A sandbox sealed before the switch fails over and opens.
		kcHAFailover(t, targets, sb.ID, "UC297_TOKEN", secret)
	})
	// Step 2 restarted every node, and each node's boot sweep converts its
	// local rows to Vault (§12). Nothing stays stale.
	kcAwaitMetric(t, nodes, "aerolvm_key_rows_stale", nil, 5*time.Minute, func(v float64, ok bool) bool { return ok && v == 0 })
	kcAwaitMetric(t, nodes, "aerolvm_key_store_calls_total", map[string]string{"key": "vault", "key3": "ok"}, 2*time.Minute, func(v float64, ok bool) bool { return ok && v > 0 })
	// After the sweep the same sandbox still opens, now through Vault, and a
	// sandbox sealed after the switch does too.
	kcHAFailover(t, targets, sb.ID, "UC297_TOKEN", secret)
	kcHAFailover(t, targets, "", "UC297_AFTER", secretValue(t, "297b"))
}

// UC-298 — the server key is wrapped on every node, and no plaintext copy
// is left on any of them.
func TestKeyCustodyWrapServerKey(t *testing.T) {
	harness.Require(t, sc, "UC-298")
	targets := kcTargets(t)
	kcVaultWrapped(t, targets)
	nodes := kcNodes(targets)
	for _, n := range nodes {
		status := kcSSH(t, n, "sudo /usr/local/bin/sandboxd key status --check "+kcKeyCLIEnv)
		for _, want := range []string{"customer key store (wrapped)", "check: every server key unwraps and matches"} {
			if !strings.Contains(status, want) {
				t.Fatalf("%s: `sandboxd key status --check` lacks %q:\n%s", n.Name, want, status)
			}
		}
		clean := kcSSH(t, n, `if sudo test -e `+kcKeyFile+`; then echo KEYFILE; fi
if sudo sh -c "grep -l '^SB_CREDENTIAL_ENCRYPTION_KEY=' /etc/sandboxd/*.env"; then echo ENVKEY; fi
sudo test -s `+kcWrapped+` && echo WRAPPED`)
		if strings.Contains(clean, "KEYFILE") || strings.Contains(clean, "ENVKEY") || !strings.Contains(clean, "WRAPPED") {
			t.Fatalf("%s still holds a plaintext server key, or has no wrapped file:\n%s", n.Name, clean)
		}
	}
	kcAwaitMetric(t, nodes, "aerolvm_key_custody", map[string]string{"key": "server key", "key2": "customer key store (wrapped)"}, time.Minute, func(v float64, ok bool) bool { return ok && v == 1 })
	kcAwaitMetric(t, nodes, "aerolvm_secret_provider_canary_ok", nil, time.Minute, func(v float64, ok bool) bool { return ok && v == 1 })
	kcHAFailover(t, targets, "", "UC298_TOKEN", secretValue(t, "298"))
}

// kcRecheckCount reads one node's re-check counter for a result.
func kcRecheckCount(t *testing.T, base, result string) float64 {
	t.Helper()
	return harness.MetricValueOrZero(nodeMetrics(t, base), "aerolvm_key_recheck_total", map[string]string{"key": result})
}

// UC-299 — a 403 from Vault is never a revoke, however long it lasts.
func TestKeyCustodyDeniedIsNotRevoked(t *testing.T) {
	harness.Require(t, sc, "UC-299")
	targets := kcTargets(t)
	seed := kcVaultWrapped(t, targets)
	nodes := kcNodes(targets)
	bases := map[string]string{}
	before := map[string]float64{}
	for _, n := range nodes {
		bases[n.Name] = nodeBase(t, n)
		before[n.Name] = kcRecheckCount(t, bases[n.Name], "denied")
	}
	noDecrypt := strings.ReplaceAll(kcPolicy, `path "transit/decrypt/`+kcTransitKey+`" { capabilities = ["update"] }`+"\n", "")
	kcBaoStdin(t, seed, "policy write aerolvm -", noDecrypt)
	t.Cleanup(func() { kcBaoStdin(t, seed, "policy write aerolvm -", kcPolicy) })

	// More denied re-checks than SB_SECRET_PROVIDER_REVOKE_AFTER on every
	// node, and none of them stops.
	deadline := time.Now().Add(kcRevokeBound)
	for {
		waiting := 0
		for _, n := range nodes {
			if kcRecheckCount(t, bases[n.Name], "denied") < before[n.Name]+3 {
				waiting++
			}
		}
		if waiting == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d nodes did not count three denied re-checks within %s", waiting, kcRevokeBound)
		}
		time.Sleep(5 * time.Second)
	}
	for _, n := range nodes {
		if v := harness.MetricValueOrZero(nodeMetrics(t, bases[n.Name]), "aerolvm_key_revoked", nil); v != 0 {
			t.Fatalf("%s stopped on a 403 (aerolvm_key_revoked=%v): only a deleted or disabled key may revoke", n.Name, v)
		}
		if h := kcNodeHealth(t, n); strings.Contains(h, "revoked") {
			t.Fatalf("%s reports revoked on a 403: %s", n.Name, h)
		}
	}
	kcBaoStdin(t, seed, "policy write aerolvm -", kcPolicy)
	kcAwaitMetric(t, nodes, "aerolvm_key_revoked", nil, time.Minute, func(v float64, ok bool) bool { return !ok || v == 0 })
}

// UC-300 — deleting the Transit key stops every node, and restoring it
// brings every node back, with no restart either way.
func TestKeyCustodyRevokeAndRecover(t *testing.T) {
	harness.Require(t, sc, "UC-300")
	targets := kcTargets(t)
	seed := kcVaultWrapped(t, targets)
	nodes := kcNodes(targets)
	c := client(t)

	backup := strings.TrimSpace(kcBao(t, seed, "read -field=backup transit/backup/"+kcTransitKey))
	if backup == "" {
		t.Fatal("no Transit backup; the key could not be restored after the revoke")
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		kcBaoStdin(t, seed, "write transit/restore/"+kcTransitKey+" backup=-", backup)
	}
	t.Cleanup(func() {
		if !restored {
			restore()
			kcAwaitMetric(t, nodes, "aerolvm_key_revoked", nil, kcRevokeBound, func(v float64, ok bool) bool { return !ok || v == 0 })
		}
	})

	kcBao(t, seed, "write transit/keys/"+kcTransitKey+"/config deletion_allowed=true")
	kcBao(t, seed, "delete transit/keys/"+kcTransitKey)
	kcAwaitMetric(t, nodes, "aerolvm_key_revoked", nil, kcRevokeBound, func(v float64, ok bool) bool { return ok && v == 1 })
	for _, n := range nodes {
		if h := kcNodeHealth(t, n); !strings.Contains(h, "revoked") {
			t.Fatalf("%s: /health does not report the revoke: %s", n.Name, h)
		}
		if evs, err := harness.NodeAuditEvents(t, n, "key_revoked"); err != nil || len(evs) == 0 {
			t.Fatalf("%s wrote no key_revoked audit record (err %v)", n.Name, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	status, body, err := c.PostStatus(ctx, "/v1/sandboxes", map[string]any{
		"image": harness.DefaultImage, "env": map[string]string{"UC300": "x"},
	})
	if err != nil || status != http.StatusServiceUnavailable || !strings.Contains(string(body), "key_revoked") {
		t.Fatalf("create with env while revoked = %d %s %v, want 503 key_revoked", status, body, err)
	}

	restore()
	kcAwaitMetric(t, nodes, "aerolvm_key_revoked", nil, kcRevokeBound, func(v float64, ok bool) bool { return ok && v == 0 })
	for _, n := range nodes {
		if evs, err := harness.NodeAuditEvents(t, n, "key_recovered"); err != nil || len(evs) == 0 {
			t.Fatalf("%s wrote no key_recovered audit record (err %v)", n.Name, err)
		}
	}
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Image: harness.DefaultImage, Env: map[string]string{"UC300": "back"}})
	if got := execEnvValue(t, c, sb.ID, "UC300", 3*time.Minute); got != "back" {
		t.Fatalf("after recovery a new sandbox reads %q", got)
	}
}

// UC-301 — with the key store unreachable a restarted node refuses to
// start, and starts by itself once the key store answers again.
func TestKeyCustodyKeyStoreDownAtBoot(t *testing.T) {
	harness.Require(t, sc, "UC-301")
	targets := kcTargets(t)
	seed := kcVaultWrapped(t, targets)
	node, ok := harness.PickRestartableNode(targets)
	if !ok {
		t.Skip("no node to restart")
	}
	t.Cleanup(func() {
		kcEnsureProxy(t, seed, node)
		kcRestart(t, node)
	})
	kcSSH(t, node, "sudo systemctl stop itest-bao-proxy; sudo systemctl reset-failed itest-bao-proxy 2>/dev/null || true")
	kcSSH(t, node, "sudo systemctl restart sandboxd || true")
	// A few failed starts (Restart=always, 5s apart), well inside the unit's
	// start limit of 10 in 5 minutes.
	time.Sleep(20 * time.Second)
	if state := strings.TrimSpace(kcSSH(t, node, "sudo systemctl is-active sandboxd || true")); state == "active" {
		t.Fatalf("%s started with its key store unreachable", node.Name)
	}
	if j := kcSSH(t, node, "sudo journalctl -u sandboxd --no-pager -n 120 || true"); !strings.Contains(j, "unwrap server key") {
		t.Fatalf("%s did not say why it refused to start:\n%s", node.Name, j)
	}
	kcEnsureProxy(t, seed, node)
	deadline := time.Now().Add(2 * time.Minute)
	for strings.TrimSpace(kcSSH(t, node, "sudo systemctl is-active sandboxd || true")) != "active" {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not start by itself after its key store came back", node.Name)
		}
		time.Sleep(5 * time.Second)
	}
	if err := waitNodeRejoined(t, node); err != nil {
		t.Fatalf("%s started but did not rejoin: %v", node.Name, err)
	}
}

// UC-302 — a node told to use a wrapped key it does not have refuses to
// start; it never makes a key of its own.
func TestKeyCustodyJoinerWithoutWrappedFile(t *testing.T) {
	harness.Require(t, sc, "UC-302")
	targets := kcTargets(t)
	kcVaultWrapped(t, targets)
	node, ok := harness.PickRestartableNode(targets)
	if !ok {
		t.Skip("no node to restart")
	}
	harness.WithNodeEnv(t, node, map[string]string{
		"SB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH": "/var/lib/sandboxd/itest-missing.key.wrapped",
	}, func(res harness.NodeBootResult) {
		if !res.RefusedWith("wrapped server key") {
			t.Fatalf("%s did not refuse to start without its wrapped server key (status %q):\n%s", node.Name, res.Status, res.Journal)
		}
	})
}

// kcLatestVersion is the Transit key's latest version.
func kcLatestVersion(t *testing.T, seed harness.IntegrationNode) int {
	t.Helper()
	v, err := strconv.Atoi(strings.TrimSpace(kcBao(t, seed, "read -field=latest_version transit/keys/"+kcTransitKey)))
	if err != nil {
		t.Fatalf("latest_version: %v", err)
	}
	return v
}

// UC-303 — a Transit rotation is followed by every row and every
// server-key file; retiring the old version strands nothing.
func TestKeyCustodyTransitRotation(t *testing.T) {
	harness.Require(t, sc, "UC-303")
	targets := kcTargets(t)
	seed := kcVaultWrapped(t, targets)
	nodes := kcNodes(targets)
	c := client(t)
	secret := secretValue(t, "303")
	sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{Env: map[string]string{"UC303_TOKEN": secret}})
	waitRunning(t, sb)

	kcBao(t, seed, "write -f transit/keys/"+kcTransitKey+"/rotate")
	latest := kcLatestVersion(t, seed)
	// The sweep runs at boot and hourly; a rolling restart runs it now.
	kcRollingRestart(t, targets)
	kcAwaitMetric(t, nodes, "aerolvm_key_rows_stale", nil, 5*time.Minute, func(v float64, ok bool) bool { return ok && v == 0 })
	want := "wrapped under: vault:v" + strconv.Itoa(latest)
	for _, n := range nodes {
		if s := kcSSH(t, n, "sudo /usr/local/bin/sandboxd key status "+kcKeyCLIEnv); !strings.Contains(s, want) {
			t.Fatalf("%s: the server-key file did not follow the rotation (%q missing):\n%s", n.Name, want, s)
		}
	}
	kcBao(t, seed, "write transit/keys/"+kcTransitKey+"/config min_decryption_version="+strconv.Itoa(latest))
	kcHAFailover(t, targets, sb.ID, "UC303_TOKEN", secret)
	kcAwaitMetric(t, nodes, "aerolvm_key_rows_retired", nil, time.Minute, func(v float64, ok bool) bool { return !ok || v == 0 })

	// `sandboxd key rewrap` follows a second rotation by hand.
	kcBao(t, seed, "write -f transit/keys/"+kcTransitKey+"/rotate")
	want = "vault:v" + strconv.Itoa(kcLatestVersion(t, seed))
	for _, n := range nodes {
		if out := kcSSH(t, n, "sudo /usr/local/bin/sandboxd key rewrap "+kcKeyCLIEnv); !strings.Contains(out, want) {
			t.Fatalf("%s: `sandboxd key rewrap` did not move the file to %s:\n%s", n.Name, want, out)
		}
	}
}

// kcCopyWrappedFile copies the seed's server-key file to every other node,
// byte for byte and 0600, as the operator does after each rotation step.
func kcCopyWrappedFile(t *testing.T, targets *harness.IntegrationTargets, from harness.IntegrationNode) {
	t.Helper()
	b64 := strings.TrimSpace(kcSSH(t, from, "sudo base64 -w0 "+kcWrapped))
	if _, err := base64.StdEncoding.DecodeString(b64); err != nil || b64 == "" {
		t.Fatalf("read %s on %s: %v", kcWrapped, from.Name, err)
	}
	for _, n := range targets.Nodes {
		if n.Name == from.Name {
			continue
		}
		kcSSHStdin(t, n, `set -e
tmp=$(sudo mktemp /var/lib/sandboxd/.itest-wrapped.XXXXXX)
base64 -d | sudo tee "$tmp" >/dev/null
sudo chmod 0600 "$tmp"
sudo mv -f "$tmp" `+kcWrapped, b64+"\n")
	}
}

// UC-304 — server-key rotation across the cluster, with a failover after
// every step.
func TestKeyCustodyServerKeyRotation(t *testing.T) {
	harness.Require(t, sc, "UC-304")
	targets := kcTargets(t)
	seed := kcVaultWrapped(t, targets)
	nodes := kcNodes(targets)
	c := client(t)
	secret := secretValue(t, "304")
	sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{Env: map[string]string{"UC304_TOKEN": secret}})
	waitRunning(t, sb)

	step := func(args string) string {
		out := kcSSH(t, seed, "sudo /usr/local/bin/sandboxd key rotate "+args+" "+kcKeyCLIEnv)
		kcCopyWrappedFile(t, targets, seed)
		return out
	}
	// The key being replaced: 0 on a cluster that never rotated, the last
	// promoted key on one that did.
	old := ""
	for _, f := range strings.Fields(kcSSH(t, seed, "sudo /usr/local/bin/sandboxd key status "+kcKeyCLIEnv+" | grep 'server keys:'")) {
		if id, ok := strings.CutSuffix(f, "=current"); ok {
			old = id
		}
	}
	if old == "" {
		t.Fatal("`sandboxd key status` names no current server key")
	}
	// A backup taken now holds only the old key (eng D24).
	const preRotation = "/var/tmp/itest-prerotation.wrapped"
	kcSSH(t, seed, "sudo cp "+kcWrapped+" "+preRotation)
	t.Cleanup(func() { kcSSH(t, seed, "sudo rm -f "+preRotation) })
	out := step("--stage")
	if !strings.Contains(out, "staged: key ") {
		t.Fatalf("stage: %s", out)
	}
	staged := strings.Fields(strings.SplitN(out, "staged: key ", 2)[1])[0]
	kcAwaitMetric(t, nodes, "aerolvm_server_key_ring", map[string]string{"key": staged, "key2": "decrypt"}, 2*time.Minute, func(v float64, ok bool) bool { return ok && v == 1 })
	kcHAFailover(t, targets, sb.ID, "UC304_TOKEN", secret)

	step("--promote")
	kcAwaitMetric(t, nodes, "aerolvm_server_key_ring", map[string]string{"key": staged, "key2": "current"}, 2*time.Minute, func(v float64, ok bool) bool { return ok && v == 1 })
	// Values on the new key somewhere in the cluster. Not on every node: a
	// node that holds no sealed value (after a failover moved its sandbox
	// away) publishes no row count at all.
	deadline := time.Now().Add(3 * time.Minute)
	for total := 0.0; ; {
		total = 0
		for _, n := range nodes {
			total += harness.MetricValueOrZero(kcMetricsOf(t, n), "aerolvm_server_key_rows", map[string]string{"key": staged})
		}
		if total > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no node reports a value sealed under key %s after the promote", staged)
		}
		time.Sleep(5 * time.Second)
	}
	for _, gone := range []string{old, "unopenable"} {
		kcAwaitMetric(t, nodes, "aerolvm_server_key_rows", map[string]string{"key": gone}, 3*time.Minute, func(v float64, ok bool) bool { return !ok || v == 0 })
	}
	kcHAFailover(t, targets, sb.ID, "UC304_TOKEN", secret)

	step("--retire " + old)
	kcAwaitMetric(t, nodes, "aerolvm_server_key_ring", map[string]string{"key": old, "key2": "retired"}, 2*time.Minute, func(v float64, ok bool) bool { return ok && v == 1 })
	// The pre-rotation backup holds key `old` only, and no node has a value
	// left on it (checked before the retire): that backup opens nothing the
	// cluster holds now.
	if keys := kcSSH(t, seed, "sudo env SB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH="+preRotation+" /usr/local/bin/sandboxd key status "+kcKeyCLIEnv+" | grep 'server keys:'"); !strings.Contains(keys, old+"=current") || strings.Contains(keys, staged+"=") {
		t.Fatalf("the pre-rotation backup's keys: %s", keys)
	}
	kcHAFailover(t, targets, sb.ID, "UC304_TOKEN", secret)
	kcHAFailover(t, targets, "", "UC304_AFTER", secretValue(t, "304b"))
	for _, n := range nodes {
		for _, kind := range []string{"key_rotation_staged", "key_rotation_promoted", "key_rotation_retired"} {
			if evs, err := harness.NodeAuditEvents(t, n, kind); err != nil || len(evs) == 0 {
				t.Fatalf("%s wrote no %s audit record (err %v)", n.Name, kind, err)
			}
		}
	}
}

// UC-305 — every node restarts while it owns secret-bearing sandboxes, and
// all of them open again without a throttled or failed key-store call.
func TestKeyCustodyRestartWithManySecrets(t *testing.T) {
	harness.Require(t, sc, "UC-305")
	targets := kcTargets(t)
	kcVaultWrapped(t, targets)
	nodes := kcNodes(targets)
	c := client(t)
	const n = 20
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Image: harness.DefaultImage, Env: map[string]string{"UC305": strconv.Itoa(i)}})
		ids = append(ids, sb.ID)
	}
	throttled := map[string]float64{}
	for _, node := range nodes {
		throttled[node.Name] = harness.MetricValueOrZero(kcMetricsOf(t, node), "aerolvm_key_store_calls_total", map[string]string{"key": "vault", "key3": "throttled"})
	}
	kcRollingRestart(t, targets)
	for i, id := range ids {
		if got := execEnvValue(t, c, id, "UC305", 3*time.Minute); got != strconv.Itoa(i) {
			t.Fatalf("sandbox %d (%s) reads %q after the restart", i, id, got)
		}
	}
	for _, node := range nodes {
		m := kcMetricsOf(t, node)
		// The counter restarted with the node, so any throttled call is new.
		if v := harness.MetricValueOrZero(m, "aerolvm_key_store_calls_total", map[string]string{"key": "vault", "key3": "throttled"}); v > 0 {
			t.Errorf("%s: %v throttled key-store calls during the restart (before it: %v)", node.Name, v, throttled[node.Name])
		}
	}
}

// UC-306 — a backup of a wrapped node carries the wrapped file and no
// plaintext key, and the restored file verifies through the key store.
func TestKeyCustodyBackupHoldsNoPlaintext(t *testing.T) {
	harness.Require(t, sc, "UC-306")
	targets := kcTargets(t)
	kcVaultWrapped(t, targets)
	node, ok := harness.PickRestartableNode(targets)
	if !ok {
		t.Skip("no node to back up")
	}
	for path, rel := range map[string]string{
		"/usr/local/lib/itest-sandboxd-backup.sh":  "scripts/sandboxd-backup.sh",
		"/usr/local/lib/itest-sandboxd-restore.sh": "scripts/sandboxd-restore.sh",
	} {
		if err := harness.InstallNodeFile(t, node, path, kcRepoFile(t, rel)); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		kcSSH(t, node, "sudo rm -rf /tmp/itest-backup.tgz /tmp/itest-restore /tmp/itest-backup-x")
	})
	kcSSH(t, node, "sudo bash /usr/local/lib/itest-sandboxd-backup.sh --output /tmp/itest-backup.tgz")
	listing := kcSSH(t, node, "sudo tar -tzf /tmp/itest-backup.tgz")
	if !strings.Contains(listing, "credential_encryption.key.wrapped") {
		t.Fatalf("the backup has no wrapped server key:\n%s", listing)
	}
	for _, line := range strings.Split(listing, "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), "/credential_encryption.key") {
			t.Fatalf("the backup holds a plaintext key file: %s", line)
		}
	}
	leak := kcSSH(t, node, `set -e
sudo rm -rf /tmp/itest-backup-x && sudo mkdir -p /tmp/itest-backup-x
sudo tar -xzf /tmp/itest-backup.tgz -C /tmp/itest-backup-x
sudo grep -rl '^SB_CREDENTIAL_ENCRYPTION_KEY=' /tmp/itest-backup-x/etc 2>/dev/null || true
sudo grep -h '^key_custody=' /tmp/itest-backup-x/MANIFEST.txt`)
	if !strings.Contains(leak, "key_custody=wrapped") || strings.Contains(leak, ".env") {
		t.Fatalf("the backup's env files or manifest are wrong:\n%s", leak)
	}
	kcSSH(t, node, "sudo bash /usr/local/lib/itest-sandboxd-restore.sh --input /tmp/itest-backup.tgz --target-root /tmp/itest-restore --force")
	out := kcSSH(t, node, "sudo env SB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH=/tmp/itest-restore"+kcWrapped+" /usr/local/bin/sandboxd key verify "+kcKeyCLIEnv)
	if !strings.Contains(out, "ok:") {
		t.Fatalf("the restored wrapped file does not verify:\n%s", out)
	}
}

// UC-313 — the three kinds of secret a sandbox carries (env, registry
// credentials, mount credentials) are all sealed through the key store and
// all come back on the node a failover recreates the sandbox on: it pulls
// the private image with the opened registry credentials and remounts the
// SSHFS share with the opened key.
func TestKeyCustodySecretKindsSurviveFailover(t *testing.T) {
	harness.Require(t, sc, "UC-313")
	targets := kcTargets(t)
	kcVaultWrapped(t, targets)
	reg := kcEnsureRegistry(t, targets)
	share := kcEnsureShare(t, targets)
	c := client(t)

	// The image really is private: without credentials it never starts,
	// whether the create fails at once or the sandbox fails afterwards.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	anon, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), Image: reg.image})
	cancel()
	if err == nil {
		t.Cleanup(func() {
			dctx, dcancel := context.WithTimeout(context.Background(), time.Minute)
			_ = c.SDK().Destroy(dctx, anon.ID)
			dcancel()
		})
		for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline) && string(anon.Status) != "error"; time.Sleep(5 * time.Second) {
			if string(anon.Status) == "started" {
				t.Fatalf("%s started without registry credentials; the registry is not private", reg.image)
			}
			rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = anon.Refresh(rctx)
			rcancel()
		}
		if string(anon.Status) != "error" {
			t.Fatalf("a create of %s without registry credentials is %q after 2 minutes, want a failure", reg.image, anon.Status)
		}
	}

	secret := secretValue(t, "313")
	sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{
		Image:    reg.image,
		Registry: &sdktypes.RegistryAuth{Server: reg.host, Username: reg.user, Password: reg.pass},
		Env:      map[string]string{"UC313_TOKEN": secret},
		Mounts: []models.MountSpec{{
			Type: models.MountTypeSSHFS, Target: "/mnt/itest-share", Source: share.source,
			Credentials: map[string]string{"private_key_pem": share.key}, ReadOnly: true,
		}},
	})
	waitRunning(t, sb)
	if got := kcExecOut(t, c, sb.ID, "cat /mnt/itest-share/token", 3*time.Minute); got != share.token {
		t.Fatalf("the share reads %q before the failover", got)
	}
	// The env secret is checked inside kcHAFailover; the new owner never
	// pulled the image before, so starting it there used the opened
	// registry credentials.
	kcHAFailover(t, targets, sb.ID, "UC313_TOKEN", secret)
	if got := kcExecOut(t, c, sb.ID, "cat /mnt/itest-share/token", 4*time.Minute); got != share.token {
		t.Fatalf("after the failover the share reads %q: the mount key was not opened", got)
	}
}

// UC-314 — disaster recovery onto a wiped node (eng D24): a backup of a
// wrapped node, restored after everything it covers is gone from the node,
// boots through the key store and rejoins, and the restored node's next
// backup holds no plaintext key either. The same machine stands in for a
// new one: the suite cannot add a node.
func TestKeyCustodyRestoreOntoAWipedNode(t *testing.T) {
	harness.Require(t, sc, "UC-314")
	targets := kcTargets(t)
	kcVaultWrapped(t, targets)
	node, ok := harness.PickRestartableNode(targets)
	if !ok {
		t.Skip("no node to restore")
	}
	target, _ := harness.SSHTarget(node)
	for path, rel := range map[string]string{
		"/usr/local/lib/itest-sandboxd-backup.sh":  "scripts/sandboxd-backup.sh",
		"/usr/local/lib/itest-sandboxd-restore.sh": "scripts/sandboxd-restore.sh",
	} {
		if err := harness.InstallNodeFile(t, node, path, kcRepoFile(t, rel)); err != nil {
			t.Fatal(err)
		}
	}
	// A safety copy that cleanup puts back if the restore does not bring
	// the node back, so a failure here does not leave the fleet short.
	kcSSH(t, node, `set -e
sudo systemctl stop sandboxd
sudo rm -rf /var/tmp/itest-safety && sudo mkdir -p /var/tmp/itest-safety
sudo cp -a /var/lib/sandboxd /var/tmp/itest-safety/lib
sudo cp -a /etc/sandboxd /var/tmp/itest-safety/etc`)
	back := false
	t.Cleanup(func() {
		if !back {
			kcSSH(t, node, `set -e
sudo systemctl stop sandboxd || true
sudo rm -rf /var/lib/sandboxd /etc/sandboxd
sudo cp -a /var/tmp/itest-safety/lib /var/lib/sandboxd
sudo cp -a /var/tmp/itest-safety/etc /etc/sandboxd`)
			restoreNodeDaemon(t, node, target)
		}
		kcSSH(t, node, "sudo rm -rf /var/tmp/itest-safety /var/tmp/itest-dr.tgz /var/tmp/itest-dr2.tgz /var/tmp/itest-dr2")
	})
	kcSSH(t, node, "sudo bash /usr/local/lib/itest-sandboxd-backup.sh --output /var/tmp/itest-dr.tgz")
	kcSSH(t, node, `set -e
sudo rm -rf /var/lib/sandboxd/state.db /var/lib/sandboxd/state.db-wal /var/lib/sandboxd/state.db-shm /var/lib/sandboxd/raft `+kcWrapped+` /etc/sandboxd
sudo bash /usr/local/lib/itest-sandboxd-restore.sh --input /var/tmp/itest-dr.tgz --target-root / --force`)
	if out := kcSSH(t, node, `if sudo test -e `+kcKeyFile+`; then echo KEYFILE; fi
if sudo sh -c "grep -l '^SB_CREDENTIAL_ENCRYPTION_KEY=' /etc/sandboxd/*.env"; then echo ENVKEY; fi
sudo test -s `+kcWrapped+` && echo WRAPPED`); strings.Contains(out, "KEYFILE") || strings.Contains(out, "ENVKEY") || !strings.Contains(out, "WRAPPED") {
		t.Fatalf("%s after the restore: a plaintext key, or no wrapped file:\n%s", node.Name, out)
	}
	restoreNodeDaemon(t, node, target)
	if t.Failed() {
		return
	}
	back = true
	if s := kcSSH(t, node, "sudo /usr/local/bin/sandboxd key status --check "+kcKeyCLIEnv); !strings.Contains(s, "check: every server key unwraps and matches") {
		t.Fatalf("%s: `sandboxd key status --check` after the restore:\n%s", node.Name, s)
	}
	kcAwaitMetric(t, []harness.IntegrationNode{node}, "aerolvm_key_custody", map[string]string{"key": "server key", "key2": "customer key store (wrapped)"}, time.Minute, func(v float64, ok bool) bool { return ok && v == 1 })
	listing := kcSSH(t, node, `set -e
sudo bash /usr/local/lib/itest-sandboxd-backup.sh --output /var/tmp/itest-dr2.tgz
sudo rm -rf /var/tmp/itest-dr2 && sudo mkdir -p /var/tmp/itest-dr2 && sudo tar -xzf /var/tmp/itest-dr2.tgz -C /var/tmp/itest-dr2
sudo find /var/tmp/itest-dr2 -name credential_encryption.key
sudo grep -rl '^SB_CREDENTIAL_ENCRYPTION_KEY=' /var/tmp/itest-dr2 2>/dev/null || true`)
	if strings.TrimSpace(listing) != "" {
		t.Fatalf("the restored node's backup holds a plaintext key:\n%s", listing)
	}
	kcHAFailover(t, targets, "", "UC314_TOKEN", secretValue(t, "314"))
}
