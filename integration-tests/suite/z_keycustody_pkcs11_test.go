//go:build integration

package suite

// Customer key custody on PKCS#11 (plans/customer-key-custody.md Phase 6),
// UC-307..309, on cluster-3-mixed-secrets-pkcs11: SoftHSM2 on every node
// with the same imported keys. This proves the code path (the helper
// process, labels, the rotation, revoke and recovery), not a network HSM.

import (
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

func kcPKCS11Wrapped(t *testing.T, targets *harness.IntegrationTargets) harness.IntegrationNode {
	t.Helper()
	return kcEnsureWrapped(t, targets, kcEnsurePKCS11)
}

// kcEnvValue reads one variable from a node's key-custody env file.
func kcEnvValue(t *testing.T, node harness.IntegrationNode, key string) string {
	t.Helper()
	for _, line := range strings.Split(kcSSH(t, node, "sudo cat "+kcEnvFile+" 2>/dev/null || true"), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k == key {
			return v
		}
	}
	return ""
}

// UC-307 — the switch to the HSM and the wrap, with the vendor library
// confined to the helper process.
func TestKeyCustodyPKCS11SwitchAndWrap(t *testing.T) {
	harness.Require(t, sc, "UC-307")
	targets := kcTargets(t)
	kcPKCS11Wrapped(t, targets)
	nodes := kcNodes(targets)
	kcAwaitMetric(t, nodes, "aerolvm_secret_provider_canary_ok", nil, time.Minute, func(v float64, ok bool) bool { return ok && v == 1 })
	kcAwaitMetric(t, nodes, "aerolvm_key_custody", map[string]string{"key": "server key", "key2": "customer key store (wrapped)"}, time.Minute, func(v float64, ok bool) bool { return ok && v == 1 })
	for _, n := range nodes {
		maps := kcSSH(t, n, `MAIN=$(systemctl show -p MainPID --value sandboxd)
HELPER=$(pgrep -f -- '--pkcs11-helper' | grep -vx "$MAIN" | head -1)
echo "main=$(sudo grep -c libsofthsm2 /proc/$MAIN/maps || true)"
echo "helper=$( [ -n "$HELPER" ] && sudo grep -c libsofthsm2 /proc/$HELPER/maps || echo none)"`)
		if !strings.Contains(maps, "main=0") || strings.Contains(maps, "helper=none") || strings.Contains(maps, "helper=0") {
			t.Fatalf("%s: the PKCS#11 library must be mapped in the helper and never in sandboxd:\n%s", n.Name, maps)
		}
		if s := kcSSH(t, n, "sudo /usr/local/bin/sandboxd key status --check "+kcKeyCLIEnv); !strings.Contains(s, "wrapped under: p11:") {
			t.Fatalf("%s: the server-key file is not wrapped by the HSM:\n%s", n.Name, s)
		}
	}
	kcHAFailover(t, targets, "", "UC307_TOKEN", secretValue(t, "307"))
}

// UC-308 — the four-step label rotation (eng D23), with a failover after
// every step: copies stay openable throughout, and the old label retires
// only once nothing is on it.
func TestKeyCustodyPKCS11LabelRotation(t *testing.T) {
	harness.Require(t, sc, "UC-308")
	targets := kcTargets(t)
	kcPKCS11Wrapped(t, targets)
	nodes := kcNodes(targets)
	c := client(t)
	from := kcEnvValue(t, nodes[0], "SB_SECRET_PKCS11_KEY_LABEL")
	to := kcLabelB
	if from == kcLabelB {
		to = kcLabelA
	}
	secret := secretValue(t, "308")
	sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{Env: map[string]string{"UC308_TOKEN": secret}})
	waitRunning(t, sb)
	apply := func(key, decrypt string) {
		for _, n := range nodes {
			kcSetEnv(t, n, map[string]string{"SB_SECRET_PKCS11_KEY_LABEL": key, "SB_SECRET_PKCS11_DECRYPT_KEY_LABELS": decrypt})
		}
		kcRollingRestart(t, targets)
	}

	// 1. The new label is decrypt-only everywhere.
	apply(from, to)
	kcAwaitMetric(t, nodes, "aerolvm_key_decryptable", map[string]string{"key": "pkcs11", "key2": "p11:" + to}, 2*time.Minute, func(v float64, ok bool) bool { return ok && v == 1 })
	kcHAFailover(t, targets, sb.ID, "UC308_TOKEN", secret)

	// 2. Switch the key label; the old one stays decryptable. The boot
	// sweep moves rows and the server-key file onto the new label.
	apply(to, from)
	kcHAFailover(t, targets, sb.ID, "UC308_TOKEN", secret)

	// 3. Nothing left on the old label, and every node seals with the new.
	kcAwaitMetric(t, nodes, "aerolvm_key_rows_stale", nil, 5*time.Minute, func(v float64, ok bool) bool { return ok && v == 0 })
	kcAwaitMetric(t, nodes, "aerolvm_key_current", map[string]string{"key": "pkcs11", "key2": "p11:" + to}, time.Minute, func(v float64, ok bool) bool { return ok && v == 1 })
	kcHAFailover(t, targets, sb.ID, "UC308_TOKEN", secret)

	// 4. Retire the old label.
	apply(to, "")
	kcAwaitMetric(t, nodes, "aerolvm_key_rows_retired", nil, time.Minute, func(v float64, ok bool) bool { return !ok || v == 0 })
	kcHAFailover(t, targets, sb.ID, "UC308_TOKEN", secret)
}

// UC-309 — destroying the key on one node's token stops that node only;
// importing the same key again brings it back without a restart.
func TestKeyCustodyPKCS11KeyDestroyed(t *testing.T) {
	harness.Require(t, sc, "UC-309")
	targets := kcTargets(t)
	kcPKCS11Wrapped(t, targets)
	node, ok := harness.PickRestartableNode(targets)
	if !ok {
		t.Skip("no node to revoke")
	}
	label := kcEnvValue(t, node, "SB_SECRET_PKCS11_KEY_LABEL")
	if label == "" {
		t.Fatalf("%s has no SB_SECRET_PKCS11_KEY_LABEL", node.Name)
	}
	reimport := `set -e
PIN=$(sudo cat ` + kcSoftHSMPIN + `)
if ! sudo pkcs11-tool --module ` + kcSoftHSMModule + ` --token-label ` + kcSoftHSMToken + ` --login --pin "$PIN" --list-objects --type secrkey 2>/dev/null | grep -q "label: *` + label + `$"; then
  sudo softhsm2-util --import ` + kcStateDir + `/` + label + `.bin --aes --token ` + kcSoftHSMToken + ` --label ` + label + ` --id "$(printf '%s' ` + label + ` | od -An -tx1 | tr -d ' \n')" --pin "$PIN" >/dev/null
fi`
	t.Cleanup(func() { kcSSH(t, node, reimport) })

	kcSSH(t, node, `set -e
PIN=$(sudo cat `+kcSoftHSMPIN+`)
sudo pkcs11-tool --module `+kcSoftHSMModule+` --token-label `+kcSoftHSMToken+` --login --pin "$PIN" --delete-object --type secrkey --label `+label+` >/dev/null`)
	kcAwaitMetric(t, []harness.IntegrationNode{node}, "aerolvm_key_revoked", nil, kcRevokeBound, func(v float64, ok bool) bool { return ok && v == 1 })
	for _, other := range targets.Nodes {
		if other.Name == node.Name {
			continue
		}
		if v := harness.MetricValueOrZero(kcMetricsOf(t, other), "aerolvm_key_revoked", nil); v != 0 {
			t.Fatalf("%s stopped too, but only %s's token lost the key", other.Name, node.Name)
		}
	}
	if evs, err := harness.NodeAuditEvents(t, node, "key_revoked"); err != nil || len(evs) == 0 {
		t.Fatalf("%s wrote no key_revoked audit record (err %v)", node.Name, err)
	}

	kcSSH(t, node, reimport)
	kcAwaitMetric(t, []harness.IntegrationNode{node}, "aerolvm_key_revoked", nil, kcRevokeBound, func(v float64, ok bool) bool { return ok && v == 0 })
	if evs, err := harness.NodeAuditEvents(t, node, "key_recovered"); err != nil || len(evs) == 0 {
		t.Fatalf("%s wrote no key_recovered audit record (err %v)", node.Name, err)
	}
}
