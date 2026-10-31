//go:build integration

package suite

// Customer key custody fixtures (plans/customer-key-custody.md Phase 6).
//
// The key-custody scenarios boot a plain local cluster. These helpers put
// the key store in place over SSH and move the cluster onto it the way a
// customer would: the key store's settings on every node first, then the
// sealing provider, then the server key wrapped node by node. Each step
// leaves a marker on the node, so a case run on its own (or a re-run)
// starts from wherever the cluster already is.
//
// Every sandboxd setting goes into one extra EnvironmentFile under a drop-in
// that sorts BEFORE the suite's transient override (WithNodeEnv), so a boot
// gate case can still override any of them for one restart.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

const (
	// OpenBao 2.1.1, the release Phase 2 tested; checksum from the
	// release's checksums-linux.txt.
	kcOpenBaoURL    = "https://github.com/openbao/openbao/releases/download/v2.1.1/bao_2.1.1_Linux_x86_64.tar.gz"
	kcOpenBaoSHA256 = "255989c90142426ff8f7336b4d4309c6e2846f8dc82f800f23f4c6b447269281"
	kcTransitKey    = "aerolvm-kek"
	// The proxy listens on loopback, the only http:// sandboxd accepts; 8100
	// stays clear of the dev server's cluster port (listen port + 1).
	kcProxyAddr = "http://127.0.0.1:8100"

	kcEnvFile    = "/etc/sandboxd/itest-keycustody.env"
	kcDropIn     = "/etc/systemd/system/sandboxd.service.d/50-itest-keycustody.conf"
	kcStateDir   = "/var/lib/itest-keycustody"
	kcKeyFile    = "/var/lib/sandboxd/credential_encryption.key"
	kcWrapped    = "/var/lib/sandboxd/credential_encryption.key.wrapped"
	kcBaoRoot    = kcStateDir + "/openbao-root"
	kcSoftHSMPIN = "/etc/sandboxd/itest-hsm-pin"

	// A short re-check so revoke and recovery cases fit in minutes; the
	// floor the config accepts is 10s.
	kcRecheck     = "15s"
	kcRevokeAfter = "2"
	// kcRevokeBound is how long a revoke may take: REVOKE_AFTER re-checks
	// of up to RECHECK +10% jitter, plus scrape slack.
	kcRevokeBound = 2*time.Minute + 30*time.Second
)

// kcKeyCLIEnv makes `sandboxd key` see what the daemon sees. The CLI applies
// the FIRST file that sets a variable (systemd applies the last), so the
// key-custody file comes first.
const kcKeyCLIEnv = "--env-file " + kcEnvFile + " --env-file /etc/sandboxd/sandboxd.env --env-file /etc/sandboxd/cluster.env"

func kcTargets(t *testing.T) *harness.IntegrationTargets {
	t.Helper()
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (set disruptive: true in the scenario caps, or drop --no-disruptive)")
	}
	for _, n := range targets.Nodes {
		harness.RequireNodeSSH(t, n)
	}
	return targets
}

// kcNodes is every node, seed first: a restart of the seed before the
// joiners is the order the rest of the suite uses (WithClusterEnv).
func kcNodes(targets *harness.IntegrationTargets) []harness.IntegrationNode {
	out := append([]harness.IntegrationNode(nil), targets.Nodes...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Seed && !out[j].Seed })
	return out
}

func kcSeed(t *testing.T, targets *harness.IntegrationTargets) harness.IntegrationNode {
	t.Helper()
	for _, n := range targets.Nodes {
		if n.Seed {
			return n
		}
	}
	t.Fatal("no seed node in the integration targets")
	return harness.IntegrationNode{}
}

// kcSSH runs script on node and fails the test on error.
func kcSSH(t *testing.T, node harness.IntegrationNode, script string) string {
	t.Helper()
	target, _ := harness.SSHTarget(node)
	out, err := harness.SSHRun(t, target, script)
	if err != nil {
		t.Fatalf("%s: %v\n%s", node.Name, err, out)
	}
	return out
}

// kcSSHStdin is kcSSH with stdin, for anything secret: it never lands on a
// command line or in the test log.
func kcSSHStdin(t *testing.T, node harness.IntegrationNode, script, stdin string) string {
	t.Helper()
	target, _ := harness.SSHTarget(node)
	out, err := harness.SSHRunStdin(t, target, script, stdin)
	if err != nil {
		t.Fatalf("%s: %v\n%s", node.Name, err, out)
	}
	return out
}

func kcMarked(t *testing.T, node harness.IntegrationNode, step string) bool {
	t.Helper()
	// sudo: the state directory is 0700 root, so the ubuntu user cannot see
	// inside it and a plain test -f always says no (the first live run redid
	// every fixture step in every case because of it).
	return strings.TrimSpace(kcSSH(t, node, "sudo test -f "+kcStateDir+"/"+step+" && echo yes || echo no")) == "yes"
}

func kcMark(t *testing.T, node harness.IntegrationNode, step string) {
	t.Helper()
	kcSSH(t, node, "sudo install -d -m 0700 "+kcStateDir+" && sudo touch "+kcStateDir+"/"+step)
}

// kcSetEnv merges kv into the node's key-custody env file. An empty value
// removes the variable. Nothing restarts.
func kcSetEnv(t *testing.T, node harness.IntegrationNode, kv map[string]string) {
	t.Helper()
	cur := map[string]string{}
	for _, line := range strings.Split(kcSSH(t, node, "sudo cat "+kcEnvFile+" 2>/dev/null || true"), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && !strings.HasPrefix(k, "#") {
			cur[k] = v
		}
	}
	for k, v := range kv {
		if v == "" {
			delete(cur, k)
		} else {
			cur[k] = v
		}
	}
	keys := make([]string, 0, len(cur))
	for k := range cur {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# Customer key custody, written by the integration suite.\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, cur[k])
	}
	kcSSHStdin(t, node, fmt.Sprintf(`set -e
sudo install -d -m 0755 /etc/systemd/system/sandboxd.service.d
sudo tee %[1]s >/dev/null
sudo chmod 0600 %[1]s
printf '[Service]\nEnvironmentFile=%[1]s\n' | sudo tee %[2]s >/dev/null
sudo systemctl daemon-reload`, kcEnvFile, kcDropIn), b.String())
}

// kcRestart restarts sandboxd on node and waits until it is back in the
// cluster.
func kcRestart(t *testing.T, node harness.IntegrationNode) {
	t.Helper()
	kcSSH(t, node, "sudo systemctl reset-failed sandboxd || true")
	harness.RestartSystemdUnit(t, node, "sandboxd")
	if harness.NodeRejoinCheck != nil {
		if err := harness.NodeRejoinCheck(t, node); err != nil {
			t.Fatalf("%s restarted but did not rejoin: %v", node.Name, err)
		}
	}
}

// kcRollingRestart restarts every node, seed first, one at a time.
func kcRollingRestart(t *testing.T, targets *harness.IntegrationTargets) {
	t.Helper()
	for _, n := range kcNodes(targets) {
		kcRestart(t, n)
	}
}

// kcMetricsOf scrapes one node's /v1/metrics.
func kcMetricsOf(t *testing.T, node harness.IntegrationNode) string {
	t.Helper()
	return nodeMetrics(t, nodeBase(t, node))
}

// kcAwaitMetric waits until pred holds for the named metric on every node
// in nodes.
func kcAwaitMetric(t *testing.T, nodes []harness.IntegrationNode, name string, labels map[string]string, timeout time.Duration, pred func(v float64, ok bool) bool) {
	t.Helper()
	bases := map[string]string{}
	for _, n := range nodes {
		bases[n.Name] = nodeBase(t, n)
	}
	deadline := time.Now().Add(timeout)
	for {
		var waiting []string
		for _, n := range nodes {
			v, ok := harness.MetricValue(nodeMetrics(t, bases[n.Name]), name, labels)
			if !pred(v, ok) {
				waiting = append(waiting, fmt.Sprintf("%s=%v(present %v)", n.Name, v, ok))
			}
		}
		if len(waiting) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s%v did not reach the expected value within %s: %s", name, labels, timeout, strings.Join(waiting, ", "))
		}
		time.Sleep(5 * time.Second)
	}
}

// kcNodeHealth returns one node's /health body.
func kcNodeHealth(t *testing.T, node harness.IntegrationNode) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := harness.NewAPIClient(nodeBase(t, node), sc.OperatorPAT).Do(ctx, http.MethodGet, "/health", nil)
	if err != nil {
		t.Fatalf("health of %s: %v", node.Name, err)
	}
	return string(resp.Body)
}

// kcHAFailover creates an HA sandbox carrying a secret (unless id is
// given), stops its owner's sandboxd and checks the secret inside the
// recreated sandbox. It returns the sandbox id. The stopped node is restored
// before it returns, and at test cleanup if the case fails first.
//
// A fresh sandbox that lands on the seed is replaced, since a joiner is the
// cheaper member to lose. A sandbox the case already owns may sit on the
// seed after an earlier failover; then the seed is stopped: a failover
// that is skipped proves nothing, and a restarted seed rejoins (UC-170).
func kcHAFailover(t *testing.T, targets *harness.IntegrationTargets, id, key, secret string) string {
	t.Helper()
	c := client(t)
	if id == "" {
		for attempt := 1; ; attempt++ {
			sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{Env: map[string]string{key: secret}})
			waitRunning(t, sb)
			if n, ok := nodeForClusterID(t, c, targets, resolvePlacementOwner(t, c, sb.ID)); !ok || !n.Seed || attempt == 4 {
				id = sb.ID
				break
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			_ = sb.Destroy(ctx)
			cancel()
		}
	}
	harness.AwaitFailoverReady(t, c, id, 3*time.Minute)
	owner := resolvePlacementOwner(t, c, id)
	victim, ok := nodeForClusterID(t, c, targets, owner)
	if !ok {
		t.Fatalf("owner %s of %s is not a node this suite can reach", owner, id)
	}
	// Read and exec through a node that stays up, on its own loopback API.
	// The suite's clients share http.DefaultTransport, whose keep-alive pool
	// can stay pinned to the victim's ingress: every call then gets a 502
	// from its Caddy for as long as the victim is down, though the cluster
	// failed over in seconds (the first wrapped-kms run lost UC-310 to that).
	var via harness.IntegrationNode
	for _, n := range kcNodes(targets) {
		if n.Name != victim.Name {
			via = n
			break
		}
	}
	viaSC := *sc
	viaSC.BaseURL = nodeBase(t, via)
	viaSC.PAT = sc.OperatorPAT
	viaClient := harness.NewClient(t, &viaSC)

	t.Logf("failing %s over: stopping its owner %s", id, victim.Name)
	restore := harness.KillNodeDaemon(t, victim)
	t.Cleanup(restore)
	newOwner := awaitNewOwner(t, viaClient, id, owner, failoverOpenTimeout)
	if got := execEnvValue(t, viaClient, id, key, 4*time.Minute); got != secret {
		t.Fatalf("after failover from %s to %s, sandbox %s reads %q, want its sealed value", owner, newOwner, id, got)
	}
	restore()
	return id
}

// kcInstallBao installs the pinned OpenBao binary on node.
const kcInstallBao = `set -euo pipefail
if ! test -x /usr/local/bin/bao; then
  curl -fsSL -o /tmp/itest-bao.tgz '` + kcOpenBaoURL + `'
  echo '` + kcOpenBaoSHA256 + `  /tmp/itest-bao.tgz' | sha256sum -c -
  sudo tar -xzf /tmp/itest-bao.tgz -C /usr/local/bin bao
  rm -f /tmp/itest-bao.tgz
fi
`

// kcBao runs a bao CLI command on the seed as the dev root token.
func kcBao(t *testing.T, seed harness.IntegrationNode, args string) string {
	t.Helper()
	return kcSSH(t, seed, `sudo env BAO_ADDR=https://127.0.0.1:8200 BAO_SKIP_VERIFY=true BAO_TOKEN="$(sudo cat `+kcBaoRoot+`)" /usr/local/bin/bao `+args)
}

// kcBaoStdin is kcBao with stdin (policies, backups).
func kcBaoStdin(t *testing.T, seed harness.IntegrationNode, args, stdin string) string {
	t.Helper()
	return kcSSHStdin(t, seed, `sudo env BAO_ADDR=https://127.0.0.1:8200 BAO_SKIP_VERIFY=true BAO_TOKEN="$(sudo cat `+kcBaoRoot+`)" /usr/local/bin/bao `+args, stdin)
}

// kcPolicy is the least-privilege policy of the docs page: no create on the
// encrypt path (Transit would recreate a deleted key), read on the key for
// the sweep's version check.
const kcPolicy = `path "transit/encrypt/` + kcTransitKey + `" { capabilities = ["update"] }
path "transit/decrypt/` + kcTransitKey + `" { capabilities = ["update"] }
path "transit/keys/` + kcTransitKey + `"    { capabilities = ["read"] }
`

// kcEnsureOpenBao runs an OpenBao dev server with TLS on the seed, with a
// Transit key that can be backed up (the revoke case restores it) and the
// policy above. The dev store is in memory: it lives as long as the unit.
func kcEnsureOpenBao(t *testing.T, targets *harness.IntegrationTargets) harness.IntegrationNode {
	t.Helper()
	seed := kcSeed(t, targets)
	if kcMarked(t, seed, "openbao") && strings.Contains(kcSSH(t, seed, "systemctl is-active itest-openbao || true"), "active") {
		return seed
	}
	kcSSH(t, seed, kcInstallBao+`
sudo install -d -m 0700 `+kcStateDir+` /var/lib/itest-openbao
if ! sudo test -s `+kcBaoRoot+`; then
  head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | sudo tee `+kcBaoRoot+` >/dev/null
  sudo chmod 0600 `+kcBaoRoot+`
fi
sudo systemctl stop itest-openbao 2>/dev/null || true
sudo systemctl reset-failed itest-openbao 2>/dev/null || true
sudo systemd-run --unit itest-openbao /usr/local/bin/bao server -dev -dev-tls \
  -dev-tls-cert-dir=/var/lib/itest-openbao -dev-listen-address=0.0.0.0:8200 \
  -dev-root-token-id="$(sudo cat `+kcBaoRoot+`)"
for _ in $(seq 1 60); do curl -sfk https://127.0.0.1:8200/v1/sys/health >/dev/null && break; sleep 1; done
curl -sfk https://127.0.0.1:8200/v1/sys/health >/dev/null`)
	kcBao(t, seed, "secrets enable transit || true")
	kcBao(t, seed, "write -f transit/keys/"+kcTransitKey+" type=aes256-gcm96 exportable=true allow_plaintext_backup=true")
	kcBaoStdin(t, seed, "policy write aerolvm -", kcPolicy)
	kcMark(t, seed, "openbao")
	return seed
}

// kcEnsureProxy runs an OpenBao Proxy on node: auto-auth from a token file
// holding a periodic token with only the aerolvm policy, and the API proxy
// adding it to every request, so sandboxd itself holds no Vault token.
func kcEnsureProxy(t *testing.T, seed, node harness.IntegrationNode) {
	t.Helper()
	if kcMarked(t, node, "bao-proxy") && strings.Contains(kcSSH(t, node, "systemctl is-active itest-bao-proxy || true"), "active") {
		return
	}
	token := strings.TrimSpace(kcBao(t, seed, "token create -policy=aerolvm -period=72h -field=token"))
	config := fmt.Sprintf(`vault {
  address         = "https://%s:8200"
  tls_skip_verify = true
}
auto_auth {
  method "token_file" {
    config = { token_file_path = "/etc/itest-bao-proxy/token" }
  }
}
api_proxy {
  use_auto_auth_token = "force"
}
listener "tcp" {
  address     = "127.0.0.1:8100"
  tls_disable = true
}
`, seed.PrivateIP)
	kcSSH(t, node, kcInstallBao+"sudo install -d -m 0700 /etc/itest-bao-proxy")
	kcSSHStdin(t, node, "sudo tee /etc/itest-bao-proxy/token >/dev/null && sudo chmod 0600 /etc/itest-bao-proxy/token", token)
	kcSSHStdin(t, node, `set -e
sudo tee /etc/itest-bao-proxy/proxy.hcl >/dev/null
sudo systemctl stop itest-bao-proxy 2>/dev/null || true
sudo systemctl reset-failed itest-bao-proxy 2>/dev/null || true
sudo systemd-run --unit itest-bao-proxy /usr/local/bin/bao proxy -config=/etc/itest-bao-proxy/proxy.hcl
for _ in $(seq 1 30); do curl -sf `+kcProxyAddr+`/v1/sys/health >/dev/null && break; sleep 1; done
curl -sf `+kcProxyAddr+`/v1/sys/health >/dev/null`, config)
	kcMark(t, node, "bao-proxy")
}

// kcVaultSettings are the key store's settings, step 1 of the switch: a
// node with them opens Vault rows whatever it seals with.
func kcVaultSettings() map[string]string {
	return map[string]string{
		"SB_SECRET_VAULT_ADDR":                kcProxyAddr,
		"SB_SECRET_VAULT_KEY_NAME":            kcTransitKey,
		"SB_SECRET_PROVIDER_RECHECK_INTERVAL": kcRecheck,
		"SB_SECRET_PROVIDER_REVOKE_AFTER":     kcRevokeAfter,
	}
}

// kcSwitchToVault is the two-step switch (§12, eng D8): every node gets the
// settings and restarts, then every node seals with Vault and restarts.
// between runs after each step (1, 2) for the switch case's assertions.
func kcSwitchToVault(t *testing.T, targets *harness.IntegrationTargets, between func(step int)) {
	t.Helper()
	seed := kcEnsureOpenBao(t, targets)
	for _, n := range kcNodes(targets) {
		kcEnsureProxy(t, seed, n)
		kcSetEnv(t, n, kcVaultSettings())
	}
	kcRollingRestart(t, targets)
	if between != nil {
		between(1)
	}
	for _, n := range kcNodes(targets) {
		kcSetEnv(t, n, map[string]string{"SB_SECRET_PROVIDER": "vault", "SB_SECRET_PROVIDER_STRICT_BOOT": "true"})
	}
	kcRollingRestart(t, targets)
	for _, n := range kcNodes(targets) {
		kcMark(t, n, "provider-switched")
	}
	if between != nil {
		between(2)
	}
}

// kcEnsureVault brings the cluster onto Vault if UC-297 has not already.
func kcEnsureVault(t *testing.T, targets *harness.IntegrationTargets) harness.IntegrationNode {
	t.Helper()
	seed := kcEnsureOpenBao(t, targets)
	for _, n := range targets.Nodes {
		if !kcMarked(t, n, "provider-switched") {
			kcSwitchToVault(t, targets, nil)
			break
		}
	}
	return seed
}

// kcWrapServerKey wraps the server key on every node (the migration of §3):
// each node wraps the cluster's shared key through the key store, then, one
// node at a time, the plaintext copies go and the node restarts on the
// wrapped file.
func kcWrapServerKey(t *testing.T, targets *harness.IntegrationTargets) {
	t.Helper()
	for _, n := range kcNodes(targets) {
		if kcMarked(t, n, "wrapped") {
			continue
		}
		kcSSH(t, n, "sudo /usr/local/bin/sandboxd key wrap "+kcKeyCLIEnv+" && sudo /usr/local/bin/sandboxd key verify "+kcKeyCLIEnv)
	}
	for _, n := range kcNodes(targets) {
		if kcMarked(t, n, "wrapped") {
			continue
		}
		kcSetEnv(t, n, map[string]string{"SB_CREDENTIAL_KEY_CUSTODY": "wrapped"})
		kcSSH(t, n, `set -e
sudo sed -i '/^SB_CREDENTIAL_ENCRYPTION_KEY=/d' /etc/sandboxd/cluster.env /etc/sandboxd/sandboxd.env
sudo rm -f `+kcKeyFile)
		kcRestart(t, n)
		kcMark(t, n, "wrapped")
	}
}

// kcEnsureWrapped is the full precondition of most cases: on the key store,
// server key wrapped.
func kcEnsureWrapped(t *testing.T, targets *harness.IntegrationTargets, ensureStore func(*testing.T, *harness.IntegrationTargets) harness.IntegrationNode) harness.IntegrationNode {
	t.Helper()
	seed := ensureStore(t, targets)
	kcWrapServerKey(t, targets)
	return seed
}

// kcRepoFile reads a file from the repository (the suite runs from
// integration-tests/suite).
func kcRepoFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}

// SoftHSM2 fixture (UC-307..309). Every node imports the SAME AES-256 keys
// under the same labels, so a copy sealed on one node opens on another.
// Throwaway test keys, generated per run on the seed and copied over SSH.
const (
	kcSoftHSMToken  = "aerolvm"
	kcSoftHSMModule = "/usr/lib/softhsm/libsofthsm2.so"
	kcLabelA        = "kek-a"
	kcLabelB        = "kek-b"
)

// kcEnsureSoftHSM installs SoftHSM2 on every node and imports the two keys.
func kcEnsureSoftHSM(t *testing.T, targets *harness.IntegrationTargets) harness.IntegrationNode {
	t.Helper()
	seed := kcSeed(t, targets)
	done := true
	for _, n := range targets.Nodes {
		done = done && kcMarked(t, n, "softhsm")
	}
	if done {
		return seed
	}
	// Two AES-256 keys and a PIN, made once on the seed. softhsm2-util
	// --import skips whitespace bytes in a key file, so a random binary key
	// would import short: the keys are 32 alphanumeric bytes instead (about
	// 190 bits, plenty for a throwaway test key).
	keys := kcSSH(t, seed, `set -e
sudo install -d -m 0700 `+kcStateDir+`
for f in kek-a kek-b; do sudo test -s `+kcStateDir+`/$f.bin || sudo sh -c "head -c 512 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 32 > `+kcStateDir+`/$f.bin"; done
sudo test -s `+kcStateDir+`/pin || sudo sh -c "head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n' > `+kcStateDir+`/pin"
printf '%s %s %s' "$(sudo base64 -w0 `+kcStateDir+`/kek-a.bin)" "$(sudo base64 -w0 `+kcStateDir+`/kek-b.bin)" "$(sudo cat `+kcStateDir+`/pin)"`)
	parts := strings.Fields(strings.TrimSpace(keys))
	if len(parts) != 3 {
		t.Fatalf("seed key material: got %d fields", len(parts))
	}
	for _, n := range kcNodes(targets) {
		if kcMarked(t, n, "softhsm") {
			continue
		}
		kcSSHStdin(t, n, `set -euo pipefail
read -r KA KB PIN
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq softhsm2 opensc >/dev/null
sudo install -d -m 0700 `+kcStateDir+`
echo "$KA" | base64 -d | sudo tee `+kcStateDir+`/kek-a.bin >/dev/null
echo "$KB" | base64 -d | sudo tee `+kcStateDir+`/kek-b.bin >/dev/null
printf '%s' "$PIN" | sudo tee `+kcSoftHSMPIN+` >/dev/null
sudo chmod 0600 `+kcSoftHSMPIN+` `+kcStateDir+`/kek-a.bin `+kcStateDir+`/kek-b.bin
# A half-finished earlier attempt is started over: one object per label.
sudo softhsm2-util --delete-token --token `+kcSoftHSMToken+` >/dev/null 2>&1 || true
sudo softhsm2-util --init-token --free --label `+kcSoftHSMToken+` --so-pin "$PIN" --pin "$PIN" >/dev/null
for L in kek-a kek-b; do
  sudo softhsm2-util --import `+kcStateDir+`/$L.bin --aes --token `+kcSoftHSMToken+` --label "$L" --id "$(printf '%s' "$L" | od -An -tx1 | tr -d ' \n')" --pin "$PIN" >/dev/null
done`, strings.Join(parts, " ")+"\n")
		kcMark(t, n, "softhsm")
	}
	return seed
}

// kcPKCS11Settings are step 1 of the switch to the HSM.
func kcPKCS11Settings(keyLabel, decryptLabels string) map[string]string {
	return map[string]string{
		"SB_SECRET_PKCS11_MODULE":             kcSoftHSMModule,
		"SB_SECRET_PKCS11_TOKEN_LABEL":        kcSoftHSMToken,
		"SB_SECRET_PKCS11_PIN_FILE":           kcSoftHSMPIN,
		"SB_SECRET_PKCS11_KEY_LABEL":          keyLabel,
		"SB_SECRET_PKCS11_DECRYPT_KEY_LABELS": decryptLabels,
		"SB_SECRET_PROVIDER_RECHECK_INTERVAL": kcRecheck,
		"SB_SECRET_PROVIDER_REVOKE_AFTER":     kcRevokeAfter,
	}
}

// kcEnsurePKCS11 brings the cluster onto the HSM, two-step, with kek-a.
func kcEnsurePKCS11(t *testing.T, targets *harness.IntegrationTargets) harness.IntegrationNode {
	t.Helper()
	seed := kcEnsureSoftHSM(t, targets)
	switched := true
	for _, n := range targets.Nodes {
		switched = switched && kcMarked(t, n, "provider-switched")
	}
	if switched {
		return seed
	}
	for _, n := range kcNodes(targets) {
		kcSetEnv(t, n, kcPKCS11Settings(kcLabelA, ""))
	}
	kcRollingRestart(t, targets)
	for _, n := range kcNodes(targets) {
		kcSetEnv(t, n, map[string]string{"SB_SECRET_PROVIDER": "pkcs11", "SB_SECRET_PROVIDER_STRICT_BOOT": "true"})
	}
	kcRollingRestart(t, targets)
	for _, n := range kcNodes(targets) {
		kcMark(t, n, "provider-switched")
	}
	return seed
}
