//go:build integration

package suite

// Customer key custody on a single node (plans/customer-key-custody.md §3),
// UC-315, on single-node-wrapped-kms: Terraform key_custody = "wrapped"
// reaches install.sh --key-custody wrapped on the one node.

import (
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-315 — a single node installed with wrapped custody never writes a
// plaintext server key, and after a restart opens its sealed values through
// AWS KMS: a sandbox from before the restart still answers (its toolbox
// token is sealed), and a new one reads its secret.
func TestKeyCustodySingleNodeWrapped(t *testing.T) {
	harness.Require(t, sc, "UC-315")
	targets := kcTargets(t)
	node := kcSeed(t, targets)
	out := kcSSH(t, node, `if sudo test -e `+kcKeyFile+`; then echo KEYFILE; fi
if sudo sh -c "grep -l '^SB_CREDENTIAL_ENCRYPTION_KEY=' /etc/sandboxd/*.env"; then echo ENVKEY; fi
sudo sh -c "grep -h '^SB_CREDENTIAL_KEY_CUSTODY=' /etc/sandboxd/*.env" || true
sudo test -s `+kcWrapped+` && echo WRAPPED
if sudo test -s /tmp/aerolvm-cred-bundle.tar.gz; then echo "BUNDLE:$(sudo tar -tzf /tmp/aerolvm-cred-bundle.tar.gz | tr '\n' ' ')"; fi`)
	if strings.Contains(out, "KEYFILE") || strings.Contains(out, "ENVKEY") || !strings.Contains(out, "WRAPPED") || !strings.Contains(out, "SB_CREDENTIAL_KEY_CUSTODY=wrapped") {
		t.Fatalf("%s: a plaintext server key, or custody not wrapped:\n%s", node.Name, out)
	}
	if i := strings.Index(out, "BUNDLE:"); i >= 0 {
		for _, f := range strings.Fields(out[i+len("BUNDLE:"):]) {
			if strings.TrimPrefix(f, "./") == "credential_encryption.key" {
				t.Fatalf("%s: the cred bundle holds a plaintext key", node.Name)
			}
		}
	}
	if s := kcSSH(t, node, "sudo /usr/local/bin/sandboxd key status --check"); !strings.Contains(s, "check: every server key unwraps and matches") {
		t.Fatalf("%s: `sandboxd key status --check` failed:\n%s", node.Name, s)
	}
	kcAwaitMetric(t, []harness.IntegrationNode{node}, "aerolvm_key_custody", map[string]string{"key": "server key", "key2": "customer key store (wrapped)"}, time.Minute, func(v float64, ok bool) bool { return ok && v == 1 })

	c := client(t)
	secret := secretValue(t, "315")
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Image: harness.DefaultImage, Env: map[string]string{"UC315_TOKEN": secret}})
	if got := execEnvValue(t, c, sb.ID, "UC315_TOKEN", 3*time.Minute); got != secret {
		t.Fatalf("before the restart the sandbox reads %q", got)
	}
	kcRestart(t, node)
	if got := execEnvValue(t, c, sb.ID, "UC315_TOKEN", 4*time.Minute); got != secret {
		t.Fatalf("after the restart the sandbox reads %q", got)
	}
	after := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Image: harness.DefaultImage, Env: map[string]string{"UC315_AFTER": "back"}})
	if got := execEnvValue(t, c, after.ID, "UC315_AFTER", 3*time.Minute); got != "back" {
		t.Fatalf("a sandbox made after the restart reads %q", got)
	}
}

// UC-316 — restore onto a fresh machine (eng D24): a backup of a wrapped
// node, restored after the machine's root disk was replaced by a new one
// from its launch image (cloud-init then installs AerolVM afresh, with a
// server key of its own), boots through the key store with the backup's
// server key and opens the values sealed before. The same instance keeps
// its address, which a restored node's config names.
func TestKeyCustodyRestoreOntoAFreshMachine(t *testing.T) {
	harness.Require(t, sc, "UC-316")
	targets := kcTargets(t)
	var node harness.IntegrationNode
	for _, n := range targets.Nodes {
		if n.Seed {
			node = n
		}
	}
	if node.InstanceID == "" {
		t.Skip("the seed has no instance id to give a fresh disk")
	}
	target, _ := harness.SSHTarget(node)
	c := client(t)
	secret := secretValue(t, "316")
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Image: harness.DefaultImage, Env: map[string]string{"UC316_TOKEN": secret}})
	if got := execEnvValue(t, c, sb.ID, "UC316_TOKEN", 3*time.Minute); got != secret {
		t.Fatalf("before the backup the sandbox reads %q", got)
	}
	installScripts := func() {
		for path, rel := range map[string]string{
			"/usr/local/lib/itest-sandboxd-backup.sh":  "scripts/sandboxd-backup.sh",
			"/usr/local/lib/itest-sandboxd-restore.sh": "scripts/sandboxd-restore.sh",
		} {
			if err := harness.InstallNodeFile(t, node, path, kcRepoFile(t, rel)); err != nil {
				t.Fatal(err)
			}
		}
	}
	installScripts()
	// A consistent backup: sandboxd stopped. The archive leaves the machine,
	// since its disk is about to go.
	kcSSH(t, node, "sudo systemctl stop sandboxd && sudo bash /usr/local/lib/itest-sandboxd-backup.sh --output /var/tmp/itest-dr.tgz >/dev/null")
	archive := strings.TrimSpace(kcSSH(t, node, "sudo base64 -w0 /var/tmp/itest-dr.tgz"))
	oldWrapped := kcSSH(t, node, "sudo sha256sum "+kcWrapped+" | cut -d' ' -f1")
	if archive == "" {
		t.Fatal("empty backup archive")
	}

	harness.ReplaceRootVolume(t, node.InstanceID, 20*time.Minute)
	// The fresh disk boots the bootstrap again: a new install, with a new
	// server key, running as a lone node.
	deadline := time.Now().Add(25 * time.Minute)
	for {
		out, err := harness.SSHRun(t, target, "sudo cloud-init status --wait >/dev/null 2>&1; cloud-init status; test -x /usr/local/bin/sandboxd && echo INSTALLED")
		if err == nil && strings.Contains(out, "status: done") && strings.Contains(out, "INSTALLED") {
			break
		}
		if err == nil && strings.Contains(out, "status: error") {
			t.Fatalf("the fresh machine's bootstrap failed:\n%s", out)
		}
		if time.Now().After(deadline) {
			t.Fatalf("the fresh machine never finished its bootstrap (last: %v %s)", err, out)
		}
		time.Sleep(15 * time.Second)
	}
	if newWrapped := kcSSH(t, node, "sudo sha256sum "+kcWrapped+" | cut -d' ' -f1"); newWrapped == oldWrapped {
		t.Fatal("the fresh install has the old wrapped server key: the disk was not replaced")
	}

	installScripts()
	kcSSHStdin(t, node, "sudo sh -c 'base64 -d > /var/tmp/itest-dr.tgz'", archive)
	kcSSH(t, node, `set -e
sudo systemctl stop sandboxd
sudo bash /usr/local/lib/itest-sandboxd-restore.sh --input /var/tmp/itest-dr.tgz --target-root / --force >/dev/null
sudo rm -f /var/tmp/itest-dr.tgz`)
	if out := kcSSH(t, node, `if sudo test -e `+kcKeyFile+`; then echo KEYFILE; fi
if sudo sh -c "grep -l '^SB_CREDENTIAL_ENCRYPTION_KEY=' /etc/sandboxd/*.env"; then echo ENVKEY; fi
sudo sha256sum `+kcWrapped+` | cut -d' ' -f1`); strings.Contains(out, "KEYFILE") || strings.Contains(out, "ENVKEY") || strings.TrimSpace(out) != strings.TrimSpace(oldWrapped) {
		t.Fatalf("after the restore: a plaintext key, or not the backup's wrapped key:\n%s", out)
	}
	restoreNodeDaemon(t, node, target)
	if t.Failed() {
		return
	}
	if s := kcSSH(t, node, "sudo /usr/local/bin/sandboxd key status --check"); !strings.Contains(s, "check: every server key unwraps and matches") {
		t.Fatalf("`sandboxd key status --check` on the restored machine:\n%s", s)
	}
	// The value sealed before the disk was replaced opens with the restored
	// key. The sandbox's container went with the old disk; its record and
	// sealed env came back with the database.
	if _, env := sandboxStatusAndEnv(t, c, sb.ID); env["UC316_TOKEN"] != secret {
		t.Fatalf("the restored machine reads UC316_TOKEN as %q", env["UC316_TOKEN"])
	}
	after := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Image: harness.DefaultImage, Env: map[string]string{"UC316_AFTER": "back"}})
	if got := execEnvValue(t, c, after.ID, "UC316_AFTER", 3*time.Minute); got != "back" {
		t.Fatalf("a sandbox made after the restore reads %q", got)
	}
}
