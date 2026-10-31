//go:build integration

package suite

// Fixtures for the live key-custody cases that close the plan's coverage
// gaps (plans/customer-key-custody.md, "Coverage gaps (2026-10-31)"): the
// scenario's own AWS KMS key, a fast re-check, and a private registry and an
// SSHFS share inside the VPC, so a failover has real registry and mount
// credentials to open. Every throwaway credential is made per cluster, kept
// in the root-only state directory on the seed, and travels on stdin.

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// kcKMSKeyID is the AWS KMS key the node was installed with: the scenario's
// own key (Terraform/kms.tf), which teardown schedules for deletion.
func kcKMSKeyID(t *testing.T, node harness.IntegrationNode) string {
	t.Helper()
	out := kcSSH(t, node, `sudo sh -c "grep -h '^SB_SECRET_AWS_KMS_KEY_ID=' /etc/sandboxd/*.env" | tail -1`)
	_, v, _ := strings.Cut(strings.TrimSpace(out), "=")
	if v = strings.Trim(v, `"'`); v == "" {
		t.Fatalf("%s has no SB_SECRET_AWS_KMS_KEY_ID in /etc/sandboxd", node.Name)
	}
	return v
}

// kcEnsureFastRecheck sets the scenario re-check (kcRecheck, revoke after
// kcRevokeAfter) on every node, so a revoke lands within kcRevokeBound.
func kcEnsureFastRecheck(t *testing.T, targets *harness.IntegrationTargets) {
	t.Helper()
	nodes := kcNodes(targets)
	if kcMarked(t, nodes[len(nodes)-1], "fast-recheck") {
		return
	}
	for _, n := range nodes {
		kcSetEnv(t, n, map[string]string{
			"SB_SECRET_PROVIDER_RECHECK_INTERVAL": kcRecheck,
			"SB_SECRET_PROVIDER_REVOKE_AFTER":     kcRevokeAfter,
		})
	}
	kcRollingRestart(t, targets)
	for _, n := range nodes {
		kcMark(t, n, "fast-recheck")
	}
}

// kcPutSecretFile writes content to path on node, owner root, mode 0600,
// inside a root-only directory. The content travels on stdin.
func kcPutSecretFile(t *testing.T, node harness.IntegrationNode, path, content string) {
	t.Helper()
	kcSSHStdin(t, node, fmt.Sprintf(`set -e
sudo install -d -m 0700 "$(dirname %[1]q)"
sudo tee %[1]q >/dev/null
sudo chmod 0600 %[1]q`, path), content)
}

// kcReadSecretFile reads a file kcPutSecretFile wrote.
func kcReadSecretFile(t *testing.T, node harness.IntegrationNode, path string) string {
	t.Helper()
	return strings.TrimSpace(kcSSH(t, node, "sudo cat "+path))
}

// kcExecOut runs command in a sandbox until the exec itself succeeds and
// returns its stdout.
func kcExecOut(t *testing.T, c *harness.Client, sandboxID, command string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		sb, err := c.SDK().Get(ctx, sandboxID)
		if err == nil {
			res, execErr := sb.Exec(ctx, sdktypes.ExecRequest{Command: command})
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
	t.Fatalf("could not run %q in sandbox %s within %s (last: %s)", command, sandboxID, timeout, last)
	return ""
}

// kcRegistry is a private registry on the seed: TLS from a per-cluster CA
// that every node trusts, and htpasswd auth. image is pushed there and
// nowhere else.
type kcRegistry struct {
	host, user, pass, image string
}

const (
	kcRegistryDir   = kcStateDir + "/registry"
	kcRegistryImage = "registry:2.8.3"
	kcRegistryCA    = "/usr/local/share/ca-certificates/itest-registry.crt"
)

// kcEnsureRegistry starts the registry once per cluster. Every node trusts
// its CA (sandboxd pulls through its own resolver, which reads the system
// roots once per process, so every node restarts once), and the seed pushes
// the suite's default image into it under a private name.
func kcEnsureRegistry(t *testing.T, targets *harness.IntegrationTargets) kcRegistry {
	t.Helper()
	seed := kcSeed(t, targets)
	reg := kcRegistry{host: net.JoinHostPort(seed.PrivateIP, "5000"), user: "itest"}
	reg.image = reg.host + "/itest/private:1"
	nodes := kcNodes(targets)
	if kcMarked(t, nodes[len(nodes)-1], "registry") {
		reg.pass = kcReadSecretFile(t, seed, kcRegistryDir+"/password")
		return reg
	}
	caPEM, certPEM, keyPEM := kcRegistryCerts(t, seed.PrivateIP)
	reg.pass = kcRandomToken(t)
	hash, err := bcrypt.GenerateFromPassword([]byte(reg.pass), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	kcPutSecretFile(t, seed, kcRegistryDir+"/password", reg.pass)
	kcPutSecretFile(t, seed, kcRegistryDir+"/htpasswd", reg.user+":"+string(hash)+"\n")
	kcPutSecretFile(t, seed, kcRegistryDir+"/server.key", keyPEM)
	kcPutSecretFile(t, seed, kcRegistryDir+"/server.crt", certPEM)
	kcSSH(t, seed, fmt.Sprintf(`set -e
sudo docker rm -f itest-registry >/dev/null 2>&1 || true
sudo docker run -d --restart always --name itest-registry -p 5000:5000 -v %[1]s:/r:ro \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/r/server.crt -e REGISTRY_HTTP_TLS_KEY=/r/server.key \
  -e REGISTRY_AUTH=htpasswd -e REGISTRY_AUTH_HTPASSWD_REALM=itest -e REGISTRY_AUTH_HTPASSWD_PATH=/r/htpasswd \
  %[2]s >/dev/null`, kcRegistryDir, kcRegistryImage))
	for _, n := range nodes {
		if err := harness.InstallNodeFile(t, n, kcRegistryCA, []byte(caPEM)); err != nil {
			t.Fatal(err)
		}
		if err := harness.InstallNodeFile(t, n, "/etc/docker/certs.d/"+reg.host+"/ca.crt", []byte(caPEM)); err != nil {
			t.Fatal(err)
		}
		kcSSH(t, n, "sudo update-ca-certificates >/dev/null")
	}
	// The image exists only in the registry: the seed's own engine drops
	// its tagged copy, so no node can start it without pulling.
	// A registry with auth answers /v2/ with 401 once it is up, over TLS
	// the seed now trusts.
	kcSSHStdin(t, seed, fmt.Sprintf(`set -e
for i in $(seq 1 30); do
  [ "$(curl -s --cacert %[4]s -o /dev/null -w '%%{http_code}' https://%[1]s/v2/ || true)" = 401 ] && break
  sleep 2
done
sudo docker pull %[2]s >/dev/null
sudo docker tag %[2]s %[3]s
sudo docker login %[1]s -u itest --password-stdin >/dev/null
sudo docker push %[3]s >/dev/null
sudo docker logout %[1]s >/dev/null
sudo docker rmi %[3]s >/dev/null`, reg.host, harness.DefaultImage, reg.image, kcRegistryCA), reg.pass)
	kcRollingRestart(t, targets)
	for _, n := range nodes {
		kcMark(t, n, "registry")
	}
	return reg
}

// kcRegistryCerts makes a CA and a server certificate for ip.
func kcRegistryCerts(t *testing.T, ip string) (caPEM, certPEM, keyPEM string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "aerolvm itest registry CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(7 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: ip},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(7 * 24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP(ip)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srv, ca, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func kcRandomToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// kcShare is a read-only SSHFS share on the seed for a dedicated user that
// can only use SFTP into it; key is that user's private key, the mount's
// sealed credential.
type kcShare struct {
	source, key, token string
}

const kcShareUser = "itestshare"

// kcEnsureShare creates the share once per cluster.
func kcEnsureShare(t *testing.T, targets *harness.IntegrationTargets) kcShare {
	t.Helper()
	seed := kcSeed(t, targets)
	share := kcShare{source: kcShareUser + "@" + seed.PrivateIP + ":/home/" + kcShareUser + "/share"}
	if kcMarked(t, seed, "share") {
		share.key = kcReadSecretFile(t, seed, kcStateDir+"/share/key")
		share.token = strings.TrimSpace(kcSSH(t, seed, "sudo cat /home/"+kcShareUser+"/share/token"))
		return share
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "aerolvm itest share")
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	share.key = string(pem.EncodeToMemory(block))
	share.token = kcRandomToken(t)
	kcPutSecretFile(t, seed, kcStateDir+"/share/key", share.key)
	// restrict: no shell, no forwarding, no pty; the SFTP subsystem sshfs
	// uses still works.
	kcSSHStdin(t, seed, fmt.Sprintf(`set -e
id %[1]s >/dev/null 2>&1 || sudo useradd -m -s /bin/bash %[1]s
sudo install -d -m 0700 -o %[1]s -g %[1]s /home/%[1]s/.ssh
sudo install -d -m 0755 -o %[1]s -g %[1]s /home/%[1]s/share
sudo sh -c 'cat > /home/%[1]s/.ssh/authorized_keys'
sudo chown %[1]s:%[1]s /home/%[1]s/.ssh/authorized_keys
sudo chmod 0600 /home/%[1]s/.ssh/authorized_keys
echo %[2]s | sudo tee /home/%[1]s/share/token >/dev/null`, kcShareUser, share.token),
		"restrict "+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))+"\n")
	kcMark(t, seed, "share")
	return share
}
