//go:build integration

package suite

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
	"golang.org/x/crypto/ssh"
)

// UC-43 — SSH into a sandbox using the per-sandbox key returned at create.
//
// The gateway routes by username (the sandbox ID) and then authorizes against
// that sandbox's authorized ed25519 key. We dial the gateway on the leased
// domain (port from AEROL_SSH_PORT, default 2220), auth with the private key
// Create handed back exactly once, and run a command.
func TestSSHWithPerSandboxKey(t *testing.T) {
	harness.Require(t, sc, "UC-43")
	c := client(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	// Create directly (not NewSandbox) so we can read SSHPrivateKey off the
	// create response — it is never returned again.
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Image: harness.DefaultImage,
		Name:  harness.UniqueName(sc, t),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().Destroy(cctx, sb.ID)
	})
	waitRunning(t, sb)

	if sb.SSHPrivateKey == "" {
		t.Fatal("create response carried no SSH private key")
	}
	signer, err := ssh.ParsePrivateKey([]byte(sb.SSHPrivateKey))
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}

	port := os.Getenv("AEROL_SSH_PORT")
	if port == "" {
		// Matches SB_SSH_LISTEN_ADDR's default (0.0.0.0:2220) on the daemon.
		port = "2220"
	}
	addr := net.JoinHostPort(sc.Domain, port)

	cfg := &ssh.ClientConfig{
		// The gateway routes by username: it must be the sandbox ID (optionally
		// "<id>+<session>"). It looks the sandbox up by that ID and then checks
		// the key against that sandbox's authorized key — a literal user fails
		// the lookup before the key is ever compared. See parseSSHUser /
		// publicKeyCallback in pkg/sshgateway/gateway.go.
		User:            sb.ID,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // throwaway test gateway
		Timeout:         15 * time.Second,
	}

	// The gateway/route can lag a few seconds behind sandbox-ready; retry.
	deadline := time.Now().Add(90 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := ssh.Dial("tcp", addr, cfg)
		if err != nil {
			lastErr = err
			time.Sleep(3 * time.Second)
			continue
		}
		defer conn.Close()
		sess, err := conn.NewSession()
		if err != nil {
			t.Fatalf("new ssh session: %v", err)
		}
		defer sess.Close()
		out, err := sess.Output("echo ssh-ok")
		if err != nil {
			t.Fatalf("run over ssh: %v", err)
		}
		if string(out) == "" {
			t.Fatal("ssh command produced no output")
		}
		return
	}
	t.Fatalf("ssh to %s never succeeded: %v", addr, lastErr)
}
