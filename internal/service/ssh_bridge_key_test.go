package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"golang.org/x/crypto/ssh"
)

func testSSHKey(t *testing.T) (authorized, fingerprint string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(key)), ssh.FingerprintSHA256(key)
}

// The owner serves a node's bridged SSH call only for the sandbox's key:
// always when the call names a key, and once every member names one (servers
// sign) also when it names none.
func TestSSHBridgeKey(t *testing.T) {
	server, _, _, _, st := signingPair(t)
	ctx := context.Background()
	authorized, fp := testSSHKey(t)
	_, otherFP := testSSHKey(t)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-ssh", Image: "alpine", Status: models.SandboxStatusStarted, SSHPublicKey: authorized,
		CPU: 1, MemoryMB: 64, DiskGB: 1, OSUser: "root", CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatal(err)
	}
	server.store = st
	if ok, err := server.SSHKeyMatches(ctx, "sb-ssh", fp); err != nil || !ok {
		t.Fatalf("the sandbox's key = %v %v", ok, err)
	}
	if ok, _ := server.SSHKeyMatches(ctx, "sb-ssh", otherFP); ok {
		t.Fatal("another key matched")
	}
	if _, err := server.SSHKeyMatches(ctx, "sb-none", fp); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown sandbox = %v", err)
	}
	// Before servers sign: an older gateway names no key and is served.
	if err := server.CheckSSHBridgeKey(ctx, "sb-ssh", ""); err != nil {
		t.Fatalf("no key before = %v", err)
	}
	if !server.KeepsSSHKeyFrom(false) || server.KeepsSSHKeyFrom(true) {
		t.Fatal("key kept for the wrong caller before")
	}
	if err := server.CheckSSHBridgeKey(ctx, "sb-ssh", otherFP); !errors.Is(err, ErrSSHBridgeKey) {
		t.Fatalf("another key before = %v", err)
	}
	turnOnServerSigning(t, server, time.Now())
	if err := server.CheckSSHBridgeKey(ctx, "sb-ssh", ""); !errors.Is(err, ErrSSHBridgeKey) {
		t.Fatalf("no key once servers sign = %v", err)
	}
	if err := server.CheckSSHBridgeKey(ctx, "sb-ssh", fp); err != nil {
		t.Fatalf("the key once servers sign = %v", err)
	}
	if err := server.CheckSSHBridgeKey(ctx, "sb-none", fp); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an unknown sandbox = %v", err)
	}
	if server.KeepsSSHKeyFrom(false) {
		t.Fatal("a node keeps the key once servers sign")
	}
	if sshKeyFingerprint("not a key") != "" || sshKeyFingerprint("") != "" {
		t.Fatal("a fingerprint for no key")
	}
}
