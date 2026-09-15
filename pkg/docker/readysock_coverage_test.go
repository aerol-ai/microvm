package docker

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/readyproto"
)

func TestCoverage95NetworkPolicyAndReadySocketHelpers(t *testing.T) {
	c := &Client{networkRules: disabledRules(t)}
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"apply empty", func() error { return c.ApplyEgressPolicy("", nil, nil) }},
		{"apply policy", func() error {
			return c.ApplyEgressPolicy("172.17.0.2", []string{"10.0.0.0/8"}, []string{"192.168.0.0/16"})
		}},
		{"clear policy", func() error { return c.ClearEgressPolicy("172.17.0.2", nil, nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err != nil {
				t.Fatal(err)
			}
		})
	}

	if err := EnsureReadyDir(""); err == nil {
		t.Fatal("empty ready dir unexpectedly succeeded")
	}
	dir := filepath.Join(t.TempDir(), "ready")
	if err := EnsureReadyDir(dir); err != nil {
		t.Fatalf("EnsureReadyDir: %v", err)
	}
	nonce, err := MintReadyNonce()
	if err != nil || len(nonce) != 32 {
		t.Fatalf("MintReadyNonce() = %q, %v", nonce, err)
	}
	if (*ReadyListener)(nil).HostSocketPath() != "" {
		t.Fatal("nil listener reported a socket path")
	}
}

func TestCoverage95ReadyListenerVerificationAndCleanup(t *testing.T) {
	dir := coverageReadyDir(t)
	ln, err := NewReadyListener(dir, "sb", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	for _, signal := range []readyproto.ReadySignal{
		{SandboxID: "wrong", Token: "token", Nonce: "nonce"},
		{SandboxID: "sb", Token: "token", Nonce: "wrong"},
		{SandboxID: "sb", Token: "wrong", Nonce: "nonce"},
	} {
		server, client := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- ln.readAndVerify(server) }()
		if err := readyproto.Encode(client, signal); err != nil {
			t.Fatal(err)
		}
		_ = client.Close()
		if err := <-done; err == nil {
			t.Fatalf("signal %+v unexpectedly verified", signal)
		}
	}

	ln.recordInvalidAttempt("manual")
	if n, reason := ln.InvalidAttempts(); n != 1 || reason != "manual" {
		t.Fatalf("InvalidAttempts() = (%d,%q)", n, reason)
	}
	if n, reason := (*ReadyListener)(nil).InvalidAttempts(); n != 0 || reason != "" {
		t.Fatalf("nil InvalidAttempts() = (%d,%q)", n, reason)
	}

	parkPath := filepath.Join(dir, "parked.sock")
	parked, err := net.Listen("unix", parkPath)
	if err != nil {
		t.Fatal(err)
	}
	parkedReadySockets.Store(parkPath, parked)
	closeParkedReadySocket(parkPath)
	if _, ok := parkedReadySockets.Load(parkPath); ok {
		t.Fatal("parked listener remained registered")
	}

	activePath := ln.HostSocketPath()
	RemoveReadySocketsForSandbox(dir, "")
	if _, err := os.Stat(activePath); err != nil {
		t.Fatalf("empty cleanup removed active socket: %v", err)
	}
	RemoveReadySocketsForSandbox("", "sb")

	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ln.ParkBindSource(); err != nil {
		t.Fatal(err)
	}
	if err := ln.ParkBindSource(); err != nil {
		t.Fatal(err)
	}
	RemoveReadySocketsForSandbox(dir, "sb")
	if _, err := os.Stat(activePath); !os.IsNotExist(err) {
		t.Fatalf("parked socket was not removed: %v", err)
	}
}

func TestCoverage95ReadyListenerWaitRejectsInvalidThenSucceeds(t *testing.T) {
	ln, err := NewReadyListener(coverageReadyDir(t), "sb", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for _, token := range []string{"wrong", "token"} {
			conn, dialErr := net.Dial("unix", ln.HostSocketPath())
			if dialErr != nil {
				return
			}
			_ = readyproto.Encode(conn, readyproto.ReadySignal{
				Event: readyproto.EventReady, SandboxID: "sb", Token: token, Nonce: "nonce",
			})
			_ = conn.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := ln.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if n, reason := ln.InvalidAttempts(); n != 1 || !strings.Contains(reason, "token") {
		t.Fatalf("invalid attempts = (%d,%q)", n, reason)
	}
}

func TestCoverage95ReadySocketSweepAndTimeoutPaths(t *testing.T) {
	dir := coverageReadyDir(t)
	active, err := NewReadyListener(dir, "active", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = active.Close() })
	orphan := filepath.Join(dir, "dead.nonce.sock")
	if err := os.WriteFile(orphan, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SweepOrphanReadySockets(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan remained: %v", err)
	}
	if _, err := os.Stat(active.HostSocketPath()); err != nil {
		t.Fatalf("active socket removed: %v", err)
	}
	if err := SweepOrphanReadySockets(""); err != nil {
		t.Fatal(err)
	}
	if err := SweepOrphanReadySockets(filepath.Join(dir, "missing")); err != nil {
		t.Fatal(err)
	}

	timeout, err := NewReadyListener(dir, "timeout", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = timeout.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := timeout.Wait(ctx); err == nil {
		t.Fatal("wait without a client unexpectedly succeeded")
	}
	for _, id := range []string{"", "../invalid", strings.Repeat("a", 129)} {
		if err := validateReadySandboxID(id); err == nil {
			t.Fatalf("invalid sandbox ID %q accepted", id)
		}
	}
}

func TestCoverage95ReadyListenerValidationAndInvalidLimit(t *testing.T) {
	for _, args := range []struct {
		dir, sandboxID, token, nonce string
	}{
		{dir: coverageReadyDir(t), token: "token", nonce: "nonce"},
		{dir: coverageReadyDir(t), sandboxID: "sandbox", nonce: "nonce"},
		{dir: coverageReadyDir(t), sandboxID: "sandbox", token: "token"},
		{sandboxID: "sandbox", token: "token", nonce: "nonce"},
	} {
		if _, err := NewReadyListener(args.dir, args.sandboxID, args.token, args.nonce); err == nil {
			t.Fatalf("NewReadyListener(%+v) unexpectedly succeeded", args)
		}
	}
	if err := (*ReadyListener)(nil).Wait(context.Background()); err == nil {
		t.Fatal("nil Wait unexpectedly succeeded")
	}

	ln, err := NewReadyListener(coverageReadyDir(t), "sandbox", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for i := 0; i < maxInvalidReadyAttempts; i++ {
			conn, dialErr := net.Dial("unix", ln.HostSocketPath())
			if dialErr != nil {
				return
			}
			_ = readyproto.Encode(conn, readyproto.ReadySignal{
				Event: readyproto.EventReady, SandboxID: "sandbox", Token: "wrong", Nonce: "nonce",
			})
			_ = conn.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := ln.Wait(ctx); err == nil {
		t.Fatal("Wait accepted too many invalid signals")
	}
}

func TestCoverage95NewReadyListenerStalePathBlocksCreate(t *testing.T) {
	dir := coverageReadyDir(t)
	path := readySocketHostPath(dir, "sb", "nonce")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "block"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewReadyListener(dir, "sb", "token", "nonce")
	if err == nil || !strings.Contains(err.Error(), "unlink stale ready socket") {
		t.Fatalf("NewReadyListener() = %v", err)
	}
}

func TestCoverage95RemoveReadySocketsSkipsActive(t *testing.T) {
	dir := coverageReadyDir(t)
	ln, err := NewReadyListener(dir, "sb", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	path := ln.HostSocketPath()
	RemoveReadySocketsForSandbox(dir, "sb")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("active socket removed: %v", err)
	}
	_ = ln.Close()
	RemoveReadySocketsForSandbox(dir, "sb")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("closed socket not removed: %v", err)
	}
}

func TestCoverage95ParkBindSourceNilSafe(t *testing.T) {
	var ln *ReadyListener
	if err := ln.ParkBindSource(); err != nil {
		t.Fatalf("nil ParkBindSource() = %v", err)
	}
}

func TestCoverage95ReadyListenerWaitAcceptTimeoutRetry(t *testing.T) {
	ln, err := NewReadyListener(coverageReadyDir(t), "sb", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := ln.Wait(ctx); err == nil {
		t.Fatal("expected timeout without valid ready push")
	}
}

func TestCoverage95SweepOrphanReadySocketsExceptKeepsPaths(t *testing.T) {
	dir := coverageReadyDir(t)
	keepPath := filepath.Join(dir, "keep.sock")
	parkedPath := filepath.Join(dir, "parked.sock")
	activePath := filepath.Join(dir, "active.sock")
	if err := os.WriteFile(keepPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", activePath)
	if err != nil {
		t.Fatal(err)
	}
	activeReadySockets.Store(activePath, struct{}{})
	parkedLn, err := net.Listen("unix", parkedPath)
	if err != nil {
		t.Fatal(err)
	}
	parkedReadySockets.Store(parkedPath, parkedLn)

	if err := SweepOrphanReadySocketsExcept(dir, map[string]struct{}{keepPath: {}}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{keepPath, parkedPath, activePath} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("path %s was removed: %v", path, statErr)
		}
	}
	orphan := filepath.Join(dir, "gone.sock")
	if err := os.WriteFile(orphan, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SweepOrphanReadySocketsExcept(dir, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan remained: %v", err)
	}
	_ = ln.Close()
	_ = parkedLn.Close()
	activeReadySockets.Delete(activePath)
	parkedReadySockets.Delete(parkedPath)
}

func TestCoverage95NewReadyListenerPathTooLong(t *testing.T) {
	dir := coverageReadyDir(t)
	longID := strings.Repeat("a", 90)
	if _, err := NewReadyListener(dir, longID, "token", "nonce"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("NewReadyListener() = %v, want path length error", err)
	}
}

func TestCoverage95ParkBindSourceAlreadyParked(t *testing.T) {
	dir := coverageReadyDir(t)
	ln, err := NewReadyListener(dir, "sb", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	path := ln.HostSocketPath()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ln.ParkBindSource(); err != nil {
		t.Fatal(err)
	}
	if err := ln.ParkBindSource(); err != nil {
		t.Fatalf("second ParkBindSource() = %v", err)
	}
	if _, ok := parkedReadySockets.Load(path); !ok {
		t.Fatal("parked socket was not registered")
	}
	closeParkedReadySocket(path)
}

func TestCoverage95ReadyListenerWaitAcceptError(t *testing.T) {
	dir := coverageReadyDir(t)
	ln, err := NewReadyListener(dir, "sb", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := ln.listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := ln.Wait(ctx); err == nil || !strings.Contains(err.Error(), "ready socket accept") {
		t.Fatalf("Wait() = %v, want accept error", err)
	}
}

func TestCoverage95ReadyListenerRecordInvalidNil(t *testing.T) {
	var ln *ReadyListener
	ln.recordInvalidAttempt("ignored")
}

func TestCoverage95ReadySocketSweepReadDirError(t *testing.T) {
	if err := SweepOrphanReadySocketsExcept(filepath.Join(t.TempDir(), "missing-parent", "ready"), nil); err != nil {
		t.Fatalf("missing dir should be ignored: %v", err)
	}
	dir := coverageReadyDir(t)
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := SweepOrphanReadySocketsExcept(dir, nil); err == nil {
		t.Fatal("expected readdir error")
	}
}
