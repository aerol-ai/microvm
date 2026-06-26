package firecracker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeFakeFirecracker drops a shell script at <dir>/firecracker that
// mimics firecracker's argument shape: it reads --api-sock <path>,
// touches that file (the real binary creates a Unix listener; for the
// process-management layer's tests we only need the path to appear), then
// traps SIGTERM and sleeps. The script exits 0 on SIGTERM so Wait
// returns a nil err on a graceful shutdown.
//
// We deliberately do not test the HTTP-over-UDS path here — that's
// pkg/firecracker's responsibility (client_test.go). The seam under test
// is exclusively process-management.
func writeFakeFirecracker(t *testing.T, dir string, opts fakeOpts) string {
	t.Helper()
	path := filepath.Join(dir, "firecracker")
	script := "#!/bin/sh\n" +
		"trap 'exit 0' TERM INT\n" +
		"sock=\"\"\n" +
		"while [ $# -gt 0 ]; do\n" +
		"  case \"$1\" in\n" +
		"    --api-sock) sock=\"$2\"; shift 2 ;;\n" +
		"    *) shift ;;\n" +
		"  esac\n" +
		"done\n"
	if opts.delayMs > 0 {
		script += "sleep " + msToShellSeconds(opts.delayMs) + "\n"
	}
	if opts.printStderr != "" {
		script += "echo " + shellQuote(opts.printStderr) + " >&2\n"
	}
	if !opts.skipTouch {
		script += "if [ -n \"$sock\" ]; then : > \"$sock\"; fi\n"
	}
	if opts.exitImmediately {
		script += "exit " + msToShellInt(opts.exitCode) + "\n"
	} else {
		// Block until killed. `wait` for a backgrounded sleep so the
		// shell's signal handler runs synchronously.
		script += "sleep 30 &\n" +
			"wait\n"
	}
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake firecracker: %v", err)
	}
	return path
}

type fakeOpts struct {
	delayMs         int    // sleep before touching the socket
	printStderr     string // emit a line to stderr before doing anything
	skipTouch       bool   // do not touch the api-sock (simulate failure to bind)
	exitImmediately bool   // exit instead of blocking
	exitCode        int    // exit status when exitImmediately
}

func msToShellSeconds(ms int) string {
	// /bin/sh sleep accepts integer seconds portably. Round up so tests
	// that need "at least N ms" don't flake on 1-second rounding.
	s := ms / 1000
	if ms%1000 != 0 {
		s++
	}
	if s < 1 {
		s = 1
	}
	return msToShellInt(s)
}

func msToShellInt(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func TestValidateSandboxID(t *testing.T) {
	for _, tc := range []struct {
		id      string
		wantErr bool
	}{
		{"abc123", false},
		{"sandbox-1", false},
		{"under_score", false},
		{"", true},
		{"with/slash", true},
		{"with space", true},
		{"dot.file", true},
		{"../escape", true},
		{strings.Repeat("a", 129), true},
	} {
		err := validateSandboxID(tc.id)
		if (err != nil) != tc.wantErr {
			t.Errorf("validateSandboxID(%q): err=%v wantErr=%v", tc.id, err, tc.wantErr)
		}
	}
}

func TestNewVMM_Validation(t *testing.T) {
	dir := t.TempDir()
	t.Run("missing binary", func(t *testing.T) {
		if _, err := newVMM(Config{RunDir: dir}, "id", nil); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("missing run dir", func(t *testing.T) {
		if _, err := newVMM(Config{FirecrackerBinary: "/x"}, "id", nil); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("invalid sandbox id", func(t *testing.T) {
		if _, err := newVMM(Config{FirecrackerBinary: "/x", RunDir: dir}, "bad/id", nil); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("ok", func(t *testing.T) {
		v, err := newVMM(Config{FirecrackerBinary: "/x", RunDir: dir}, "ok-id", nil)
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		wantSock := filepath.Join(dir, "ok-id", "api.sock")
		if v.APISocket() != wantSock {
			t.Errorf("APISocket = %q, want %q", v.APISocket(), wantSock)
		}
		if !strings.HasSuffix(v.RunDir(), "ok-id") {
			t.Errorf("RunDir = %q, want suffix ok-id", v.RunDir())
		}
		if got := v.buildArgs(); len(got) != 2 || got[0] != "--api-sock" || got[1] != wantSock {
			t.Errorf("buildArgs = %v, want [--api-sock %s]", got, wantSock)
		}
	})
}

// TestVMM_StartWaitSocketShutdown exercises the full happy path:
// spawn, wait for the api-sock to appear, signal SIGTERM, observe a
// clean Wait. This is the contract Driver.Create will rely on.
func TestVMM_StartWaitSocketShutdown(t *testing.T) {
	dir := t.TempDir()
	fcBin := writeFakeFirecracker(t, dir, fakeOpts{})
	cfg := Config{FirecrackerBinary: fcBin, RunDir: dir}

	v, err := newVMM(cfg, "sandbox-1", nil)
	if err != nil {
		t.Fatalf("newVMM: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := v.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if v.Pid() == 0 {
		t.Fatal("Pid is 0 after Start")
	}

	if err := v.WaitSocket(ctx, 45*time.Second); err != nil {
		t.Fatalf("WaitSocket: %v (tail: %s)", err, v.StderrTail())
	}

	if err := v.Shutdown(ctx, 2*time.Second); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := v.Wait(); err != nil {
		t.Fatalf("Wait after Shutdown: %v", err)
	}

	if err := v.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(v.RunDir()); !os.IsNotExist(err) {
		t.Fatalf("RunDir still exists after Cleanup: %v", err)
	}
}

func TestVMM_RequestContextCancelDoesNotKillProcess(t *testing.T) {
	dir := t.TempDir()
	fcBin := writeFakeFirecracker(t, dir, fakeOpts{})
	cfg := Config{FirecrackerBinary: fcBin, RunDir: dir}

	v, err := newVMM(cfg, "sandbox-ctx", nil)
	if err != nil {
		t.Fatalf("newVMM: %v", err)
	}
	reqCtx, cancelReq := context.WithCancel(context.Background())
	if err := v.Start(reqCtx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := v.WaitSocket(reqCtx, 45*time.Second); err != nil {
		t.Fatalf("WaitSocket: %v (tail: %s)", err, v.StderrTail())
	}

	cancelReq()
	select {
	case <-v.waitCh:
		t.Fatalf("VMM exited after request context cancellation: %v", v.waitErr)
	case <-time.After(150 * time.Millisecond):
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := v.Shutdown(ctx, 2*time.Second); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := v.Wait(); err != nil {
		t.Fatalf("Wait after Shutdown: %v", err)
	}
}

func TestVMM_StartTwiceIsError(t *testing.T) {
	dir := t.TempDir()
	fcBin := writeFakeFirecracker(t, dir, fakeOpts{})
	cfg := Config{FirecrackerBinary: fcBin, RunDir: dir}
	v, err := newVMM(cfg, "sandbox-2x", nil)
	if err != nil {
		t.Fatalf("newVMM: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := v.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = v.Shutdown(ctx, 5*time.Second) }()
	if err := v.Start(ctx); err == nil {
		t.Fatal("expected error on second Start")
	}
}

// TestVMM_ExitsBeforeSocket simulates the operator-visible failure mode:
// firecracker dies during early init before binding the API socket. The
// driver needs the stderr tail surfaced so the operator can see *why*.
func TestVMM_ExitsBeforeSocket(t *testing.T) {
	dir := t.TempDir()
	fcBin := writeFakeFirecracker(t, dir, fakeOpts{
		printStderr:     "bad kernel image: signature mismatch",
		skipTouch:       true,
		exitImmediately: true,
		exitCode:        1,
	})
	cfg := Config{FirecrackerBinary: fcBin, RunDir: dir}
	v, err := newVMM(cfg, "sandbox-die", nil)
	if err != nil {
		t.Fatalf("newVMM: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := v.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Full-suite runs can have transient scheduler delay before waitCh observes
	// the fast process exit; use a slightly wider budget to avoid timeout flakes.
	err = v.WaitSocket(ctx, 5*time.Second)
	if err == nil {
		t.Fatal("expected error from WaitSocket when fc exits early")
	}
	if !strings.Contains(err.Error(), "exited before API socket bound") {
		t.Errorf("WaitSocket error did not name the failure mode: %v", err)
	}
	if !strings.Contains(err.Error(), "signature mismatch") {
		t.Errorf("WaitSocket error did not surface stderr tail: %v", err)
	}
}

// TestVMM_KillIdempotent confirms calling Kill twice does not panic or
// block. Destroy callers may invoke this from a cleanup path that has
// already raced with a concurrent Shutdown.
func TestVMM_KillIdempotent(t *testing.T) {
	dir := t.TempDir()
	fcBin := writeFakeFirecracker(t, dir, fakeOpts{})
	cfg := Config{FirecrackerBinary: fcBin, RunDir: dir}
	v, err := newVMM(cfg, "sandbox-kill", nil)
	if err != nil {
		t.Fatalf("newVMM: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := v.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := v.WaitSocket(ctx, 20*time.Second); err != nil {
		t.Fatalf("WaitSocket: %v", err)
	}
	if err := v.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if err := v.Kill(); err != nil {
		t.Fatalf("Kill (second): %v", err)
	}
}

func TestVMM_ShutdownBeforeStartIsNoop(t *testing.T) {
	dir := t.TempDir()
	v, err := newVMM(Config{FirecrackerBinary: "/x", RunDir: dir}, "noop", nil)
	if err != nil {
		t.Fatalf("newVMM: %v", err)
	}
	if err := v.Shutdown(context.Background(), 1*time.Second); err != nil {
		t.Errorf("Shutdown on unstarted vmm: %v", err)
	}
	if err := v.Kill(); err != nil {
		t.Errorf("Kill on unstarted vmm: %v", err)
	}
}

// TestVMM_CleanupRejectsEscape ensures the defense-in-depth check in
// Cleanup rejects a RunDir outside the configured root. validateSandboxID
// already prevents this at construction; the second check exists in case
// of mutation through future code paths.
func TestVMM_CleanupRejectsEscape(t *testing.T) {
	v := &vmm{
		runDir: "/tmp/elsewhere",
		cfg:    Config{RunDir: "/var/run/sb"},
	}
	if err := v.Cleanup(); err == nil {
		t.Fatal("expected Cleanup to reject path outside RunDir")
	}
}

func TestCappedBuffer(t *testing.T) {
	b := newCappedBuffer(8)
	n, _ := b.Write([]byte("12345"))
	if n != 5 {
		t.Fatalf("Write n = %d", n)
	}
	if got := b.String(); got != "12345" {
		t.Fatalf("String = %q", got)
	}
	// Fill exactly to cap.
	_, _ = b.Write([]byte("678"))
	if got := b.String(); got != "12345678" {
		t.Fatalf("String = %q", got)
	}
	// Overflow — first byte accepted up to cap, rest reported dropped.
	_, _ = b.Write([]byte("XXXXX"))
	got := b.String()
	if !strings.HasPrefix(got, "12345678\n[... ") {
		t.Fatalf("overflow report missing: %q", got)
	}
	if !strings.Contains(got, "5 more bytes dropped") {
		t.Fatalf("dropped byte count missing: %q", got)
	}
}
