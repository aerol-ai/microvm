package toolhost

import (
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// ─── exec_stream helpers ──────────────────────────────────────────────────────

func TestMergeExecEnv(t *testing.T) {
	// no extra env → returns os.Environ()
	base := mergeExecEnv(nil)
	if len(base) == 0 {
		t.Fatal("mergeExecEnv with nil should return os.Environ()")
	}
	// extra env is added
	merged := mergeExecEnv(map[string]string{"TEST_VAR": "hello"})
	found := false
	for _, e := range merged {
		if e == "TEST_VAR=hello" {
			found = true
		}
	}
	if !found {
		t.Fatal("TEST_VAR not found in merged env")
	}
}

func TestWaitExec(t *testing.T) {
	// Successful command
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start true: %v", err)
	}
	code, sig := waitExec(cmd)
	if code != 0 || sig != "" {
		t.Fatalf("true: code=%d sig=%q", code, sig)
	}

	// Failing command (exit 2)
	cmd = exec.Command("sh", "-c", "exit 2")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sh: %v", err)
	}
	code, sig = waitExec(cmd)
	if code != 2 {
		t.Fatalf("exit 2 code = %d", code)
	}
	_ = sig
}

func TestSignalExecNilProcess(t *testing.T) {
	// should not panic
	signalExec(nil, "TERM")
	signalExec(&exec.Cmd{}, "TERM") // Process is nil
}

func TestSignalExecUnknownSignal(t *testing.T) {
	// should silently ignore unknown signal
	cmd := exec.Command("sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	defer func() { _ = cmd.Process.Signal(syscall.SIGKILL) }()
	signalExec(cmd, "SIGUSR99") // unknown — no panic
}

func TestSignalExecKnownSignals(t *testing.T) {
	for _, sig := range []string{"TERM", "SIGTERM", "KILL", "SIGKILL", "INT", "SIGINT"} {
		cmd := exec.Command("sleep", "60")
		if err := cmd.Start(); err != nil {
			t.Fatalf("start sleep for %s: %v", sig, err)
		}
		signalExec(cmd, sig)
		// Don't wait — just confirm no panic. The signal may or may not kill before cleanup.
		_ = cmd.Process.Signal(syscall.SIGKILL)
	}
}

// ─── coderun helpers ──────────────────────────────────────────────────────────

func TestEnvMapToSlice(t *testing.T) {
	if envMapToSlice(nil) != nil {
		t.Fatal("nil map should return nil")
	}
	if envMapToSlice(map[string]string{}) != nil {
		t.Fatal("empty map should return nil")
	}
	result := envMapToSlice(map[string]string{"A": "1", "B": "2"})
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
	for _, kv := range result {
		if !strings.Contains(kv, "=") {
			t.Fatalf("missing = in %q", kv)
		}
	}
}

func TestInterpretWaitResult(t *testing.T) {
	// nil error → exit code 0
	code, err := interpretWaitResult(nil)
	if code != 0 || err != nil {
		t.Fatalf("nil: code=%d err=%v", code, err)
	}

	// ExitError → extracts code
	cmd := exec.Command("sh", "-c", "exit 5")
	_ = cmd.Run()
	exitErr := &exec.ExitError{}
	if errors.As(cmd.Wait(), &exitErr) || true {
		// Run() already waited; construct manually via a new command
		cmd2 := exec.Command("sh", "-c", "exit 5")
		runErr := cmd2.Run()
		code2, _ := interpretWaitResult(runErr)
		if code2 != 5 {
			t.Fatalf("exit 5: code = %d", code2)
		}
	}

	// Non-ExitError → code 1
	code, err = interpretWaitResult(errors.New("some other error"))
	if code != 1 || err == nil {
		t.Fatalf("generic error: code=%d err=%v", code, err)
	}
}

func TestWriteCodeRunScript(t *testing.T) {
	dir := t.TempDir()
	path, cleanup, err := writeCodeRunScript(dir, "echo hello", ".sh")
	if err != nil {
		t.Fatalf("writeCodeRunScript: %v", err)
	}
	defer cleanup()
	if path == "" {
		t.Fatal("script path should not be empty")
	}
	// cleanup removes the dir
	cleanup()
	// Calling cleanup again should not panic
	cleanup()
}

// ─── files helper ─────────────────────────────────────────────────────────────

func TestStrconvQuote(t *testing.T) {
	if got := strconvQuote(""); got != `""` {
		t.Fatalf("empty = %q", got)
	}
	if got := strconvQuote("file.txt"); got != `"file.txt"` {
		t.Fatalf("simple = %q", got)
	}
	if got := strconvQuote(`file"with"quotes`); got != `"file\"with\"quotes"` {
		t.Fatalf("with quotes = %q", got)
	}
}

// ─── host.go New with sessions ────────────────────────────────────────────────

func TestNewHostWithSessions(t *testing.T) {
	// When sessions is nil, daytona should also be nil
	h := New(Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
	})
	if h == nil {
		t.Fatal("New returned nil")
	}
	// no panic accessing the handler
	_ = h.Handler()
}
