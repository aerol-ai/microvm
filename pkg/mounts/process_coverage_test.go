package mounts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

func TestHelperOutputKeepsTheTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "0.log")
	f, out, err := openHelperOutput(path)
	if err != nil {
		t.Fatalf("openHelperOutput: %v", err)
	}
	payload := strings.Repeat("x", maxCapturedMountBytes+512) + "LAST\n"
	if _, err := f.WriteString(payload); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	got := out.String()
	if len(got) != maxCapturedMountBytes-1 || !strings.HasSuffix(got, "LAST") {
		t.Fatalf("String() = %d bytes ending %q, want the last %d bytes trimmed", len(got), got[max(len(got)-8, 0):], maxCapturedMountBytes)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("log mode = %v, %v; want 0600", st.Mode().Perm(), err)
	}

	// A new run starts from an empty log.
	f, out, err = openHelperOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if got := out.String(); got != "" {
		t.Fatalf("String() after reopen = %q, want empty", got)
	}

	var nilOut *helperOutput
	if nilOut.String() != "" {
		t.Fatal("nil helperOutput is not empty")
	}
	nilOut.trim() // no panic
	if (&helperOutput{path: filepath.Join(t.TempDir(), "missing")}).String() != "" {
		t.Fatal("a missing log is not empty")
	}
	if _, _, err := openHelperOutput(filepath.Join(t.TempDir(), "no", "dir", "0.log")); err == nil {
		t.Fatal("openHelperOutput in a missing directory succeeded")
	}
}

func TestHelperOutputTrim(t *testing.T) {
	path := filepath.Join(t.TempDir(), "0.log")
	out := &helperOutput{path: path}
	if err := os.WriteFile(path, []byte(strings.Repeat("y", maxHelperLogBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	out.trim()
	if st, _ := os.Stat(path); st.Size() != maxHelperLogBytes {
		t.Fatalf("trim cut a log at the cap: size %d", st.Size())
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("y", maxHelperLogBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	out.trim()
	if st, _ := os.Stat(path); st.Size() != 0 {
		t.Fatalf("trim left %d bytes of a log over the cap", st.Size())
	}
}

// The supervisor keeps a running tool's log under the cap.
func TestSuperviseExitTrimsTheLog(t *testing.T) {
	prev := helperLogTrimInterval
	helperLogTrimInterval = 10 * time.Millisecond
	t.Cleanup(func() { helperLogTrimInterval = prev })

	m := newTestManager(t, nil)
	path := filepath.Join(t.TempDir(), "0.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("z", maxHelperLogBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	exit := &procExit{done: make(chan struct{})}
	state := &mountState{sandboxID: "sb-trim", output: &helperOutput{path: path}, exit: exit}
	done := make(chan struct{})
	go func() { m.superviseExit(state); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if st, err := os.Stat(path); err == nil && st.Size() == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the supervisor never trimmed the log")
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(exit.done) // untracked state: the supervisor returns without a restart
	<-done
}

func TestSpawnHelperWithEnv(t *testing.T) {
	m := newTestManager(t, nil)
	logPath := filepath.Join(t.TempDir(), "0.log")
	cmd, out, exit, err := m.spawnHelper(adapters.Plan{
		Argv: []string{"sh", "-c", `echo "env=$MOUNT_SPAWN_ENV"`},
		Env:  []string{"MOUNT_SPAWN_ENV=1"},
	}, logPath)
	if err != nil {
		t.Fatalf("spawnHelper: %v", err)
	}
	t.Cleanup(func() { _ = killMount(cmd) })
	<-exit.done
	if got := out.String(); got != "env=1" {
		t.Fatalf("captured output = %q, want env=1 written by the tool into its log", got)
	}

	if _, _, _, err := m.spawnHelper(adapters.Plan{Argv: []string{"true"}}, filepath.Join(t.TempDir(), "no", "dir", "0.log")); err == nil {
		t.Fatal("spawnHelper with an unopenable log succeeded")
	}
	if _, _, _, err := m.spawnHelper(adapters.Plan{Argv: []string{"/no/such/mount-tool"}}, logPath); err == nil {
		t.Fatal("spawnHelper of a missing tool succeeded")
	}
}
