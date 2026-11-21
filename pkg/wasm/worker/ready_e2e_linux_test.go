//go:build linux

package worker

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A confined worker says it serves once it has dropped and installed its
// filter: the pipe it took before the drop still works under the filter,
// and the first ping after the signal answers.
func TestConfinedWorkerSignalsReady(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the worker drops from root")
	}
	if !canMakePIDNamespace() {
		t.Skip("needs a host (or privileged container) that allows new PID namespaces, as sandboxd's does")
	}
	spawn := Confine(func(ctx context.Context, socketPath string) (*exec.Cmd, error) {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConfinedWorkerChild$")
		cmd.Env = append(workerEnvironment(ctx), confinedChildEnv+"="+socketPath)
		cmd.Stderr = os.Stderr
		return cmd, nil
	}, Confinement{UID: e2eWorkerUID, GID: e2eWorkerUID})
	sup := NewSupervisor(spawn)
	sock := filepath.Join(t.TempDir(), "w.sock")
	t.Cleanup(func() { _ = sup.Stop("sb-ready") })
	start := time.Now()
	if err := sup.Ensure(context.Background(), "sb-ready", sock); err != nil {
		t.Fatal(err)
	}
	if !readyWithin(sup.Ready("sb-ready"), 20*time.Second) {
		t.Fatal("the confined worker never said it serves")
	}
	t.Logf("ready %v after the start", time.Since(start))
	if err := NewClient(sock).Ping("sb-ready"); err != nil {
		t.Fatalf("ping right after the signal: %v", err)
	}
	sup.mu.Lock()
	pid := sup.slots["sb-ready"].cmd.Process.Pid
	sup.mu.Unlock()
	if uid := procStatus(t, pid)["Uid"]; !strings.HasPrefix(uid, strconv.Itoa(e2eWorkerUID)) {
		t.Fatalf("the worker that signalled runs as uid %q", uid)
	}
}
