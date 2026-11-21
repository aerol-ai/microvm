//go:build linux

package cni

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestExecRunnerProcessGroup (PR 4 review): the bridge plugin runs its
// IPAM plugin as a child. With ProcessGroup, a DEL whose call is cancelled
// takes that child with it, so it can never free an address after the
// call's retry has built the slot again; without it (the agent's own
// runner, single mode) only the plugin itself is killed, as before.
func TestExecRunnerProcessGroup(t *testing.T) {
	for _, group := range []bool{true, false} {
		t.Run("group="+strconv.FormatBool(group), func(t *testing.T) {
			dir := t.TempDir()
			pidf := filepath.Join(dir, "ipam.pid")
			freed := filepath.Join(dir, "freed")
			// The IPAM stand-in records its pid, waits, then "frees the
			// lease"; the bridge stand-in runs it and waits for it.
			script := "#!/bin/sh\ncat >/dev/null\n" +
				"sh -c 'echo $$ > " + pidf + "; sleep 2; touch " + freed + "' &\nwait\n"
			if err := os.WriteFile(filepath.Join(dir, "bridge"), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			r, err := NewExecRunner(Config{PluginDir: dir, ConfPath: writeConflist(t, dir), ProcessGroup: group})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- r.Del(ctx, "/run/netns/sb-1", "sb-1") }()
			var pid int
			for end := time.Now().Add(5 * time.Second); pid == 0 && time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
				if raw, err := os.ReadFile(pidf); err == nil && strings.HasSuffix(string(raw), "\n") {
					pid, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
				}
			}
			if pid == 0 {
				t.Fatal("the IPAM stand-in never started")
			}
			cancel()
			if err := <-done; err == nil {
				t.Fatal("a cancelled DEL reported success")
			}
			time.Sleep(2500 * time.Millisecond)
			_, statErr := os.Stat(freed)
			if group && statErr == nil {
				t.Fatal("the IPAM plugin of a cancelled DEL went on and freed the lease")
			}
			if !group && statErr != nil {
				t.Fatal("without a process group the IPAM plugin is expected to outlive the call (single mode is unchanged)")
			}
		})
	}
}
