package mounts

import (
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

func TestCapturedOutputTailTruncation(t *testing.T) {
	out := &capturedOutput{}
	payload := strings.Repeat("x", maxCapturedMountBytes+512)
	if n, err := out.Write([]byte(payload)); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	out.mu.Lock()
	bufLen := len(out.buf)
	out.mu.Unlock()
	if bufLen != maxCapturedMountBytes {
		t.Fatalf("buffer len = %d, want %d", bufLen, maxCapturedMountBytes)
	}
}

func TestSpawnMountProcessWithEnv(t *testing.T) {
	cmd, out, err := spawnMountProcess(adapters.Plan{
		Argv: []string{"true"},
		Env:  []string{"MOUNT_SPAWN_ENV=1"},
	})
	if err != nil {
		t.Fatalf("spawnMountProcess: %v", err)
	}
	t.Cleanup(func() { _ = killMount(cmd) })
	if out == nil {
		t.Fatal("expected captured output")
	}
}
