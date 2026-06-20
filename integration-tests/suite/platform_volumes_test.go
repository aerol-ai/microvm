//go:build integration

package suite

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// volumeName returns a deployment-unique volume name. The native SDK has no
// volume-delete (that lives on the Daytona facade), so volumes created here
// persist after the run; a unique name keeps each run's data isolated and
// leaves cleanup to the operator's storage lifecycle policy.
func volumeName(t *testing.T) string {
	t.Helper()
	return strings.ToLower(fmt.Sprintf("it-%d", time.Now().UnixNano()))
}

// execOK runs a command and fails the test if it errors or exits non-zero.
func execOK(t *testing.T, sb *microvm.Sandbox, command string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := sb.ExecCommand(ctx, command)
	if err != nil {
		t.Fatalf("exec %q: %v", command, err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exec %q exited %d (stderr=%q)", command, res.ExitCode, res.Stderr)
	}
	return res.Stdout
}

// readBackWithRetry polls `cat path` until it contains want or the deadline
// passes. The default S3 backend is eventually consistent, so a fresh write may
// not be immediately visible to a second reader.
func readBackWithRetry(t *testing.T, sb *microvm.Sandbox, path, want string) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		res, err := sb.ExecCommand(ctx, "cat "+path)
		cancel()
		if err == nil && strings.Contains(res.Stdout, want) {
			return
		}
		if err == nil {
			last = res.Stdout
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("never read %q from %s (last=%q)", want, path, last)
}

// UC-81 — attach a named platform volume, write a file into it, and read it
// back inside the same sandbox.
func TestPlatformVolumeWriteReadBack(t *testing.T) {
	harness.Require(t, sc, "UC-81")
	c := client(t)
	vol := volumeName(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:            harness.UniqueName(sc, t),
		PlatformVolumes: []sdktypes.PlatformVolumeMount{{Name: vol, Path: "/vol"}},
	})
	waitRunning(t, sb)

	execOK(t, sb, "echo hello-volume > /vol/marker.txt")
	out := execOK(t, sb, "cat /vol/marker.txt")
	if !strings.Contains(out, "hello-volume") {
		t.Fatalf("read-back = %q, want hello-volume", out)
	}
}

// UC-82 — a volume persists across the sandbox lifecycle: write in one sandbox,
// destroy it, then re-attach the same volume name from a fresh sandbox and see
// the data. In a cluster scenario the second sandbox may be placed on a
// different node, which is exactly the cross-node-reattach guarantee that makes
// shared storage (not a host dir) the source of truth.
func TestPlatformVolumePersistsAcrossDestroy(t *testing.T) {
	harness.Require(t, sc, "UC-82")
	c := client(t)
	vol := volumeName(t)

	first := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:            harness.UniqueName(sc, t),
		PlatformVolumes: []sdktypes.PlatformVolumeMount{{Name: vol, Path: "/vol"}},
	})
	waitRunning(t, first)
	execOK(t, first, "echo persisted-payload > /vol/persist.txt")

	// Explicitly destroy the writer before re-attaching, proving the data
	// outlives the sandbox (the auto-cleanup destroy is then a no-op 404).
	dctx, dcancel := context.WithTimeout(context.Background(), time.Minute)
	if err := c.SDK().Destroy(dctx, first.ID); err != nil {
		t.Fatalf("destroy first sandbox: %v", err)
	}
	dcancel()

	second := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:            harness.UniqueName(sc, t),
		PlatformVolumes: []sdktypes.PlatformVolumeMount{{Name: vol, Path: "/vol"}},
	})
	waitRunning(t, second)
	readBackWithRetry(t, second, "/vol/persist.txt", "persisted-payload")
}

// UC-83 — two concurrently-running sandboxes mount the same volume; data
// written by one is readable by the other.
func TestPlatformVolumeSharedByTwoSandboxes(t *testing.T) {
	harness.Require(t, sc, "UC-83")
	c := client(t)
	vol := volumeName(t)

	writer := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:            harness.UniqueName(sc, t),
		PlatformVolumes: []sdktypes.PlatformVolumeMount{{Name: vol, Path: "/shared"}},
	})
	reader := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:            harness.UniqueName(sc, t),
		PlatformVolumes: []sdktypes.PlatformVolumeMount{{Name: vol, Path: "/shared"}},
	})
	waitRunning(t, writer)
	waitRunning(t, reader)

	execOK(t, writer, "echo shared-bytes > /shared/from-writer.txt")
	readBackWithRetry(t, reader, "/shared/from-writer.txt", "shared-bytes")
}

// UC-84 — a read-only volume mount rejects writes from inside the sandbox.
func TestPlatformVolumeReadOnlyRejectsWrites(t *testing.T) {
	harness.Require(t, sc, "UC-84")
	c := client(t)
	vol := volumeName(t)

	// Seed the volume read-write first so the read-only mount has something to
	// read (and to prove the mount itself is functional, not just absent).
	seed := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:            harness.UniqueName(sc, t),
		PlatformVolumes: []sdktypes.PlatformVolumeMount{{Name: vol, Path: "/vol"}},
	})
	waitRunning(t, seed)
	execOK(t, seed, "echo seeded > /vol/seed.txt")

	ro := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:            harness.UniqueName(sc, t),
		PlatformVolumes: []sdktypes.PlatformVolumeMount{{Name: vol, Path: "/vol", ReadOnly: true}},
	})
	waitRunning(t, ro)
	readBackWithRetry(t, ro, "/vol/seed.txt", "seeded")

	// A write to the read-only mount must fail (non-zero exit).
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := ro.ExecCommand(ctx, "echo nope > /vol/should-fail.txt")
	if err == nil && res.ExitCode == 0 {
		t.Fatalf("write to read-only volume succeeded (exit=0, stdout=%q)", res.Stdout)
	}
}
