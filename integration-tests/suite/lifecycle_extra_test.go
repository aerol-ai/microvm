//go:build integration

package suite

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-72 — The clone-generation token is readable and stable for a sandbox that
// has never been resumed from a snapshot. A fresh sandbox has ResumedAt==0, and
// two consecutive reads return the same token (it only changes on resume).
func TestCloneGenerationToken(t *testing.T) {
	harness.Require(t, sc, "UC-72")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	first, err := sb.CloneGeneration(ctx)
	if err != nil {
		t.Fatalf("clone generation: %v", err)
	}
	second, err := sb.CloneGeneration(ctx)
	if err != nil {
		t.Fatalf("clone generation (2nd read): %v", err)
	}
	if first.Generation != second.Generation {
		t.Fatalf("token changed without a resume: %q -> %q", first.Generation, second.Generation)
	}
}

// UC-73 — List filters by tag (AND semantics). A sandbox tagged uc73=yes is
// returned when filtering on that pair and absent when filtering on a pair it
// doesn't carry.
func TestListFilteredByTags(t *testing.T) {
	harness.Require(t, sc, "UC-73")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		Tags: map[string]string{"uc73": "yes"},
	})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	matching, err := c.SDK().List(ctx, microvm.WithTags(map[string]string{"uc73": "yes"}))
	if err != nil {
		t.Fatalf("list with matching tag: %v", err)
	}
	if !containsSandbox(matching, sb.ID) {
		t.Fatalf("tag-filtered list (%d) did not include %s", len(matching), sb.ID)
	}

	other, err := c.SDK().List(ctx, microvm.WithTags(map[string]string{"uc73": "no"}))
	if err != nil {
		t.Fatalf("list with non-matching tag: %v", err)
	}
	if containsSandbox(other, sb.ID) {
		t.Fatalf("list filtered on uc73=no still returned %s", sb.ID)
	}
}

func containsSandbox(list []*microvm.Sandbox, id string) bool {
	for _, s := range list {
		if s.ID == id {
			return true
		}
	}
	return false
}

// UC-74 — CreateWithImage compiles an Image-builder graph to a content-addressed
// tag and creates the sandbox from it in one call. The built artifact is present
// in the running sandbox.
func TestCreateWithImage(t *testing.T) {
	harness.Require(t, sc, "UC-74")
	c := client(t)
	img := microvm.BaseImage("alpine:3.20").
		RunCommands("echo created-with-image-74 > /uc74.txt")
	if err := img.Err(); err != nil {
		t.Fatalf("build image spec: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	sb, err := c.SDK().CreateWithImage(ctx, img, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
	})
	if err != nil {
		t.Fatalf("create with image: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().Destroy(cctx, sb.ID)
	})
	waitRunning(t, sb)

	res, err := sb.ExecCommand(ctx, "cat /uc74.txt")
	if err != nil {
		t.Fatalf("exec cat: %v", err)
	}
	if !strings.Contains(res.Stdout, "created-with-image-74") {
		t.Fatalf("built artifact missing: stdout = %q", res.Stdout)
	}
}

// UC-75 — RegisterSnapshot persists a named snapshot from a pre-built image; a
// sandbox can then be created from the snapshot's resolved image reference.
func TestRegisterSnapshotAndCreate(t *testing.T) {
	harness.Require(t, sc, "UC-75")
	c := client(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	snap, err := c.SDK().RegisterSnapshot(ctx, sdktypes.RegisterSnapshotOptions{
		Name:  harness.UniqueName(sc, t) + "-reg",
		Image: "alpine:3.20",
	})
	if err != nil {
		t.Fatalf("register snapshot: %v", err)
	}
	if snap.Image == "" {
		t.Fatal("registered snapshot has empty image reference")
	}

	// Create from the resolved image. In cluster mode a derived create can land
	// on a node before the snapshot image has propagated, so retry the transient
	// pull-404 window rather than hard-failing (mirrors UC-21).
	var derived *microvm.Sandbox
	deadline := time.Now().Add(3 * time.Minute)
	for {
		derived, err = c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
			Image: snap.Image,
			Name:  harness.UniqueName(sc, t),
		})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("create from registered snapshot never succeeded: %v", err)
		}
		time.Sleep(5 * time.Second)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().Destroy(cctx, derived.ID)
	})
	waitRunning(t, derived)
}
