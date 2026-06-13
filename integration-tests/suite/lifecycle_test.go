//go:build integration

package suite

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// waitRunning polls until the sandbox reaches "started" or the deadline passes.
// Creation is async on some runtimes, so a fresh sandbox may report "creating"
// briefly.
func waitRunning(t *testing.T, sb *microvm.Sandbox) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		if string(sb.Status) == "started" {
			return
		}
		if string(sb.Status) == "error" {
			t.Fatalf("sandbox %s entered error state: %s", sb.ID, sb.LastError)
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandbox %s never reached started (last status %q)", sb.ID, sb.Status)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := sb.Refresh(ctx)
		cancel()
		if err != nil {
			t.Fatalf("refresh %s: %v", sb.ID, err)
		}
		time.Sleep(2 * time.Second)
	}
}

// UC-11 — create a docker sandbox and confirm it reaches running.
func TestCreateDockerSandbox(t *testing.T) {
	harness.Require(t, sc, "UC-11")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Image: harness.DefaultImage,
		Name:  harness.UniqueName(sc, t),
	})
	if sb.ID == "" {
		t.Fatal("created sandbox has empty ID")
	}
	waitRunning(t, sb)
}

// UC-16 — delete a sandbox; a subsequent Get must return not-found.
func TestDeleteSandbox(t *testing.T) {
	harness.Require(t, sc, "UC-16")
	c := client(t)

	// Create directly (not via NewSandbox) because this test owns the delete;
	// a t.Cleanup destroy of an already-deleted sandbox would just log noise.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Image: harness.DefaultImage,
		Name:  harness.UniqueName(sc, t),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	waitRunning(t, sb)

	if err := c.SDK().Destroy(ctx, sb.ID); err != nil {
		t.Fatalf("destroy %s: %v", sb.ID, err)
	}

	if _, err := c.SDK().Get(ctx, sb.ID); err == nil {
		t.Fatalf("Get after destroy returned no error; expected not-found")
	}
	// Any error on Get of a destroyed sandbox satisfies the contract. A stricter
	// typed not-found assertion is a follow-up once the SDK surfaces one.
}
