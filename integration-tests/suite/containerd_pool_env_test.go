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

// containerdWarmHit reports whether the last create's Server-Timing shows a
// containerd warm-pool adopt: the pool stage, and no cold container create.
func containerdWarmHit(c *harness.Client) (hit, timingSeen bool, stages map[string]float64) {
	stages, ok := c.LastServerCreateStages()
	_, pool := stages["containerd_pool"]
	_, cold := stages["containerd_create"]
	return ok && pool && !cold, ok, stages
}

// UC-483 — the containerd warm pool takes a create that carries env (plan
// cluster-phase-2 L3). The env rides the adopt frame into toolboxd's store,
// so the create is a warm hit and the sandbox's processes read it; a stop and
// start sends it again from the sealed row; and a key toolboxd reads for
// itself at boot (SB_*) keeps a create cold, because a warm container would
// ignore it.
func TestContainerdPoolCreateWithEnvIsWarmHit(t *testing.T) {
	harness.Require(t, sc, "UC-483")
	c := client(t)
	secret := secretValue(t, "483")

	// The pool pins harness.DefaultImage when no images are configured. A few
	// tries ride out the first park after boot and a slot being refilled.
	var sb *microvm.Sandbox
	for attempt := 1; attempt <= 8; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		got, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
			Name: harness.UniqueName(sc, t), Image: harness.DefaultImage,
			Env: map[string]string{"UC483_TOKEN": secret},
		})
		cancel()
		if err != nil {
			t.Fatalf("create with env: %v", err)
		}
		if hit, seen, stages := containerdWarmHit(c); hit {
			t.Logf("UC-483: create %d (%s) was a warm hit with env (stages %v)", attempt, got.ID, stages)
			sb = got
			break
		} else {
			t.Logf("UC-483: create %d was not a warm hit (stages %v, timing seen %v)", attempt, stages, seen)
		}
		destroyBest(c, got.ID)
		time.Sleep(15 * time.Second)
	}
	if sb == nil {
		t.Fatal("no create with env was served by the containerd warm pool")
	}
	t.Cleanup(func() { destroyBest(c, sb.ID) })

	if got := execEnvValue(t, c, sb.ID, "UC483_TOKEN", 3*time.Minute); got != secret {
		t.Fatalf("the warm sandbox reads UC483_TOKEN as %q", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := sb.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if got := execEnvValue(t, c, sb.ID, "UC483_TOKEN", 3*time.Minute); got != secret {
		t.Fatalf("after a stop and start the sandbox reads UC483_TOKEN as %q", got)
	}

	reserved := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Image: harness.DefaultImage, Env: map[string]string{"SB_UC483": "x"},
	})
	if hit, seen, stages := containerdWarmHit(c); seen && hit {
		t.Fatalf("a create that sets an SB_ key took a warm container (%s, stages %v)", reserved.ID, stages)
	}
}
