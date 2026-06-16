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

// waitTemplateReady polls until a Firecracker template reaches ready+snapshot.
func waitTemplateReady(t *testing.T, c *harness.Client, id string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Minute)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		tmpl, err := c.SDK().GetTemplate(ctx, id)
		cancel()
		if err != nil {
			t.Fatalf("get template %s: %v", id, err)
		}
		switch tmpl.Status {
		case sdktypes.TemplateStatusReady:
			if tmpl.HasSnapshot {
				return
			}
			t.Fatalf("template %s ready but HasSnapshot=false", id)
		case sdktypes.TemplateStatusFailed:
			t.Fatalf("template %s failed: %s", id, tmpl.SnapshotError)
		}
		if time.Now().After(deadline) {
			t.Fatalf("template %s not ready after timeout (status=%s)", id, tmpl.Status)
		}
		time.Sleep(5 * time.Second)
	}
}

func readGuestURandomHex(t *testing.T, sb *microvm.Sandbox) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := sb.ExecCommand(ctx, `head -c 32 /dev/urandom | base64 | tr -d '\n'`)
	if err != nil {
		t.Fatalf("read /dev/urandom in %s: %v", sb.ID, err)
	}
	out := strings.TrimSpace(res.Stdout)
	if len(out) < 32 {
		t.Fatalf("short urandom read in %s: %q", sb.ID, out)
	}
	return out
}

// UC-80 — Two Firecracker sandboxes cloned from the same template must not
// share kernel CRNG output (vmgenid/FDT on arm64, ACPI on amd64). Proves the
// snapshot-clone entropy invariant on whichever arch the scenario runs.
func TestUC80_FirecrackerTemplateClonesDistinctEntropy(t *testing.T) {
	harness.Require(t, sc, "UC-80")
	c := client(t)

	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Minute)
	defer cancel()

	tmpl, err := c.SDK().CreateTemplate(ctx, sdktypes.CreateTemplateOptions{
		Image: "docker://alpine:3.20",
	})
	if err != nil {
		t.Fatalf("create template: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().DeleteTemplate(cctx, tmpl.ID)
	})
	waitTemplateReady(t, c, tmpl.ID)

	sb1 := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:       harness.UniqueName(sc, t) + "-a",
		Runtime:    "firecracker",
		TemplateID: tmpl.ID,
	})
	sb2 := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:       harness.UniqueName(sc, t) + "-b",
		Runtime:    "firecracker",
		TemplateID: tmpl.ID,
	})
	waitRunning(t, sb1)
	waitRunning(t, sb2)

	r1 := readGuestURandomHex(t, sb1)
	r2 := readGuestURandomHex(t, sb2)
	if r1 == r2 {
		t.Fatalf("two template clones returned identical /dev/urandom bytes (%s); CRNG reseed did not fire", r1)
	}

	gen1, err := sb1.CloneGeneration(ctx)
	if err != nil {
		t.Fatalf("clone generation sb1: %v", err)
	}
	gen2, err := sb2.CloneGeneration(ctx)
	if err != nil {
		t.Fatalf("clone generation sb2: %v", err)
	}
	if gen1.ResumedAt == 0 || gen2.ResumedAt == 0 {
		t.Fatalf("template clones should report ResumedAt>0 (got %d, %d)", gen1.ResumedAt, gen2.ResumedAt)
	}
}
