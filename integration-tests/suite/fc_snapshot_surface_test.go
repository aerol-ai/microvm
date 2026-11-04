//go:build integration

package suite

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// registerImageSnapshot records a name → public-image snapshot (no build, no
// pull until first use) and returns the name. Cleanup deletes it best-effort.
func registerImageSnapshot(t *testing.T, c *harness.Client, ctx context.Context, label string) string {
	t.Helper()
	name := fcSnapshotName(t, label)
	if _, err := c.SDK().RegisterSnapshot(ctx, sdktypes.RegisterSnapshotOptions{Name: name, Image: "alpine:3.20"}); err != nil {
		t.Fatalf("register snapshot %q: %v", name, err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = c.SDK().DeleteSnapshot(cctx, name)
	})
	return name
}

// UC-233 — v1 register a snapshot then read it back by name.
func TestV1SnapshotGetByName(t *testing.T) {
	harness.Require(t, sc, "UC-233")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	name := registerImageSnapshot(t, c, ctx, "get")
	got, err := c.SDK().GetSnapshot(ctx, name)
	if err != nil {
		t.Fatalf("GetSnapshot(%q): %v", name, err)
	}
	if got.Name != name {
		t.Fatalf("GetSnapshot name = %q, want %q", got.Name, name)
	}
}

// UC-234 — v1 list snapshots returns the registered snapshot.
func TestV1SnapshotListContains(t *testing.T) {
	harness.Require(t, sc, "UC-234")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	name := registerImageSnapshot(t, c, ctx, "list")
	if !snapshotInList(t, c, ctx, name) {
		t.Fatalf("snapshot %q not found in v1 list", name)
	}
}

// snapshotInList pages the v1 snapshot list looking for name.
func snapshotInList(t *testing.T, c *harness.Client, ctx context.Context, name string) bool {
	t.Helper()
	after := ""
	for {
		page, err := c.SDK().ListSnapshots(ctx, sdktypes.ListSnapshotsOptions{Limit: 100, StartingAfter: after})
		if err != nil {
			t.Fatalf("ListSnapshots: %v", err)
		}
		for _, s := range page.Snapshots {
			if s.Name == name {
				return true
			}
		}
		if !page.HasMore || len(page.Snapshots) == 0 {
			return false
		}
		after = page.Snapshots[len(page.Snapshots)-1].Name
	}
}

// UC-235 — v1 snapshot list paginates by name with limit + starting_after.
func TestV1SnapshotListPaginates(t *testing.T) {
	harness.Require(t, sc, "UC-235")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Register three snapshots so a limit=1 page must report has_more and a
	// cursor must advance.
	for _, l := range []string{"pg1", "pg2", "pg3"} {
		registerImageSnapshot(t, c, ctx, l)
	}
	first, err := c.SDK().ListSnapshots(ctx, sdktypes.ListSnapshotsOptions{Limit: 1})
	if err != nil {
		t.Fatalf("ListSnapshots limit=1: %v", err)
	}
	if len(first.Snapshots) != 1 || !first.HasMore {
		t.Fatalf("limit=1 page = %d snapshots has_more=%v, want 1/true", len(first.Snapshots), first.HasMore)
	}
	second, err := c.SDK().ListSnapshots(ctx, sdktypes.ListSnapshotsOptions{Limit: 1, StartingAfter: first.Snapshots[0].Name})
	if err != nil {
		t.Fatalf("ListSnapshots cursor: %v", err)
	}
	if len(second.Snapshots) != 1 {
		t.Fatalf("cursor page = %d snapshots, want 1", len(second.Snapshots))
	}
	if second.Snapshots[0].Name == first.Snapshots[0].Name {
		t.Fatalf("cursor did not advance: both pages returned %q", first.Snapshots[0].Name)
	}
}

// UC-236 — v1 delete a snapshot then a get by name is 404.
func TestV1SnapshotDelete(t *testing.T) {
	harness.Require(t, sc, "UC-236")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	name := fcSnapshotName(t, "del")
	if _, err := c.SDK().RegisterSnapshot(ctx, sdktypes.RegisterSnapshotOptions{Name: name, Image: "alpine:3.20"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := c.SDK().DeleteSnapshot(ctx, name); err != nil {
		t.Fatalf("DeleteSnapshot(%q): %v", name, err)
	}
	if _, err := c.SDK().GetSnapshot(ctx, name); err == nil {
		t.Fatalf("GetSnapshot after delete returned no error, want not-found")
	}
}

// UC-237 — v1 delete a missing snapshot is a not-found error.
func TestV1SnapshotDeleteMissing(t *testing.T) {
	harness.Require(t, sc, "UC-237")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	err := c.SDK().DeleteSnapshot(ctx, "uc237-does-not-exist-"+harness.UniqueName(sc, t))
	if err == nil {
		t.Fatal("DeleteSnapshot of a missing snapshot returned no error, want not-found")
	}
}

// UC-238 — v1 snapshot a running sandbox then read it in get + list.
func TestV1SnapshotFromRunningSandbox(t *testing.T) {
	harness.Require(t, sc, "UC-238")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	name := fcSnapshotName(t, "running")
	if _, err := c.SDK().CreateSnapshot(ctx, sb.ID, name); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = c.SDK().DeleteSnapshot(cctx, name)
	})
	if got, err := c.SDK().GetSnapshot(ctx, name); err != nil || got.Name != name {
		t.Fatalf("GetSnapshot(%q) = %+v, %v", name, got, err)
	}
	// A committed snapshot's row lives only on its home node and the v1 list is
	// not cluster-aggregated yet, so read the list on the owner. GetSnapshot
	// above already proved the snapshot is registered and routable cluster-wide
	// (the home-node index), which is what this UC is really asserting.
	ownerURL := ownerAPI(t, c, sb.ID)
	if st, body := getWithRetry(t, ctx, ownerURL, "/v1/snapshots?limit=500", http.StatusOK); st != http.StatusOK || !strings.Contains(string(body), name) {
		t.Fatalf("committed snapshot %q not in v1 list on owner = %d; body=%s", name, st, string(body))
	}
}

// UC-260 — a v1-registered snapshot creates a working sandbox (catalogue
// round-trip ending in a real exec).
func TestV1SnapshotCreateRoundTrip(t *testing.T) {
	harness.Require(t, sc, "UC-260")
	c := client(t)
	src := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, src)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	snapName := fcSnapshotName(t, "roundtrip")
	if _, err := c.SDK().CreateSnapshot(ctx, src.ID, snapName); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = c.SDK().DeleteSnapshot(cctx, snapName)
	})

	// Create from the snapshot by its NAME, not the committed image ref
	// (aerolvm-snapshot/<hash>) the commit returns. That reserved tag resolves
	// only on the home node; off it there is no reverse map from hash to the
	// pushed registry copy, so a non-home ingress leaves it as docker.io/... and
	// the pull fails. The name resolves deterministically to the owner-namespaced
	// AOCR ref on any node, which is the cluster-portable way to create from a
	// snapshot. Retry rides out the post-commit AOCR push window.
	var derived *microvm.Sandbox
	var err error
	deadline := time.Now().Add(4 * time.Minute)
	for {
		derived, err = c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{Image: snapName, Name: harness.UniqueName(sc, t)})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("create from snapshot never succeeded: %v", err)
		}
		time.Sleep(5 * time.Second)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = c.SDK().Destroy(cctx, derived.ID)
	})
	waitRunning(t, derived)

	res, err := derived.ExecCommand(ctx, "echo uc260-ok")
	if err != nil {
		t.Fatalf("exec on snapshot-derived sandbox: %v", err)
	}
	if !strings.Contains(res.Stdout, "uc260-ok") {
		t.Fatalf("exec stdout = %q, want uc260-ok", res.Stdout)
	}
}
