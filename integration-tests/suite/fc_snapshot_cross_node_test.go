//go:build integration

package suite

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/models"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-368 — a snapshot of a stopped Firecracker sandbox, taken on one node,
// boots on a different node. The disk travels as an image through the
// cluster registry; nothing else carries it, because the second node never
// held the source sandbox. Runs once in each direction across the first two
// Firecracker nodes, so a cluster whose nodes use different container engines
// (Docker on one, containerd on the other) covers both engines' export and
// import.
//
// Needs two Firecracker nodes: cluster-bank-flagship, cluster-arm64 and
// cluster-hetero-benchmark-with-obs have them. Elsewhere it skips.
func TestFirecrackerSnapshotOnAnotherNode(t *testing.T) {
	harness.Require(t, sc, "UC-368")
	c := client(t)
	nodes := firecrackerNodes(t, c)
	if len(nodes) < 2 {
		t.Skipf("needs two Firecracker nodes; this cluster has %d", len(nodes))
	}
	for _, from := range nodes[:2] {
		from := from
		t.Run("from-"+from, func(t *testing.T) {
			fcSnapshotToAnotherNode(t, c, from)
		})
	}
}

func fcSnapshotToAnotherNode(t *testing.T, c *harness.Client, from string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	src, _, _ := createPlacedOn(t, ctx, c, sdktypes.CreateSandboxOptions{
		Runtime: models.RuntimeFirecracker,
		Image:   harness.DefaultImage,
	}, func(owner string) bool { return owner == from })

	// Random data, a hard link, a symlink and a nested file: the export has to
	// carry all of them, not just regular files.
	wantData := guestOut(t, ctx, src, "dd if=/dev/urandom of=/root/data bs=1M count=16 2>/dev/null"+
		" && ln /root/data /root/data.hard && ln -s data /root/data.link"+
		" && mkdir -p /root/deep/a/b && echo nested > /root/deep/a/b/f"+
		" && sync && sha256sum /root/data | cut -c1-64")
	srcToken := guestOut(t, ctx, src, "sha256sum /etc/toolboxd.env | cut -c1-64")
	if len(wantData) != 64 || len(srcToken) != 64 {
		t.Fatalf("source setup: data sha %q, token sha %q", wantData, srcToken)
	}

	name := fcSnapshotName(t, "fcxnode")
	// A running guest may still hold writes in its page cache, so the API
	// refuses rather than export a disk that is not settled.
	if st, body := fcDo(t, ctx, http.MethodPost, "", "/v1/sandboxes/"+src.ID+"/snapshot",
		map[string]string{"name": name}, nil); st != http.StatusConflict {
		t.Fatalf("snapshot of a running Firecracker sandbox = %d, want 409; body=%s", st, string(body))
	}
	if err := src.Stop(ctx); err != nil {
		t.Fatalf("stop source: %v", err)
	}
	t0 := time.Now()
	snap, err := c.SDK().CreateSnapshot(ctx, src.ID, name)
	if err != nil {
		t.Fatalf("snapshot of the stopped source on %s: %v", from, err)
	}
	t.Logf("snapshot %s on %s in %s (image %s)", name, from, time.Since(t0).Round(time.Millisecond), snap.Image)
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().DeleteSnapshot(cctx, name)
	})

	// Placement treats a snapshot as pinned to its home node until the push
	// is active, so wait for that before asking for another node.
	t0 = time.Now()
	for {
		got, err := c.SDK().GetSnapshot(ctx, name)
		if err == nil && got.PushState == models.SnapshotPushStateActive && got.ImageRegistryRef != "" {
			t.Logf("pushed to %s in %s", got.ImageRegistryRef, time.Since(t0).Round(time.Second))
			break
		}
		if err == nil && got.PushState == models.SnapshotPushStateError {
			t.Logf("push error (the reconciler retries): %s", got.PushError)
		}
		if time.Since(t0) > 8*time.Minute {
			t.Fatalf("snapshot never pushed: %+v, %v", got, err)
		}
		time.Sleep(5 * time.Second)
	}

	// The snapshot has to outlive its source. Destroying the source also
	// leaves both nodes nearly empty, so placement has no load reason to keep
	// the next creates on the snapshot's home node.
	destroyNow(t, ctx, c, src.ID)

	elsewhere := func(owner string) bool { return owner != "" && owner != from }
	vm, vmOwner, took := createPlacedOn(t, ctx, c, sdktypes.CreateSandboxOptions{
		Runtime: models.RuntimeFirecracker,
		Image:   name,
	}, elsewhere)
	t.Logf("Firecracker sandbox from the snapshot on %s, started in %s (image %s)",
		vmOwner, took.Round(time.Millisecond), vm.Image)
	got := strings.Fields(guestOut(t, ctx, vm, "sha256sum /root/data | cut -c1-64; stat -c %h /root/data;"+
		" readlink /root/data.link; cat /root/deep/a/b/f; sha256sum /etc/toolboxd.env | cut -c1-64"))
	if len(got) != 5 || got[0] != wantData || got[1] != "2" || got[2] != "data" || got[3] != "nested" {
		t.Fatalf("Firecracker sandbox on %s: got %q, want data %s, 2 links, link to data, nested", vmOwner, got, wantData)
	}
	// The snapshot leaves the source's agent token out; the new VM gets its own.
	if got[4] == srcToken {
		t.Fatalf("the new VM on %s carries the source's toolbox token file", vmOwner)
	}

	// The VM would make its node look fuller than the snapshot's home node.
	destroyNow(t, ctx, c, vm.ID)
	ct, ctOwner, took := createPlacedOn(t, ctx, c, sdktypes.CreateSandboxOptions{Image: name}, elsewhere)
	t.Logf("container from the snapshot on %s, started in %s", ctOwner, took.Round(time.Millisecond))
	got = strings.Fields(guestOut(t, ctx, ct, "sha256sum /root/data | cut -c1-64;"+
		" test -e /etc/toolboxd.env && echo token-file || echo no-token-file"))
	if len(got) != 2 || got[0] != wantData || got[1] != "no-token-file" {
		t.Fatalf("container from the snapshot on %s = %q, want data %s and no token file", ctOwner, got, wantData)
	}

	if err := c.SDK().DeleteSnapshot(ctx, name); err != nil {
		t.Fatalf("delete snapshot: %v", err)
	}
	if _, err := c.SDK().GetSnapshot(ctx, name); err == nil {
		t.Fatal("snapshot still readable after delete")
	}
}

// firecrackerNodes lists the live, undrained members that advertise the
// Firecracker runtime, sorted so both directions run in a stable order.
func firecrackerNodes(t *testing.T, c *harness.Client) []string {
	t.Helper()
	members := fetchMembers(t, c)
	var out []string
	for _, m := range members.Members {
		if m.Alive && !m.Drained && nodeAdvertisesRuntime(members, m.NodeID, models.RuntimeFirecracker) {
			out = append(out, m.NodeID)
		}
	}
	sort.Strings(out)
	return out
}

// createPlacedOn creates sandboxes until one is placed on a node accept takes,
// and returns it with its owner and how long that create took to start. The
// API has no way to name a node, so a sandbox that lands elsewhere is kept
// running while the next is created: the load it adds pushes placement to
// another node. Those are destroyed once one lands where wanted; the one
// returned is destroyed when the test ends. A failed create is retried, since
// a snapshot can briefly be unknown to a node right after its push.
func createPlacedOn(t *testing.T, ctx context.Context, c *harness.Client, opts sdktypes.CreateSandboxOptions, accept func(owner string) bool) (*microvm.Sandbox, string, time.Duration) {
	t.Helper()
	const maxPlaced = 5
	what := opts.Runtime
	if what == "" {
		what = "container"
	}
	var misplaced []string
	defer func() {
		for _, id := range misplaced {
			destroyNow(t, ctx, c, id)
		}
	}()
	deadline := time.Now().Add(6 * time.Minute)
	for placed := 0; placed < maxPlaced; {
		o := opts
		o.Name = harness.UniqueName(sc, t)
		t0 := time.Now()
		sb, err := c.SDK().Create(ctx, o)
		if err != nil {
			if time.Now().After(deadline) {
				t.Fatalf("create %s from %q: %v", what, o.Image, err)
			}
			t.Logf("create %s from %q failed, retrying: %v", what, o.Image, err)
			time.Sleep(5 * time.Second)
			continue
		}
		placed++
		t.Cleanup(func() {
			cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
			defer ccancel()
			_ = c.SDK().Destroy(cctx, sb.ID)
		})
		waitRunning(t, sb)
		took := time.Since(t0)
		owner := resolvePlacementOwner(t, c, sb.ID)
		if accept(owner) {
			return sb, owner, took
		}
		misplaced = append(misplaced, sb.ID)
		t.Logf("%s %s landed on %s; keeping it while the next is created", what, sb.ID, owner)
	}
	t.Fatalf("no create of a %s from %q was placed where wanted in %d tries", what, opts.Image, maxPlaced)
	return nil, "", 0
}

// destroyNow destroys a sandbox now rather than at the end of the test.
func destroyNow(t *testing.T, ctx context.Context, c *harness.Client, id string) {
	t.Helper()
	if err := c.SDK().Destroy(ctx, id); err != nil {
		t.Logf("destroy %s: %v", id, err)
	}
}

// guestOut runs a command and returns its trimmed stdout, failing on a
// non-zero exit.
func guestOut(t *testing.T, ctx context.Context, sb *microvm.Sandbox, cmd string) string {
	t.Helper()
	res, err := sb.ExecCommand(ctx, cmd)
	if err != nil {
		t.Fatalf("exec on %s: %v", sb.ID, err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exec on %s exited %d: %s%s", sb.ID, res.ExitCode, res.Stdout, res.Stderr)
	}
	return strings.TrimSpace(res.Stdout)
}
