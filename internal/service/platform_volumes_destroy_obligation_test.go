package service

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// review923FailAttachments is the reviewer's volume store: listing a
// sandbox's attachments fails.
type review923FailAttachments struct{ volumeMetaStore }

func (m review923FailAttachments) AttachmentsForSandbox(context.Context, string) ([]models.VolumeAttachment, error) {
	return nil, errors.New("transient metadata read failure")
}

// Review 2 finding 7 (#948): a transient lookup failure during a destroy
// must not lose the last cleanup obligation of a delete_with_sandbox volume.
func TestReview923DestroyMustRetainVolumeCleanupObligation(t *testing.T) {
	svc, st, fr := lifetimeHarness(t)
	ctx := context.Background()
	vol := attachVolume(t, svc, st, "sb-review", "review-scratch", true)
	svc.testVolumeMeta = review923FailAttachments{svc.volumeMeta()}
	err := svc.DestroySandbox(ctx, "sb-review")
	svc.testVolumeMeta = nil
	if err != nil {
		return
	} // Failing closed preserves the retry anchor.
	svc.runVolumeReclaim(ctx)
	pending, err := st.ListPendingVolumeDeletions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if volumeExists(t, svc, vol) && len(pending) == 0 && len(reclaimedSources(fr)) == 0 {
		t.Fatal("sandbox deleted, attachments gone, volume remains with no cleanup obligation")
	}
}

// failVolumeLookup fails ByID for the destroy's lookup only.
type failVolumeLookup struct{ volumeMetaStore }

func (m failVolumeLookup) ByID(context.Context, string, string) (*models.Volume, error) {
	return nil, errors.New("metadata store busy")
}

// Whichever destroy lookup fails, the volume, its row and its bytes, still
// goes: the sandbox row delete wrote the obligation, and one sweep pass
// finishes it.
func TestDestroyLookupFailureStillDeletesDeleteWithSandboxVolume(t *testing.T) {
	for _, tc := range []struct {
		name string
		meta func(volumeMetaStore) volumeMetaStore
	}{
		{"attachment list fails", func(m volumeMetaStore) volumeMetaStore { return review923FailAttachments{m} }},
		{"volume lookup fails", func(m volumeMetaStore) volumeMetaStore { return failVolumeLookup{m} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, st, fr := lifetimeHarness(t)
			ctx := context.Background()
			vol := attachVolume(t, svc, st, "sb-flaky", "flaky", true)
			svc.testVolumeMeta = tc.meta(svc.volumeMeta())
			if err := svc.DestroySandbox(ctx, "sb-flaky"); err != nil {
				t.Fatalf("destroy: %v", err)
			}
			svc.testVolumeMeta = nil
			pending, err := st.ListPendingVolumeDeletions(ctx)
			if err != nil || len(pending) != 1 || pending[0].VolumeID != vol.ID || pending[0].Source != vol.Source {
				t.Fatalf("obligation after destroy = %+v, %v", pending, err)
			}
			svc.runVolumeReclaim(ctx)
			if volumeExists(t, svc, vol) {
				t.Fatal("the sweep must delete the volume row")
			}
			if got := reclaimedSources(fr); len(got) != 1 || got[0] != vol.Source {
				t.Fatalf("reclaimed = %v, want the volume's bytes once", got)
			}
			if pending, _ := st.ListPendingVolumeDeletions(ctx); len(pending) != 0 {
				t.Fatalf("ledger after the sweep = %+v", pending)
			}
		})
	}
}

// reclaimLedgerCluster is a single-process cluster with the replicated
// reclaim ledger of cluster/fsm_volume_reclaims.go, in memory. Entries held
// by a node named "dead-*" are offered for adoption, as a server offers the
// entries of a node gossip reports gone.
type reclaimLedgerCluster struct {
	*cluster.Noop
	mu       sync.Mutex
	entries  map[string]cluster.VolumeReclaim // by volume id
	listErr  error
	claimErr error
	ackErr   error
	claims   []string
	acks     []string
	// olderServer reports a server that predates the replicated ledger.
	olderServer bool
	deletes     int
}

func newReclaimLedgerCluster() *reclaimLedgerCluster {
	return &reclaimLedgerCluster{Noop: cluster.NewNoop("self", "http://self", ""), entries: map[string]cluster.VolumeReclaim{}}
}

func (c *reclaimLedgerCluster) put(r cluster.VolumeReclaim) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[r.VolumeID] = r
}

func (c *reclaimLedgerCluster) has(volumeID string) (cluster.VolumeReclaim, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.entries[volumeID]
	return r, ok
}

func (c *reclaimLedgerCluster) VolumeReclaimsReplicated() bool { return !c.olderServer }

// VolumeDeleteOwingBytes is opDeleteVolume with the record: the row goes and
// the entry appears in one step, held by this node.
func (c *reclaimLedgerCluster) VolumeDeleteOwingBytes(ctx context.Context, tenant, id, source string) error {
	row, err := c.Noop.VolumeByID(ctx, tenant, id)
	if err != nil {
		return err
	}
	if err := c.Noop.VolumeDelete(ctx, tenant, id); err != nil {
		return err
	}
	if row.Source != "" {
		source = row.Source
	}
	c.mu.Lock()
	c.deletes++
	c.mu.Unlock()
	c.put(cluster.VolumeReclaim{Tenant: tenant, VolumeID: id, Name: row.Name, Backend: row.Backend, Source: source,
		NodeID: c.SelfNodeID(), RecordedUnixNano: time.Now().UnixNano()})
	return nil
}

func (c *reclaimLedgerCluster) VolumeReclaimsFor(_ context.Context, nodeID string, limit int) ([]cluster.VolumeReclaim, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.listErr != nil {
		return nil, c.listErr
	}
	var out []cluster.VolumeReclaim
	for _, r := range c.entries {
		if r.NodeID == nodeID || strings.HasPrefix(r.NodeID, "dead-") {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VolumeID < out[j].VolumeID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (c *reclaimLedgerCluster) ClaimVolumeReclaim(_ context.Context, r cluster.VolumeReclaim, nodeID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.claimErr != nil {
		return c.claimErr
	}
	cur, ok := c.entries[r.VolumeID]
	if !ok || cur.NodeID != r.NodeID || cur.RecordedUnixNano != r.RecordedUnixNano {
		return cluster.ErrVolumeReclaimMoved
	}
	cur.NodeID = nodeID
	c.entries[r.VolumeID] = cur
	c.claims = append(c.claims, r.VolumeID)
	return nil
}

func (c *reclaimLedgerCluster) AckVolumeReclaim(_ context.Context, r cluster.VolumeReclaim) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ackErr != nil {
		return c.ackErr
	}
	if cur, ok := c.entries[r.VolumeID]; ok && cur.RecordedUnixNano == r.RecordedUnixNano {
		delete(c.entries, r.VolumeID)
	}
	c.acks = append(c.acks, r.VolumeID)
	return nil
}

// clusterReclaimHarness is a worker in cluster mode whose volume metadata
// lives in the (in-memory) replicated store, with one delete_with_sandbox
// volume whose last sandbox is already gone.
func clusterReclaimHarness(t *testing.T) (*Service, *store.Store, *fakeReclaimer, *reclaimLedgerCluster, models.Volume) {
	t.Helper()
	svc, st, fr := lifetimeHarness(t)
	svc.cfg.EnableCluster = true
	c := newReclaimLedgerCluster()
	svc.AttachCluster(c)
	ctx := context.Background()
	tenant, err := svc.volumeTenant(ctx)
	if err != nil {
		t.Fatal(err)
	}
	row, err := firstUseVolumeRow(svc.cfg.PlatformVolumes, tenant, "orphaned")
	if err != nil {
		t.Fatal(err)
	}
	row.ID, row.DeleteWithSandbox = "vol-orphaned", true
	vol, _, err := svc.volumeMeta().GetOrCreate(ctx, row, 0)
	if err != nil {
		t.Fatal(err)
	}
	return svc, st, fr, c, *vol
}

func reclaimFor(v models.Volume, node string, at time.Time) cluster.VolumeReclaim {
	return cluster.VolumeReclaim{Tenant: v.Tenant, VolumeID: v.ID, Name: v.Name, Backend: v.Backend, Source: v.Source,
		SandboxID: "sb-gone", NodeID: node, RecordedUnixNano: at.UnixNano()}
}

// The worker that destroyed the sandbox is gone for good, with its SQLite
// ledger. The replicated entry it left is taken over by another worker,
// whose sweep deletes the volume row and its bytes and then acks the entry.
func TestClusterVolumeReclaimFromLostWorkerIsFinishedByAnother(t *testing.T) {
	svc, st, fr, c, vol := clusterReclaimHarness(t)
	ctx := context.Background()
	c.put(reclaimFor(vol, "dead-wkr", time.Now().Add(-time.Hour)))

	svc.runVolumeReclaim(ctx)

	if len(c.claims) != 1 || c.claims[0] != vol.ID {
		t.Fatalf("claims = %v, want the lost worker's entry taken over", c.claims)
	}
	if volumeExists(t, svc, vol) {
		t.Fatal("the volume row must be deleted")
	}
	if got := reclaimedSources(fr); len(got) != 1 || got[0] != vol.Source {
		t.Fatalf("reclaimed = %v", got)
	}
	if _, ok := c.has(vol.ID); ok {
		t.Fatal("the entry must be acked once the bytes are gone")
	}
	if pending, _ := st.ListPendingVolumeDeletions(ctx); len(pending) != 0 {
		t.Fatalf("local ledger = %+v", pending)
	}
}

// The usual case: the destroying worker has both its own ledger row and
// the replicated entry for the volume. One reclaim deletes the bytes once
// and clears both.
func TestClusterVolumeReclaimPairedWithLocalRowReclaimsOnce(t *testing.T) {
	svc, st, fr, c, vol := clusterReclaimHarness(t)
	ctx := context.Background()
	if err := svc.volumeMeta().DeleteRow(ctx, vol.Tenant, vol.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.SchedulePendingVolumeDeletion(ctx, vol, vol.Source); err != nil {
		t.Fatal(err)
	}
	c.put(reclaimFor(vol, "self", time.Now()))

	svc.runVolumeReclaim(ctx)

	if got := reclaimedSources(fr); len(got) != 1 {
		t.Fatalf("reclaimed = %v, want the bytes deleted once", got)
	}
	if _, ok := c.has(vol.ID); ok {
		t.Fatal("the replicated entry must be acked")
	}
	if pending, _ := st.ListPendingVolumeDeletions(ctx); len(pending) != 0 {
		t.Fatalf("local ledger = %+v", pending)
	}
	if len(c.claims) != 0 {
		t.Fatalf("an own entry must not be claimed: %v", c.claims)
	}
}

// The obligation stays until the bytes are confirmed gone, whatever fails
// on the way, and is dropped without touching the bytes only when they are
// no longer this volume's to delete.
func TestClusterVolumeReclaimKeepsObligationUntilBytesGone(t *testing.T) {
	cases := []struct {
		name        string
		setup       func(t *testing.T, svc *Service, c *reclaimLedgerCluster, fr *fakeReclaimer, vol models.Volume)
		recordedAgo time.Duration
		node        string
		wantEntry   bool
		wantRow     bool
		wantBytes   bool
	}{
		{
			name: "another worker took it first",
			setup: func(_ *testing.T, _ *Service, c *reclaimLedgerCluster, _ *fakeReclaimer, _ models.Volume) {
				c.claimErr = cluster.ErrVolumeReclaimMoved
			},
			node: "dead-wkr", wantEntry: true, wantRow: true,
		},
		{
			name: "the cluster list fails",
			setup: func(_ *testing.T, _ *Service, c *reclaimLedgerCluster, _ *fakeReclaimer, _ models.Volume) {
				c.listErr = errors.New("no server reachable")
			},
			node: "self", wantEntry: true, wantRow: true,
		},
		{
			name: "the backend delete fails",
			setup: func(_ *testing.T, _ *Service, _ *reclaimLedgerCluster, fr *fakeReclaimer, vol models.Volume) {
				fr.fail = map[string]error{vol.Source: errors.New("s3 down")}
			},
			node: "self", wantEntry: true, wantBytes: true,
		},
		{
			name: "the ack fails",
			setup: func(_ *testing.T, _ *Service, c *reclaimLedgerCluster, _ *fakeReclaimer, _ models.Volume) {
				c.ackErr = errors.New("raft away")
			},
			node: "self", wantEntry: true, wantBytes: true,
		},
		{
			name: "attached again, recently",
			setup: func(t *testing.T, svc *Service, _ *reclaimLedgerCluster, _ *fakeReclaimer, vol models.Volume) {
				attachTo(t, svc, vol, "sb-new")
			},
			node: "self", wantEntry: true, wantRow: true,
		},
		{
			name: "attached again, past the grace: the new holder records it",
			setup: func(t *testing.T, svc *Service, _ *reclaimLedgerCluster, _ *fakeReclaimer, vol models.Volume) {
				attachTo(t, svc, vol, "sb-new")
			},
			recordedAgo: 2 * deleteWithSandboxPendingGrace,
			node:        "self", wantRow: true,
		},
		{
			name: "a recreated volume owns the bytes",
			setup: func(t *testing.T, svc *Service, _ *reclaimLedgerCluster, _ *fakeReclaimer, vol models.Volume) {
				ctx := context.Background()
				if err := svc.volumeMeta().DeleteRow(ctx, vol.Tenant, vol.ID); err != nil {
					t.Fatal(err)
				}
				again := vol
				again.ID, again.DeleteWithSandbox = "vol-again", false
				if _, _, err := svc.volumeMeta().GetOrCreate(ctx, &again, 0); err != nil {
					t.Fatal(err)
				}
			},
			node: "self",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, fr, c, vol := clusterReclaimHarness(t)
			c.put(reclaimFor(vol, tc.node, time.Now().Add(-tc.recordedAgo)))
			tc.setup(t, svc, c, fr, vol)
			svc.runVolumeReclaim(context.Background())
			if _, ok := c.has(vol.ID); ok != tc.wantEntry {
				t.Fatalf("entry kept = %v, want %v", ok, tc.wantEntry)
			}
			if got := volumeExists(t, svc, vol); got != tc.wantRow {
				t.Fatalf("volume row exists = %v, want %v", got, tc.wantRow)
			}
			if got := len(reclaimedSources(fr)) > 0; got != tc.wantBytes {
				t.Fatalf("backend delete called = %v, want %v", got, tc.wantBytes)
			}
		})
	}
}

// attachTo attaches vol to a new sandbox, as a create naming it would.
func attachTo(t *testing.T, svc *Service, vol models.Volume, sandboxID string) {
	t.Helper()
	if err := svc.volumeMeta().PutAttachments(context.Background(), []models.VolumeAttachment{{
		Tenant: vol.Tenant, VolumeID: vol.ID, SandboxID: sandboxID, IncarnationID: "inc-" + sandboxID, Target: "/x", Source: vol.Source,
	}}); err != nil {
		t.Fatal(err)
	}
}

// A cluster client without the replicated ledger (an older build's, or the
// single-node Noop) leaves the sweep to the local ledger.
func TestClusterVolumeReclaimsNeedTheLedger(t *testing.T) {
	svc, _, _ := lifetimeHarness(t)
	svc.cfg.EnableCluster = true
	svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	if got := svc.clusterVolumeReclaims(context.Background()); got != nil {
		t.Fatalf("reclaims without a ledger = %+v", got)
	}
	o := localVolumeObligation(models.PendingVolumeDeletion{VolumeID: "v", CreatedAt: time.Unix(10, 0)})
	o.fsm = &cluster.VolumeReclaim{RecordedUnixNano: time.Unix(20, 0).UnixNano()}
	if got := o.recordedAt(); !got.Equal(time.Unix(20, 0)) {
		t.Fatalf("recordedAt = %v, want the newer record", got)
	}
	o.fsm.RecordedUnixNano = time.Unix(5, 0).UnixNano()
	if got := o.recordedAt(); !got.Equal(time.Unix(10, 0)) {
		t.Fatalf("recordedAt = %v, want the newer record", got)
	}
}
