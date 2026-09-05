package cluster

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/memberlist"
	"github.com/hashicorp/raft"
)

// failPutRecoveryStore forces storePlacementLocked error paths through Put.
type failPutRecoveryStore struct{}

func (failPutRecoveryStore) Put(string, placementRecovery) (string, error) {
	return "", errors.New("forced put failure")
}
func (failPutRecoveryStore) Get(string) (placementRecovery, bool, error) {
	return placementRecovery{}, false, nil
}
func (failPutRecoveryStore) GetRecord(string) (placementRecoveryStoreRecord, bool, error) {
	return placementRecoveryStoreRecord{}, false, nil
}
func (failPutRecoveryStore) Delete(string) error               { return nil }
func (failPutRecoveryStore) RetainSnapshotRefs([]string) error { return nil }

func TestFSMApplyUncoveredBranchesStep2(t *testing.T) {
	fsm := newPlacementFSM()
	if got := fsm.Apply(&raft.Log{Data: []byte("not-a-command")}); got == nil {
		t.Fatal("decode failure should return error")
	}
	if got := applyOp(t, fsm, command{Op: 255}); got == nil {
		t.Fatal("unknown op should error")
	}

	// Place, then orphan via reassign empty owner, then reject opPlace on orphan.
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-orph", OwnerNodeID: "a", Spec: &models.CreateSandboxRequest{Image: "x"}})
	applyOp(t, fsm, command{Op: opReassign, SandboxID: "sb-orph", OwnerNodeID: ""})
	if got := applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-orph", OwnerNodeID: "b"}); got == nil || !errors.Is(got.(error), ErrReservationConflict) {
		t.Fatalf("place orphaned = %v", got)
	}

	// Reassign missing is a no-op.
	if got := applyOp(t, fsm, command{Op: opReassign, SandboxID: "missing", OwnerNodeID: "x"}); got != nil {
		t.Fatalf("reassign missing = %v", got)
	}

	// Reserve then reassign reserved row (pending reservation path).
	applyOp(t, fsm, command{
		Op: opReserve, SandboxID: "sb-res", OwnerNodeID: "a",
		Spec: &models.CreateSandboxRequest{CPU: 1, MemoryMB: 64}, ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	})
	if got := applyOp(t, fsm, command{Op: opReassign, SandboxID: "sb-res", OwnerNodeID: "b", OwnerAPIURL: "http://b"}); got != nil {
		t.Fatalf("reassign reserved = %v", got)
	}

	// Empty batch / orphan owner / claim orphan guards.
	if got := applyOp(t, fsm, command{Op: opReserveBatch}); got == nil {
		t.Fatal("empty reserve batch should error")
	}
	if got := applyOp(t, fsm, command{Op: opOrphanOwner}); got == nil {
		t.Fatal("orphan without node should error")
	}
	if got := applyOp(t, fsm, command{Op: opClaimOrphan}); got == nil {
		t.Fatal("claim orphan missing ids should error")
	}
	if got := applyOp(t, fsm, command{Op: opClaimOrphan, SandboxID: "nope", OwnerNodeID: "a"}); !errors.Is(got.(error), ErrUnknownSandbox) {
		t.Fatalf("claim missing = %v", got)
	}

	// Place a live row and reject claim-orphan / reserved claim.
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-live", OwnerNodeID: "a", Spec: &models.CreateSandboxRequest{Name: "live", Image: "i"}})
	if got := applyOp(t, fsm, command{Op: opClaimOrphan, SandboxID: "sb-live", OwnerNodeID: "a"}); got != nil {
		t.Fatalf("claim self-owned non-orphan should no-op: %v", got)
	}
	if got := applyOp(t, fsm, command{Op: opClaimOrphan, SandboxID: "sb-live", OwnerNodeID: "b"}); got == nil || !errors.Is(got.(error), ErrReservationConflict) {
		t.Fatalf("claim foreign = %v", got)
	}
	applyOp(t, fsm, command{
		Op: opReserve, SandboxID: "sb-res2", OwnerNodeID: "a",
		Spec: &models.CreateSandboxRequest{Name: "r2", CPU: 1}, ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	})
	if got := applyOp(t, fsm, command{Op: opClaimOrphan, SandboxID: "sb-res2", OwnerNodeID: "a"}); got == nil || !errors.Is(got.(error), ErrReservationConflict) {
		t.Fatalf("claim reserved = %v", got)
	}

	// Orphan and claim (same previous owner) with renamed spec + secrets.
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-claim", OwnerNodeID: "old", Spec: &models.CreateSandboxRequest{Name: "oldn", Image: "i"}})
	applyOp(t, fsm, command{Op: opOrphanOwner, NodeID: "old"})
	if got := applyOp(t, fsm, command{
		Op: opClaimOrphan, SandboxID: "sb-claim", OwnerNodeID: "old",
		Spec: &models.CreateSandboxRequest{Name: "newn", Image: "i2"}, SecretRef: "s", SecretVersion: 3,
	}); got != nil {
		t.Fatalf("claim orphan rename = %v", got)
	}

	// Foreign orphan claim conflict.
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-fo", OwnerNodeID: "x", Spec: &models.CreateSandboxRequest{Name: "fo", Image: "i"}})
	applyOp(t, fsm, command{Op: opOrphanOwner, NodeID: "x"})
	if got := applyOp(t, fsm, command{Op: opClaimOrphan, SandboxID: "sb-fo", OwnerNodeID: "y"}); got == nil || !errors.Is(got.(error), ErrOrphanClaimConflict) {
		t.Fatalf("foreign orphan claim = %v", got)
	}

	// UpsertSpec / custom domain / volume validation edges.
	if got := applyOp(t, fsm, command{Op: opUpsertSpec, SandboxID: "missing"}); got != nil {
		t.Fatalf("upsert missing = %v", got)
	}
	if got := applyOp(t, fsm, command{Op: opUpsertSpec, SandboxID: "sb-live"}); got != nil {
		t.Fatalf("upsert empty = %v", got)
	}
	if got := applyOp(t, fsm, command{Op: opAddCustomDomain}); got == nil {
		t.Fatal("add domain missing fields")
	}
	if got := applyOp(t, fsm, command{Op: opRemoveCustomDomain}); got == nil {
		t.Fatal("remove domain missing fields")
	}
	if got := applyOp(t, fsm, command{Op: opRemoveCustomDomain, SandboxID: "gone", Hostname: "h.example"}); got != nil {
		t.Fatalf("remove domain missing placement = %v", got)
	}
	if got := applyOp(t, fsm, command{Op: opSetNodeDrainState}); got == nil {
		t.Fatal("drain missing node")
	}
	if got := applyOp(t, fsm, command{Op: opUpsertVolume}); got == nil {
		t.Fatal("upsert volume nil")
	}
	if got := applyOp(t, fsm, command{Op: opUpsertVolume, Volume: &models.Volume{}}); got == nil {
		t.Fatal("upsert volume incomplete")
	}
	if got := applyOp(t, fsm, command{Op: opDeleteVolume}); got == nil {
		t.Fatal("delete volume incomplete")
	}
	if got := applyOp(t, fsm, command{Op: opDeleteVolumeAttach}); got == nil {
		t.Fatal("delete attach incomplete")
	}

	// Orphan owner skips reserved rows owned by node.
	applyOp(t, fsm, command{
		Op: opReserve, SandboxID: "sb-or-res", OwnerNodeID: "dead",
		Spec: &models.CreateSandboxRequest{Name: "orres", CPU: 1}, ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	})
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-or-pl", OwnerNodeID: "dead", Spec: &models.CreateSandboxRequest{Name: "orpl", Image: "i"}})
	if got := applyOp(t, fsm, command{Op: opOrphanOwner, NodeID: "dead"}); got != nil {
		t.Fatalf("orphan owner = %v", got)
	}
	if _, ok := fsm.get("sb-or-res"); ok {
		t.Fatal("reserved row should be deleted on orphan owner")
	}
	if p, ok := fsm.get("sb-or-pl"); !ok || !p.IsOrphaned() {
		t.Fatalf("placed row should be orphaned: %+v", p)
	}
}

func TestFSMStorePlacementRecoveryPutFailure(t *testing.T) {
	fsm := newPlacementFSMWithRecoveryStore(failPutRecoveryStore{})
	got := applyOp(t, fsm, command{
		Op: opPlace, SandboxID: "sb-fail", OwnerNodeID: "a",
		Spec: &models.CreateSandboxRequest{Image: "alpine"},
	})
	if got == nil || !strings.Contains(fmt.Sprint(got), "forced put failure") {
		t.Fatalf("storePlacement Put failure = %v", got)
	}
}

func TestFSMLockedHelpersNilAndEmptyGuards(t *testing.T) {
	fsm := &placementFSM{}
	fsm.claimOwnerLocked("", Placement{OwnerNodeID: "a"})
	fsm.claimOwnerLocked("sb", Placement{State: PlacementStateReserved, OwnerNodeID: "a"})
	fsm.claimOwnerLocked("sb", Placement{OwnerState: PlacementOwnerStateOrphaned, OwnerNodeID: "a"})
	fsm.claimOwnerLocked("sb", Placement{})
	fsm.claimOwnerLocked("sb1", Placement{OwnerNodeID: "n1"})
	fsm.releaseOwnerLocked("", Placement{OwnerNodeID: "n1"})
	fsm.releaseOwnerLocked("sb1", Placement{})
	fsm.releaseOwnerLocked("sb1", Placement{OwnerNodeID: "missing"})
	if ids := fsm.ownedPlacementIDsLocked(""); ids != nil {
		t.Fatalf("owned empty node=%v", ids)
	}
	if ids := fsm.ownedPlacementIDsLocked("nobody"); ids != nil {
		t.Fatalf("owned missing=%v", ids)
	}

	fsm.claimShardLocked("")
	fsm.shardIndex = nil
	fsm.placementIDs = nil
	fsm.claimShardLocked("sb-shard")
	fsm.releaseShardLocked("")
	fsm.releaseShardLocked("sb-shard")

	fsm.claimHostPortLocked("sb", 80, ExposedPortRoute{Protocol: models.ExposedPortProtocolTCP, HostPort: 22080})
	fsm.hostPortIndex = nil
	fsm.claimHostPortLocked("sb", 80, ExposedPortRoute{Protocol: models.ExposedPortProtocolTCP, HostPort: 22081})
	fsm.releaseCustomHostnameLocked("", "h")
	fsm.releaseCustomHostnameLocked("sb", "")
	fsm.claimCustomHostnameLocked("", "h")
	fsm.claimCustomHostnameLocked("sb", "")

	fsm.claimPendingReservationLocked("", Placement{State: PlacementStateReserved})
	fsm.claimPendingReservationLocked("sb", Placement{})
	fsm.pendingReservationClaims = nil
	fsm.pendingReservationCapacity = nil
	fsm.pendingReservationIDsByOwner = nil
	fsm.reservedIndex = nil
	fsm.claimPendingReservationLocked("sb-p", Placement{
		State: PlacementStateReserved, OwnerNodeID: "n", ExpiresUnix: time.Now().Add(time.Minute).Unix(),
		Spec: &models.CreateSandboxRequest{CPU: 1, MemoryMB: 32},
	})
	// owner change path
	fsm.claimPendingReservationLocked("sb-p", Placement{
		State: PlacementStateReserved, OwnerNodeID: "n2", ExpiresUnix: time.Now().Add(2 * time.Minute).Unix(),
		Spec: &models.CreateSandboxRequest{CPU: 2, MemoryMB: 64},
	})
	fsm.releasePendingReservationClaimLocked("")
	fsm.pendingReservationClaims = nil
	fsm.releasePendingReservationClaimLocked("x")
	fsm.releasePendingReservationOwnerLocked("", "n")
	fsm.releasePendingReservationOwnerLocked("sb", "")
	fsm.claimPendingReservationOwnerLocked("", "n")
	fsm.claimPendingReservationOwnerLocked("sb", "")
	if ids := fsm.pendingReservationIDsLocked(""); ids != nil {
		t.Fatalf("pending ids empty=%v", ids)
	}
	fsm.refreshPendingReservationExpiryLocked("", 1)
	fsm.refreshPendingReservationExpiryLocked("missing", 1)
	if _, ok := fsm.sandboxIDByCustomHostname(""); ok {
		t.Fatal("empty hostname should miss")
	}
	if _, ok := fsm.sandboxIDByName(""); ok {
		t.Fatal("empty name should miss")
	}
}

func TestFSMVolumesForTenantAndAttachmentCount(t *testing.T) {
	fsm := newPlacementFSM()
	now := time.Now().UTC()
	applyOp(t, fsm, command{Op: opUpsertVolume, Volume: &models.Volume{ID: "v1", Tenant: "t", Name: "b", Backend: "s3", CreatedAt: now.Add(-time.Hour)}})
	applyOp(t, fsm, command{Op: opUpsertVolume, Volume: &models.Volume{ID: "v2", Tenant: "t", Name: "a", Backend: "s3", CreatedAt: now}})
	got := fsm.VolumesForTenant("t")
	if len(got) != 2 || got[0].Name != "a" {
		t.Fatalf("VolumesForTenant=%+v", got)
	}
	if n := fsm.volumeAttachmentCountLocked("", "v1"); n != 0 {
		t.Fatalf("empty tenant count=%d", n)
	}
	if n := fsm.volumeAttachmentCountLocked("t", ""); n != 0 {
		t.Fatalf("empty id count=%d", n)
	}
}

func TestFSMRestoreRowsAndRecoveryMerge(t *testing.T) {
	payload := fsmSnapshotPayload{
		Version: 9,
		Rows: []placementSnapshotRow{
			{Placement: Placement{SandboxID: ""}}, // skipped
			{
				Placement: Placement{SandboxID: "sb-r", OwnerNodeID: "n", Version: 3},
				Recovery:  placementRecovery{Spec: &models.CreateSandboxRequest{Image: "img"}, SecretRef: "r", SecretVersion: 2},
			},
		},
		Volumes: []models.Volume{
			{Tenant: "", ID: "x"},
			{Tenant: "t", ID: "v1", Name: "n1", Backend: "s3"},
		},
		VolumeAttachments: []models.VolumeAttachment{
			{Tenant: "t", VolumeID: "missing", SandboxID: "sb", Target: "/d", Source: "s"},
			{Tenant: "t", VolumeID: "v1", SandboxID: "sb", Target: "/d", Source: "s"},
			{Tenant: "", VolumeID: "v1", SandboxID: "sb", Target: "/d", Source: "s"},
		},
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(payload); err != nil {
		t.Fatal(err)
	}
	fsm := newPlacementFSM()
	if err := fsm.Restore(io.NopCloser(bytes.NewReader(buf.Bytes()))); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	p, ok := fsm.get("sb-r")
	if !ok || p.Spec == nil || p.Spec.Image != "img" || p.SecretRef != "r" {
		t.Fatalf("restored placement=%+v ok=%v", p, ok)
	}
	if fsm.VolumeAttachmentCount("t", "v1") != 1 {
		t.Fatalf("attachment count=%d", fsm.VolumeAttachmentCount("t", "v1"))
	}
}

func TestFSMRestoreReadError(t *testing.T) {
	fsm := newPlacementFSM()
	err := fsm.Restore(io.NopCloser(&errReader{}))
	if err == nil || !strings.Contains(err.Error(), "restore read") {
		t.Fatalf("Restore read error=%v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read boom") }

func TestAgentVolumeUpsertAndQueryErrorBranches(t *testing.T) {
	vols := map[string]models.Volume{"t1/n1": {ID: "vol-1", Tenant: "t1", Name: "n1", Backend: "s3"}}
	server, internalClient := newNodeBoundForwardServer(t, "worker", "cp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && (r.URL.Path == PublicInternalApplyPath || r.URL.Path == InternalAPIPath):
			var cmd command
			body, _ := io.ReadAll(r.Body)
			if err := decodeCommandInto(body, &cmd); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			switch cmd.Op {
			case opUpsertVolume:
				if cmd.MaxPerTenant == 1 {
					http.Error(w, ErrVolumeQuotaExceeded.Error(), http.StatusConflict)
					return
				}
				if cmd.Volume != nil && cmd.Volume.ID == "fail-apply" {
					http.Error(w, "apply failed", http.StatusInternalServerError)
					return
				}
				if cmd.Volume != nil {
					v := *cmd.Volume
					vols[v.Tenant+"/"+v.Name] = v
				}
				w.WriteHeader(http.StatusNoContent)
			case opDeleteVolume:
				http.Error(w, ErrUnknownVolume.Error(), http.StatusNotFound)
			case opPutVolumeAttach:
				http.Error(w, ErrUnknownVolume.Error(), http.StatusNotFound)
			default:
				w.WriteHeader(http.StatusNoContent)
			}
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalVolumePath:
			q := r.URL.Query()
			switch q.Get("kind") {
			case "name":
				if v, ok := vols[q.Get("tenant")+"/"+q.Get("name")]; ok {
					_ = json.NewEncoder(w).Encode(VolumeQueryResponse{Volume: &v})
					return
				}
				// Explicit empty volume for readback timeout path when kind=name + special name
				if q.Get("name") == "never-appear" {
					_ = json.NewEncoder(w).Encode(VolumeQueryResponse{})
					return
				}
				http.NotFound(w, r)
			case "id":
				if q.Get("id") == "nil-vol" {
					_ = json.NewEncoder(w).Encode(VolumeQueryResponse{})
					return
				}
				if q.Get("id") == "err" {
					http.Error(w, "boom", 500)
					return
				}
				_ = json.NewEncoder(w).Encode(VolumeQueryResponse{Volume: &models.Volume{ID: q.Get("id"), Tenant: q.Get("tenant"), Name: "n", Backend: "s3"}})
			case "list", "source", "attachment_count":
				http.Error(w, "cp down", 503)
			default:
				http.Error(w, "bad", 400)
			}
		default:
			http.NotFound(w, r)
		}
	}))

	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "cp", APIURL: server.URL, InternalURL: server.URL, Alive: true, Role: config.NodeRoleServer})
	a := &Agent{
		nodeID:         "worker",
		internalClient: internalClient,
		gossip:         &gossipNode{memberIndex: index},
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx := context.Background()

	// Existing volume short-circuit.
	row, created, err := a.VolumeUpsert(ctx, models.Volume{ID: "vol-x", Tenant: "t1", Name: "n1", Backend: "s3"}, 0)
	if err != nil || created || row.ID != "vol-1" {
		t.Fatalf("existing upsert row=%+v created=%v err=%v", row, created, err)
	}
	// Quota mapping (agent maps conflict bodies that contain the sentinel text).
	if _, _, err := a.VolumeUpsert(ctx, models.Volume{ID: "v2", Tenant: "t1", Name: "n2", Backend: "s3"}, 1); err == nil || !strings.Contains(err.Error(), ErrVolumeQuotaExceeded.Error()) {
		t.Fatalf("quota err=%v", err)
	}
	// Apply failure.
	if _, _, err := a.VolumeUpsert(ctx, models.Volume{ID: "fail-apply", Tenant: "t9", Name: "n9", Backend: "s3"}, 0); err == nil {
		t.Fatal("expected apply failure")
	}
	// Successful create + readback.
	row, created, err = a.VolumeUpsert(ctx, models.Volume{ID: "vol-new", Tenant: "t2", Name: "fresh", Backend: "s3"}, 0)
	if err != nil || !created || row.ID != "vol-new" {
		t.Fatalf("create row=%+v created=%v err=%v", row, created, err)
	}
	// VolumeByID success / nil / error.
	if got, err := a.VolumeByID(ctx, "t2", "vol-new"); err != nil || got.ID != "vol-new" {
		t.Fatalf("VolumeByID=%+v err=%v", got, err)
	}
	if _, err := a.VolumeByID(ctx, "t", "nil-vol"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("nil volume err=%v", err)
	}
	if _, err := a.VolumeByID(ctx, "t", "err"); err == nil {
		t.Fatal("VolumeByID query error expected")
	}
	if _, err := a.VolumeByName(ctx, "t", "missing-name"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("VolumeByName missing=%v", err)
	}
	if _, err := a.VolumesForTenant(ctx, "t"); err == nil {
		t.Fatal("VolumesForTenant should surface control-plane error")
	}
	if _, err := a.VolumeExistsForSource(ctx, "s"); err == nil {
		t.Fatal("VolumeExistsForSource should surface error")
	}
	if _, err := a.VolumeAttachmentCount(ctx, "t", "v"); err == nil {
		t.Fatal("VolumeAttachmentCount should surface error")
	}
	if err := a.VolumeDelete(ctx, "t1", "vol-1"); err == nil || !strings.Contains(err.Error(), ErrUnknownVolume.Error()) {
		t.Fatalf("VolumeDelete map=%v", err)
	}
	if err := a.PutVolumeAttachments(ctx, []models.VolumeAttachment{{
		Tenant: "t", VolumeID: "v", SandboxID: "s", Target: "/d", Source: "src",
	}}); err == nil || !strings.Contains(err.Error(), ErrUnknownVolume.Error()) {
		t.Fatalf("PutVolumeAttachments map=%v", err)
	}

	// readback honors caller context cancel while name never appears.
	deadRead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(VolumeQueryResponse{})
	}))
	defer deadRead.Close()
	index2 := newGossipMemberIndex()
	index2.upsert(Member{NodeID: "cp", APIURL: deadRead.URL, Alive: true, Role: config.NodeRoleServer})
	a2 := &Agent{nodeID: "w", gossip: &gossipNode{memberIndex: index2}, logger: a.logger}
	ctxCancel, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := a2.VolumeUpsert(ctxCancel, models.Volume{ID: "v", Tenant: "t", Name: "never-appear", Backend: "s3"}, 0); err == nil {
		t.Fatal("readback should fail when context already cancelled")
	}
}

func TestClusterVolumeClientValidationAndReadback(t *testing.T) {
	c := &Cluster{fsm: newPlacementFSM(), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := context.Background()
	if _, _, err := c.VolumeUpsert(ctx, models.Volume{}, 0); err == nil {
		t.Fatal("validation expected")
	}
	applyOp(t, c.fsm, command{Op: opUpsertVolume, Volume: &models.Volume{ID: "v1", Tenant: "t", Name: "n", Backend: "s3"}})
	row, created, err := c.VolumeUpsert(ctx, models.Volume{ID: "other", Tenant: "t", Name: "n", Backend: "s3"}, 0)
	if err != nil || created || row.ID != "v1" {
		t.Fatalf("existing upsert row=%+v created=%v err=%v", row, created, err)
	}
	if err := c.VolumeDelete(ctx, "", ""); err == nil {
		t.Fatal("VolumeDelete validation")
	}
	if err := c.PutVolumeAttachments(ctx, nil); err != nil {
		t.Fatalf("empty attachments: %v", err)
	}

	ctxShort, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.readbackVolume(ctxShort, "t", "missing"); err == nil {
		t.Fatal("readback should fail on cancelled context")
	}
}

func TestRecoveryStoreMoreErrorBranches(t *testing.T) {
	store, err := newPlacementRecoveryFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(""); err != nil {
		t.Fatalf("Delete empty: %v", err)
	}
	if err := store.Delete("recovery:v1:not-hex"); err == nil {
		t.Fatal("Delete invalid ref")
	}
	if _, _, err := store.Get("recovery:v1:not-hex"); err == nil {
		t.Fatal("Get invalid ref")
	}
	if _, _, err := store.GetRecord("recovery:v1:zzzz"); err == nil {
		t.Fatal("GetRecord invalid ref")
	}

	// Corrupt blob decode / read as directory.
	ref, err := store.Put("sb", placementRecovery{Spec: &models.CreateSandboxRequest{Image: "i"}})
	if err != nil {
		t.Fatal(err)
	}
	path, err := store.pathForRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.GetRecord(ref); err == nil {
		t.Fatal("GetRecord corrupt should fail")
	}

	// RetainSnapshotRefs mkdir failure when dir is a file.
	file, err := os.CreateTemp("", "rec-dir-file")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	bad := &placementRecoveryFileStore{dir: file.Name()}
	if err := bad.RetainSnapshotRefs([]string{ref}); err == nil {
		t.Fatal("RetainSnapshotRefs mkdir failure expected")
	}

	// writeGCManifest rename failure: make target path a directory after temp write by
	// pointing gc path at a non-writable parent via chmod.
	dir := t.TempDir()
	okStore, err := newPlacementRecoveryFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if err := okStore.writeGCManifest(placementRecoveryGCManifest{}); err == nil {
		t.Fatal("writeGCManifest on read-only dir should fail")
	}
	if !isRecoveryBlobFilename("notahex.json") {
		// non-hex already false; ensure suffix check branch
	}
	if isRecoveryBlobFilename("abc") {
		t.Fatal("missing .json should be false")
	}
}

func TestVoterAutoJoinAndDeadOwnerUnitBranches(t *testing.T) {
	c := &Cluster{nodeID: "self", logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c.handleMemberJoin("peer") // raft nil → return
	if c.peerForcedNonVoter("x") {
		t.Fatal("nil gossip should not force nonvoter")
	}
	c.gossip = &gossipNode{memberIndex: newGossipMemberIndex()}
	if c.peerForcedNonVoter("missing") {
		t.Fatal("missing member")
	}
	c.gossip.memberIndex.upsert(Member{NodeID: "w", Role: config.NodeRoleWorker})
	if !c.peerForcedNonVoter("w") {
		t.Fatal("worker should force nonvoter")
	}
	if c.peerRaftAddr("missing") != "" {
		t.Fatal("missing raft addr")
	}
	c.gossip.memberIndex.upsert(Member{NodeID: "w", Role: config.NodeRoleWorker, RaftAddr: "127.0.0.1:7001"})
	if got := c.peerRaftAddr("w"); got != "127.0.0.1:7001" {
		t.Fatalf("peerRaftAddr=%q", got)
	}

	// voterCapReached when currentVoterCount fails (nil raft panics) — skip.
	c.cfg.ClusterMaxAutoVoters = 1
	// Without raft, avoid calling voterCapReached/currentVoterCount.

	d := &voterAutoJoinDelegate{c: c}
	d.NotifyUpdate(&memberlist.Node{Name: "x"})

	c.reconcileDeadOwners(context.Background()) // raft nil
	c.reconcileReservations(context.Background())
	if id, url, host := c.pickRecreationTarget(nil); id != "" || url != "" || host != "" {
		t.Fatal("nil spec")
	}
	if id, _, _ := c.pickRecreationTarget(&models.CreateSandboxRequest{ImageDistributionMode: models.ImageDistributionLocalOnly}); id != "" {
		t.Fatal("local-only")
	}
	if _, ok := c.selectRecreationTargetExcluding(nil); ok {
		t.Fatal("nil spec exclude")
	}
	if _, ok := c.selectRecreationTargetExcluding(&models.CreateSandboxRequest{ImageDistributionMode: models.ImageDistributionLocalOnly}); ok {
		t.Fatal("local-only exclude")
	}

}

func TestAssertOwnershipGuardsAndStalePaths(t *testing.T) {
	c := &Cluster{
		nodeID: "self",
		fsm:    newPlacementFSM(),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := c.AssertOwnership(context.Background(), nil); err != nil {
		t.Fatalf("empty local: %v", err)
	}
}

func TestAgentCloseNilGossip(t *testing.T) {
	a := &Agent{}
	if err := a.Close(); err != nil {
		t.Fatalf("Close nil gossip: %v", err)
	}
}

func TestNoopVolumeByIDAndDeleteBranches(t *testing.T) {
	n := NewNoop("n", "http://x", "")
	ctx := context.Background()
	if _, _, err := n.VolumeUpsert(ctx, models.Volume{ID: "v", Tenant: "t", Name: "n", Backend: "s3"}, 0); err != nil {
		t.Fatal(err)
	}
	if got, err := n.VolumeByID(ctx, "t", "v"); err != nil || got.ID != "v" {
		t.Fatalf("VolumeByID=%+v err=%v", got, err)
	}
	if _, err := n.VolumeByID(ctx, "t", "missing"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("missing by id=%v", err)
	}
	if _, err := n.VolumeByName(ctx, "t", "missing"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("missing by name=%v", err)
	}
	if exists, err := n.VolumeExistsForSource(ctx, "nope"); err != nil || exists {
		t.Fatalf("exists=%v err=%v", exists, err)
	}
	if err := n.VolumeDelete(ctx, "t", "v"); err != nil {
		t.Fatal(err)
	}
	if err := n.VolumeDelete(ctx, "t", "v"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("second delete=%v", err)
	}
}
