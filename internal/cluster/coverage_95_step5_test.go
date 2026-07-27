package cluster

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestNoopVolumeValidationAndAttachmentOverwrite(t *testing.T) {
	n := NewNoop("n", "http://x", "")
	ctx := context.Background()
	if _, _, err := n.VolumeUpsert(ctx, models.Volume{}, 0); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("validation=%v", err)
	}
	if _, _, err := n.VolumeUpsert(ctx, models.Volume{ID: "v1", Tenant: "t", Name: "n1", Backend: "s3"}, 0); err != nil {
		t.Fatal(err)
	}
	// Idempotent existing-name return (111-113).
	row, created, err := n.VolumeUpsert(ctx, models.Volume{ID: "other", Tenant: "t", Name: "n1", Backend: "s3"}, 0)
	if err != nil || created || row.ID != "v1" {
		t.Fatalf("existing name row=%+v created=%v err=%v", row, created, err)
	}
	if err := n.PutVolumeAttachments(ctx, []models.VolumeAttachment{{
		Tenant: "t", VolumeID: "v1", SandboxID: "", Target: "/d", Source: "s",
	}}); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("incomplete attachment=%v", err)
	}
	a := models.VolumeAttachment{Tenant: "t", VolumeID: "v1", SandboxID: "sb", Target: "/d", Source: "s"}
	if err := n.PutVolumeAttachments(ctx, []models.VolumeAttachment{a}); err != nil {
		t.Fatal(err)
	}
	// Overwrite same key → release existing branch (255-257).
	a.Source = "s2"
	if err := n.PutVolumeAttachments(ctx, []models.VolumeAttachment{a}); err != nil {
		t.Fatal(err)
	}
}

func TestClonePlacementsEmptyAndSplitHostPortBad(t *testing.T) {
	if got := clonePlacements(nil); got != nil {
		t.Fatalf("nil=%v", got)
	}
	if got := clonePlacements([]Placement{}); got != nil {
		t.Fatalf("empty=%v", got)
	}
	if _, _, err := splitHostPort("host:notaport"); err == nil {
		t.Fatal("expected atoi error")
	}
}

func TestProxyCacheDoubleCheckAndErrorHandler(t *testing.T) {
	pc := newProxyCache(http.DefaultTransport)
	p1, err := pc.get("http://example.invalid")
	if err != nil || p1 == nil {
		t.Fatalf("get=%v err=%v", p1, err)
	}
	p2, err := pc.get("http://example.invalid")
	if err != nil || p2 != p1 {
		t.Fatalf("cache hit p2=%v err=%v", p2, err)
	}
	if _, err := pc.get("://bad"); err == nil {
		t.Fatal("expected parse error")
	}
	// Fire ErrorHandler.
	w := httptest.NewRecorder()
	p1.ErrorHandler(w, httptest.NewRequest(http.MethodGet, "http://x", nil), errors.New("boom"))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestDeriveInternalAdvertiseEmptyHostPort(t *testing.T) {
	// bound addr that parses to empty host shouldn't happen often; exercise port-empty path
	// via bare host already covered — force host=="" branch via listen/bound both empty-ish.
	if got := deriveInternalAdvertiseURL("", "", ":8443"); got != "https://127.0.0.1:8443" {
		t.Fatalf("empty hosts with port=%q", got)
	}
}

func TestFSMOrphanOwnerSkipReservedAndMissing(t *testing.T) {
	fsm := newPlacementFSM()
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "live", OwnerNodeID: "n", Spec: &models.CreateSandboxRequest{Image: "i", Name: "live"}})
	applyOp(t, fsm, command{
		Op: opReserve, SandboxID: "res", OwnerNodeID: "n",
		Spec: &models.CreateSandboxRequest{Name: "res", CPU: 1}, ExpiresUnix: 9999999999,
	})
	// Manually poison owner index with a missing id and a reserved id so orphan skips them.
	fsm.mu.Lock()
	fsm.ownerIndex["n"]["ghost"] = struct{}{}
	fsm.ownerIndex["n"]["res"] = struct{}{} // reserved also in pending; ownedPlacementIDs may still list if poisoned
	fsm.mu.Unlock()
	if got := applyOp(t, fsm, command{Op: opOrphanOwner, NodeID: "n"}); got != nil {
		t.Fatalf("orphan=%v", got)
	}
}

func TestAddExposedPortMissingPlacement(t *testing.T) {
	fsm := newPlacementFSM()
	if got := applyOp(t, fsm, command{Op: opAddExposedPort, SandboxID: "missing", Port: 80, Protocol: "http"}); got != nil {
		t.Fatalf("missing placement add port=%v", got)
	}
	if got := applyOp(t, fsm, command{Op: opAddExposedPort, SandboxID: "missing", Port: 0, Protocol: "http"}); got != nil {
		t.Fatalf("zero port=%v", got)
	}
}

func TestTinyCoverageHelpersStep5(t *testing.T) {
	if got := insertSortedHostname([]string{"b.com"}, ""); len(got) != 1 || got[0] != "b.com" {
		t.Fatalf("empty hostname insert=%v", got)
	}
	if got := removeHostname([]string{"a.com"}, ""); len(got) != 1 {
		t.Fatalf("empty remove=%v", got)
	}

	fsm := newPlacementFSM()
	fsm.mu.Lock()
	fsm.volumeNameIndex[volumeNameKey("t", "ghost")] = "missing-id"
	fsm.mu.Unlock()
	if _, err := fsm.VolumeByName("t", "ghost"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("orphan name index=%v", err)
	}
	fsm.mu.Lock()
	fsm.releaseVolumeAttachmentsForSandboxLocked("")
	fsm.mu.Unlock()

	// Same CreatedAt forces Name tie-break in VolumesForTenant sort.
	now := time.Now().UTC()
	applyOp(t, fsm, command{Op: opUpsertVolume, Volume: &models.Volume{ID: "v1", Tenant: "t2", Name: "b", Backend: "s3", CreatedAt: now}})
	applyOp(t, fsm, command{Op: opUpsertVolume, Volume: &models.Volume{ID: "v2", Tenant: "t2", Name: "a", Backend: "s3", CreatedAt: now}})
	got := fsm.VolumesForTenant("t2")
	if len(got) != 2 || got[0].Name != "a" {
		t.Fatalf("tie-break VolumesForTenant=%+v", got)
	}

	if classifyClusterMetricError(nil) != "" {
		t.Fatal("nil classify")
	}
	if classifyClusterMetricError(errors.New("context deadline exceeded")) != "timeout" {
		t.Fatal("timeout classify")
	}
	if classifyClusterMetricError(errors.New("peer API URL unknown")) != "target_unknown" {
		t.Fatal("unknown classify")
	}

	members := []Member{
		{NodeID: "s1", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s2", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s3", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s4", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s5", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s6", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s7", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s8", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s9", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s10", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "s11", Alive: true, Role: config.NodeRoleServer},
	}
	if err := LargeClusterTopologyError(members); err == nil {
		t.Fatal("expected topology error for server-only large cluster")
	}
}
