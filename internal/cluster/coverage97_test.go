package cluster

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCoverage97PlacementEdges(t *testing.T) {
	image := docker.BuildTagForNode("FROM scratch\n", nil, "worker-a")
	pinned := capacityRequestFromSpec(&models.CreateSandboxRequest{Image: image})
	if pinned.RequiredNodeID == "" {
		t.Fatal("built image did not pin a node")
	}

	bundle := models.JSBundleRefForNode("main.js", "node-a")
	isolate := capacityRequestFromSpec(&models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: bundle,
	})
	if isolate.RequiredNodeID != "node-a" {
		t.Fatalf("isolate node = %q", isolate.RequiredNodeID)
	}

	wasm := capacityRequestFromSpec(&models.CreateSandboxRequest{
		Runtime: models.RuntimeWasm, MemoryMB: 64,
		GPUs: &models.GPURequest{Count: 0, Vendor: models.GPUVendorNVIDIA},
	})
	if wasm.MemoryMB != 72 || wasm.GPUs != 1 {
		t.Fatalf("wasm request = %+v", wasm)
	}

	got := SelectSecretRecipients("sb", []Member{{NodeID: " "}, {NodeID: "b"}, {NodeID: "c"}}, "a", -1)
	if len(got) != 1 || got[0] != "a" {
		t.Fatalf("negative backups = %#v", got)
	}
}

func TestCoverage97CapacityLeaseNilGuards(t *testing.T) {
	var cache *capacityLeaseCache
	cache.recordResponsiveness("", true)
	cache.recordResponsiveness("n", false)
	if cache.tooSlowToProbe("n") {
		t.Fatal("nil cache reported a slow peer")
	}
	cache.setAdmitter(nil)
	cache.SetLocalTemplateIDsProvider(nil)
	cache.SetLocalTemplateCatalogProvider(nil)
	cache.SetLocalWasmModuleIDsProvider(nil)
	cache.set("", capacity.Snapshot{}, time.Now())
	if !cache.due("n", time.Now()) {
		t.Fatal("nil cache should treat every peer as due")
	}
	cache.recordFetchResult("", time.Now(), nil)
	cache.recordAttempt("", time.Now())
	if cache.staleness("n", time.Now()) != 0 {
		t.Fatal("nil staleness")
	}
	if cache.retain(map[string]struct{}{"a": {}}) != 0 {
		t.Fatal("nil retain")
	}
	if got := cache.apply([]Member{{NodeID: "a"}}, time.Now()); len(got) != 1 {
		t.Fatalf("nil apply = %#v", got)
	}

	empty := &capacityLeaseCache{}
	empty.recordResponsiveness("n", false)
	empty.set("n", capacity.Snapshot{}, time.Now())
	empty.recordFetchResult("n", time.Now(), errors.New("timeout"))
	empty.recordAttempt("n", time.Now())
	if empty.slowPeers == nil || empty.leases == nil || empty.nextAttempt == nil || empty.failures == nil || empty.lastAttempt == nil {
		t.Fatal("zero cache did not initialize its maps")
	}

	pruned := &capacityLeaseCache{
		selfID:      "self",
		leases:      map[string]capacityLease{"gone": {}},
		nextAttempt: map[string]time.Time{"orphan": time.Now()},
		failures:    map[string]int{"orphan": 2},
		lastAttempt: map[string]time.Time{"orphan": time.Now()},
		slowPeers:   map[string]bool{"orphan": true},
	}
	if pruned.retain(map[string]struct{}{"self": {}}) != 1 {
		t.Fatal("retain did not drop the departed lease")
	}
	if _, ok := pruned.nextAttempt["orphan"]; ok {
		t.Fatal("retain left an orphan backoff entry")
	}

	admitter := capacity.New(capacity.HostInfo{CPUCores: 2}, capacity.Limits{}, nil)
	live := newCapacityLeaseCache("self", admitter, time.Second, nil)
	live.SetLocalTemplateCatalogProvider(func() ([]string, bool) { return []string{"base"}, true })
	live.refreshLocal(time.Now())

	if got := passConcurrency(3, time.Nanosecond, time.Second, 8); got <= 0 {
		t.Fatalf("passConcurrency = %d", got)
	}
	sweep := &Cluster{capacityLeases: &capacityLeaseCache{ttl: time.Millisecond}}
	if sweep.capacityLeaseSweepBudget() != time.Second {
		t.Fatalf("sweep budget = %s", sweep.capacityLeaseSweepBudget())
	}
	(&Cluster{}).refreshCapacityLeases(context.Background())
}

func TestCoverage97AuditACLIndexEdges(t *testing.T) {
	f := &placementFSM{}
	f.retainAuditACLLocked(AuditACL{}, 1)
	acl := AuditACL{SandboxID: "sb", IncarnationID: "inc", ExpiresUnix: 50, RetainedVersion: 2}
	f.retainAuditACLLocked(acl, 10)
	acl.RetainedVersion = 3
	f.retainAuditACLLocked(acl, 10)
	f.auditACLLatest = nil
	f.refreshAuditACLLatestLocked("sb")

	orphanFSM := &placementFSM{}
	orphanFSM.ensureAuditACLIndexesLocked()
	orphanFSM.auditACLs["ghost-a"] = AuditACL{SandboxID: "g", IncarnationID: "i", ExpiresUnix: 5, RetainedVersion: 1}
	orphanFSM.auditACLs["ghost-b"] = AuditACL{SandboxID: "g", IncarnationID: "j", ExpiresUnix: 6, RetainedVersion: 2}
	orphanFSM.retainAuditACLLocked(AuditACL{SandboxID: "live", IncarnationID: "k", ExpiresUnix: 9, RetainedVersion: 9}, 1)

	stuck := &placementFSM{}
	stuck.ensureAuditACLIndexesLocked()
	orphan := auditACLOrder{Version: 1, Expires: 1, Key: "missing"}
	stuck.auditACLByVersion.ReplaceOrInsert(orphan)
	stuck.auditACLByExpiry.ReplaceOrInsert(orphan)
	stuck.auditACLs["keep"] = AuditACL{SandboxID: "s", IncarnationID: "i", ExpiresUnix: 50, RetainedVersion: 50}
	stuck.retainAuditACLLocked(AuditACL{SandboxID: "s2", IncarnationID: "j", ExpiresUnix: 60, RetainedVersion: 60}, 1)

	prune := &placementFSM{}
	prune.ensureAuditACLIndexesLocked()
	prune.auditACLByVersion.ReplaceOrInsert(orphan)
	prune.auditACLByExpiry.ReplaceOrInsert(orphan)
	if got := prune.pruneAuditACLLocked(10); got != 0 {
		t.Fatalf("orphan prune removed %d rows", got)
	}
}

func TestCoverage97ClusterGuardRails(t *testing.T) {
	ctx := context.Background()
	var clusterNil *Cluster
	if err := clusterNil.RetireNodeStorage(ctx, "node-a", "op", "disk", time.Time{}); err == nil {
		t.Fatal("nil cluster retired storage")
	}
	if err := (&Cluster{}).RetireNodeStorage(ctx, "  ", "op", "disk", time.Now()); err == nil {
		t.Fatal("blank node id was accepted")
	}
	if err := clusterNil.RevokeNodeStorageRetirement(ctx, "node-a"); err == nil {
		t.Fatal("nil cluster revoked storage")
	}
	if err := (&Cluster{}).RevokeNodeStorageRetirement(ctx, ""); err == nil {
		t.Fatal("blank revoke was accepted")
	}
	if err := (&Cluster{}).awaitAuthoritativeFSM(ctx); err == nil {
		t.Fatal("missing raft was treated as authoritative")
	}
	if got := (&Cluster{}).NodeStorageRetirementsForPeer(); got.Authoritative {
		t.Fatal("nil fsm reported an authoritative retirement set")
	}
	var agentNil *Agent
	if err := agentNil.RetireNodeStorage(ctx, "node-a", "op", "disk", time.Time{}); err == nil {
		t.Fatal("nil agent retired storage")
	}
	if err := (&Agent{}).RetireNodeStorage(ctx, "", "op", "disk", time.Time{}); err == nil {
		t.Fatal("blank agent node id was accepted")
	}
	if err := (&Agent{}).RetireNodeStorage(ctx, "node-a", "op", "disk", time.Time{}); err == nil {
		t.Fatal("agent with no control plane retired storage")
	}
	if err := agentNil.RevokeNodeStorageRetirement(ctx, "node-a"); err == nil {
		t.Fatal("nil agent revoked storage")
	}

	var noCluster *Cluster
	if noCluster.raftReplicaAdmissionBlocked("node-a") {
		t.Fatal("nil cluster blocked admission")
	}
	if (&Cluster{}).raftReplicaBudget() != MaxMixedClusterNodes {
		t.Fatal("missing gossip did not use the small-cluster budget")
	}
	(&Cluster{}).logReplicaBudgetRefusal("node-a", "10.0.0.1:8300")
	if (&Cluster{}).peerRaftAddr("node-a") != "" {
		t.Fatal("missing gossip returned a raft address")
	}

	c := &Cluster{fsm: &placementFSM{placements: map[string]Placement{
		"sb": {SandboxID: "sb"},
	}}}
	if err := c.DeletePlacement(ctx, "  "); err != nil {
		t.Fatalf("blank delete = %v", err)
	}
	if c.SpecOf("sb") != nil {
		t.Fatal("placement without a spec returned one")
	}
	if err := c.ReassignPlacement(ctx, "sb", PlacementTarget{NodeID: "node-b"}); err == nil || !strings.Contains(err.Error(), "incarnation") {
		t.Fatalf("reassign = %v", err)
	}
	if err := c.applyCommand(ctx, command{Op: opDelete}); err == nil {
		t.Fatal("delete command without an incarnation was applied")
	}
}

func TestCoverage97GossipPeerRememberIOErrors(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&gossipPeerCache{path: filepath.Join(parent, "peers.json")}).remember([]string{"10.0.0.2:7946"}); err == nil {
		t.Fatal("remember into a file parent succeeded")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "peers.json")
	if err := os.MkdirAll(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (&gossipPeerCache{path: path}).remember([]string{"10.0.0.3:7946"}); err == nil {
		t.Fatal("remember over a directory temp path succeeded")
	}
}

func TestCoverage97NilReceiversAndCatalogGuards(t *testing.T) {
	ctx := context.Background()
	var agentNil *Agent
	agentNil.AttachRecreator(nil)
	if agentNil.currentRecreator() != nil {
		t.Fatal("nil agent returned a recreator")
	}
	if err := agentNil.DeletePlacement(ctx, "  "); err != nil {
		t.Fatalf("blank delete = %v", err)
	}
	if err := agentNil.PublishArtifactCatalog(ctx, ArtifactCatalogSnapshot{}); err == nil {
		t.Fatal("nil agent published a catalogue")
	}
	if _, err := agentNil.ArtifactCatalog(ctx, ArtifactCatalogRequest{}); err == nil {
		t.Fatal("nil agent read a catalogue")
	}

	var clusterNil *Cluster
	if err := clusterNil.PublishArtifactCatalog(ctx, ArtifactCatalogSnapshot{}); err == nil {
		t.Fatal("nil cluster published a catalogue")
	}
	if _, err := clusterNil.ArtifactCatalog(ctx, ArtifactCatalogRequest{}); err == nil {
		t.Fatal("nil cluster read a catalogue")
	}
	if err := clusterNil.ReassignStuckPlacement(ctx, "node-a", "sb", "inc"); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("nil reassign = %v", err)
	}
	if err := (&Cluster{fsm: &placementFSM{}}).ReassignStuckPlacement(ctx, "", "sb", "inc"); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("blank reassign = %v", err)
	}
	if got := (&Cluster{}).recreationCandidates(Placement{SecretRef: "ref"}); got != nil {
		t.Fatalf("candidates = %#v", got)
	}

	chunk := ArtifactCatalogSnapshot{Kind: ArtifactKindTemplate, NodeID: "node-a", Epoch: 1, Revision: 1, Rows: []ArtifactCatalogRow{{}}}
	if err := validateArtifactCatalogChunk(chunk); err == nil {
		t.Fatal("row without an id was accepted")
	}
	(&placementFSM{artifactCatalog: map[string]*artifactCatalogKindState{"wasm": nil}}).withdrawArtifactCatalogCoverageLocked("node-a")
	if (&placementFSM{}).artifactCatalogPublisherEpoch("wasm", "node-a") != 0 {
		t.Fatal("missing catalogue reported a publisher epoch")
	}
	clearPendingForPublication(nil, "node-a", 1, 1)

	(&recreateFailureTracker{}).markPermanent("sb")
	stuck := &Cluster{logger: slog.New(slog.DiscardHandler)}
	err := stuck.tryReassignStuckPlacement(ctx, "sb", Placement{Spec: &models.CreateSandboxRequest{
		Failover:              &models.Failover{Policy: models.FailoverPolicyRecreate},
		ImageDistributionMode: models.ImageDistributionLocalOnly,
	}})
	if !errors.Is(err, ErrNoReassignTarget) {
		t.Fatalf("stuck reassign = %v", err)
	}
}

func TestCoverage97CapacityLeaseAndReserveGuards(t *testing.T) {
	ctx := context.Background()
	admitter := capacity.New(capacity.HostInfo{CPUCores: 2}, capacity.Limits{}, nil)
	cache := &capacityLeaseCache{selfID: "self", admitter: admitter}
	cache.SetLocalTemplateCatalogProvider(func() ([]string, bool) { return []string{"tpl"}, true })
	cache.SetLocalWasmModuleIDsProvider(func() ([]string, bool) { return []string{"mod"}, true })
	cache.refreshLocal(time.Now())
	cache.recordResponsiveness("peer", false)
	(&capacityLeaseCache{}).recordFetchResult("peer", time.Now(), errors.New("down"))
	(&capacityLeaseCache{}).recordAttempt("peer", time.Now())

	leased := &Cluster{capacityLeases: &capacityLeaseCache{ttl: time.Millisecond}}
	if leased.capacityLeaseSweepBudget() != time.Second {
		t.Fatalf("budget = %s", leased.capacityLeaseSweepBudget())
	}
	var nilCluster *Cluster
	if _, err := nilCluster.fetchMemberCapacity(ctx, Member{}, 0); err == nil {
		t.Fatal("fetch with no peer url succeeded")
	}
	if err := (&Cluster{}).ReserveOnTarget(ctx, "sb", PlacementTarget{}, nil, PlacementSecrets{}, 0); err == nil {
		t.Fatal("zero ttl reservation succeeded")
	}
	if err := (&Cluster{}).ReserveBatchOnTargets(ctx, []PlacementReservation{{
		SandboxID: "sb",
		TTL:       time.Second,
		Secrets:   PlacementSecrets{Version: 1},
	}}); err == nil {
		t.Fatal("invalid batch secret succeeded")
	}

	dir := t.TempDir()
	recovery, err := newPlacementRecoveryFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "snapshots.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.readGCManifest(); err == nil {
		t.Fatal("corrupt gc manifest was accepted")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if err := recovery.RetainSnapshotRefs(nil); err == nil {
		t.Fatal("read-only recovery dir accepted a snapshot")
	}
}
