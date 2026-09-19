package service

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
)

type retirementCluster struct {
	*cluster.Noop
	mu      sync.Mutex
	members []cluster.Member
}

func (c *retirementCluster) LocalMembers() []cluster.Member {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]cluster.Member(nil), c.members...)
}

func (c *retirementCluster) Members() []cluster.Member { return c.LocalMembers() }

func newRetirementService(t *testing.T, cl cluster.Client) (*Service, *store.Store) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := &Service{cfg: config.Config{DBPath: dbPath, EnableCluster: cl != nil}, store: st}
	if cl != nil {
		svc.cluster = cl
	}
	return svc, st
}

// Membership disappearance is never cleanup success: a decommissioned node may
// still hold a disk full of ciphertext. The only sanctioned discharge besides
// an authenticated ACK is an explicit operator attestation naming the node.
func TestRetireNodeStorageRequiresADeadNode(t *testing.T) {
	cl := &retirementCluster{
		Noop: cluster.NewNoop("node-self", "http://node-self", ""),
		members: []cluster.Member{
			{NodeID: "node-self", Alive: true},
			{NodeID: "node-live", Alive: true},
			{NodeID: "node-gone", Alive: false},
		},
	}
	svc, _ := newRetirementService(t, cl)
	ctx := context.Background()

	if err := svc.RetireNodeStorage(ctx, "node-live", "op", "decom"); !errors.Is(err, ErrNodeStorageRetirementAlive) {
		t.Fatalf("attesting a live node = %v, want ErrNodeStorageRetirementAlive", err)
	}
	if err := svc.RetireNodeStorage(ctx, "node-self", "op", "decom"); !errors.Is(err, ErrNodeStorageRetirementAlive) {
		t.Fatalf("attesting self = %v, want refusal", err)
	}
	if err := svc.RetireNodeStorage(ctx, "", "op", ""); err == nil {
		t.Fatal("empty node id accepted")
	}
	if err := svc.RetireNodeStorage(ctx, "node-gone", "op", "disk shredded"); err != nil {
		t.Fatalf("attesting a dead node: %v", err)
	}

	recs, err := svc.ListNodeStorageRetirements(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(recs) != 1 || recs[0].NodeID != "node-gone" || recs[0].Actor != "op" || recs[0].Reason != "disk shredded" {
		t.Fatalf("retirements = %+v", recs)
	}
}

// A node that is alive again can ACK, so its attestation is withdrawn and its
// obligations become pending once more. This is also what stops a reused node
// id from inheriting a previous machine's attestation.
func TestLiveNodeRevokesItsStorageRetirement(t *testing.T) {
	cl := &retirementCluster{
		Noop:    cluster.NewNoop("node-self", "http://node-self", ""),
		members: []cluster.Member{{NodeID: "node-self", Alive: true}, {NodeID: "node-gone", Alive: false}},
	}
	svc, _ := newRetirementService(t, cl)
	ctx := context.Background()
	if err := svc.RetireNodeStorage(ctx, "node-gone", "op", ""); err != nil {
		t.Fatal(err)
	}

	cl.mu.Lock()
	cl.members[1].Alive = true
	cl.mu.Unlock()
	svc.reapLiveNodeStorageRetirements(ctx)

	recs, err := svc.ListNodeStorageRetirements(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("a node that came back alive kept its attestation: %+v", recs)
	}
}

// The attestation is fenced by the obligation's journalling time: obligations
// created afterwards belong to a different physical node behind a reused id
// and must still be ACK'd.
func TestDischargeIsFencedByObligationAge(t *testing.T) {
	attested := time.Now()
	retired := map[string]time.Time{"node-gone": attested}

	before := attested.Add(-time.Hour)
	pending, discharged := dischargeRetiredStorageRecipients([]string{"node-gone", "node-live"}, retired, before, nil)
	if len(discharged) != 1 || discharged[0] != "node-gone" {
		t.Fatalf("discharged = %v, want [node-gone]", discharged)
	}
	if len(pending) != 1 || pending[0] != "node-live" {
		t.Fatalf("pending = %v, want [node-live]", pending)
	}

	after := attested.Add(time.Hour)
	pending, discharged = dischargeRetiredStorageRecipients([]string{"node-gone"}, retired, after, nil)
	if len(discharged) != 0 {
		t.Fatalf("an obligation journalled AFTER the attestation was discharged (%v); a reused node id must inherit nothing", discharged)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %v, want the obligation retained", pending)
	}

	// No attestations at all: nothing changes.
	pending, discharged = dischargeRetiredStorageRecipients([]string{"node-a"}, nil, before, nil)
	if len(discharged) != 0 || len(pending) != 1 {
		t.Fatalf("pending=%v discharged=%v with no attestations", pending, discharged)
	}
}

// End to end: a pending obligation to a permanently lost node is retained
// until the attestation, then discharged — with evidence that says it was an
// attestation, never an ACK.
func TestDeleteOutboxDischargedByStorageRetirement(t *testing.T) {
	const (
		sandboxID     = "sb-retired"
		incarnationID = "inc-1"
	)
	cl := &retirementCluster{
		Noop: cluster.NewNoop("node-self", "http://node-self", ""),
		members: []cluster.Member{
			{NodeID: "node-self", Alive: true},
			{NodeID: "node-gone", Alive: false},
		},
	}
	svc, st := newRetirementService(t, cl)
	svc.testSecretPeerPusher = &fakePeerPusher{deleteErr: errors.New("peer unreachable")}
	t.Cleanup(svc.CloseSecretAuditSink)
	ctx := context.Background()

	if err := st.UpsertSecretDeleteOutbox(ctx, sandboxID, incarnationID, []string{"node-gone"}, 1); err != nil {
		t.Fatalf("seed outbox: %v", err)
	}

	rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, sandboxID, incarnationID)
	if err != nil || rec == nil {
		t.Fatalf("outbox row: %v", err)
	}
	// Before any attestation the obligation survives an unreachable peer.
	svc.reconcileSecretDeleteOutboxRecord(ctx, rec, nil)
	rec, err = st.GetSecretDeleteOutboxForIncarnation(ctx, sandboxID, incarnationID)
	if err != nil {
		t.Fatal(err)
	}
	if rec == nil || len(rec.Recipients) != 1 {
		t.Fatalf("an unreachable peer discharged the obligation: %+v", rec)
	}

	if err := svc.RetireNodeStorage(ctx, "node-gone", "op", "disk destroyed"); err != nil {
		t.Fatal(err)
	}
	svc.reconcileSecretDeleteOutboxRecord(ctx, rec, nil)

	rec, err = st.GetSecretDeleteOutboxForIncarnation(ctx, sandboxID, incarnationID)
	if err != nil {
		t.Fatal(err)
	}
	if rec != nil && len(rec.Recipients) != 0 {
		t.Fatalf("obligation still pending after the attestation: %+v", rec)
	}
}

// The evidence must distinguish "the holder confirmed deletion" from "an
// operator attested the disk is gone".
func TestStorageRetirementDischargeIsAudited(t *testing.T) {
	cl := &retirementCluster{
		Noop:    cluster.NewNoop("node-self", "http://node-self", ""),
		members: []cluster.Member{{NodeID: "node-self", Alive: true}},
	}
	svc, _ := newRetirementService(t, cl)
	sink := &retirementAuditSink{}
	// Install the sink directly: secretAuditOnce guards construction, so
	// consuming it here keeps ensureSecretAuditSink from replacing this.
	svc.secretAudit = sink
	svc.secretAuditOnce.Do(func() {})
	t.Cleanup(svc.CloseSecretAuditSink)

	svc.recordStorageRetirementDischarge("sb-1", "inc-1", 3, []string{"node-gone"})

	events := sink.events()
	if len(events) != 1 {
		t.Fatalf("emitted %d audit events, want 1", len(events))
	}
	ev := events[0]
	if ev.Reason != secretAuditReasonStorageRetired {
		t.Fatalf("reason = %q, want %q — evidence must not read as an ACK", ev.Reason, secretAuditReasonStorageRetired)
	}
	if ev.NodeID != "node-gone" || ev.SandboxID != "sb-1" || ev.IncarnationID != "inc-1" {
		t.Fatalf("event = %+v, want it tied to the exact identity and obligation", ev)
	}
	if secretObligationsDischargedTotal.Value() == 0 {
		t.Fatal("discharge counter did not move; operators need to see unconfirmed deletions")
	}
}

// retirementAuditSink captures emitted evidence.
type retirementAuditSink struct {
	mu   sync.Mutex
	seen []SecretAuditEvent
}

func (s *retirementAuditSink) Emit(ev SecretAuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, ev)
}

func (s *retirementAuditSink) Close() {}

func (s *retirementAuditSink) events() []SecretAuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]SecretAuditEvent(nil), s.seen...)
}

// An upsert MERGES recipients into an existing row and deliberately keeps the
// original created_at, so the row-wide timestamp describes the oldest
// obligation in the row — not the one being judged. A recipient added after
// the attestation inherited that older age and was discharged without an ACK.
func TestDischargeUsesPerRecipientCopyProvenance(t *testing.T) {
	attested := time.Now()
	retired := map[string]time.Time{"node-gone": attested}
	rowCreatedAt := attested.Add(-time.Hour)

	for _, tc := range []struct {
		name          string
		copiedAt      map[string]time.Time
		wantDischarge bool
	}{
		{
			name:          "copy predates the attestation",
			copiedAt:      map[string]time.Time{"node-gone": attested.Add(-30 * time.Minute)},
			wantDischarge: true,
		},
		{
			name:          "copy handed over after the attestation",
			copiedAt:      map[string]time.Time{"node-gone": attested.Add(time.Minute)},
			wantDischarge: false,
		},
		{
			name:          "no provenance falls back to the row age",
			copiedAt:      nil,
			wantDischarge: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pending, discharged := dischargeRetiredStorageRecipients([]string{"node-gone"}, retired, rowCreatedAt, tc.copiedAt)
			if tc.wantDischarge && len(discharged) != 1 {
				t.Fatalf("discharged = %v, pending = %v; the copy existed when the operator attested", discharged, pending)
			}
			if !tc.wantDischarge && len(discharged) != 0 {
				t.Fatalf("discharged = %v; a copy handed over after the attestation belongs to a reused node id and is still owed an ACK", discharged)
			}
		})
	}
}

// The store has to carry that provenance per recipient, across the merge that
// preserves the row's creation time.
func TestSecretDeleteOutboxKeepsPerRecipientProvenance(t *testing.T) {
	_, st := newRetirementService(t, nil)
	ctx := context.Background()

	old := time.Now().Add(-time.Hour).UTC()
	if err := st.UpsertSecretDeleteOutboxCopiedAt(ctx, "sb-prov", "inc", []string{"peer-old"}, 1, old); err != nil {
		t.Fatalf("seed: %v", err)
	}
	later := time.Now().UTC()
	if err := st.UpsertSecretDeleteOutboxCopiedAt(ctx, "sb-prov", "inc", []string{"peer-new"}, 2, later); err != nil {
		t.Fatalf("merge: %v", err)
	}

	rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-prov", "inc")
	if err != nil || rec == nil {
		t.Fatalf("read row: %v", err)
	}
	if len(rec.Recipients) != 2 {
		t.Fatalf("recipients = %v, want both", rec.Recipients)
	}
	if got := rec.RecipientCopiedAt["peer-old"]; !got.Equal(old) {
		t.Fatalf("peer-old provenance = %v, want %v (the merge must not re-date an existing obligation)", got, old)
	}
	if got := rec.RecipientCopiedAt["peer-new"]; got.Before(later) {
		t.Fatalf("peer-new provenance = %v, want >= %v (it was added now, not when the row was created)", got, later)
	}
	if !rec.CreatedAt.Before(later) {
		t.Fatal("the fixture no longer models a merge into an older row")
	}
}

// A recipient merged in AFTER an attestation must not be discharged by it,
// even though the row it joins is older than the attestation.
func TestRetirementDoesNotDischargeRecipientAddedAfterAttestation(t *testing.T) {
	cl := &retirementCluster{
		Noop:    cluster.NewNoop("node-self", "http://node-self", ""),
		members: []cluster.Member{{NodeID: "node-self", Alive: true}, {NodeID: "node-gone", Alive: false}},
	}
	svc, st := newRetirementService(t, cl)
	svc.testSecretPeerPusher = &fakePeerPusher{deleteErr: errors.New("peer unreachable")}
	t.Cleanup(svc.CloseSecretAuditSink)
	ctx := context.Background()

	// An older obligation for an unrelated peer creates the row.
	if err := st.UpsertSecretDeleteOutboxCopiedAt(ctx, "sb-merge", "inc", []string{"other-peer"}, 1, time.Now().Add(-time.Hour).UTC()); err != nil {
		t.Fatal(err)
	}
	if err := svc.RetireNodeStorage(ctx, "node-gone", "op", "disk destroyed"); err != nil {
		t.Fatal(err)
	}
	// A NEW copy is handed to the reused node id after the attestation.
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-merge", "inc", []string{"node-gone"}, 2); err != nil {
		t.Fatal(err)
	}

	rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-merge", "inc")
	if err != nil || rec == nil {
		t.Fatalf("outbox row: %v", err)
	}
	svc.reconcileSecretDeleteOutboxRecord(ctx, rec, nil)

	after, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-merge", "inc")
	if err != nil {
		t.Fatal(err)
	}
	if after == nil || !slices.Contains(after.Recipients, "node-gone") {
		t.Fatal("an obligation created after the attestation was discharged without an ACK; it inherited the older row's creation time")
	}
}

// The reverse: a copy that existed before the disk was destroyed, whose
// deletion is journalled afterwards. That job belongs to the destroyed disk
// and must be dischargeable, or it pins the row forever against a node that
// can never ACK.
func TestRetirementDischargesCopyThatPredatesDestruction(t *testing.T) {
	cl := &retirementCluster{
		Noop:    cluster.NewNoop("node-self", "http://node-self", ""),
		members: []cluster.Member{{NodeID: "node-self", Alive: true}, {NodeID: "node-gone", Alive: false}},
	}
	svc, st := newRetirementService(t, cl)
	svc.testSecretPeerPusher = &fakePeerPusher{deleteErr: errors.New("disk permanently destroyed")}
	t.Cleanup(svc.CloseSecretAuditSink)
	ctx := context.Background()

	// The ciphertext is distributed first...
	seedClusterSecretRow(t, st, "old-secret", []string{"node-self", "node-gone"})
	// ...the operator attests the disk destroyed...
	if err := svc.RetireNodeStorage(ctx, "node-gone", "op", "disk destroyed"); err != nil {
		t.Fatal(err)
	}
	// ...and only then is the sandbox deleted, journalling the obligation.
	if _, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "old-secret", "inc-old-secret", []string{"node-gone"}); err != nil {
		t.Fatal(err)
	}

	rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "old-secret", "inc-old-secret")
	if err != nil || rec == nil {
		t.Fatalf("outbox row: %v", err)
	}
	if !rec.CreatedAt.After(svc.nodeStorageRetirements(ctx)["node-gone"]) {
		t.Fatal("the fixture must journal the deletion after the attestation")
	}
	svc.reconcileSecretDeleteOutboxRecord(ctx, rec, nil)

	after, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "old-secret", "inc-old-secret")
	if err != nil {
		t.Fatal(err)
	}
	if after != nil && slices.Contains(after.Recipients, "node-gone") {
		t.Fatal("a copy that existed before the disk was destroyed stayed pinned; the row's creation time is not the copy's provenance")
	}
}

// replicatedRetirementRegistry stands in for the placement FSM's attestation
// map: one shared, authoritative set that every node in the cluster reads,
// however many local stores there are.
type replicatedRetirementRegistry struct {
	mu      sync.Mutex
	entries map[string]cluster.NodeStorageRetirement
	err     error
}

func (r *replicatedRetirementRegistry) retire(rec cluster.NodeStorageRetirement) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = map[string]cluster.NodeStorageRetirement{}
	}
	r.entries[rec.NodeID] = rec
}

type registryCluster struct {
	*retirementCluster
	registry *replicatedRetirementRegistry
}

func (c *registryCluster) RetireNodeStorage(_ context.Context, nodeID, actor, reason string, attestedAt time.Time) error {
	c.registry.retire(cluster.NodeStorageRetirement{
		NodeID: nodeID, Actor: actor, Reason: reason, AttestedUnix: attestedAt.UTC().Unix(),
	})
	return nil
}

func (c *registryCluster) RevokeNodeStorageRetirement(_ context.Context, nodeID string) error {
	c.registry.mu.Lock()
	defer c.registry.mu.Unlock()
	delete(c.registry.entries, nodeID)
	return nil
}

func (c *registryCluster) NodeStorageRetirements(context.Context) ([]cluster.NodeStorageRetirement, error) {
	c.registry.mu.Lock()
	defer c.registry.mu.Unlock()
	if c.registry.err != nil {
		return nil, c.registry.err
	}
	out := make([]cluster.NodeStorageRetirement, 0, len(c.registry.entries))
	for _, rec := range c.registry.entries {
		out = append(out, rec)
	}
	return out, nil
}

func newRegistryCluster(self string, registry *replicatedRetirementRegistry, members []cluster.Member) *registryCluster {
	return &registryCluster{
		retirementCluster: &retirementCluster{Noop: cluster.NewNoop(self, "http://"+self, ""), members: members},
		registry:          registry,
	}
}

// The operator's request lands on whichever node answers the API; the deletion
// obligations it discharges live in the owner's outbox. Writing the
// attestation to the entry node's own SQLite table means no owner ever learns,
// and list/revoke through another entry node sees a different set.
func TestNodeStorageRetirementReachesTheObligationOwner(t *testing.T) {
	registry := &replicatedRetirementRegistry{}
	members := []cluster.Member{{NodeID: "node-gone", Alive: false}}
	entry, _ := newRetirementService(t, newRegistryCluster("ingress", registry, members))
	owner, ownerStore := newRetirementService(t, newRegistryCluster("worker", registry, members))
	owner.testSecretPeerPusher = &fakePeerPusher{deleteErr: errors.New("peer unreachable")}
	t.Cleanup(owner.CloseSecretAuditSink)
	ctx := context.Background()

	// The owner holds the obligation.
	if err := ownerStore.UpsertSecretDeleteOutboxCopiedAt(ctx, "sb-owned", "inc", []string{"node-gone"}, 1, time.Now().Add(-time.Hour).UTC()); err != nil {
		t.Fatal(err)
	}
	// The operator attests through the ingress node.
	if err := entry.RetireNodeStorage(ctx, "node-gone", "op", "disk destroyed"); err != nil {
		t.Fatalf("RetireNodeStorage: %v", err)
	}

	// Every entry node must report the same set.
	onEntry, err := entry.ListNodeStorageRetirements(ctx)
	if err != nil {
		t.Fatal(err)
	}
	onOwner, err := owner.ListNodeStorageRetirements(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(onEntry) != 1 || len(onOwner) != 1 {
		t.Fatalf("entry sees %d attestations, owner sees %d; a retirement recorded through one node must be visible from another", len(onEntry), len(onOwner))
	}

	rec, err := ownerStore.GetSecretDeleteOutboxForIncarnation(ctx, "sb-owned", "inc")
	if err != nil || rec == nil {
		t.Fatalf("outbox row: %v", err)
	}
	owner.reconcileSecretDeleteOutboxRecord(ctx, rec, nil)

	after, err := ownerStore.GetSecretDeleteOutboxForIncarnation(ctx, "sb-owned", "inc")
	if err != nil {
		t.Fatal(err)
	}
	if after != nil && len(after.Recipients) > 0 {
		t.Fatal("the owner never learned about the attestation, so its obligation stays pending forever against a destroyed disk")
	}

	// Revoking through the owner node must be visible to the entry node too.
	removed, err := owner.RevokeNodeStorageRetirement(ctx, "node-gone")
	if err != nil || !removed {
		t.Fatalf("revoke through the owner: removed=%v err=%v", removed, err)
	}
	if left, err := entry.ListNodeStorageRetirements(ctx); err != nil || len(left) != 0 {
		t.Fatalf("entry still reports %d attestations after a revoke elsewhere (err=%v)", len(left), err)
	}
}

// An unreachable registry is not an empty registry: discharging is
// irreversible, so a failed read must leave obligations pending.
func TestNodeStorageRetirementReadFailureKeepsObligationsPending(t *testing.T) {
	registry := &replicatedRetirementRegistry{err: errors.New("control plane unreachable")}
	svc, st := newRetirementService(t, newRegistryCluster("worker", registry, []cluster.Member{{NodeID: "node-gone", Alive: false}}))
	svc.testSecretPeerPusher = &fakePeerPusher{deleteErr: errors.New("peer unreachable")}
	t.Cleanup(svc.CloseSecretAuditSink)
	ctx := context.Background()

	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-unreachable", "inc", []string{"node-gone"}, 1); err != nil {
		t.Fatal(err)
	}
	rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-unreachable", "inc")
	if err != nil || rec == nil {
		t.Fatalf("outbox row: %v", err)
	}
	svc.reconcileSecretDeleteOutboxRecord(ctx, rec, nil)

	after, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-unreachable", "inc")
	if err != nil {
		t.Fatal(err)
	}
	if after == nil || len(after.Recipients) != 1 {
		t.Fatal("a failed attestation read discharged the obligation; an unavailable control plane must never read as 'no attestations'")
	}
}

// flakyDurableAuditSink fails its durable writes until healed.
type flakyDurableAuditSink struct {
	mu       sync.Mutex
	failing  bool
	attempts int
	seen     []SecretAuditEvent
}

func (s *flakyDurableAuditSink) Emit(ev SecretAuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, ev)
}

func (s *flakyDurableAuditSink) EmitDurable(ev SecretAuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if s.failing {
		return errors.New("audit disk full")
	}
	s.seen = append(s.seen, ev)
	return nil
}

func (s *flakyDurableAuditSink) Close() {}

func (s *flakyDurableAuditSink) persisted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

func (s *flakyDurableAuditSink) heal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failing = false
}

// A discharge with no journalled evidence is an undocumented deletion. The
// obligation is the only thing that brings it back for another attempt, and
// the node-level attestation cannot say which sandbox, incarnation and
// generation it covered — so a failed audit write must keep the obligation.
func TestStorageRetirementDischargeWaitsForDurableEvidence(t *testing.T) {
	cl := &retirementCluster{
		Noop:    cluster.NewNoop("node-self", "http://node-self", ""),
		members: []cluster.Member{{NodeID: "node-self", Alive: true}, {NodeID: "node-gone", Alive: false}},
	}
	svc, st := newRetirementService(t, cl)
	svc.cfg.EnterpriseMode = true
	sink := &flakyDurableAuditSink{failing: true}
	svc.secretAudit = sink
	svc.secretAuditOnce.Do(func() {})
	t.Cleanup(svc.CloseSecretAuditSink)
	ctx := context.Background()

	if err := st.UpsertSecretDeleteOutboxCopiedAt(ctx, "sb-evidence", "inc", []string{"node-gone"}, 1, time.Now().Add(-time.Hour).UTC()); err != nil {
		t.Fatal(err)
	}
	if err := svc.RetireNodeStorage(ctx, "node-gone", "op", "disk destroyed"); err != nil {
		t.Fatal(err)
	}

	rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-evidence", "inc")
	if err != nil || rec == nil {
		t.Fatalf("outbox row: %v", err)
	}
	svc.reconcileSecretDeleteOutboxRecord(ctx, rec, nil)

	after, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-evidence", "inc")
	if err != nil {
		t.Fatal(err)
	}
	if after == nil || len(after.Recipients) != 1 {
		t.Fatal("the obligation was cleared although its discharge evidence was never persisted; nothing will retry it and no record says what was discharged")
	}
	if sink.persisted() != 0 {
		t.Fatal("a failed durable write must not count as evidence")
	}

	// Once the sink recovers, the retained obligation completes the discharge.
	sink.heal()
	rec, err = st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-evidence", "inc")
	if err != nil || rec == nil {
		t.Fatalf("outbox row: %v", err)
	}
	svc.reconcileSecretDeleteOutboxRecord(ctx, rec, nil)

	healed, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-evidence", "inc")
	if err != nil {
		t.Fatal(err)
	}
	if healed != nil && len(healed.Recipients) > 0 {
		t.Fatal("the retained obligation was not discharged after the audit sink recovered")
	}
	if sink.persisted() != 1 {
		t.Fatalf("persisted %d evidence records, want 1", sink.persisted())
	}
}

// A partial failure must clear exactly the recipients whose evidence landed.
func TestStorageRetirementDischargeIsPartialWhenOnlySomeEvidencePersists(t *testing.T) {
	cl := &retirementCluster{
		Noop:    cluster.NewNoop("node-self", "http://node-self", ""),
		members: []cluster.Member{{NodeID: "node-self", Alive: true}},
	}
	svc, _ := newRetirementService(t, cl)
	svc.cfg.EnterpriseMode = true
	sink := &selectiveDurableAuditSink{failFor: "node-b"}
	svc.secretAudit = sink
	svc.secretAuditOnce.Do(func() {})
	t.Cleanup(svc.CloseSecretAuditSink)

	recorded := svc.recordStorageRetirementDischarge("sb-partial", "inc", 2, []string{"node-a", "node-b"})
	if len(recorded) != 1 || recorded[0] != "node-a" {
		t.Fatalf("recorded = %v, want only the recipient whose evidence persisted", recorded)
	}
}

type selectiveDurableAuditSink struct {
	failFor string
}

func (s *selectiveDurableAuditSink) Emit(SecretAuditEvent) {}
func (s *selectiveDurableAuditSink) EmitDurable(ev SecretAuditEvent) error {
	if ev.NodeID == s.failFor {
		return errors.New("audit disk full")
	}
	return nil
}
func (s *selectiveDurableAuditSink) Close() {}

// A partial discharge — some recipients' evidence journalled, some not —
// must remove exactly the journalled ones from the durable obligation.
func TestReconcileDischargesOnlyTheRecipientsWithEvidence(t *testing.T) {
	cl := &retirementCluster{
		Noop: cluster.NewNoop("node-self", "http://node-self", ""),
		members: []cluster.Member{
			{NodeID: "node-self", Alive: true},
			{NodeID: "node-a", Alive: false},
			{NodeID: "node-b", Alive: false},
		},
	}
	svc, st := newRetirementService(t, cl)
	svc.cfg.EnterpriseMode = true
	svc.secretAudit = &selectiveDurableAuditSink{failFor: "node-b"}
	svc.secretAuditOnce.Do(func() {})
	svc.testSecretPeerPusher = &fakePeerPusher{deleteErr: errors.New("peer unreachable")}
	t.Cleanup(svc.CloseSecretAuditSink)
	ctx := context.Background()

	copied := time.Now().Add(-time.Hour).UTC()
	if err := st.UpsertSecretDeleteOutboxCopiedAt(ctx, "sb-partial", "inc", []string{"node-a", "node-b"}, 1, copied); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"node-a", "node-b"} {
		if err := svc.RetireNodeStorage(ctx, id, "op", "disk destroyed"); err != nil {
			t.Fatal(err)
		}
	}

	rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-partial", "inc")
	if err != nil || rec == nil {
		t.Fatalf("outbox row: %v", err)
	}
	svc.reconcileSecretDeleteOutboxRecord(ctx, rec, nil)

	after, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-partial", "inc")
	if err != nil {
		t.Fatal(err)
	}
	if after == nil || len(after.Recipients) != 1 || after.Recipients[0] != "node-b" {
		t.Fatalf("remaining recipients = %+v, want only the one whose evidence failed", after)
	}
}

// withoutRecipients is the partial-discharge bookkeeping: it drops exactly
// the journalled ids and keeps the order of the rest.
func TestWithoutRecipients(t *testing.T) {
	all := []string{"a", "b", "c"}
	if got := withoutRecipients(all, nil); len(got) != 3 {
		t.Fatalf("no drops changed the set: %v", got)
	}
	got := withoutRecipients(all, []string{" b "})
	if len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Fatalf("remaining = %v, want [a c]", got)
	}
}

// Standalone mode keeps using the local table, and a service with no store
// refuses rather than pretending.
func TestNodeStorageRetirementStandaloneAndUnconfigured(t *testing.T) {
	ctx := context.Background()
	var none *Service
	if err := none.RetireNodeStorage(ctx, "n", "op", ""); err == nil {
		t.Fatal("attestation without a store was accepted")
	}
	if _, err := none.RevokeNodeStorageRetirement(ctx, "n"); err == nil {
		t.Fatal("revoke without a store was accepted")
	}
	if _, err := none.ListNodeStorageRetirements(ctx); err == nil {
		t.Fatal("list without a store was accepted")
	}
	if got := none.nodeStorageRetirements(ctx); got != nil {
		t.Fatalf("retirements without a store = %v", got)
	}

	svc, _ := newRetirementService(t, nil)
	if err := svc.RetireNodeStorage(ctx, "node-gone", "op", "disk destroyed"); err != nil {
		t.Fatalf("standalone attestation: %v", err)
	}
	if got := svc.nodeStorageRetirements(ctx); len(got) != 1 {
		t.Fatalf("standalone retirements = %v, want the local row", got)
	}
	removed, err := svc.RevokeNodeStorageRetirement(ctx, "node-gone")
	if err != nil || !removed {
		t.Fatalf("standalone revoke: removed=%v err=%v", removed, err)
	}
	if removed, err := svc.RevokeNodeStorageRetirement(ctx, "node-gone"); err != nil || removed {
		t.Fatalf("second revoke: removed=%v err=%v (must be idempotent)", removed, err)
	}
}
