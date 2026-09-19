package service

import (
	"context"
	"errors"
	"path/filepath"
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
	pending, discharged := dischargeRetiredStorageRecipients([]string{"node-gone", "node-live"}, retired, before)
	if len(discharged) != 1 || discharged[0] != "node-gone" {
		t.Fatalf("discharged = %v, want [node-gone]", discharged)
	}
	if len(pending) != 1 || pending[0] != "node-live" {
		t.Fatalf("pending = %v, want [node-live]", pending)
	}

	after := attested.Add(time.Hour)
	pending, discharged = dischargeRetiredStorageRecipients([]string{"node-gone"}, retired, after)
	if len(discharged) != 0 {
		t.Fatalf("an obligation journalled AFTER the attestation was discharged (%v); a reused node id must inherit nothing", discharged)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %v, want the obligation retained", pending)
	}

	// No attestations at all: nothing changes.
	pending, discharged = dischargeRetiredStorageRecipients([]string{"node-a"}, nil, before)
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
