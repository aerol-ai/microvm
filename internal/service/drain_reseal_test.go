package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// drainingResealCluster answers drain questions per node only — the fallback
// path every client without DrainedNodes takes.
type drainingResealCluster struct {
	*resealPlacementCluster
	drained map[string]bool
}

func (c *drainingResealCluster) IsNodeDrained(id string) bool { return c.drained[id] }

// drainingResealSetCluster also serves the whole set in one read, the way the
// FSM and the agent's cached view do.
type drainingResealSetCluster struct {
	*drainingResealCluster
}

func (c *drainingResealSetCluster) DrainedNodes() map[string]bool { return c.drained }

var _ cluster.DrainedNodesReader = (*drainingResealSetCluster)(nil)

func drainTestMembers() []cluster.Member {
	return []cluster.Member{
		{NodeID: "node-a", Alive: true, Role: config.NodeRoleMixed},
		{NodeID: "held-b", Alive: true, Role: config.NodeRoleWorker},
		{NodeID: "live-c", Alive: true, Role: config.NodeRoleWorker},
		{NodeID: "live-d", Alive: true, Role: config.NodeRoleWorker},
	}
}

// UC-122 offline. A holder that is drained but perfectly healthy must be
// resealed away from; before the fix only a holder gossip reported DEAD
// triggered a reseal, so the drained node kept its copy forever (T18).
func TestResealMovesTheCopyOffADrainedHolder(t *testing.T) {
	for _, tc := range []struct {
		name       string
		drained    map[string]bool
		wholeSet   bool
		wantReseal bool
	}{
		{name: "drained holder, whole-set client", drained: map[string]bool{"held-b": true}, wholeSet: true, wantReseal: true},
		{name: "drained holder, per-node client", drained: map[string]bool{"held-b": true}, wantReseal: true},
		// The control: the same healthy, fully-replicated set with nothing
		// drained must NOT reseal, or the fix is just a reseal-every-tick.
		{name: "nothing drained is left alone", drained: nil, wholeSet: true, wantReseal: false},
		// A drained node that holds no copy is not this sandbox's problem.
		{name: "a drained non-holder changes nothing", drained: map[string]bool{"live-d": true}, wholeSet: true, wantReseal: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			sandboxID := "sb-drain-reseal"
			base := cluster.Placement{
				SandboxID: sandboxID, OwnerNodeID: "node-a", IncarnationID: "inc-a",
				SecretRecipients: []string{"node-a", "held-b", "live-c"},
				SecretRef:        secrets.FormatRef(sandboxID, "inc-a", secrets.RefVersion),
				SecretVersion:    secrets.RefVersion, SecretSealGeneration: 1,
			}
			rpc := &resealPlacementCluster{Noop: cluster.NewNoop("node-a", "http://a", ""), placement: base, members: drainTestMembers()}
			per := &drainingResealCluster{resealPlacementCluster: rpc, drained: tc.drained}
			var cl cluster.Client = per
			if tc.wholeSet {
				cl = &drainingResealSetCluster{drainingResealCluster: per}
			}
			st := openSealTestStore(t)
			cipher := newTestCipher(t)
			svc := &Service{
				cfg: config.Config{SecretRecipientBackupCount: 2}, cipher: cipher, store: st, cluster: cl,
				secretProvider:       secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
				testSecretPeerPusher: &fakePeerPusher{acked: []string{"live-c", "live-d"}},
				logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
			}
			sealCtx := secrets.ContextWithIncarnationID(ctx, "inc-a")
			handle, err := svc.secretProvider.Put(sealCtx, sandboxID, secrets.Secrets{Env: map[string]string{"TOKEN": "secret"}}, base.SecretRecipients)
			if err != nil {
				t.Fatal(err)
			}
			rpc.mu.Lock()
			rpc.placement.SecretRef, rpc.placement.SecretVersion, rpc.placement.SecretSealGeneration = handle.Ref, handle.Version, handle.SealGeneration
			rpc.mu.Unlock()
			clearSecretFanoutHolders(sandboxID)
			t.Cleanup(func() { clearSecretFanoutHolders(sandboxID) })
			resetSecretHoldersForGeneration(sandboxID, "inc-a", handle.SealGeneration, "node-a")
			setSecretHolderTargets(sandboxID, "inc-a", handle.SealGeneration, base.SecretRecipients)

			if err := svc.expandAndResealDeadSecretTargets(ctx, sandboxID); err != nil {
				t.Fatalf("reseal: %v", err)
			}
			rpc.mu.Lock()
			defer rpc.mu.Unlock()
			if !tc.wantReseal {
				if rpc.updateCalls != 0 {
					t.Fatalf("resealed (%d updates, recipients %v) with no drained holder", rpc.updateCalls, rpc.placement.SecretRecipients)
				}
				return
			}
			if rpc.updateCalls != 1 {
				t.Fatalf("drained holder was not resealed away from: updates=%d recipients=%v", rpc.updateCalls, rpc.placement.SecretRecipients)
			}
			if slices.Contains(rpc.placement.SecretRecipients, "held-b") {
				t.Fatalf("the drained holder is still a recipient: %v", rpc.placement.SecretRecipients)
			}
			if !slices.Contains(rpc.placement.SecretRecipients, "node-a") || len(rpc.placement.SecretRecipients) != 3 {
				t.Fatalf("reseal must keep the owner and restore two backups: %v", rpc.placement.SecretRecipients)
			}
		})
	}
}

// New copies never land on a drained node — except the owner itself, which
// must keep its copy until its sandbox moves.
func TestSelectReplacementRecipientsSkipsDrainedNodes(t *testing.T) {
	rpc := &resealPlacementCluster{Noop: cluster.NewNoop("node-a", "", ""), members: drainTestMembers()}
	for _, tc := range []struct {
		name    string
		drained map[string]bool
	}{
		{name: "drained backup is skipped", drained: map[string]bool{"held-b": true}},
		{name: "a drained owner still keeps its copy", drained: map[string]bool{"held-b": true, "node-a": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl := &drainingResealSetCluster{&drainingResealCluster{resealPlacementCluster: rpc, drained: tc.drained}}
			svc := &Service{cfg: config.Config{SecretRecipientBackupCount: 2}, cluster: cl}
			got := svc.selectReplacementRecipients("sb", "node-a", 2)
			if slices.Contains(got, "held-b") {
				t.Fatalf("drained node chosen as a recipient: %v", got)
			}
			if !slices.Contains(got, "node-a") {
				t.Fatalf("owner dropped: %v", got)
			}
		})
	}
}

func TestDrainedNodeSetFallsBackPerNode(t *testing.T) {
	if drainedNodeSet(nil, []string{"a"}) != nil {
		t.Fatal("nil client must report nothing drained")
	}
	per := &drainingResealCluster{resealPlacementCluster: &resealPlacementCluster{Noop: cluster.NewNoop("n", "", "")}, drained: map[string]bool{"b": true}}
	got := drainedNodeSet(per, []string{"a", "b", " "})
	if len(got) != 1 || !got["b"] {
		t.Fatalf("per-node fallback = %v, want only b", got)
	}
	if drainedNodeSet(per, []string{"a"}) != nil {
		t.Fatal("no drained id should yield a nil set")
	}
}

// The same drain, driven through the holder-refresh pass that SCHEDULES the
// reseal in production. The first fix made the reseal drain-aware but left
// this pass on plain gossip liveness: it judged a drained holder healthy,
// never scheduled the reseal, and UC-122 still failed live while the direct
// test above passed (T18 round 2).
func TestHolderRefreshSchedulesTheResealForADrainedHolder(t *testing.T) {
	for _, tc := range []struct {
		name       string
		drained    map[string]bool
		wantReseal bool
	}{
		{name: "drained holder is scheduled and resealed away from", drained: map[string]bool{"held-b": true}, wantReseal: true},
		{name: "nothing drained, nothing scheduled", drained: nil, wantReseal: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			const sandboxID = "sb-drain-refresh"
			base := cluster.Placement{
				SandboxID: sandboxID, OwnerNodeID: "node-a", IncarnationID: "inc-a",
				SecretRecipients: []string{"node-a", "held-b", "live-c"},
				SecretRef:        secrets.FormatRef(sandboxID, "inc-a", secrets.RefVersion),
				SecretVersion:    secrets.RefVersion, SecretSealGeneration: 1,
			}
			rpc := &resealPlacementCluster{Noop: cluster.NewNoop("node-a", "http://a", ""), placement: base, members: drainTestMembers()}
			cl := &drainingResealSetCluster{&drainingResealCluster{resealPlacementCluster: rpc, drained: tc.drained}}
			st := openSealTestStore(t)
			cipher := newTestCipher(t)
			svc := &Service{
				cfg: config.Config{SecretRecipientBackupCount: 2}, cipher: cipher, store: st, cluster: cl,
				secretProvider:       secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
				testSecretPeerPusher: &fakePeerPusher{acked: []string{"live-c", "live-d"}},
				logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
			}
			sealCtx := secrets.ContextWithIncarnationID(ctx, "inc-a")
			handle, err := svc.secretProvider.Put(sealCtx, sandboxID, secrets.Secrets{Env: map[string]string{"TOKEN": "secret"}}, base.SecretRecipients)
			if err != nil {
				t.Fatal(err)
			}
			rpc.mu.Lock()
			rpc.placement.SecretRef, rpc.placement.SecretVersion, rpc.placement.SecretSealGeneration = handle.Ref, handle.Version, handle.SealGeneration
			rpc.mu.Unlock()
			clearSecretFanoutHolders(sandboxID)
			t.Cleanup(func() { clearSecretFanoutHolders(sandboxID) })
			resetSecretHoldersForGeneration(sandboxID, "inc-a", handle.SealGeneration, "node-a")
			setSecretHolderTargets(sandboxID, "inc-a", handle.SealGeneration, base.SecretRecipients)

			svc.refreshSecretHolderPossession(ctx)

			rpc.mu.Lock()
			defer rpc.mu.Unlock()
			if !tc.wantReseal {
				if rpc.updateCalls != 0 {
					t.Fatalf("refresh resealed a healthy set: updates=%d recipients=%v", rpc.updateCalls, rpc.placement.SecretRecipients)
				}
				return
			}
			if rpc.updateCalls != 1 || slices.Contains(rpc.placement.SecretRecipients, "held-b") {
				t.Fatalf("refresh did not reseal away from the drained holder: updates=%d recipients=%v", rpc.updateCalls, rpc.placement.SecretRecipients)
			}
		})
	}
}

// drainAllBackupsFixture is a 3-node cluster whose HA sandbox holds a sealed
// copy on every node (owner node-a plus backups held-b and held-c) — the
// UC-124 topology before its two concurrent drains.
type drainAllBackupsFixture struct {
	svc    *Service
	rpc    *resealPlacementCluster
	cl     *drainingResealSetCluster
	pusher *fakePeerPusher
	bag    secrets.Secrets
}

func newDrainAllBackupsFixture(t *testing.T, sandboxID string, drained map[string]bool, acked []string) *drainAllBackupsFixture {
	t.Helper()
	ctx := context.Background()
	base := cluster.Placement{
		SandboxID: sandboxID, OwnerNodeID: "node-a", IncarnationID: "inc-a",
		SecretRecipients: []string{"node-a", "held-b", "held-c"},
		SecretRef:        secrets.FormatRef(sandboxID, "inc-a", secrets.RefVersion),
		SecretVersion:    secrets.RefVersion, SecretSealGeneration: 1,
	}
	rpc := &resealPlacementCluster{
		Noop: cluster.NewNoop("node-a", "http://a", ""), placement: base,
		members: []cluster.Member{
			{NodeID: "node-a", Alive: true, Role: config.NodeRoleMixed},
			{NodeID: "held-b", Alive: true, Role: config.NodeRoleWorker},
			{NodeID: "held-c", Alive: true, Role: config.NodeRoleWorker},
		},
	}
	cl := &drainingResealSetCluster{&drainingResealCluster{resealPlacementCluster: rpc, drained: drained}}
	st := openSealTestStore(t)
	cipher := newTestCipher(t)
	// deletePending keeps every journalled delete visible to the assertions
	// instead of racing the async delete fan-out that would clear it.
	pusher := &fakePeerPusher{acked: acked, deletePending: true}
	svc := &Service{
		cfg: config.Config{SecretRecipientBackupCount: 2}, cipher: cipher, store: st, cluster: cl,
		secretProvider:       secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		testSecretPeerPusher: pusher,
		logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	bag := secrets.Secrets{Env: map[string]string{"TOKEN": "secret"}}
	handle, err := svc.secretProvider.Put(secrets.ContextWithIncarnationID(ctx, "inc-a"), sandboxID, bag, base.SecretRecipients)
	if err != nil {
		t.Fatal(err)
	}
	rpc.placement.SecretRef, rpc.placement.SecretVersion, rpc.placement.SecretSealGeneration = handle.Ref, handle.Version, handle.SealGeneration
	clearSecretFanoutHolders(sandboxID)
	t.Cleanup(func() {
		waitForSecretCreateFanoutIdle(t, sandboxID)
		clearSecretFanoutHolders(sandboxID)
	})
	resetSecretHoldersForGeneration(sandboxID, "inc-a", handle.SealGeneration, "node-a")
	setSecretHolderTargets(sandboxID, "inc-a", handle.SealGeneration, base.SecretRecipients)
	return &drainAllBackupsFixture{svc: svc, rpc: rpc, cl: cl, pusher: pusher, bag: bag}
}

// localRow and pendingDelete are exactly what GET
// /v1/cluster/sandboxes/{id}/secret-holders reports (SecretHoldersForSandbox
// reads the owner's sealed row and its delete outbox).
func (f *drainAllBackupsFixture) localRow(t *testing.T, sandboxID string) *storepkg.ClusterSecretRecord {
	t.Helper()
	rec, err := f.svc.store.GetClusterSecretForSandboxIncarnation(context.Background(), sandboxID, "inc-a")
	if err != nil {
		t.Fatalf("owner's sealed row: %v", err)
	}
	return rec
}

func (f *drainAllBackupsFixture) pendingDelete(t *testing.T, sandboxID string) *storepkg.SecretDeleteOutboxRecord {
	t.Helper()
	rec, err := f.svc.store.GetSecretDeleteOutboxForIncarnation(context.Background(), sandboxID, "inc-a")
	if errors.Is(err, storepkg.ErrNotFound) {
		return nil
	}
	if err != nil {
		t.Fatalf("delete outbox: %v", err)
	}
	return rec
}

func (f *drainAllBackupsFixture) raft() (recipients []string, gen int64, updates int) {
	f.rpc.mu.Lock()
	defer f.rpc.mu.Unlock()
	recipients = append([]string(nil), f.rpc.placement.SecretRecipients...)
	slices.Sort(recipients)
	return recipients, f.rpc.placement.SecretSealGeneration, f.rpc.updateCalls
}

// UC-124 offline. Both backups are drained at once and no other node can take
// a copy. The durability floor (a replacement ACK precedes the Raft CAS) keeps
// the current generation authoritative — so the reseal must leave NOTHING
// behind. Before the fix it sealed an owner-only generation over the owner's
// row and staged deletes to both drained holders, and only THEN noticed there
// was no replacement. finalizeResealedSecret refuses an owner-only stage, so
// that generation could never be promoted or replaced: the deletes stayed
// pending forever, secret-holders reported an owner-only set Raft never held,
// and the sandbox never resealed again, even after a replacement joined.
func TestResealWithNoReplacementStagesNothingAndResumesWhenOneJoins(t *testing.T) {
	ctx := context.Background()
	const sandboxID = "sb-drain-all-backups"
	f := newDrainAllBackupsFixture(t, sandboxID, map[string]bool{"held-b": true, "held-c": true}, []string{"live-d"})

	if err := f.svc.expandAndResealDeadSecretTargets(ctx, sandboxID); err == nil {
		t.Fatal("reseal with no live replacement reported success")
	}
	if row := f.localRow(t, sandboxID); row.SealGeneration != 1 || !slices.Equal(secrets.NormalizeRecipients(row.Recipients), []string{"held-b", "held-c", "node-a"}) {
		t.Fatalf("owner's row was rewritten with no replacement to promote it: generation=%d recipients=%v, want generation 1 for [held-b held-c node-a]",
			row.SealGeneration, row.Recipients)
	}
	if del := f.pendingDelete(t, sandboxID); del != nil {
		t.Fatalf("deletes staged to %v (generation %d, awaiting=%v) for a reseal that cannot be promoted", del.Recipients, del.Generation, del.AwaitingPromotion)
	}
	if _, _, updates := f.raft(); updates != 0 {
		t.Fatalf("raft updated %d times with no replacement", updates)
	}
	if f.pusher.pushCalls != 0 {
		t.Fatalf("pushed %d times with no replacement", f.pusher.pushCalls)
	}

	// A replacement joins. The same trigger must now complete the reseal and
	// owe the drained holders their deletes.
	f.rpc.members = append(f.rpc.members, cluster.Member{NodeID: "live-d", Alive: true, Role: config.NodeRoleWorker})
	if err := f.svc.expandAndResealDeadSecretTargets(ctx, sandboxID); err != nil {
		t.Fatalf("reseal once a replacement joined: %v", err)
	}
	recipients, gen, updates := f.raft()
	if updates != 1 || !slices.Equal(recipients, []string{"live-d", "node-a"}) || gen != 2 {
		t.Fatalf("raft after the replacement joined: updates=%d recipients=%v generation=%d, want 1 update to [live-d node-a] at generation 2", updates, recipients, gen)
	}
	del := f.pendingDelete(t, sandboxID)
	if del == nil || del.AwaitingPromotion || del.Generation != gen || !slices.Equal(secrets.NormalizeRecipients(del.Recipients), []string{"held-b", "held-c"}) {
		t.Fatalf("drained holders are not owed a promoted delete: %+v", del)
	}
}

// A node upgraded from a build with the bug already has the wedge on disk: an
// owner-only generation staged ahead of Raft, plus a staged delete to the
// drained holders. It must not stay wedged. While there is still no
// replacement nothing new is staged; once there is one, or the drains are
// undone, the reseal supersedes the unpromotable stage from the owner's copy.
func TestResealSupersedesAnOwnerOnlyStageLeftByAnOlderBuild(t *testing.T) {
	for _, tc := range []struct {
		name           string
		id             string
		drained        map[string]bool
		replacement    bool
		acked          []string
		wantErr        bool
		wantRecipients []string
		wantDelete     []string
	}{
		{
			name: "still no replacement: nothing new is staged", id: "sb-wedged-no-replacement",
			drained: map[string]bool{"held-b": true, "held-c": true}, acked: []string{"live-d"},
			wantErr: true,
		},
		{
			name: "a replacement joined: the drained copies are retired", id: "sb-wedged-replacement",
			drained: map[string]bool{"held-b": true, "held-c": true}, replacement: true, acked: []string{"live-d"},
			wantRecipients: []string{"live-d", "node-a"}, wantDelete: []string{"held-b", "held-c"},
		},
		{
			// Retiring nobody leaves the old stage's delete row behind unless
			// it is dropped, and promoting it would delete current copies.
			name: "drains undone: the original set is resealed and owes nothing", id: "sb-wedged-uncordoned",
			drained: nil, acked: []string{"held-b", "held-c"},
			wantRecipients: []string{"held-b", "held-c", "node-a"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			sandboxID := tc.id
			f := newDrainAllBackupsFixture(t, sandboxID, tc.drained, tc.acked)
			// Reproduce what the old build left behind: generation 2 sealed
			// to the owner alone, with both backups staged for deletion.
			stageCtx := secrets.ContextWithRetiredRecipients(secrets.ContextWithIncarnationID(ctx, "inc-a"), []string{"held-b", "held-c"})
			if _, err := f.svc.secretProvider.Put(stageCtx, sandboxID, f.bag, []string{"node-a"}); err != nil {
				t.Fatal(err)
			}
			if del := f.pendingDelete(t, sandboxID); del == nil || !del.AwaitingPromotion || del.Generation != 2 {
				t.Fatalf("precondition: want a staged generation-2 delete, got %+v", del)
			}
			if tc.replacement {
				f.rpc.members = append(f.rpc.members, cluster.Member{NodeID: "live-d", Alive: true, Role: config.NodeRoleWorker})
			}

			err := f.svc.expandAndResealDeadSecretTargets(ctx, sandboxID)
			recipients, gen, updates := f.raft()
			if tc.wantErr {
				if err == nil {
					t.Fatal("reseal with no live replacement reported success")
				}
				if row := f.localRow(t, sandboxID); row.SealGeneration != 2 || updates != 0 {
					t.Fatalf("a reseal with no replacement staged generation %d / updated raft %d times", row.SealGeneration, updates)
				}
				return
			}
			if err != nil {
				t.Fatalf("the unpromotable stage was not superseded: %v", err)
			}
			if updates != 1 || gen != 3 || !slices.Equal(recipients, tc.wantRecipients) {
				t.Fatalf("raft: updates=%d generation=%d recipients=%v, want 1 update to %v at generation 3", updates, gen, recipients, tc.wantRecipients)
			}
			if row := f.localRow(t, sandboxID); row.SealGeneration != gen || !slices.Equal(secrets.NormalizeRecipients(row.Recipients), tc.wantRecipients) {
				t.Fatalf("owner's row disagrees with raft: generation=%d recipients=%v", row.SealGeneration, row.Recipients)
			}
			opened, openErr := f.svc.secretProvider.Open(secrets.ContextWithIncarnationID(ctx, "inc-a"), sandboxID,
				secrets.Handle{Ref: secrets.FormatRef(sandboxID, "inc-a", secrets.RefVersion), Version: secrets.RefVersion, SealGeneration: gen}, "node-a")
			if openErr != nil || opened.Env["TOKEN"] != "secret" {
				t.Fatalf("owner cannot open the promoted generation: %v", openErr)
			}
			del := f.pendingDelete(t, sandboxID)
			if tc.wantDelete == nil {
				if del != nil {
					t.Fatalf("the old stage's delete survived: %v at generation %d (awaiting=%v) — promoting it would delete current copies",
						del.Recipients, del.Generation, del.AwaitingPromotion)
				}
				return
			}
			if del == nil || del.AwaitingPromotion || del.Generation != gen || !slices.Equal(secrets.NormalizeRecipients(del.Recipients), tc.wantDelete) {
				t.Fatalf("delete obligations after supersede: %+v, want %v promoted at generation %d", del, tc.wantDelete, gen)
			}
		})
	}
}
