package service

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
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
