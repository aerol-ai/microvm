package service

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// TestWitnessNodeIDPrefersTheConfiguredIdentity pins the fix for an
// enterprise node refusing to boot against a head the witness was holding all
// along (TODOS.md, "Enterprise boot can fail its own witness check").
//
// The Service is built with a Noop cluster named "standalone" and the real
// cluster is attached later. A boot-time witness check that reads the node id
// off the cluster handle therefore asks about "standalone", while the shipper
// — which always runs after the attach — stored the head under the real node
// id. The node then fails CLOSED on a mismatch that does not exist.
func TestWitnessNodeIDPrefersTheConfiguredIdentity(t *testing.T) {
	svc := &Service{cfg: config.Config{
		DBPath: filepath.Join(t.TempDir(), "state.db"),
		NodeID: "aerolvm-itest-node1",
	}}
	// Exactly how the daemon builds it before AttachCluster runs.
	svc.cluster = cluster.NewNoop("standalone", "", "")

	if got := svc.witnessNodeID(); got != "aerolvm-itest-node1" {
		t.Fatalf("witnessNodeID() = %q, want the configured id; a boot check running before AttachCluster would query the witness under the Noop's placeholder and fail closed on a head that IS witnessed", got)
	}

	// Once the real cluster is attached the two agree, so the preference is
	// invisible on a healthy node rather than a second source of truth.
	svc.cluster = cluster.NewNoop("aerolvm-itest-node1", "", "")
	if got := svc.witnessNodeID(); got != "aerolvm-itest-node1" {
		t.Fatalf("witnessNodeID() = %q after attach, want the same id", got)
	}
}

// Without SB_NODE_ID there is no configured identity, and the cluster
// handle's answer is the correct one rather than a race. A fix that returned
// "" here would ship every head under an empty key.
func TestWitnessNodeIDFallsBackToTheClusterHandle(t *testing.T) {
	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	svc.cluster = cluster.NewNoop("standalone", "", "")
	if got := svc.witnessNodeID(); got != "standalone" {
		t.Fatalf("witnessNodeID() = %q with no SB_NODE_ID, want the cluster handle's id", got)
	}
	if got := (*Service)(nil).witnessNodeID(); got != "" {
		t.Fatalf("nil receiver = %q, want empty", got)
	}
}

// A configured id that is only whitespace is not an identity. Trimming it to
// empty must fall through rather than ship heads under " ".
func TestWitnessNodeIDIgnoresBlankConfiguredID(t *testing.T) {
	svc := &Service{cfg: config.Config{
		DBPath: filepath.Join(t.TempDir(), "state.db"),
		NodeID: "   ",
	}}
	svc.cluster = cluster.NewNoop("standalone", "", "")
	if got := svc.witnessNodeID(); got != "standalone" {
		t.Fatalf("witnessNodeID() = %q for a blank SB_NODE_ID, want the fallback", got)
	}
}

// Only the two designated helpers may touch the cluster handle. Any other
// witness call site that reads s.Cluster().SelfNodeID() reintroduces exactly
// this bug, and it would show up only as an intermittent refusal to boot on
// a live node.
func TestNoWitnessCallSiteReadsTheClusterHandleDirectly(t *testing.T) {
	raw, err := os.ReadFile("secret_audit_witness.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)

	allowed := []string{
		"func (s *Service) witnessNodeID()",
		"func (s *Service) witnessNodeIDCandidates()",
	}
	body := src
	stripped := 0
	for _, sig := range allowed {
		i := strings.Index(body, sig)
		if i < 0 {
			t.Fatalf("%s is gone; this guard no longer checks what it claims to", sig)
		}
		end := strings.Index(body[i:], "\n}\n")
		if end < 0 {
			t.Fatalf("could not delimit %s", sig)
		}
		body = body[:i] + body[i+end:]
		stripped++
	}
	if stripped != len(allowed) {
		t.Fatalf("stripped %d of %d helpers", stripped, len(allowed))
	}
	if strings.Contains(body, "SelfNodeID()") {
		t.Error("a witness call site derives the node id from the cluster handle again; use witnessNodeID() — the handle is the Noop's \"standalone\" until AttachCluster runs")
	}
}

// The upgrade case, and the reason the read path accepts either id.
//
// A single-node enterprise box never runs AttachCluster, so the older build
// shipped every head under the Noop's "standalone". Reading only under the
// new canonical id would find nothing and fail that node CLOSED on its next
// boot — turning an intermittent bug into a certain one for exactly the
// deployments that already have audit history, which is worse than the bug.
func TestWitnessNodeIDCandidatesCoverThePreUpgradeIdentity(t *testing.T) {
	svc := &Service{cfg: config.Config{
		DBPath: filepath.Join(t.TempDir(), "state.db"),
		NodeID: "aerolvm-itest-node1",
	}}
	svc.cluster = cluster.NewNoop("standalone", "", "")

	got := svc.witnessNodeIDCandidates()
	want := []string{"aerolvm-itest-node1", "standalone"}
	if len(got) != len(want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidates = %v, want %v (canonical must come first: it is what ships)", got, want)
		}
	}

	// No duplicate once the handle agrees, so the witness is not asked twice
	// for the same key on every healthy node.
	svc.cluster = cluster.NewNoop("aerolvm-itest-node1", "", "")
	if got := svc.witnessNodeIDCandidates(); len(got) != 1 || got[0] != "aerolvm-itest-node1" {
		t.Fatalf("candidates = %v, want exactly one id when the handle agrees", got)
	}

	if got := (*Service)(nil).witnessNodeIDCandidates(); got != nil {
		t.Fatalf("nil receiver = %v, want nil", got)
	}
}

// lastWitnessedHeadAny must actually consult the second candidate, and must
// not report a head that no candidate holds.
func TestLastWitnessedHeadAnyFindsAPreUpgradeReceipt(t *testing.T) {
	svc := &Service{cfg: config.Config{
		DBPath: filepath.Join(t.TempDir(), "state.db"),
		NodeID: "node1",
	}}
	svc.cluster = cluster.NewNoop("standalone", "", "")

	w := &nodeKeyedWitness{heads: map[string]string{"standalone": "deadbeef"}}
	head, ok, err := svc.lastWitnessedHeadAny(context.Background(), w)
	if err != nil || !ok || head != "deadbeef" {
		t.Fatalf("head=%q ok=%v err=%v; the pre-upgrade receipt under \"standalone\" was not found, so this node would fail closed on upgrade", head, ok, err)
	}
	if !slices.Contains(w.asked, "node1") || !slices.Contains(w.asked, "standalone") {
		t.Fatalf("asked = %v, want both candidates tried", w.asked)
	}

	// The canonical id wins when both hold something.
	w = &nodeKeyedWitness{heads: map[string]string{"node1": "new", "standalone": "old"}}
	if head, _, _ := svc.lastWitnessedHeadAny(context.Background(), w); head != "new" {
		t.Fatalf("head = %q, want the canonical id's head", head)
	}

	// Nothing anywhere stays nothing — the fallback must not invent a head.
	w = &nodeKeyedWitness{heads: map[string]string{}}
	if head, ok, err := svc.lastWitnessedHeadAny(context.Background(), w); ok || head != "" || err != nil {
		t.Fatalf("head=%q ok=%v err=%v, want an honest miss", head, ok, err)
	}
}

type nodeKeyedWitness struct {
	heads map[string]string
	asked []string
	err   error
}

func (w *nodeKeyedWitness) WitnessHeads(context.Context, []controlplane.AuditHead) (controlplane.WitnessReceipt, error) {
	return controlplane.WitnessReceipt{}, nil
}

func (w *nodeKeyedWitness) LastWitnessedHead(_ context.Context, nodeID string) (string, bool, error) {
	w.asked = append(w.asked, nodeID)
	if w.err != nil {
		return "", false, w.err
	}
	h, ok := w.heads[nodeID]
	return h, ok, nil
}
