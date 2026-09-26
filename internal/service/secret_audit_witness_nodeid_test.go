package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
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

// Every witness call site must go through the helper. A new one that reads
// s.Cluster().SelfNodeID() directly reintroduces exactly this bug, and it
// would only show up as an intermittent refusal to boot on a live node.
func TestNoWitnessCallSiteReadsTheClusterHandleDirectly(t *testing.T) {
	raw, err := os.ReadFile("secret_audit_witness.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	body := src
	if i := strings.Index(src, "func (s *Service) witnessNodeID()"); i >= 0 {
		end := strings.Index(src[i:], "\n}\n")
		body = src[:i] + src[i+end:]
	}
	if strings.Contains(body, "c.SelfNodeID()") {
		t.Fatal("a witness call site derives the node id from the cluster handle again; use witnessNodeID() — the handle is the Noop's \"standalone\" until AttachCluster runs")
	}
}
