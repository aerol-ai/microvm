package cluster

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/hashicorp/memberlist"
)

// TestGossipPublicHostRoundTrip pins that PublicHost survives the
// encode/decode cycle and the realistic-size meta still fits the 512-byte
// MetaMaxSize ceiling — adding a new gossiped field is the canonical way to
// silently push past the limit and break voter auto-join (see the comment
// on nodeMeta). If this test ever fails on the budget assertion, audit
// whether a field can be dropped or moved out of gossip rather than
// quietly relaxing the bound.
func TestGossipPublicHostRoundTrip(t *testing.T) {
	d := newGossipDelegate(
		"ip-10-42-1-76",
		"aerolvm-node2",
		"http://10.42.1.76:21212",
		"10.42.1.76",
		"10.42.1.76:7000",
		"https://10.42.1.76:7002",
		config.NodeRoleMixed,
		"ingress.example.com",
		nil,
	)

	encoded := d.NodeMeta(memberlist.MetaMaxSize)
	if len(encoded) > memberlist.MetaMaxSize {
		t.Fatalf("encoded meta len=%d exceeds MetaMaxSize=%d — peers would receive truncated/fallback metadata", len(encoded), memberlist.MetaMaxSize)
	}

	var meta nodeMeta
	if err := json.Unmarshal(encoded, &meta); err != nil {
		t.Fatalf("encoded meta is not valid JSON: %v; %q", err, string(encoded))
	}
	if meta.PublicHost != "ingress.example.com" {
		t.Fatalf("PublicHost did not round-trip: got %q, want %q", meta.PublicHost, "ingress.example.com")
	}

	m := memberFromMemberlistNode(&memberlist.Node{
		Name:  "ip-10-42-1-76",
		State: memberlist.StateAlive,
		Meta:  encoded,
	})
	if m.PublicHost != "ingress.example.com" {
		t.Fatalf("Member.PublicHost = %q, want ingress.example.com", m.PublicHost)
	}
}

// TestGossipPublicHostDroppedFirstUnderBudget pins the fallback ordering:
// when nodeMeta exceeds MetaMaxSize, PublicHost (DNS-helper only) is shed
// before identity / raft join fields. Losing PublicHost degrades the
// DNS-helper API gracefully; losing RaftAddr breaks voter auto-join.
func TestGossipPublicHostDroppedFirstUnderBudget(t *testing.T) {
	d := newGossipDelegate(
		"ip-10-42-1-76",
		strings.Repeat("very-long-node-name-segment-", 30),
		"http://10.42.1.76:21212",
		"10.42.1.76",
		"10.42.1.76:7000",
		"https://10.42.1.76:7002",
		config.NodeRoleMixed,
		"ingress.example.com",
		nil,
	)
	if len(d.encoded) <= memberlist.MetaMaxSize {
		t.Fatalf("test setup: encoded meta len=%d, want > %d so the fallback path runs", len(d.encoded), memberlist.MetaMaxSize)
	}

	encoded := d.NodeMeta(memberlist.MetaMaxSize)
	var meta nodeMeta
	if err := json.Unmarshal(encoded, &meta); err != nil {
		t.Fatalf("fallback meta is not valid JSON: %v", err)
	}
	if meta.PublicHost != "" {
		t.Fatalf("fallback should drop PublicHost first, got %q", meta.PublicHost)
	}
	if meta.RaftAddr != "10.42.1.76:7000" {
		t.Fatalf("fallback dropped RaftAddr=%q, want preserved — voter auto-join depends on it", meta.RaftAddr)
	}
}
