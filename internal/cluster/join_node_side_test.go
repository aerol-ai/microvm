package cluster

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/version"
)

// What the node side of a join (sandboxd init, join and preflight, Phase
// 2b) needs from the join service: a token the caller made registered as
// is and safely again, and preflight's node ID check. What the answer
// says about the PAT is in peer_cert_auth_test.go.

func TestCreateJoinTokenRegistersAGivenToken(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newJoinTestCluster(t, "given-seed", true, nil, joinClusterOpts{caDir: writeSharedCAStore(t)})
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	ctx := context.Background()

	given, _ := GenerateJoinToken()
	first, err := leader.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleWorker, TTL: "0", Reusable: true, Token: given})
	if err != nil || first.Token != given || first.ExpiresAt != nil || !first.Reusable || first.Role != JoinRoleWorker {
		t.Fatalf("register a given token = %+v %v", first, err)
	}
	id, _, _ := ParseJoinToken(given)
	if first.ID != id {
		t.Fatalf("id = %q, want %q", first.ID, id)
	}

	// A re-run of init registers it again: the stored row answers, and its
	// first expiry stands.
	server, _ := GenerateJoinToken()
	a, err := leader.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleServer, TTL: "24h", Reusable: true, Token: server})
	if err != nil || a.ExpiresAt == nil {
		t.Fatalf("server token = %+v %v", a, err)
	}
	time.Sleep(5 * time.Millisecond)
	b, err := leader.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleServer, TTL: "24h", Reusable: true, Token: server})
	if err != nil || b.ExpiresAt == nil || !b.ExpiresAt.Equal(*a.ExpiresAt) {
		t.Fatalf("repeat = %+v %v, want the first expiry %v", b, err, a.ExpiresAt)
	}
	if list, _ := leader.ListJoinTokens(ctx); len(list.Tokens) != 2 {
		t.Fatalf("tokens = %+v, want 2", list.Tokens)
	}

	// The same id as another role, or with another secret, is refused and
	// never retried under a new id.
	if _, err := leader.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleIngress, TTL: "0", Reusable: true, Token: given}); !errors.Is(err, ErrJoinTokenIDTaken) {
		t.Fatalf("same token, other role = %v", err)
	}
	if _, err := leader.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleWorker, TTL: "0", Token: given}); !errors.Is(err, ErrJoinTokenIDTaken) {
		t.Fatalf("same token, single use = %v", err)
	}
	other := id + ".00000000000000000000000000000000"
	if _, err := leader.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleWorker, TTL: "0", Reusable: true, Token: other}); !errors.Is(err, ErrJoinTokenIDTaken) {
		t.Fatalf("same id, other secret = %v", err)
	}
	// A malformed token is a bad request; the TTL rules still apply.
	if _, err := leader.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleWorker, Token: "abc.def"}); !errors.Is(err, ErrJoinBadRequest) {
		t.Fatalf("malformed token = %v", err)
	}
	if _, err := leader.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleServer, TTL: "0", Token: given}); !errors.Is(err, ErrJoinTTLInvalid) {
		t.Fatalf("never-expiring server token = %v", err)
	}

	// The given token works for a join's discovery like a random one.
	info, err := leader.ClusterInfo(id)
	if err != nil || !VerifyClusterInfo(given, info) {
		t.Fatalf("cluster-info for a given token = %+v %v", info, err)
	}
}

func TestPreflightReportsATakenNodeID(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newJoinTestCluster(t, "pf-seed", true, nil, joinClusterOpts{caDir: writeSharedCAStore(t)})
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	ctx := context.Background()
	created, err := leader.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleWorker, Reusable: true})
	if err != nil {
		t.Fatal(err)
	}
	src := netip.MustParseAddr("127.0.0.1")
	ports := dialBackListeners(t, 2)
	jp := &JoinPorts{Gossip: ports[0], Internal: ports[1]}
	key, csr := newCSR(t, "pf-wkr")
	keyHash, _ := PublicKeyHash(key.Public())
	if _, err := leader.Join(ctx, JoinRequest{Token: created.Token, NodeID: "pf-wkr", CSR: csr, Version: version.Version, Ports: jp}, src); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, nodeID, keyHash string
		inUse                 bool
	}{
		{"no node id asked", "", "", false},
		{"a free id", "pf-new", "", false},
		{"the seed, live and never admitted", "pf-seed", "", true},
		{"admitted for another key", "pf-wkr", testKey("other"), true},
		{"admitted with no key given", "pf-wkr", "", true},
		{"admitted for this key (a re-run)", "pf-wkr", keyHash, false},
	}
	for _, tc := range cases {
		resp, err := leader.JoinPreflight(ctx, PreflightRequest{Token: created.Token, Ports: jp, NodeID: tc.nodeID, KeyHash: tc.keyHash}, src)
		if err != nil || resp.NodeIDInUse != tc.inUse || resp.OK == tc.inUse {
			t.Fatalf("%s: preflight = %+v %v, want in use %t", tc.name, resp, err, tc.inUse)
		}
	}
}
