package cluster

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/version"
)

// Edge paths of the join service that need no Raft: a Cluster literal with
// an FSM, TLS material and a CA store.

func edgeCluster(t *testing.T, nodeID string) *Cluster {
	t.Helper()
	ct, err := loadClusterTLS(writeTestClusterTLSDir(t, nodeID))
	if err != nil {
		t.Fatal(err)
	}
	return &Cluster{
		nodeID: nodeID, fsm: newPlacementFSM(), tls: ct,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		denyHits: &denyHitRecorder{},
		cfg:      config.Config{ClusterCADir: filepath.Join(t.TempDir(), "ca")},
	}
}

func putToken(t *testing.T, c *Cluster, role string, ttl time.Duration) string {
	t.Helper()
	token, rec := testJoinToken(t, role, time.Now().UnixNano(), ttl, false)
	applyDenyLogAt(t, c.fsm, 1, putTokenCmd(rec, time.Now().UnixNano()))
	return token
}

func TestJoinServiceEdges(t *testing.T) {
	c := edgeCluster(t, "edge-1")
	src := netip.MustParseAddr("127.0.0.1")
	ctx := context.Background()

	// cluster-info needs a live token and TLS material.
	if _, err := c.ClusterInfo("zzzzzz"); !errors.Is(err, ErrJoinTokenInvalid) {
		t.Fatalf("unknown token = %v", err)
	}
	token := putToken(t, c, JoinRoleWorker, time.Hour)
	id, _, _ := ParseJoinToken(token)
	info, err := c.ClusterInfo(id)
	if err != nil || !VerifyClusterInfo(token, info) {
		t.Fatalf("cluster-info = %+v %v", info, err)
	}
	if VerifyClusterInfo(token, ClusterInfo{MAC: "!!", InfoMAC: "!!"}) || VerifyClusterInfo("garbage", info) {
		t.Fatal("bad MAC encodings passed")
	}
	noTLS := &Cluster{fsm: c.fsm}
	if _, err := noTLS.ClusterInfo(id); err == nil || noTLS.clusterID() != "" {
		t.Fatal("cluster-info without TLS material")
	}
	var nilCluster *Cluster
	if _, _, err := nilCluster.clusterCACert(); err == nil {
		t.Fatal("nil cluster CA")
	}

	// A wrong secret is the same answer as an unknown token.
	if _, err := c.checkJoinToken(id + "." + "0123456789abcdef0123456789abcdef"); !errors.Is(err, ErrJoinTokenInvalid) {
		t.Fatalf("wrong secret = %v", err)
	}
	if _, err := c.JoinPreflight(ctx, PreflightRequest{Token: token, Role: JoinRoleServer}, src); !errors.Is(err, ErrJoinRoleMismatch) {
		t.Fatalf("preflight role mismatch = %v", err)
	}
	if _, err := c.JoinPreflight(ctx, PreflightRequest{Token: token, Ports: &JoinPorts{Gossip: 99999}}, src); !errors.Is(err, ErrJoinBadRequest) {
		t.Fatalf("preflight bad port = %v", err)
	}
	expired, rec := testJoinToken(t, JoinRoleWorker, time.Now().Add(-2*time.Hour).UnixNano(), time.Hour, false)
	applyDenyLogAt(t, c.fsm, 2, putTokenCmd(rec, time.Now().UnixNano()))
	if _, err := c.JoinPreflight(ctx, PreflightRequest{Token: expired}, src); !errors.Is(err, ErrJoinTokenExpired) {
		t.Fatalf("preflight expired = %v", err)
	}
	if _, err := c.ClusterInfo(rec.ID); !errors.Is(err, ErrJoinTokenInvalid) {
		t.Fatalf("cluster-info for an expired token = %v", err)
	}

	// Join refusals before anything is used.
	_, csr := newCSR(t, "n")
	for name, tc := range map[string]struct {
		req  JoinRequest
		want error
	}{
		"bad token":  {JoinRequest{Token: "x"}, ErrJoinTokenInvalid},
		"role":       {JoinRequest{Token: token, Role: JoinRoleIngress}, ErrJoinRoleMismatch},
		"node id":    {JoinRequest{Token: token, NodeID: "bad id!"}, ErrJoinNodeIDInvalid},
		"no version": {JoinRequest{Token: token, NodeID: "n1"}, ErrJoinVersion},
		"bad csr":    {JoinRequest{Token: token, NodeID: "n1", Version: version.Version, CSR: "x"}, ErrJoinBadRequest},
		"no signer":  {JoinRequest{Token: token, NodeID: "n1", Version: version.Version, CSR: csr}, ErrNoCASigner},
	} {
		if _, err := c.Join(ctx, tc.req, src); !errors.Is(err, tc.want) {
			t.Fatalf("%s = %v, want %v", name, err, tc.want)
		}
	}
	c.ca.set(mustSharedCA(t))
	if _, err := c.Join(ctx, JoinRequest{Token: token, NodeID: "n1", Version: version.Version, CSR: csr, Ports: &JoinPorts{Raft: -1}}, src); !errors.Is(err, ErrJoinBadRequest) {
		t.Fatalf("bad ports = %v", err)
	}
	// Without Raft the admit write can't land.
	live := dialBackListeners(t, 2)
	if _, err := c.Join(ctx, JoinRequest{Token: token, NodeID: "n1", Version: version.Version, CSR: csr, Ports: &JoinPorts{Gossip: live[0], Internal: live[1]}}, src); err == nil {
		t.Fatal("join without Raft succeeded")
	}

	// Small helpers.
	if c.joinVersionAllowed("", 0) || c.joinVersionAllowed("v9.9.9", 0) || !c.joinVersionAllowed(version.Version, 0) {
		t.Fatal("joinVersionAllowed without gossip")
	}
	if got := c.bootstrapPeers(); got == nil || len(got) != 0 {
		t.Fatalf("bootstrap peers without gossip = %v", got)
	}
	if c.liveMemberHoldsID("n1", "k") != nil {
		t.Fatal("live check without gossip refused")
	}
	for ttl, want := range map[time.Duration]time.Duration{0: NodeCertLifetime, 10 * time.Minute: 10 * time.Minute, 200 * 24 * time.Hour: NodeCertLifetime} {
		c.cfg.ClusterNodeCertTTL = ttl
		if got := c.nodeCertTTL(); got != want {
			t.Fatalf("nodeCertTTL(%s) = %s", ttl, got)
		}
	}
	c.internalURL = "https://10.9.8.7:7002"
	if got := c.joinURLs(); len(got) != 1 || got[0] != "https://10.9.8.7:7003" {
		t.Fatalf("join URLs = %v", got)
	}
	c.internalURL = "::bad"
	if got := c.joinURLs(); got == nil || len(got) != 0 {
		t.Fatalf("join URLs from a bad URL = %v", got)
	}
}

func mustSharedCA(t *testing.T) *ClusterCA {
	t.Helper()
	ca, err := ParseClusterCA(sharedTestCAPEM, sharedCAKeyPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestJoinCredentialBundle(t *testing.T) {
	dir := t.TempDir()
	key, wrapped := filepath.Join(dir, "k"), filepath.Join(dir, "k.wrapped")
	_ = os.WriteFile(key, []byte("plain"), 0o600)
	_ = os.WriteFile(key+".ring", []byte("ring"), 0o600)
	_ = os.WriteFile(wrapped, []byte("sealed"), 0o600)
	c := &Cluster{cfg: config.Config{CredentialKeyCustody: "file", CredentialEncryptionKeyPath: key, CredentialKeyWrappedPath: wrapped}}
	if b := c.credentialBundle(); b.Custody != "file" || b.Key != "cGxhaW4=" || b.KeyRing != "cmluZw==" || b.Wrapped != "" {
		t.Fatalf("file custody bundle = %+v", b)
	}
	// Wrapped custody sends only the wrapped blob (plans/customer-key-custody.md).
	c.cfg.CredentialKeyCustody = "wrapped"
	if b := c.credentialBundle(); b.Custody != "wrapped" || b.Wrapped != "c2VhbGVk" || b.Key != "" || b.KeyRing != "" {
		t.Fatalf("wrapped custody bundle = %+v", b)
	}
	c.cfg = config.Config{CredentialKeyCustody: "file", CredentialEncryptionKeyPath: filepath.Join(dir, "missing")}
	if b := c.credentialBundle(); b.Key != "" || b.KeyRing != "" {
		t.Fatalf("missing files = %+v", b)
	}
	c.cfg = config.Config{CredentialKeyCustody: "wrapped"}
	if b := c.credentialBundle(); b.Wrapped != "" {
		t.Fatalf("no wrapped path = %+v", b)
	}
}

func TestRenewAndCAKeyEdges(t *testing.T) {
	c := edgeCluster(t, "edge-2")
	ctx := context.Background()
	if _, err := c.RenewNodeCert(ctx, "x", nil, nil); !errors.Is(err, ErrNoCASigner) {
		t.Fatalf("renew without a signer = %v", err)
	}
	if _, err := c.CAKeyForPeer("x"); !errors.Is(err, ErrPeerNotServer) {
		t.Fatalf("CA key without Raft = %v", err)
	}
	ca := mustSharedCA(t)
	c.ca.set(ca)
	oldKey, _, _ := NewNodeKey()
	_, oldLeaf, _ := ca.SignNodeCert(NodeCertRequest{PublicKey: &oldKey.PublicKey, NodeID: "w", Role: JoinRoleWorker})
	otherKey, _, _ := NewNodeKey()
	_, otherLeaf, _ := ca.SignNodeCert(NodeCertRequest{PublicKey: &otherKey.PublicKey, NodeID: "w", Role: JoinRoleWorker})
	applyDenyLogAt(t, c.fsm, 1, command{Op: opAdoptNodes, StampUnixNano: 1, JoinAdopt: &JoinAdoptCommand{Nodes: []AdmittedNode{
		{NodeID: "w", Role: JoinRoleWorker, KeyHash: CertKeyHash(oldLeaf)},
		{NodeID: "gone", Role: JoinRoleWorker, KeyHash: testKey("gone")},
	}}})
	applyDenyLogAt(t, c.fsm, 2, command{Op: opDenyNode, StampUnixNano: time.Now().UnixNano(), NodeDeny: &NodeDenyRecord{NodeID: "gone"}})
	sameCSR, _ := NewNodeCSR(oldKey, "w")
	// The leaf must be the admitted key.
	if _, err := c.RenewNodeCert(ctx, "w", otherLeaf, sameCSR); !errors.Is(err, ErrPeerKeyNotAdmitted) {
		t.Fatalf("renew from another key = %v", err)
	}
	// Same key: signed with the admitted role, no Raft write.
	resp, err := c.RenewNodeCert(ctx, "w", oldLeaf, sameCSR)
	if err != nil || resp.Rekeyed || resp.NodeCert == "" {
		t.Fatalf("same-key renew = %+v %v", resp, err)
	}
	// A CSR for a tombstoned key is refused before any write. Build a
	// tombstone whose key we hold.
	tombKey, _, _ := NewNodeKey()
	tombHash, _ := PublicKeyHash(&tombKey.PublicKey)
	applyDenyLogAt(t, c.fsm, 3, command{Op: opAdoptNodes, StampUnixNano: 3, JoinAdopt: &JoinAdoptCommand{Nodes: []AdmittedNode{{NodeID: "t", Role: JoinRoleWorker, KeyHash: tombHash}}}})
	applyDenyLogAt(t, c.fsm, 4, command{Op: opDenyNode, StampUnixNano: time.Now().UnixNano(), NodeDeny: &NodeDenyRecord{NodeID: "t"}})
	tombCSR, _ := NewNodeCSR(tombKey, "w")
	if _, err := c.RenewNodeCert(ctx, "w", oldLeaf, tombCSR); !errors.Is(err, ErrJoinKeyRevoked) {
		t.Fatalf("renew onto a revoked key = %v", err)
	}
	// A new key needs a Raft write, which this literal can't make.
	newKey, _, _ := NewNodeKey()
	newCSRPEM, _ := NewNodeCSR(newKey, "w")
	if _, err := c.RenewNodeCert(ctx, "w", oldLeaf, newCSRPEM); err == nil {
		t.Fatal("rekey without Raft succeeded")
	}
	// renewViaServers falls back to peers, and there are none.
	selfLeaf, _ := c.currentLeaf()
	applyDenyLogAt(t, c.fsm, 5, command{Op: opAdoptNodes, StampUnixNano: 5, JoinAdopt: &JoinAdoptCommand{Nodes: []AdmittedNode{{NodeID: "edge-2", Role: JoinRoleServer, KeyHash: CertKeyHash(selfLeaf)}}}})
	selfCSR, _ := NewNodeCSR(mustTLSKey(t, c), "edge-2")
	c.ca.set(nil)
	if _, err := c.renewViaServers(ctx, selfCSR); err == nil {
		t.Fatal("renew with no signer and no peers succeeded")
	}
	c.ca.set(ca)
	if got, err := c.renewViaServers(ctx, selfCSR); err != nil || len(got) == 0 {
		t.Fatalf("in-process renew = %v", err)
	}
	// In-process renewal for a node with no record is a stop, not a retry.
	c.nodeID = "nobody"
	if _, err := c.renewViaServers(ctx, sameCSR); err == nil {
		t.Fatal("renew for an unadmitted self succeeded")
	}
}

func TestAdoptAndStartEdges(t *testing.T) {
	ctx := context.Background()
	if _, err := (&Cluster{}).Adopt(ctx, AdoptRequest{}); err == nil {
		t.Fatal("adopt without TLS")
	}
	c := edgeCluster(t, "edge-3")
	// A CA store holding another cluster's CA is refused.
	if err := SaveClusterCA(c.cfg.ClusterCADir, mustCA(t)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ensureCAKey(ctx, c.tls.caPEM, ""); err == nil {
		t.Fatal("adopt took another cluster's CA store")
	}
	// startJoinService refuses it too, and never fails.
	c.startJoinService()
	if c.ca.get() != nil {
		t.Fatal("signer from another cluster's CA store")
	}
	c.certRenewStop()
	// An unreadable store (key without cert) is logged and skipped.
	_ = os.Remove(filepath.Join(c.cfg.ClusterCADir, caStoreCertFile))
	c.startJoinService()
	c.certRenewStop()
	// This cluster's CA in the store: adopt reads it from there.
	if err := SaveClusterCA(c.cfg.ClusterCADir, mustSharedCA(t)); err != nil {
		t.Fatal(err)
	}
	src, imported, err := c.ensureCAKey(ctx, c.tls.caPEM, "")
	if err != nil || src != "ca_store" || imported {
		t.Fatalf("ensureCAKey from the store = %s %v %v", src, imported, err)
	}
	// No gossip: no members to collect, adopt writes nothing and succeeds.
	res, err := c.Adopt(ctx, AdoptRequest{})
	if err != nil || len(res.Admitted) != 0 {
		t.Fatalf("adopt with no members = %+v %v", res, err)
	}
	// A request key that does not parse, or a store that can't be written.
	if _, _, err := c.ensureCAKey(ctx, c.tls.caPEM, "junk"); err == nil {
		t.Fatal("junk CA key accepted")
	}
	c.cfg.ClusterCADir = ""
	if _, _, err := c.ensureCAKey(ctx, c.tls.caPEM, string(sharedCAKeyPEM(t))); err == nil {
		t.Fatal("CA key saved with no store")
	}
	// No key anywhere and no peers.
	c.ca.set(nil)
	if _, _, err := c.ensureCAKey(ctx, c.tls.caPEM, ""); err == nil {
		t.Fatal("ensureCAKey with nothing succeeded")
	}
	// Member-key helpers.
	if nodes, _ := c.collectMemberKeys(ctx); nodes != nil {
		t.Fatal("members without gossip")
	}
	if _, err := (&Cluster{}).currentLeaf(); err == nil {
		t.Fatal("leaf without TLS")
	}
	for _, m := range []Member{{NodeID: "x"}, {NodeID: "x", InternalURL: "::bad"}, {NodeID: "x", InternalURL: "https://127.0.0.1:1"}} {
		if _, err := c.peerLeaf(ctx, m); err == nil {
			t.Fatalf("peerLeaf(%+v) succeeded", m)
		}
	}
	if err := c.postToServerPeers(ctx, "/x", struct{}{}, nil); err == nil {
		t.Fatal("post to peers without gossip")
	}
	if err := postPeerJSON(ctx, nil, "https://x", "a", "", nil, nil); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("postPeerJSON without a client = %v", err)
	}
	if _, err := startJoinServer("127.0.0.1:0", nil, c, nil, nil); err == nil {
		t.Fatal("join server without TLS")
	}
	var js *joinServer
	if js.Close() != nil {
		t.Fatal("nil join server close")
	}
	if _, err := startJoinServer("256.0.0.1:0", c.tls, c, nil, nil); err == nil {
		t.Fatal("join server on a bad address")
	}
}
