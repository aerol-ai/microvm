package cluster

import (
	"context"
	"crypto/x509"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
)

// roleCert is a verified node certificate for id signed for role
// (DNS:role:<role>); "" names no role, as one signed before roles.
func roleCert(id, role string) *x509.Certificate {
	names := []string{"node:" + id}
	if role != "" {
		names = append(names, "role:"+role)
	}
	return &x509.Certificate{DNSNames: names}
}

// admittedLog is an FSM with gw-1 admitted as ingress, wkr-1 as a worker
// and srv-2 as a server.
func admittedLog(t *testing.T) *joinLog {
	t.Helper()
	l := newJoinLog(t)
	for i, n := range []struct{ id, role string }{{"gw-1", JoinRoleIngress}, {"wkr-1", JoinRoleWorker}, {"srv-2", JoinRoleServer}} {
		_, tok := testJoinToken(t, n.role, 100, time.Hour, true)
		l.apply(putTokenCmd(tok, 100))
		if _, ok := l.apply(admitCmd(tok.ID, n.id, n.role, testKey(n.id), int64(101+i))).(JoinAdmitResult); !ok {
			t.Fatalf("admit %s", n.id)
		}
	}
	return l
}

// The role a peer was admitted with, as a node can tell, never from
// gossip: on a server the admitted record wins over the certificate (a
// certificate cannot raise a worker), then Raft membership, then the
// certificate; a worker or gateway (no FSM) reads the certificate alone.
func TestPeerRole(t *testing.T) {
	c := &Cluster{fsm: admittedLog(t).f}
	for _, tc := range []struct {
		peer string
		cert *x509.Certificate
		want string
	}{
		{"wkr-1", roleCert("wkr-1", JoinRoleServer), JoinRoleWorker},
		{"gw-1", roleCert("gw-1", ""), JoinRoleIngress},
		{"srv-2", roleCert("srv-2", JoinRoleWorker), JoinRoleServer},
		{"new-1", roleCert("new-1", JoinRoleWorker), JoinRoleWorker},
		{"old-1", roleCert("old-1", ""), ""},
		{"old-1", nil, ""},
		{"", roleCert("x", JoinRoleServer), ""},
	} {
		if got := PeerRole(c, tc.peer, tc.cert); got != tc.want {
			t.Errorf("server's view of %q = %q, want %q", tc.peer, got, tc.want)
		}
	}
	agent := &Agent{}
	if got := PeerRole(agent, "wkr-1", roleCert("wkr-1", JoinRoleIngress)); got != JoinRoleIngress {
		t.Errorf("an agent reads the certificate: %q", got)
	}
	if got := PeerRole(nil, "wkr-1", roleCert("wkr-1", JoinRoleWorker)); got != JoinRoleWorker {
		t.Errorf("no cluster reads the certificate: %q", got)
	}
	if !PeerIsServer(c, "srv-2", nil) || PeerIsServer(c, "wkr-1", roleCert("wkr-1", JoinRoleServer)) {
		t.Error("PeerIsServer")
	}
	if _, ok := (*Cluster)(nil).AdmittedPeerRole("srv-2"); ok {
		t.Error("a nil cluster names a role")
	}

	// A Raft server with no admitted record (a scripted cluster before
	// adopt, whose certificates name no role) is a server.
	rc, cleanup := newTestCluster(t, "role-peer-a", true, nil)
	defer cleanup()
	waitForLeader(t, rc, 10*time.Second)
	if got := PeerRole(rc, "role-peer-a", roleCert("role-peer-a", "")); got != JoinRoleServer {
		t.Errorf("Raft server = %q", got)
	}
	if got := PeerRole(rc, "stranger", roleCert("stranger", "")); got != "" {
		t.Errorf("a node neither admitted nor in Raft = %q", got)
	}
}

// What each role may propose through the raw apply routes: a server
// anything; a worker, a gateway or an unknown role only the Agent ops,
// and its drain mark only for itself.
func TestPeerMayPropose(t *testing.T) {
	serverOnly := []opCode{
		opPutAPIToken, opDeleteAPIToken, opPutIdentityKeys, opPutIdentityRole, opDeleteIdentityRole,
		opPutEgressProfile, opDeleteEgressProfile, opPutTeamQuota, opDeleteTeamQuota, opPutWarmPool,
		opDeleteWarmPool, opSetKubeWarmDepths, opSetRunStates, opRetireNodeStorage, opRevokeNodeStorage,
		opOrphanOwner, opPruneAuditACL, opReserveBatch, opAllocateArtifactEpoch, opDenyNode,
		opPutJoinToken, opDeleteJoinToken, opAdmitNode, opAdoptNodes, opRekeyNode, opAdmitNodeByCert,
		opSetActiveVersion, opRolloutCommand, opRolloutNode,
	}
	for _, op := range serverOnly {
		if !peerMayPropose(JoinRoleServer, "srv-2", command{Op: op}) {
			t.Errorf("a server may not propose op %d", op)
		}
		for _, role := range []string{JoinRoleWorker, JoinRoleIngress, ""} {
			if peerMayPropose(role, "wkr-1", command{Op: op}) {
				t.Errorf("a %q node may propose op %d", role, op)
			}
		}
	}
	for op := range agentProposableOps {
		cmd := command{Op: op, NodeID: "wkr-1"}
		for _, role := range []string{JoinRoleWorker, JoinRoleIngress, ""} {
			if !peerMayPropose(role, "wkr-1", cmd) {
				t.Errorf("a %q node may not propose agent op %d", role, op)
			}
		}
	}
	drainOther := command{Op: opSetNodeDrainState, NodeID: "gw-1", Drained: true}
	if peerMayPropose(JoinRoleWorker, "wkr-1", drainOther) || peerMayPropose(JoinRoleWorker, "", command{Op: opSetNodeDrainState}) {
		t.Error("a worker may drain another node")
	}
	if !peerMayPropose(JoinRoleServer, "srv-2", drainOther) {
		t.Error("a server may not drain another node")
	}
}

// Every op the Agent code proposes (a command literal or a command
// builder reached from an Agent method) is one a worker or gateway may
// propose: a new Agent op must be added to agentProposableOps, or the
// leader refuses it from every worker.
func TestAgentProposalsAreProposable(t *testing.T) {
	ops := agentProposedOps(t)
	if len(ops) < 20 {
		t.Fatalf("found only %d Agent ops: the scan is broken: %v", len(ops), ops)
	}
	for _, name := range ops {
		if !agentProposableOpNames()[name] {
			t.Errorf("Agent code proposes %s, which agentProposableOps does not allow", name)
		}
	}
}

// agentProposableOpNames names agentProposableOps' ops, read from this
// package's source.
func agentProposableOpNames() map[string]bool {
	out := map[string]bool{}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "peer_proposals.go", nil, 0)
	if err != nil {
		return out
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if vs, ok := n.(*ast.ValueSpec); ok && len(vs.Names) == 1 && vs.Names[0].Name == "agentProposableOps" {
			if cl, ok := vs.Values[0].(*ast.CompositeLit); ok {
				for _, e := range cl.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						if id, ok := kv.Key.(*ast.Ident); ok {
							out[id.Name] = true
						}
					}
				}
			}
		}
		return true
	})
	return out
}

// agentProposedOps scans the package for the ops Agent methods propose:
// Op: opX in a command literal, x.Op = opX, and the same in any package
// function an Agent method calls that builds a command.
func agentProposedOps(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
	var agentMethods []*ast.FuncDecl
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if fd.Recv == nil {
				funcs[fd.Name.Name] = fd
				continue
			}
			if star, ok := fd.Recv.List[0].Type.(*ast.StarExpr); ok {
				if id, ok := star.X.(*ast.Ident); ok && id.Name == "Agent" {
					agentMethods = append(agentMethods, fd)
				}
			}
		}
	}
	found := map[string]bool{}
	seen := map[string]bool{}
	var walk func(fd *ast.FuncDecl)
	walk = func(fd *ast.FuncDecl) {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.KeyValueExpr:
				if k, ok := x.Key.(*ast.Ident); ok && k.Name == "Op" {
					if v, ok := x.Value.(*ast.Ident); ok && strings.HasPrefix(v.Name, "op") {
						found[v.Name] = true
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range x.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "Op" && i < len(x.Rhs) {
						if v, ok := x.Rhs[i].(*ast.Ident); ok && strings.HasPrefix(v.Name, "op") {
							found[v.Name] = true
						}
					}
				}
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && !seen[id.Name] {
					if callee, ok := funcs[id.Name]; ok && returnsCommand(callee) {
						seen[id.Name] = true
						walk(callee)
					}
				}
			}
			return true
		})
	}
	for _, m := range agentMethods {
		walk(m)
	}
	out := make([]string, 0, len(found))
	for name := range found {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func returnsCommand(fd *ast.FuncDecl) bool {
	if fd.Type.Results == nil {
		return false
	}
	for _, r := range fd.Type.Results.List {
		if id, ok := r.Type.(*ast.Ident); ok && id.Name == "command" {
			return true
		}
	}
	return false
}

// The leader refuses a raw apply a worker may not propose, before it is
// proposed, with a 403 every listener gives; a server's passes the role
// check; a request whose sender was not recorded is held to the least.
func TestApplyEncodedChecksTheSendersRole(t *testing.T) {
	c, cleanup := newTestCluster(t, "lp-leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	tokenCmd, err := encodeCommand(command{Op: opPutAPIToken, StampUnixNano: time.Now().UnixNano()})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		refused bool
	}{
		{"worker", ContextWithApplyPeer(context.Background(), "wkr-9", roleCert("wkr-9", JoinRoleWorker)), true},
		{"gateway", ContextWithApplyPeer(context.Background(), "gw-9", roleCert("gw-9", JoinRoleIngress)), true},
		{"unknown role", ContextWithApplyPeer(context.Background(), "old-9", roleCert("old-9", "")), true},
		{"no recorded sender", context.Background(), true},
		{"server (Raft member)", ContextWithApplyPeer(context.Background(), "lp-leader", roleCert("lp-leader", "")), false},
	} {
		err := c.ApplyEncoded(tc.ctx, tokenCmd)
		if got := errors.Is(err, ErrPeerProposalRefused); got != tc.refused {
			t.Errorf("%s: %v", tc.name, err)
		}
		if tc.refused && ApplyErrorStatus(err) != http.StatusForbidden {
			t.Errorf("%s: status %d", tc.name, ApplyErrorStatus(err))
		}
	}
	if page := c.APITokenPage("", 10); len(page.Tokens) != 0 {
		t.Fatal("a refused proposal reached the log")
	}
	// A worker's own ops still go through.
	drainSelf, _ := encodeCommand(command{Op: opSetNodeDrainState, NodeID: "wkr-9", Drained: true, StampUnixNano: time.Now().UnixNano()})
	if err := c.ApplyEncoded(ContextWithApplyPeer(context.Background(), "wkr-9", roleCert("wkr-9", JoinRoleWorker)), drainSelf); err != nil {
		t.Fatalf("a worker's own drain mark: %v", err)
	}
	drainOther, _ := encodeCommand(command{Op: opSetNodeDrainState, NodeID: "lp-leader", Drained: true, StampUnixNano: time.Now().UnixNano()})
	if err := c.ApplyEncoded(ContextWithApplyPeer(context.Background(), "wkr-9", roleCert("wkr-9", JoinRoleWorker)), drainOther); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("a worker's drain mark on another node: %v", err)
	}
}

// A worker or gateway holds no Raft state: a peer's raw apply that reached
// its listener is answered "not leader" (the peer tries a server), never
// sent on as this node's own proposal.
func TestAgentDoesNotRelayAPeersApply(t *testing.T) {
	a := &Agent{}
	payload, _ := encodeCommand(command{Op: opPutAPIToken})
	if err := a.ApplyEncoded(ContextWithApplyPeer(context.Background(), "wkr-2", nil), payload); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("relay = %v", err)
	}
	if ApplyErrorStatus(ErrNotLeader) != http.StatusServiceUnavailable {
		t.Fatal("not leader must stay retryable")
	}
}

// Who writes cluster-wide settings, and what a worker may write to the
// identity key set: the first key, and a reseal.
func TestSettingsWriters(t *testing.T) {
	l := admittedLog(t)
	c := &Cluster{fsm: l.f}
	for peer, want := range map[string]bool{"gw-1": true, "srv-2": true, "wkr-1": false, "nobody": false} {
		if got := c.IsSettingsWritePeer(peer, roleCert(peer, "")); got != want {
			t.Errorf("IsSettingsWritePeer(%s) = %v", peer, got)
		}
	}
	now := time.Unix(1700000000, 0)
	first := identityKeyRec(t, 0, now)
	role := IdentityWriteRequest{Role: &IdentityRoleRecord{Owner: "team:p", Tag: "deploy", MinRole: "runner"}}
	keys := func(gen int64, ks ...cloudidentity.KeyRecord) IdentityWriteRequest {
		return IdentityWriteRequest{Keys: &IdentityKeysWrite{ExpectedGeneration: gen, Keys: ks}}
	}
	// No key yet: a worker may make the first one, and nothing else.
	for _, tc := range []struct {
		name string
		peer string
		req  IdentityWriteRequest
		want error
	}{
		{"worker role write", "wkr-1", role, ErrIdentityWriterRefused},
		{"worker role delete", "wkr-1", IdentityWriteRequest{Role: role.Role, DeleteRole: true}, ErrIdentityWriterRefused},
		{"gateway role write", "gw-1", role, nil},
		{"server role write", "srv-2", role, nil},
		{"worker first key", "wkr-1", keys(0, first), nil},
		{"worker two first keys", "wkr-1", keys(0, first, identityKeyRec(t, 1, now)), ErrIdentityWriterRefused},
		{"worker stale generation", "wkr-1", keys(3, first), ErrIdentityKeysConflict},
		{"unknown role first key", "old-1", keys(0, first), nil},
	} {
		if err := c.CheckIdentityWriter(tc.peer, roleCert(tc.peer, ""), tc.req); !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	// With a key: a worker may reseal it, never rotate or replace it.
	if _, ok := l.apply(command{Op: opPutIdentityKeys, IdentityKeys: &IdentityKeysWrite{ExpectedGeneration: 0, Keys: []cloudidentity.KeyRecord{first}}}).(identityKeysApplyResult); !ok {
		t.Fatal("put the first key")
	}
	gen := l.f.identityKeys().Generation
	resealed := first.Clone()
	resealed.SealedPrivate = append([]byte("resealed:"), first.SealedPrivate...)
	retired := first.Clone()
	retired.RetiredUnixNano = now.Add(time.Hour).UnixNano()
	otherKey := first.Clone()
	otherKey.PublicJWK = identityKeyRec(t, 1, now).PublicJWK
	for _, tc := range []struct {
		name string
		req  IdentityWriteRequest
		want error
	}{
		{"reseal", keys(gen, resealed), nil},
		{"rotate (retire and add)", keys(gen, retired, identityKeyRec(t, 1, now)), ErrIdentityWriterRefused},
		{"retire the key", keys(gen, retired), ErrIdentityWriterRefused},
		{"swap the public key", keys(gen, otherKey), ErrIdentityWriterRefused},
		{"replace with a new first key", keys(gen, identityKeyRec(t, 1, now)), ErrIdentityWriterRefused},
		{"drop every key", keys(gen), ErrIdentityWriterRefused},
	} {
		if err := c.CheckIdentityWriter("wkr-1", roleCert("wkr-1", ""), tc.req); !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
			t.Errorf("worker %s: %v, want %v", tc.name, err, tc.want)
		}
		if err := c.CheckIdentityWriter("gw-1", roleCert("gw-1", ""), tc.req); err != nil {
			t.Errorf("gateway %s: %v", tc.name, err)
		}
	}
	if err := (*Cluster)(nil).CheckIdentityWriter("wkr-1", nil, keys(0, first)); !errors.Is(err, ErrIdentityWriterRefused) {
		t.Errorf("a node with no FSM: %v", err)
	}
	// The refusal survives the wire as its own code.
	out := IdentityWriteOutcome(ErrIdentityWriterRefused)
	if out.Code != identityCodeWriterRefused || !errors.Is(out.err(), ErrIdentityWriterRefused) {
		t.Fatalf("outcome %+v", out)
	}
}

// The internal listener's apply route hands the apply side the peer it
// verified and that peer's certificate, so the leader can check what the
// peer's role may propose; a refusal is the 403 every listener gives.
func TestInternalApplyCarriesThePeer(t *testing.T) {
	pool, tlsCert, err := generateTestCertForNode("worker-1")
	if err != nil {
		t.Fatal(err)
	}
	ct := &ClusterTLS{nodeCert: tlsCert, caPool: pool}
	var got applyPeer
	srv, err := startInternalServer("127.0.0.1:0", ct, func(ctx context.Context, _ []byte) error {
		got, _ = applyPeerFromContext(ctx)
		return ErrPeerProposalRefused
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.SetPeerAuthorizer(func(id string) bool { return id == "worker-1" })
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: ct.clientConfig()}}
	resp, err := client.Post("https://"+srv.Addr()+InternalAPIPath, "application/octet-stream", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || got.nodeID != "worker-1" || got.leaf == nil || ExtractPeerNodeID(got.leaf) != "worker-1" {
		t.Fatalf("status %d, peer %+v", resp.StatusCode, got)
	}
}
