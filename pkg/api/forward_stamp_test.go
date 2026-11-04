package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// ---------------------------------------------------------------------------
// Call-site test: every forward path calls cluster.StampForward (finding 1.2).
// ---------------------------------------------------------------------------

// peerRequestBuilders is every function in pkg/api that builds a fresh
// request to a peer carrying a user's request. Each must call
// cluster.StampForward. The list is pinned so the scan cannot pass by
// finding nothing; a new fan-out client is added here in the same change.
var peerRequestBuilders = []string{
	"clusterlist.fetchPeerJSON",
	"v1.clusterListFromPeer",
	"v1.runImageBuildOnTarget",
	"v1.templatePeerRequest",
}

// TestForwardPathsCallStampForward fails the build on a forward path that
// skips cluster.StampForward:
//
//   - every pkg/api function that addresses a peer (it stamps
//     X-Cluster-Peer-Node-ID with cluster.SetPeerNodeIDHeader) also calls
//     cluster.StampForward, and the set of such functions is exactly
//     peerRequestBuilders;
//   - the reverse-proxy Director behind cluster.ForwardHTTP (clusterroute,
//     clustercreate, runloop forwardToNode, js-bundle and template routing)
//     stamps through StampForward;
//   - nothing outside StampForward sets X-Cluster-Forwarded itself, so the
//     marker and the headers that travel with it can never come apart.
func TestForwardPathsCallStampForward(t *testing.T) {
	var builders []string
	forEachGoFunc(t, ".", func(pkg, file, fn string, body *ast.BlockStmt) {
		if !callsSelector(body, "cluster", "SetPeerNodeIDHeader") {
			return
		}
		name := pkg + "." + fn
		builders = append(builders, name)
		if !callsSelector(body, "cluster", "StampForward") {
			t.Errorf("%s (%s) sends a request to a peer without cluster.StampForward", name, file)
		}
	})
	sort.Strings(builders)
	if !reflect.DeepEqual(builders, peerRequestBuilders) {
		t.Errorf("peer request builders = %v\nwant %v (add a new fan-out client to peerRequestBuilders after making it call cluster.StampForward)", builders, peerRequestBuilders)
	}

	// The reverse-proxy Director.
	directorStamps := false
	forEachGoFunc(t, "../../internal/cluster", func(_, file, fn string, body *ast.BlockStmt) {
		if filepath.Base(file) == "forward.go" && fn == "getForPeer" && callsIdent(body, "stampForwardFromContext") {
			directorStamps = true
		}
	})
	if !directorStamps {
		t.Error("the ForwardHTTP reverse-proxy Director (internal/cluster/forward.go getForPeer) no longer stamps through StampForward")
	}

	// Only StampForward sets the forwarded marker.
	for _, root := range []string{".", "../../internal/cluster"} {
		forEachGoFunc(t, root, func(pkg, file, fn string, body *ast.BlockStmt) {
			if filepath.Base(file) == "forward_stamp.go" {
				return
			}
			ast.Inspect(body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "Set" && sel.Sel.Name != "Add") {
					return true
				}
				if isForwardedMarker(call.Args[0]) {
					t.Errorf("%s.%s (%s) sets X-Cluster-Forwarded itself; use cluster.StampForward", pkg, fn, file)
				}
				return true
			})
		})
	}
}

func isForwardedMarker(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return strings.EqualFold(strings.Trim(v.Value, "`\""), cluster.HeaderForwarded)
	case *ast.SelectorExpr:
		return v.Sel.Name == "HeaderForwarded"
	case *ast.Ident:
		return v.Name == "HeaderForwarded"
	}
	return false
}

// forEachGoFunc parses every non-test Go file under root and calls visit
// for each function declaration (closures are part of their enclosing
// function's body).
func forEachGoFunc(t *testing.T, root string, visit func(pkg, file, fn string, body *ast.BlockStmt)) {
	t.Helper()
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Body != nil {
				visit(f.Name.Name, path, fd.Name.Name, fd.Body)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan %s: %v", root, err)
	}
}

func callsSelector(body *ast.BlockStmt, pkg, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == pkg {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

func callsIdent(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == name {
				found = true
			}
		}
		return !found
	})
	return found
}

// ---------------------------------------------------------------------------
// E6: a multi-team caller's list fan-out answers one team on every peer.
// ---------------------------------------------------------------------------

// multiTeamCredential stands in for an OIDC token that matches two team
// bindings (T6). T1's team selection is single-binding, so the test plays
// the T6 rule itself: the X-AerolVM-Team header picks among the bindings
// the token matches, and with no header the first binding wins.
type multiTeamCredential struct{ bindings []string }

func (m multiTeamCredential) Authenticate(r *http.Request, bearer string) (controlplane.Access, bool, error) {
	if bearer != "avm_multi" {
		return controlplane.Access{}, false, nil
	}
	team := m.bindings[0]
	for _, b := range m.bindings {
		if b == r.Header.Get(HeaderTeam) {
			team = b
		}
	}
	return controlplane.Access{
		Identity:  controlplane.Identity{OwnerRef: controlplane.TeamOwnerRef(team)},
		Role:      controlplane.RoleRunner,
		Principal: controlplane.Principal{Kind: controlplane.PrincipalToken, ID: "tok_multi", Name: "multi"},
	}, true, nil
}

// peerSideCluster is the cluster a peer node sees: the edge is a live member,
// so the forward markers it sends pass clusterControlHeaderGuard.
type peerSideCluster struct {
	*cluster.Noop
	edge string
}

func (c *peerSideCluster) LookupMember(id string) (cluster.Member, bool) {
	if id == c.edge {
		return cluster.Member{NodeID: id, Alive: true}, true
	}
	return c.Noop.LookupMember(id)
}

// edgeSideCluster is the edge's view: a small fleet whose placement index is
// still cold, so the list fans out to every owner peer with no id filter and
// whatever a peer answers reaches the caller.
type edgeSideCluster struct {
	*cluster.Noop
	members []cluster.Member
	clients map[string]*http.Client
}

func (c *edgeSideCluster) Members() []cluster.Member { return c.members }
func (c *edgeSideCluster) PlacementPage(cluster.PlacementPageRequest) cluster.PlacementPageResponse {
	return cluster.PlacementPageResponse{}
}
func (c *edgeSideCluster) PeerInternalHTTPClient() *http.Client { return http.DefaultClient }
func (c *edgeSideCluster) ClientForPeer(id string) *http.Client { return c.clients[id] }

func storeWith(t *testing.T, name string, sandboxes ...*models.Sandbox) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), name+".db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	for _, sb := range sandboxes {
		if err := st.Create(context.Background(), sb); err != nil {
			t.Fatalf("create %s: %v", sb.ID, err)
		}
	}
	return st
}

func ownedSandbox(id, team string) *models.Sandbox {
	now := time.Now().UTC()
	return &models.Sandbox{
		ID: id, Image: "alpine:3.19", Status: models.SandboxStatusStarted, Runtime: models.RuntimeDocker,
		CPU: 1, MemoryMB: 256, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		AuditIncarnationID: "inc-" + id, OwnerRef: controlplane.TeamOwnerRef(team),
	}
}

// TestClusterListFanOutKeepsTeamAndCorrelation is E6: a caller whose token
// matches teams alpha and bravo lists with X-AerolVM-Team: bravo through an
// edge node. Every peer holds sandboxes of both teams. Before StampForward
// the fan-out sent only Authorization, so each peer re-resolved the token
// with no team header and answered for alpha; now every peer answers for
// bravo, and every peer sees the one correlation id the edge used.
func TestClusterListFanOutKeepsTeamAndCorrelation(t *testing.T) {
	cred := WithCredentialAuthenticator(controlplane.PrincipalToken, multiTeamCredential{bindings: []string{"alpha", "bravo"}})
	cfg := config.Config{IdentityEnabled: true, EnableCluster: true}

	type seen struct {
		team, correlation, forwarded string
	}
	var mu sync.Mutex
	peerSaw := map[string]seen{}
	clients := map[string]*http.Client{}
	var members []cluster.Member
	for _, id := range []string{"peer-1", "peer-2"} {
		id := id
		st := storeWith(t, id, ownedSandbox("sb-alpha-"+id, "alpha"), ownedSandbox("sb-bravo-"+id, "bravo"))
		svc := service.New(config.Config{EnableCluster: true}, discardLogger(), st, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(&peerSideCluster{Noop: cluster.NewNoop(id, "", ""), edge: "edge"})
		peer := NewServer(discardLogger(), svc, nil, nil, cfg, "pat-token", nil, cred)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			peerSaw[id] = seen{team: r.Header.Get(HeaderTeam), correlation: r.Header.Get(cluster.HeaderCorrelationID), forwarded: r.Header.Get(cluster.HeaderForwarded)}
			mu.Unlock()
			// The internal listener verified the edge's certificate.
			r.TLS = peerTLS("edge")
			peer.Handler().ServeHTTP(w, r)
		}))
		t.Cleanup(srv.Close)
		clients[id] = srv.Client()
		members = append(members, cluster.Member{NodeID: id, Alive: true, Role: config.NodeRoleWorker, InternalURL: srv.URL})
	}
	edgeStore := storeWith(t, "edge", ownedSandbox("sb-alpha-edge", "alpha"), ownedSandbox("sb-bravo-edge", "bravo"))
	edgeSvc := service.New(config.Config{EnableCluster: true}, discardLogger(), edgeStore, nil, nil, nil, nil, nil, nil)
	edgeSvc.AttachCluster(&edgeSideCluster{
		Noop:    cluster.NewNoop("edge", "", ""),
		members: append([]cluster.Member{{NodeID: "edge", Alive: true, Role: config.NodeRoleWorker}}, members...),
		clients: clients,
	})
	edge := NewServer(discardLogger(), edgeSvc, nil, nil, cfg, "pat-token", nil, cred)

	list := func(t *testing.T, team, correlation string) []string {
		t.Helper()
		mu.Lock()
		peerSaw = map[string]seen{}
		mu.Unlock()
		req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
		req.Header.Set("Authorization", "Bearer avm_multi")
		if team != "" {
			req.Header.Set(HeaderTeam, team)
		}
		if correlation != "" {
			req.Header.Set("X-Correlation-ID", correlation)
		}
		rec := httptest.NewRecorder()
		edge.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
		}
		if partial := rec.Header().Get("X-Cluster-List-Partial"); partial != "false" {
			t.Fatalf("list partial = %q (missing %q)", partial, rec.Header().Get("X-Cluster-List-Missing"))
		}
		var rows []models.Sandbox
		if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(rows))
		for _, sb := range rows {
			ids = append(ids, sb.ID)
		}
		sort.Strings(ids)
		return ids
	}

	t.Run("selected team bravo, caller's correlation id", func(t *testing.T) {
		got := list(t, "bravo", "corr-e6")
		want := []string{"sb-bravo-edge", "sb-bravo-peer-1", "sb-bravo-peer-2"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("list = %v, want only team bravo from every node: %v", got, want)
		}
		for _, id := range []string{"peer-1", "peer-2"} {
			if s := peerSaw[id]; s != (seen{team: "bravo", correlation: "corr-e6", forwarded: "1"}) {
				t.Fatalf("%s saw %+v", id, s)
			}
		}
	})

	t.Run("no team header: the first binding, named explicitly to every peer, one minted id", func(t *testing.T) {
		got := list(t, "", "")
		want := []string{"sb-alpha-edge", "sb-alpha-peer-1", "sb-alpha-peer-2"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("list = %v, want %v", got, want)
		}
		first, second := peerSaw["peer-1"], peerSaw["peer-2"]
		if first.team != "alpha" || second.team != "alpha" {
			t.Fatalf("peers saw teams %q and %q, want alpha", first.team, second.team)
		}
		if first.correlation == "" || first.correlation != second.correlation {
			t.Fatalf("peers saw correlation ids %q and %q, want one shared id", first.correlation, second.correlation)
		}
	})
}

// ---------------------------------------------------------------------------
// Forwarded attribution: the owner records the edge caller with via.
// ---------------------------------------------------------------------------

// openGateCluster is an owner whose gossip view says every member reads the
// caller field, with edge-1 a live peer.
type openGateCluster struct{ peerSideCluster }

func (c *openGateCluster) AuditCallerWritesAllowed() bool { return true }

// TestForwardedRequestAttributedOnOwner is the forwarded attribution test:
// edge-1 forwards a team token's mounts read (a secret open) to the owner
// over mTLS. The owner re-authenticates the original credential, takes Via
// from the verified peer certificate, and chains a record naming the edge
// caller, its team, edge-1 as via and the edge's correlation id. The chain
// on disk still verifies.
func TestForwardedRequestAttributedOnOwner(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "owner.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cipher, err := secrets.NewCipher("", filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	sb := ownedSandbox("sb-owned", "payments")
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
	plain, _ := json.Marshal(models.MountSpecFile{Mounts: []models.MountSpec{{Type: "nfs", Source: "nfs.example.com:/export", Target: "/mnt/data"}}})
	sealed, err := cipher.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutMounts(context.Background(), sb.ID, sealed); err != nil {
		t.Fatal(err)
	}
	svcCfg := config.Config{DBPath: dbPath, EnableCluster: true, SecretAuditRetentionDays: 30}
	svc := service.New(svcCfg, discardLogger(), st, nil, nil, nil, cipher, nil, nil)
	svc.AttachCluster(&openGateCluster{peerSideCluster{Noop: cluster.NewNoop("owner-1", "", ""), edge: "edge-1"}})
	owner := NewServer(discardLogger(), svc, nil, nil, config.Config{IdentityEnabled: true, EnableCluster: true}, "pat-token", nil,
		WithCredentialAuthenticator(controlplane.PrincipalToken, stubTokens()))

	// What edge-1's StampForward put on the wire, arriving on the owner's
	// internal listener from edge-1's verified certificate.
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/"+sb.ID+"/mounts", nil)
	req.TLS = peerTLS("edge-1")
	req.Header.Set(cluster.PeerNodeIDHeader, "edge-1")
	req.Header.Set("Authorization", "Bearer avm_payments")
	req.Header.Set(cluster.HeaderForwarded, "1")
	req.Header.Set(HeaderTeam, "payments")
	req.Header.Set(cluster.HeaderCorrelationID, "corr-fwd")
	rec := httptest.NewRecorder()
	owner.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("forwarded mounts read = %d %s", rec.Code, rec.Body.String())
	}
	svc.CloseSecretAuditSink()

	raw, err := os.ReadFile(filepath.Join(dir, "audit", "secrets.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if _, err := auditlog.ScanChain(bytes.NewReader(raw), auditlog.ScanOptions{}); err != nil {
		t.Fatalf("owner chain no longer verifies: %v", err)
	}
	var found *auditlog.Event
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		var ev auditlog.Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err == nil && ev.Ref == "mounts:"+sb.ID {
			found = &ev
		}
	}
	if found == nil {
		t.Fatalf("no secret_open for the mounts read in %s", raw)
	}
	want := &auditlog.Caller{Kind: "token", ID: "tok_7Hq2", Name: "ci-deploy", Team: "payments", Via: "edge-1"}
	if !reflect.DeepEqual(found.Caller, want) {
		t.Fatalf("owner record caller = %+v, want %+v", found.Caller, want)
	}
	if found.CorrelationID != "corr-fwd" || found.NodeID != "owner-1" || found.OwnerRef != "team:payments" {
		t.Fatalf("owner record = %+v: want the edge's correlation id, written by owner-1 for team:payments", found)
	}
}

// TestWithCorrelationID: every authenticated request carries one
// correlation id: the caller's, else one already on the context, else a
// fresh one.
func TestWithCorrelationID(t *testing.T) {
	server := newIdentityServer(nil)
	var got []string
	protected := server.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, auditlog.CorrelationIDFromContext(r.Context()))
		w.WriteHeader(http.StatusNoContent)
	}))
	call := func(ctx context.Context, header, value string) {
		req := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer pat-token")
		if header != "" {
			req.Header.Set(header, value)
		}
		protected.ServeHTTP(httptest.NewRecorder(), req)
	}
	call(context.Background(), "X-Correlation-ID", "corr-1")
	call(context.Background(), "X-Request-ID", "req-1")
	call(auditlog.ContextWithCorrelationID(context.Background(), "outer-mcp"), "", "")
	call(context.Background(), "", "")
	call(context.Background(), "", "")
	if got[0] != "corr-1" || got[1] != "req-1" || got[2] != "outer-mcp" {
		t.Fatalf("correlation ids = %v", got)
	}
	if got[3] == "" || got[4] == "" || got[3] == got[4] {
		t.Fatalf("minted ids = %q, %q: want two distinct non-empty ids", got[3], got[4])
	}
}
