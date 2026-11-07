package clusterroute

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// fleet is an in-process cluster for routing tests. Its nodes share one
// placement table (the server tier) and forward to each other by calling the
// peer's handler, the way the reverse proxy does over mTLS: the outbound
// request is stamped by cluster.StampForward and the peer sees only headers,
// the body and the caller's re-authenticated identity, never the edge's
// context.
type fleet struct {
	t       testing.TB
	mu      sync.Mutex
	place   map[string]fleetPlacement  // sandbox id -> placement
	rows    map[string]map[string]bool // node -> sandbox ids it holds a local row for
	nodes   map[string]*fleetNode
	dead    map[string]bool // nodes gossip reports dead
	lookups atomic.Int64    // control-plane reads made by every node's router
}

type fleetPlacement struct {
	node     string
	ownerRef string
	orphaned bool
}

type fleetNode struct {
	*cluster.Noop
	f     *fleet
	id    string
	cache *cluster.OwnerCache
	h     http.Handler
	// view, when set, replaces the shared table for this node: a lagging
	// placement view.
	view map[string]fleetPlacement

	served   atomic.Int64 // local handler runs that found a row
	notHere  atomic.Int64 // "not here" answers this node gave
	forwards atomic.Int64 // forwards this node sent
	hinted   atomic.Int64 // forwards this node sent with the route hint
	// localAnswer, when set, is what this node's local handler writes for a
	// row it holds (the sandbox's own answer).
	localAnswer func(w http.ResponseWriter, r *http.Request)
	lastState   *auditlog.CallState // audit state of the last forward this node received
}

// newFleet builds nodes with the given ids; withCache turns the owner cache
// on for every node, as SB_CLUSTER_OWNER_CACHE would on each worker/ingress.
func newFleet(t testing.TB, withCache bool, ids ...string) *fleet {
	t.Helper()
	f := &fleet{
		t:     t,
		place: map[string]fleetPlacement{},
		rows:  map[string]map[string]bool{},
		nodes: map[string]*fleetNode{},
		dead:  map[string]bool{},
	}
	for _, id := range ids {
		n := &fleetNode{Noop: cluster.NewNoop(id, "http://"+id, ""), f: f, id: id}
		if withCache {
			n.cache = cluster.NewOwnerCache(id, 0, 0, f.member)
		}
		mux := http.NewServeMux()
		mux.Handle("/x/{id}", Wrap(svcWith(t, n), Options{WriteError: writeErr}, http.HandlerFunc(n.serveLocal)))
		n.h = mux
		f.nodes[id] = n
	}
	return f
}

// placeOn records sandbox id on node (with a local row there) for tenant.
func (f *fleet) placeOn(id, node, ownerRef string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.place[id] = fleetPlacement{node: node, ownerRef: ownerRef}
	f.holdLocked(node, id)
}

func (f *fleet) holdLocked(node, id string) {
	if f.rows[node] == nil {
		f.rows[node] = map[string]bool{}
	}
	f.rows[node][id] = true
}

// move reassigns id to node; the old owner keeps its local row, the way a
// cut-off or slow old owner does until reconcile stops its copy.
func (f *fleet) move(id, node string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.place[id]
	p.node = node
	f.place[id] = p
	f.holdLocked(node, id)
}

func (f *fleet) remove(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.place, id)
}

func (f *fleet) orphan(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.place[id]
	p.node, p.orphaned = "", true
	f.place[id] = p
}

func (f *fleet) markDead(node string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dead[node] = true
}

func (f *fleet) member(node string) (cluster.Member, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.nodes[node]; !ok {
		return cluster.Member{}, false
	}
	return cluster.Member{NodeID: node, Alive: !f.dead[node], APIURL: "http://" + node, InternalURL: "https://" + node + ":7002"}, true
}

func (n *fleetNode) lookup(id string) (fleetPlacement, bool) {
	n.f.lookups.Add(1)
	n.f.mu.Lock()
	defer n.f.mu.Unlock()
	if n.view != nil {
		p, ok := n.view[id]
		return p, ok
	}
	p, ok := n.f.place[id]
	return p, ok
}

func (n *fleetNode) OwnerOf(id string) (cluster.OwnerInfo, error) {
	p, ok := n.lookup(id)
	switch {
	case !ok:
		return cluster.OwnerInfo{}, cluster.ErrUnknownSandbox
	case p.orphaned:
		return cluster.OwnerInfo{}, cluster.ErrOrphaned
	}
	return cluster.OwnerInfo{NodeID: p.node, APIURL: "http://" + p.node, InternalURL: "https://" + p.node + ":7002", IsSelf: p.node == n.id}, nil
}

func (n *fleetNode) PlacementOf(id string) (cluster.Placement, bool) {
	p, ok := n.lookup(id)
	if !ok {
		return cluster.Placement{}, false
	}
	return cluster.Placement{SandboxID: id, OwnerNodeID: p.node, OwnerRef: p.ownerRef}, true
}

func (n *fleetNode) OwnerOfName(string, string) (string, cluster.OwnerInfo, error) {
	n.f.lookups.Add(1)
	return "", cluster.OwnerInfo{}, cluster.ErrUnknownSandbox
}

func (n *fleetNode) OwnerCache() *cluster.OwnerCache { return n.cache }

func (n *fleetNode) ForwardHTTP(target cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	n.forwards.Add(1)
	peer, ok := n.f.nodes[target.NodeID]
	if !ok {
		http.Error(w, "no such node", http.StatusBadGateway)
		return
	}
	access, _ := controlplane.AccessFromContext(r.Context())
	out := r.Clone(r.Context())
	cluster.StampForward(out, access)
	if out.Header.Get(cluster.HeaderRouteHint) != "" {
		n.hinted.Add(1)
	}
	// What arrives at the peer: a fresh request context carrying only the
	// re-authenticated caller and the peer's own audit state.
	ctx := context.Background()
	if _, ok := controlplane.AccessFromContext(r.Context()); ok {
		ctx = controlplane.ContextWithAccess(ctx, access)
	}
	ctx, st := auditlog.ContextWithCallState(ctx)
	peer.lastState = st
	in := out.WithContext(ctx)
	ow := &observeWriter{ResponseWriter: w}
	peer.h.ServeHTTP(ow, in)
	if ow.notHere {
		peer.notHere.Add(1)
	}
}

func (n *fleetNode) serveLocal(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n.f.mu.Lock()
	held := n.f.rows[n.id][id]
	n.f.mu.Unlock()
	if !held {
		http.Error(w, "sandbox not found", http.StatusNotFound)
		return
	}
	n.served.Add(1)
	if n.localAnswer != nil {
		n.localAnswer(w, r)
		return
	}
	body, _ := io.ReadAll(r.Body)
	w.Header().Set("X-Served-By", n.id)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// call sends one client request to node and returns the response.
func (f *fleet) call(node, method, id, body, tenant string) *httptest.ResponseRecorder {
	f.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/x/"+id, rd)
	ctx, _ := auditlog.ContextWithCallState(r.Context())
	if tenant != "" {
		ctx = controlplane.ContextWithAccess(ctx, controlplane.Access{Identity: controlplane.Identity{ExternalID: "u-" + tenant, OwnerRef: tenant}})
	}
	r = r.WithContext(ctx)
	rr := httptest.NewRecorder()
	f.nodes[node].h.ServeHTTP(rr, r)
	return rr
}

// counters is a snapshot of every node's routing counters.
type counters struct {
	lookups                           int64
	served, notHere, forwards, hinted map[string]int64
}

func (f *fleet) snapshot() counters {
	c := counters{lookups: f.lookups.Load(), served: map[string]int64{}, notHere: map[string]int64{}, forwards: map[string]int64{}, hinted: map[string]int64{}}
	for id, n := range f.nodes {
		c.served[id] = n.served.Load()
		c.notHere[id] = n.notHere.Load()
		c.forwards[id] = n.forwards.Load()
		c.hinted[id] = n.hinted.Load()
	}
	return c
}

// since is c minus an earlier snapshot.
func (c counters) since(prev counters) counters {
	d := counters{lookups: c.lookups - prev.lookups, served: map[string]int64{}, notHere: map[string]int64{}, forwards: map[string]int64{}, hinted: map[string]int64{}}
	for id := range c.served {
		d.served[id] = c.served[id] - prev.served[id]
		d.notHere[id] = c.notHere[id] - prev.notHere[id]
		d.forwards[id] = c.forwards[id] - prev.forwards[id]
		d.hinted[id] = c.hinted[id] - prev.hinted[id]
	}
	return d
}

// observeWriter notes a peer's "not here" as it passes through.
type observeWriter struct {
	http.ResponseWriter
	notHere bool
}

func (o *observeWriter) WriteHeader(code int) {
	if code == http.StatusMisdirectedRequest && o.Header().Get(cluster.HeaderNotOwner) != "" {
		o.notHere = true
	}
	o.ResponseWriter.WriteHeader(code)
}
