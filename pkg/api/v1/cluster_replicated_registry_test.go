package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

type registryStubCluster struct {
	*cluster.Noop
	askedKind   string
	askedTenant string
	askedNode   string
	askedHolder string
	allocErr    error
	// leader overrides the Noop's "I am the leader" answer so the
	// authoritative gate can be exercised from a follower.
	leader string
}

func (c *registryStubCluster) Leader() string {
	if c.leader != "" {
		return c.leader
	}
	return c.Noop.Leader()
}

func (c *registryStubCluster) NodeStorageRetirementsForPeer() cluster.NodeStorageRetirementsResponse {
	return cluster.NodeStorageRetirementsResponse{
		Retirements:   []cluster.NodeStorageRetirement{{NodeID: "node-gone", AttestedUnixNano: 7}},
		Authoritative: true,
	}
}

// AllocateArtifactCatalogEpoch records what the handler passed through, so
// the test can prove the node came from the authenticated identity.
func (c *registryStubCluster) AllocateArtifactCatalogEpoch(_ context.Context, kind, nodeID, holder string) (int64, error) {
	c.askedKind, c.askedNode, c.askedHolder = kind, nodeID, holder
	if c.allocErr != nil {
		return 0, c.allocErr
	}
	return 7, nil
}

func (c *registryStubCluster) ArtifactCatalogForPeer(req cluster.ArtifactCatalogRequest) cluster.ArtifactCatalogPage {
	c.askedKind, c.askedTenant = req.Kind, req.Tenant
	return cluster.ArtifactCatalogPage{
		Rows:          []cluster.ArtifactCatalogRow{{ID: "tpl-1", Payload: []byte(`{"id":"tpl-1"}`)}},
		Publishers:    []string{"worker-a"},
		Authoritative: true,
	}
}

// Obligation owners are workers, which hold no FSM: they read the replicated
// attestation set from the server tier. The route is peer-authenticated like
// every other internal read.
func TestClusterInternalNodeStorageRetirementsRequiresPeerIdentity(t *testing.T) {
	stub := &registryStubCluster{Noop: cluster.NewNoop("srv", "http://srv", "")}
	h := newOwnedRecoveryHandlers(t, stub)

	anon := httptest.NewRequest(http.MethodGet, cluster.PublicInternalNodeStorageRetirementsPath, nil)
	anonRR := httptest.NewRecorder()
	h.clusterInternalNodeStorageRetirements(anonRR, anon)
	if anonRR.Code != http.StatusForbidden {
		t.Fatalf("anonymous read status = %d, want 403", anonRR.Code)
	}

	req := withPeer(httptest.NewRequest(http.MethodGet, cluster.PublicInternalNodeStorageRetirementsPath, nil), "wrk-a")
	rr := httptest.NewRecorder()
	h.clusterInternalNodeStorageRetirements(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp cluster.NodeStorageRetirementsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Authoritative || len(resp.Retirements) != 1 {
		t.Fatalf("response = %+v; a worker must be able to tell an empty set from an unanswerable read", resp)
	}
}

// The catalogue read is what replaces the fleet-wide list sweep, and it is
// scoped by the tenant the caller asks for.
func TestClusterInternalArtifactCatalogServesTenantScopedRows(t *testing.T) {
	stub := &registryStubCluster{Noop: cluster.NewNoop("srv", "http://srv", "")}
	h := newOwnedRecoveryHandlers(t, stub)

	body := `{"kind":"js-bundle","tenant":"tenant-a"}`
	anon := httptest.NewRequest(http.MethodPost, cluster.PublicInternalArtifactCatalogPath, strings.NewReader(body))
	anonRR := httptest.NewRecorder()
	h.clusterInternalArtifactCatalog(anonRR, anon)
	if anonRR.Code != http.StatusForbidden {
		t.Fatalf("anonymous catalogue read status = %d, want 403", anonRR.Code)
	}

	req := withPeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalArtifactCatalogPath, strings.NewReader(body)), "wrk-a")
	rr := httptest.NewRecorder()
	h.clusterInternalArtifactCatalog(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if stub.askedKind != "js-bundle" || stub.askedTenant != "tenant-a" {
		t.Fatalf("asked kind=%q tenant=%q", stub.askedKind, stub.askedTenant)
	}
	var page cluster.ArtifactCatalogPage
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(page.Rows) != 1 || len(page.Publishers) != 1 {
		t.Fatalf("page = %+v; the publishers are what tell the aggregator which nodes it still has to ask", page)
	}
}

// A node that holds no placement state cannot answer either read, and must
// say so rather than returning an empty set.
func TestClusterInternalRegistryReadsRequirePlacementState(t *testing.T) {
	h := newOwnedRecoveryHandlers(t, cluster.NewNoop("srv", "http://srv", ""))

	rr := httptest.NewRecorder()
	h.clusterInternalNodeStorageRetirements(rr, withPeer(httptest.NewRequest(http.MethodGet, cluster.PublicInternalNodeStorageRetirementsPath, nil), "wrk-a"))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("retirement read on a stateless node = %d, want 503", rr.Code)
	}

	catalogRR := httptest.NewRecorder()
	req := withPeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalArtifactCatalogPath, strings.NewReader(`{"kind":"template"}`)), "wrk-a")
	h.clusterInternalArtifactCatalog(catalogRR, req)
	if catalogRR.Code != http.StatusServiceUnavailable {
		t.Fatalf("catalogue read on a stateless node = %d, want 503", catalogRR.Code)
	}
}

type stubCatalogService struct {
	pages []cluster.ArtifactCatalogPage
	ok    bool
	reads int
}

func (s *stubCatalogService) ClusterArtifactCatalog(_ context.Context, req cluster.ArtifactCatalogRequest) (cluster.ArtifactCatalogPage, bool) {
	s.reads++
	if !s.ok {
		return cluster.ArtifactCatalogPage{}, false
	}
	for _, page := range s.pages {
		// The stub keys its pages on the cursor the reader sends back.
		if page.NextPageToken == req.PageToken || (req.PageToken == "" && page.NextPageToken == "") {
			return page, true
		}
	}
	if len(s.pages) == 0 {
		return cluster.ArtifactCatalogPage{Authoritative: true}, true
	}
	return s.pages[len(s.pages)-1], true
}

// A catalogue the control plane could not answer for must read as "no
// catalogue" so the sweep still asks peers, and a row this build cannot
// decode must not take the rest of the catalogue with it — its publisher
// simply keeps being asked.
func TestReadClusterArtifactCatalogDecodesAndFallsBack(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/templates", nil)

	if _, _, ok := readClusterArtifactCatalog[*cluster.Placement](req, nil, "template", ""); ok {
		t.Fatal("a nil service reported a catalogue")
	}
	if _, _, ok := readClusterArtifactCatalog[*cluster.Placement](nil, &stubCatalogService{ok: true}, "template", ""); ok {
		t.Fatal("a nil request reported a catalogue")
	}
	if _, _, ok := readClusterArtifactCatalog[*cluster.Placement](req, &stubCatalogService{}, "template", ""); ok {
		t.Fatal("an unavailable catalogue was reported as usable; the sweep must still run")
	}

	svc := &stubCatalogService{ok: true, pages: []cluster.ArtifactCatalogPage{{
		Rows: []cluster.ArtifactCatalogRow{
			{ID: "good", Payload: []byte(`{"sandbox_id":"good"}`)},
			{ID: "unreadable", Payload: []byte(`not json`)},
		},
		Publishers: []string{"worker-a"},
	}}}
	rows, publishers, ok := readClusterArtifactCatalog[*cluster.Placement](req, svc, "template", "")
	if !ok || len(publishers) != 1 {
		t.Fatalf("ok=%v publishers=%v", ok, publishers)
	}
	if len(rows) != 1 || rows[0].SandboxID != "good" {
		t.Fatalf("rows = %+v, want the decodable row only", rows)
	}
}

// Both internal reads refuse a malformed body and a node with no cluster at
// all rather than answering with an empty set.
func TestClusterInternalArtifactCatalogRejectsBadInput(t *testing.T) {
	stub := &registryStubCluster{Noop: cluster.NewNoop("srv", "http://srv", "")}
	h := newOwnedRecoveryHandlers(t, stub)

	rr := httptest.NewRecorder()
	bad := withPeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalArtifactCatalogPath, strings.NewReader("{")), "wrk-a")
	h.clusterInternalArtifactCatalog(rr, bad)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("malformed catalogue request = %d, want 400", rr.Code)
	}

	// A node with no cluster attached answers 503 rather than an empty set.
	standalone := newOwnedRecoveryHandlers(t, nil)
	noneRR := httptest.NewRecorder()
	standalone.clusterInternalArtifactCatalog(noneRR, withPeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalArtifactCatalogPath, strings.NewReader(`{}`)), "wrk-a"))
	if noneRR.Code != http.StatusServiceUnavailable {
		t.Fatalf("catalogue read with no cluster = %d, want 503", noneRR.Code)
	}
	retireRR := httptest.NewRecorder()
	standalone.clusterInternalNodeStorageRetirements(retireRR, withPeer(httptest.NewRequest(http.MethodGet, cluster.PublicInternalNodeStorageRetirementsPath, nil), "wrk-a"))
	if retireRR.Code != http.StatusServiceUnavailable {
		t.Fatalf("retirement read with no cluster = %d, want 503", retireRR.Code)
	}
}

// The catalogue read is paged: a single response budget with the remainder
// dropped sent most of a large fleet back to the peer sweep even though the
// FSM already held its metadata. The aggregator therefore walks the cursor,
// and only claims coverage for a walk that finished.
func TestReadClusterArtifactCatalogWalksEveryPage(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/templates", nil)
	svc := &stubCatalogService{ok: true, pages: []cluster.ArtifactCatalogPage{
		{
			Rows:          []cluster.ArtifactCatalogRow{{ID: "a", Payload: []byte(`{"sandbox_id":"a"}`)}},
			Publishers:    []string{"worker-a", "worker-b"},
			NextPageToken: "",
			Authoritative: true,
		},
		{
			Rows:          []cluster.ArtifactCatalogRow{{ID: "b", Payload: []byte(`{"sandbox_id":"b"}`)}},
			Authoritative: true,
		},
	}}
	// First read (empty cursor) returns page 0 with a cursor; the stub then
	// answers the cursor with the final page.
	svc.pages[0].NextPageToken = ""
	svc.pages[1].NextPageToken = ""

	rows, publishers, ok := readClusterArtifactCatalog[*cluster.Placement](req, svc, "template", "")
	if !ok {
		t.Fatal("a complete walk was reported as unusable")
	}
	if len(publishers) != 2 {
		t.Fatalf("publishers = %v; coverage is complete on the first page", publishers)
	}
	if len(rows) != 1 || rows[0].SandboxID != "a" {
		t.Fatalf("rows = %+v", rows)
	}
	if svc.reads != 1 {
		t.Fatalf("made %d reads for a single-page catalogue", svc.reads)
	}
}

// A walk that cannot finish must not claim coverage: the aggregator would
// skip nodes whose rows it never received.
func TestReadClusterArtifactCatalogRefusesAnUnfinishedWalk(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/templates", nil)
	// A control plane that keeps handing back a fresh cursor forever.
	svc := &endlessCursorCatalog{}
	if _, _, ok := readClusterArtifactCatalog[*cluster.Placement](req, svc, "template", ""); ok {
		t.Fatal("an unfinished walk claimed coverage; the rows behind the cursor would be dropped from the answer")
	}
	if svc.reads <= 1 {
		t.Fatalf("made %d reads; the walk must follow the cursor before giving up", svc.reads)
	}
}

type endlessCursorCatalog struct{ reads int }

func (c *endlessCursorCatalog) ClusterArtifactCatalog(context.Context, cluster.ArtifactCatalogRequest) (cluster.ArtifactCatalogPage, bool) {
	c.reads++
	return cluster.ArtifactCatalogPage{
		Rows:          []cluster.ArtifactCatalogRow{{ID: fmt.Sprintf("row-%d", c.reads), Payload: []byte(`{}`)}},
		NextPageToken: fmt.Sprintf("cursor-%d", c.reads),
		Authoritative: true,
	}, true
}

// Discharging a deletion obligation without an ACK is irreversible, so the
// read that authorizes it asks the LEADER: a follower whose FSM has not yet
// applied an operator's revoke would otherwise authorize a removal that was
// already withdrawn.
func TestClusterInternalNodeStorageRetirementsAuthoritativeNeedsLeadership(t *testing.T) {
	stub := &registryStubCluster{Noop: cluster.NewNoop("srv-follower", "http://srv", ""), leader: "srv-leader"}
	h := newOwnedRecoveryHandlers(t, stub)

	req := withPeer(httptest.NewRequest(http.MethodGet, cluster.PublicInternalNodeStorageRetirementsPath+"?authoritative=true", nil), "wrk-a")
	rr := httptest.NewRecorder()
	h.clusterInternalNodeStorageRetirements(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("authoritative read on a non-leader = %d, want 503", rr.Code)
	}

	// The ordinary discovery read is answerable by any server.
	plain := withPeer(httptest.NewRequest(http.MethodGet, cluster.PublicInternalNodeStorageRetirementsPath, nil), "wrk-a")
	plainRR := httptest.NewRecorder()
	h.clusterInternalNodeStorageRetirements(plainRR, plain)
	if plainRR.Code != http.StatusOK {
		t.Fatalf("discovery read = %d, want 200", plainRR.Code)
	}
}

// staleFSMCluster answers the raw peer read from a lagging FSM and the
// barriered read from the committed state, which is the difference a newly
// elected leader's apply queue makes.
type staleFSMCluster struct {
	*cluster.Noop
	rawReads       int
	barrieredReads int
	barrierErr     error
}

func (c *staleFSMCluster) NodeStorageRetirementsForPeer() cluster.NodeStorageRetirementsResponse {
	c.rawReads++
	// The stale view: an attestation the operator has already revoked.
	return cluster.NodeStorageRetirementsResponse{
		Retirements:   []cluster.NodeStorageRetirement{{NodeID: "node-gone", AttestedUnixNano: 1}},
		Authoritative: true,
	}
}

func (c *staleFSMCluster) NodeStorageRetirementsForPeerAuthoritative(context.Context) (cluster.NodeStorageRetirementsResponse, error) {
	c.barrieredReads++
	if c.barrierErr != nil {
		return cluster.NodeStorageRetirementsResponse{}, c.barrierErr
	}
	return cluster.NodeStorageRetirementsResponse{Authoritative: true}, nil
}

// The authoritative request must go through the barriered read, not the FSM
// snapshot: a leader whose apply queue has not drained would otherwise
// authorize a discharge the operator already revoked.
func TestClusterInternalRetirementsAuthoritativeUsesTheBarrieredRead(t *testing.T) {
	stub := &staleFSMCluster{Noop: cluster.NewNoop("srv", "http://srv", "")}
	h := newOwnedRecoveryHandlers(t, stub)

	req := withPeer(httptest.NewRequest(http.MethodGet, cluster.PublicInternalNodeStorageRetirementsPath+"?authoritative=true", nil), "wrk-a")
	rr := httptest.NewRecorder()
	h.clusterInternalNodeStorageRetirements(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if stub.barrieredReads != 1 || stub.rawReads != 0 {
		t.Fatalf("barriered=%d raw=%d; the authoritative path must not read the FSM directly", stub.barrieredReads, stub.rawReads)
	}
	var resp cluster.NodeStorageRetirementsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Retirements) != 0 {
		t.Fatalf("served %+v; the revoked attestation came from the lagging FSM", resp.Retirements)
	}

	// A barrier that cannot be established fails closed.
	stub.barrierErr = errors.New("not leader")
	failRR := httptest.NewRecorder()
	h.clusterInternalNodeStorageRetirements(failRR, withPeer(httptest.NewRequest(http.MethodGet, cluster.PublicInternalNodeStorageRetirementsPath+"?authoritative=true", nil), "wrk-a"))
	if failRR.Code != http.StatusServiceUnavailable {
		t.Fatalf("unestablished barrier = %d, want 503", failRR.Code)
	}

	// The ordinary discovery read still uses the cheap FSM snapshot.
	plainRR := httptest.NewRecorder()
	h.clusterInternalNodeStorageRetirements(plainRR, withPeer(httptest.NewRequest(http.MethodGet, cluster.PublicInternalNodeStorageRetirementsPath, nil), "wrk-a"))
	if plainRR.Code != http.StatusOK || stub.rawReads != 1 {
		t.Fatalf("discovery read status=%d rawReads=%d", plainRR.Code, stub.rawReads)
	}
}

// A publisher's fencing token is bound to the mTLS identity, never to a body
// field: a node that could name another node in the body could fence that
// node's publications out of the catalogue. Allocation is a raft write, so a
// non-leader answers 503 and the caller walks on to the leader.
func TestClusterInternalArtifactCatalogEpochBindsTheNodeToThePeerIdentity(t *testing.T) {
	stub := &registryStubCluster{Noop: cluster.NewNoop("srv", "http://srv", "")}
	h := newOwnedRecoveryHandlers(t, stub)
	body := `{"kind":"template","holder":"process-1","node_id":"some-other-node"}`

	anonRR := httptest.NewRecorder()
	h.clusterInternalArtifactCatalogEpoch(anonRR, httptest.NewRequest(http.MethodPost, cluster.PublicInternalArtifactCatalogEpochPath, strings.NewReader(body)))
	if anonRR.Code != http.StatusForbidden {
		t.Fatalf("anonymous allocation status = %d, want 403", anonRR.Code)
	}

	rr := httptest.NewRecorder()
	h.clusterInternalArtifactCatalogEpoch(rr, withPeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalArtifactCatalogEpochPath, strings.NewReader(body)), "wrk-a"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if stub.askedNode != "wrk-a" || stub.askedKind != "template" || stub.askedHolder != "process-1" {
		t.Fatalf("allocated for node=%q kind=%q holder=%q; the node must come from the peer identity", stub.askedNode, stub.askedKind, stub.askedHolder)
	}
	var resp cluster.ArtifactCatalogEpochResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Epoch != 7 {
		t.Fatalf("epoch = %d, want the issued 7", resp.Epoch)
	}

	// A follower cannot allocate; 503 is what sends the caller to the leader.
	stub.allocErr = cluster.ErrNotLeader
	notLeaderRR := httptest.NewRecorder()
	h.clusterInternalArtifactCatalogEpoch(notLeaderRR, withPeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalArtifactCatalogEpochPath, strings.NewReader(body)), "wrk-a"))
	if notLeaderRR.Code != http.StatusServiceUnavailable {
		t.Fatalf("allocation on a follower = %d, want 503", notLeaderRR.Code)
	}

	// A node that holds no placement state must say so, not answer 0.
	statelessRR := httptest.NewRecorder()
	stateless := newOwnedRecoveryHandlers(t, cluster.NewNoop("srv", "http://srv", ""))
	stateless.clusterInternalArtifactCatalogEpoch(statelessRR, withPeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalArtifactCatalogEpochPath, strings.NewReader(body)), "wrk-a"))
	if statelessRR.Code != http.StatusServiceUnavailable {
		t.Fatalf("allocation on a stateless node = %d, want 503", statelessRR.Code)
	}

	badRR := httptest.NewRecorder()
	h.clusterInternalArtifactCatalogEpoch(badRR, withPeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalArtifactCatalogEpochPath, strings.NewReader("not json")), "wrk-a"))
	if badRR.Code != http.StatusBadRequest {
		t.Fatalf("malformed allocation body = %d, want 400", badRR.Code)
	}
}
