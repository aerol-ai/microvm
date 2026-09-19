package v1

import (
	"context"
	"encoding/json"
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
}

func (c *registryStubCluster) NodeStorageRetirementsForPeer() cluster.NodeStorageRetirementsResponse {
	return cluster.NodeStorageRetirementsResponse{
		Retirements:   []cluster.NodeStorageRetirement{{NodeID: "node-gone", AttestedUnix: 7}},
		Authoritative: true,
	}
}

func (c *registryStubCluster) ArtifactCatalogForPeer(kind, tenant string) cluster.ArtifactCatalogPage {
	c.askedKind, c.askedTenant = kind, tenant
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
	page cluster.ArtifactCatalogPage
	ok   bool
}

func (s stubCatalogService) ClusterArtifactCatalog(context.Context, string, string) (cluster.ArtifactCatalogPage, bool) {
	return s.page, s.ok
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
	if _, _, ok := readClusterArtifactCatalog[*cluster.Placement](nil, stubCatalogService{ok: true}, "template", ""); ok {
		t.Fatal("a nil request reported a catalogue")
	}
	if _, _, ok := readClusterArtifactCatalog[*cluster.Placement](req, stubCatalogService{}, "template", ""); ok {
		t.Fatal("an unavailable catalogue was reported as usable; the sweep must still run")
	}

	svc := stubCatalogService{ok: true, page: cluster.ArtifactCatalogPage{
		Rows: []cluster.ArtifactCatalogRow{
			{ID: "good", Payload: []byte(`{"sandbox_id":"good"}`)},
			{ID: "unreadable", Payload: []byte(`not json`)},
		},
		Publishers: []string{"worker-a"},
	}}
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
