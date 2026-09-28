package v1

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
)

type ownedRecoveryStubCluster struct {
	*cluster.Noop
	askedOwner    string
	askedLimit    int
	askedToken    string
	reassignFrom  string
	reassignID    string
	reassignIncID string
	reassignErr   error
}

func (c *ownedRecoveryStubCluster) OwnedRecoveryPlacements(ownerID string, limit int, pageToken string) cluster.OwnedRecoveryResponse {
	c.askedOwner, c.askedLimit, c.askedToken = ownerID, limit, pageToken
	return cluster.OwnedRecoveryResponse{
		Placements:    []cluster.Placement{{SandboxID: "sb-owned", OwnerNodeID: ownerID}},
		Authoritative: true,
	}
}

func (c *ownedRecoveryStubCluster) ReassignStuckPlacement(_ context.Context, requesterID, sandboxID, incarnationID string) error {
	c.reassignFrom, c.reassignID, c.reassignIncID = requesterID, sandboxID, incarnationID
	return c.reassignErr
}

func newOwnedRecoveryHandlers(t *testing.T, stub cluster.Client) *handlers {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(stub)
	return &handlers{deps: Deps{Service: svc, Logger: logger}}
}

func withPeer(r *http.Request, nodeID string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), clusterPeerNodeIDContextKey{}, nodeID))
}

// The owner is the mTLS-authenticated peer identity, never a request field —
// otherwise a worker could ask for (and receive the specs and secret handles
// of) another node's placements.
func TestClusterInternalOwnedRecoveryUsesAuthenticatedPeer(t *testing.T) {
	stub := &ownedRecoveryStubCluster{Noop: cluster.NewNoop("srv", "http://srv", "")}
	h := newOwnedRecoveryHandlers(t, stub)

	body := `{"limit":64,"page_token":"sb-cursor"}`
	req := withPeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalOwnedRecoveryPath, strings.NewReader(body)), "wrk-a")
	rr := httptest.NewRecorder()
	h.clusterInternalOwnedRecovery(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if stub.askedOwner != "wrk-a" || stub.askedLimit != 64 || stub.askedToken != "sb-cursor" {
		t.Fatalf("asked owner=%q limit=%d token=%q", stub.askedOwner, stub.askedLimit, stub.askedToken)
	}
	var resp cluster.OwnedRecoveryResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Authoritative || len(resp.Placements) != 1 {
		t.Fatalf("response = %+v", resp)
	}

	anon := httptest.NewRequest(http.MethodPost, cluster.PublicInternalOwnedRecoveryPath, strings.NewReader(`{}`))
	anonRR := httptest.NewRecorder()
	h.clusterInternalOwnedRecovery(anonRR, anon)
	if anonRR.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated owned-recovery = %d, want 403", anonRR.Code)
	}
}

// A node with no FSM cannot answer the query; that must be a 503, not an empty
// "you own nothing" the worker would act on.
func TestClusterInternalOwnedRecoveryWithoutPlacementState(t *testing.T) {
	h := newOwnedRecoveryHandlers(t, cluster.NewNoop("wrk", "http://wrk", ""))
	req := withPeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalOwnedRecoveryPath, strings.NewReader(`{}`)), "wrk-a")
	rr := httptest.NewRecorder()
	h.clusterInternalOwnedRecovery(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClusterInternalReassignStuck(t *testing.T) {
	stub := &ownedRecoveryStubCluster{Noop: cluster.NewNoop("srv", "http://srv", "")}
	h := newOwnedRecoveryHandlers(t, stub)

	body := `{"sandbox_id":"sb-stuck","incarnation_id":"inc-1"}`
	req := withPeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalReassignStuckPath, strings.NewReader(body)), "wrk-a")
	rr := httptest.NewRecorder()
	h.clusterInternalReassignStuck(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if stub.reassignFrom != "wrk-a" || stub.reassignID != "sb-stuck" || stub.reassignIncID != "inc-1" {
		t.Fatalf("reassign from=%q id=%q inc=%q", stub.reassignFrom, stub.reassignID, stub.reassignIncID)
	}

	stub.reassignErr = cluster.ErrStuckReassignNotOwner
	conflict := withPeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalReassignStuckPath, strings.NewReader(body)), "wrk-old")
	conflictRR := httptest.NewRecorder()
	h.clusterInternalReassignStuck(conflictRR, conflict)
	if conflictRR.Code != http.StatusConflict {
		t.Fatalf("non-owner reassign = %d, want 409", conflictRR.Code)
	}

	stub.reassignErr = cluster.ErrUnknownSandbox
	missing := withPeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalReassignStuckPath, strings.NewReader(body)), "wrk-a")
	missingRR := httptest.NewRecorder()
	h.clusterInternalReassignStuck(missingRR, missing)
	if missingRR.Code != http.StatusNotFound {
		t.Fatalf("unknown sandbox reassign = %d, want 404", missingRR.Code)
	}

	anon := httptest.NewRequest(http.MethodPost, cluster.PublicInternalReassignStuckPath, strings.NewReader(body))
	anonRR := httptest.NewRecorder()
	h.clusterInternalReassignStuck(anonRR, anon)
	if anonRR.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated reassign = %d, want 403", anonRR.Code)
	}
}
