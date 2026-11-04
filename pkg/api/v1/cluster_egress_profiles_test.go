package v1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// profileStubCluster stands in for a server's replicated profile store.
type profileStubCluster struct {
	*cluster.Noop
	writeErr error
	readErr  error
	wrote    cluster.EgressProfileWriteRequest
}

func (s *profileStubCluster) WriteEgressProfile(_ context.Context, req cluster.EgressProfileWriteRequest) (cluster.EgressProfileWriteResponse, error) {
	s.wrote = req
	if s.writeErr != nil {
		return cluster.EgressProfileWriteResponse{}, s.writeErr
	}
	p := req.Profile
	p.Generation = 4
	return cluster.EgressProfileWriteResponse{Profile: p, Changed: true}, nil
}

func (s *profileStubCluster) ReadEgressProfiles(_ context.Context, req cluster.EgressProfileReadRequest) (cluster.EgressProfileReadResponse, error) {
	if s.readErr != nil {
		return cluster.EgressProfileReadResponse{}, s.readErr
	}
	return cluster.EgressProfileReadResponse{Profiles: []cluster.EgressProfileRecord{{Owner: req.Owner, Name: "python"}}, Authoritative: true}, nil
}

func TestClusterInternalEgressProfileRoutes(t *testing.T) {
	stub := &profileStubCluster{Noop: cluster.NewNoop("srv", "http://srv", "")}
	h := newOwnedRecoveryHandlers(t, stub)
	call := func(fn http.HandlerFunc, path, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		fn(rr, withPeer(httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)), "wrk-a"))
		return rr
	}
	write := `{"profile":{"owner":"acct","name":"python","allow_out":["pypi.org"],"hostname_count":1}}`
	rr := call(h.clusterInternalEgressProfileWrite, cluster.PublicInternalEgressProfileWritePath, write)
	var out cluster.EgressProfileWriteResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != http.StatusOK || out.Profile.Generation != 4 || stub.wrote.Profile.Name != "python" {
		t.Fatalf("write = %d %+v", rr.Code, out)
	}
	// FSM refusals answer 200 with a code; anything else is a retryable 503.
	stub.writeErr = cluster.ErrEgressProfileInUse
	rr = call(h.clusterInternalEgressProfileWrite, cluster.PublicInternalEgressProfileWritePath, write)
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != http.StatusOK || out.Code == "" {
		t.Fatalf("refusal = %d %+v", rr.Code, out)
	}
	stub.writeErr = errors.New("raft apply timed out")
	if rr := call(h.clusterInternalEgressProfileWrite, cluster.PublicInternalEgressProfileWritePath, write); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("transient = %d", rr.Code)
	}
	if rr := call(h.clusterInternalEgressProfileWrite, cluster.PublicInternalEgressProfileWritePath, "not json"); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad body = %d", rr.Code)
	}

	rr = call(h.clusterInternalEgressProfileRead, cluster.PublicInternalEgressProfileReadPath, `{"owner":"acct","names":["python"]}`)
	var read cluster.EgressProfileReadResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &read)
	if rr.Code != http.StatusOK || len(read.Profiles) != 1 || !read.Authoritative {
		t.Fatalf("read = %d %+v", rr.Code, read)
	}
	stub.readErr = errors.New("no fsm")
	if rr := call(h.clusterInternalEgressProfileRead, cluster.PublicInternalEgressProfileReadPath, `{}`); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("read error = %d", rr.Code)
	}
	if rr := call(h.clusterInternalEgressProfileRead, cluster.PublicInternalEgressProfileReadPath, "x"); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad read body = %d", rr.Code)
	}

	// A node without a replicated store says so.
	stateless := newOwnedRecoveryHandlers(t, cluster.NewNoop("srv", "http://srv", ""))
	if rr := call(stateless.clusterInternalEgressProfileWrite, cluster.PublicInternalEgressProfileWritePath, write); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("stateless write = %d", rr.Code)
	}
	if rr := call(stateless.clusterInternalEgressProfileRead, cluster.PublicInternalEgressProfileReadPath, `{}`); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("stateless read = %d", rr.Code)
	}
}
