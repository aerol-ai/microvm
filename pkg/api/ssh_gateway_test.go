package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/sshgateway"
)

// gatewayRequest is a call the SSH gateway makes to its own node's API:
// over loopback, with the operator token, attested for call.
func gatewayRequest(method, path string, call auditlog.SSHGatewayCall) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "127.0.0.1:41000"
	req.Header.Set("Authorization", "Bearer pat-token")
	sshgateway.AttestBridgedCall(req.Header, call)
	return req
}

// TestSSHGatewaySessionRecordedOnOwner is UC-287 on a cluster, end to end
// through two API servers. The gateway on edge-1 bridges an SSH session for
// sb-owned, which owner-1 runs: the session's create (it opens the session)
// and its attach go to edge-1's API over loopback with the operator token
// and are forwarded to owner-1. Before: owner-1 recorded both calls as
// caller=operator via edge-1, and the ssh record sat in edge-1's own log,
// which the sandbox's audit read never asks. Now the sandbox's audit read
// on owner-1 holds exactly one ssh record and both calls, all three naming
// sandbox_key:sb-owned via edge-1; edge-1 records nothing; the gateway's
// loopback headers never leave edge-1; and owner-1's chain still verifies.
func TestSSHGatewaySessionRecordedOnOwner(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "owner.db")
	ownerStore := storeWith(t, "owner-store", ownedSandbox("sb-owned", "payments"))
	ownerSvc := service.New(config.Config{DBPath: dbPath, EnableCluster: true, SecretAuditRetentionDays: 30}, discardLogger(), ownerStore, nil, nil, nil, nil, nil, nil)
	ownerSvc.AttachCluster(&openGateCluster{peerSideCluster{Noop: cluster.NewNoop("owner-1", "", ""), edge: "edge-1"}})
	tokens := WithCredentialAuthenticator(controlplane.PrincipalToken, stubTokens())
	clusterCfg := config.Config{IdentityEnabled: true, EnableCluster: true}
	owner := NewServer(discardLogger(), ownerSvc, nil, nil, clusterCfg, "pat-token", nil, tokens)

	edgeSvc := service.New(config.Config{EnableCluster: true}, discardLogger(), storeWith(t, "edge"), nil, nil, nil, nil, nil, nil)
	edgeSink := &recSink{}
	edgeSvc.UseAuditSinkForTest(edgeSink)
	var wireMu sync.Mutex
	var wire []http.Header
	edgeSvc.AttachCluster(&forwardingCluster{Noop: cluster.NewNoop("edge-1", "", ""), owner: owner, wire: func(h http.Header) {
		wireMu.Lock()
		wire = append(wire, h)
		wireMu.Unlock()
	}})
	edge := NewServer(discardLogger(), edgeSvc, nil, nil, clusterCfg, "pat-token", nil, tokens)

	for _, req := range []*http.Request{
		gatewayRequest(http.MethodPost, "/v1/sandboxes/sb-owned/sessions", auditlog.SSHGatewayCall{SandboxID: "sb-owned", Open: true, Session: "default"}),
		gatewayRequest(http.MethodGet, "/v1/sandboxes/sb-owned/sessions/sess-1/attach", auditlog.SSHGatewayCall{SandboxID: "sb-owned"}),
	} {
		edge.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}
	if got := edgeSink.records(); len(got) != 0 {
		t.Fatalf("edge-1 recorded calls it forwarded: %+v", got)
	}

	// The sandbox's audit read on owner-1: what GET /v1/sandboxes/{id}/audit
	// answers an auditor. The writer is buffered, so wait for all three.
	want := &auditlog.Caller{Kind: "sandbox_key", ID: "sb-owned", Via: "edge-1"}
	var page service.SecretAuditPage
	deadline := time.Now().Add(5 * time.Second)
	for {
		req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-owned/audit?kind=api", nil)
		req.RemoteAddr = "127.0.0.1:42000"
		req.Header.Set("Authorization", "Bearer pat-token")
		rec := httptest.NewRecorder()
		owner.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("audit read = %d %s", rec.Code, rec.Body.String())
		}
		page = service.SecretAuditPage{}
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Events) >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	var ssh, calls int
	for _, ev := range page.Events {
		if ev.Caller == nil || ev.Caller.Kind == string(controlplane.PrincipalOperator) {
			t.Fatalf("the operator is blamed for the key holder's session: %+v (caller %+v)", ev, ev.Caller)
		}
		if !reflect.DeepEqual(ev.Caller, want) || ev.SandboxID != "sb-owned" || ev.NodeID != "owner-1" || ev.Request == nil || ev.Request.Surface != auditlog.SurfaceSSH {
			t.Fatalf("record %q = %+v caller %+v request %+v, want caller %+v with surface ssh on owner-1", ev.Ref, ev, ev.Caller, ev.Request, want)
		}
		switch ev.Ref {
		case auditlog.RefSSH:
			ssh++
			if ev.Request.Target != "default" || ev.IncarnationID != "inc-sb-owned" || ev.OwnerRef != "team:payments" {
				t.Fatalf("ssh record = %+v request %+v", ev, ev.Request)
			}
		case "POST /v1/sandboxes/{id}/sessions", "GET /v1/sandboxes/{id}/sessions/{path...}":
			calls++
		default:
			t.Fatalf("unexpected record %q", ev.Ref)
		}
	}
	if ssh != 1 || calls != 2 {
		t.Fatalf("the sandbox's audit holds %d ssh records and %d session calls, want 1 and 2: %+v", ssh, calls, page.Events)
	}

	wireMu.Lock()
	for _, h := range wire {
		if h.Get("X-Aerol-Ssh-Gateway") != "" || h.Get("X-Aerol-Ssh-Gateway-Mac") != "" {
			t.Fatalf("the gateway's loopback attestation left edge-1: %v", h)
		}
		if h.Get(cluster.HeaderSSHGateway) == "" {
			t.Fatalf("a bridged call reached owner-1 without its marker: %v", h)
		}
	}
	if len(wire) != 2 {
		t.Fatalf("forwards = %d, want 2", len(wire))
	}
	wireMu.Unlock()

	ownerSvc.CloseSecretAuditSink()
	raw, err := os.ReadFile(filepath.Join(dir, "audit", "secrets.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if _, err := auditlog.ScanChain(bytes.NewReader(raw), auditlog.ScanOptions{}); err != nil {
		t.Fatalf("owner chain no longer verifies: %v", err)
	}
}

// TestSSHGatewayAttributionTrustBoundary: only a call this process's gateway
// attested, or a live peer's forward of one, is recorded as a sandbox key
// holder's, and only with the operator token, on the sessions routes, for
// the sandbox the path names. Every other combination is recorded as what
// it is. The two rows that name sandbox_key fail on a build without the
// fix; the others pin that the fix never over-trusts a header.
func TestSSHGatewayAttributionTrustBoundary(t *testing.T) {
	ownerSvc := service.New(config.Config{EnableCluster: true}, discardLogger(), storeWith(t, "owner", ownedSandbox("sb-owned", "payments")), nil, nil, nil, nil, nil, nil)
	sink := &recSink{}
	ownerSvc.UseAuditSinkForTest(sink)
	ownerSvc.AttachCluster(&openGateCluster{peerSideCluster{Noop: cluster.NewNoop("owner-1", "", ""), edge: "edge-1"}})
	tokens := WithCredentialAuthenticator(controlplane.PrincipalToken, stubTokens())
	owner := NewServer(discardLogger(), ownerSvc, nil, nil, config.Config{IdentityEnabled: true, EnableCluster: true}, "pat-token", nil, tokens)

	single, singleSink, _ := auditServer(t, config.Config{}, ownedSandbox("sb-owned", "payments"))

	const sessions = "/v1/sandboxes/sb-owned/sessions"
	open := auditlog.SSHGatewayCall{SandboxID: "sb-owned", Open: true, Session: "default"}
	// fromPeer is a request arriving on owner-1's internal listener from
	// edge-1's verified certificate.
	fromPeer := func(path, bearer string, forwarded bool, marker string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.TLS = peerTLS("edge-1")
		req.Header.Set(cluster.PeerNodeIDHeader, "edge-1")
		req.Header.Set("Authorization", "Bearer "+bearer)
		if forwarded {
			req.Header.Set(cluster.HeaderForwarded, "1")
		}
		if marker != "" {
			req.Header.Set(cluster.HeaderSSHGateway, marker)
		}
		return req
	}
	withBearer := func(req *http.Request, bearer string) *http.Request {
		req.Header.Set("Authorization", "Bearer "+bearer)
		return req
	}
	operatorVia := &auditlog.Caller{Kind: "operator", ID: "operator", Via: "edge-1"}
	tokenCaller := &auditlog.Caller{Kind: "token", ID: "tok_7Hq2", Name: "ci-deploy", Team: "payments"}
	cases := []struct {
		name    string
		srv     *Server
		sink    *recSink
		req     *http.Request
		want    *auditlog.Caller // the call's record; nil for no record at all
		wantSSH bool             // an ssh record naming want
	}{
		{name: "this node's gateway, attested", srv: owner, sink: sink,
			req:  gatewayRequest(http.MethodPost, sessions, open),
			want: &auditlog.Caller{Kind: "sandbox_key", ID: "sb-owned"}, wantSSH: true},
		{name: "a live peer's forward of its gateway's call", srv: owner, sink: sink,
			req:  fromPeer(sessions, "pat-token", true, open.Encode()),
			want: &auditlog.Caller{Kind: "sandbox_key", ID: "sb-owned", Via: "edge-1"}, wantSSH: true},
		{name: "attested for another sandbox than the path names", srv: owner, sink: sink,
			req:  gatewayRequest(http.MethodPost, sessions, auditlog.SSHGatewayCall{SandboxID: "sb-other", Open: true}),
			want: &auditlog.Caller{Kind: "operator", ID: "operator"}},
		{name: "a forged attestation", srv: owner, sink: sink,
			req: func() *http.Request {
				req := gatewayRequest(http.MethodPost, sessions, open)
				req.Header.Set("X-Aerol-Ssh-Gateway-Mac", "00ff")
				return req
			}(),
			want: &auditlog.Caller{Kind: "operator", ID: "operator"}},
		{name: "a real attestation on a team token's call", srv: owner, sink: sink,
			req:  withBearer(gatewayRequest(http.MethodPost, sessions, open), "avm_payments"),
			want: tokenCaller},
		{name: "attested, but not a sessions route", srv: owner, sink: sink,
			req:  gatewayRequest(http.MethodPost, "/v1/sandboxes/sb-owned/stop", open),
			want: &auditlog.Caller{Kind: "operator", ID: "operator"}},
		{name: "the cluster marker from a caller with no certificate", srv: owner, sink: sink,
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, sessions, nil)
				req.Header.Set("Authorization", "Bearer pat-token")
				req.Header.Set(cluster.HeaderForwarded, "1")
				req.Header.Set(cluster.HeaderSSHGateway, open.Encode())
				return req
			}()},
		{name: "a peer's forward naming another sandbox", srv: owner, sink: sink,
			req:  fromPeer(sessions, "pat-token", true, "sandbox=sb-other&open=default"),
			want: operatorVia},
		{name: "a peer's forward with a marker that is not a call", srv: owner, sink: sink,
			req:  fromPeer(sessions, "pat-token", true, "%zz"),
			want: operatorVia},
		{name: "a peer's forward of a team token", srv: owner, sink: sink,
			req:  fromPeer(sessions, "avm_payments", true, open.Encode()),
			want: &auditlog.Caller{Kind: "token", ID: "tok_7Hq2", Name: "ci-deploy", Team: "payments", Via: "edge-1"}},
		{name: "a peer acting for itself, not forwarding", srv: owner, sink: sink,
			req:  fromPeer(sessions, "pat-token", false, open.Encode()),
			want: &auditlog.Caller{Kind: "node", ID: "node:edge-1"}},
		{name: "the cluster marker on a single node is dropped", srv: single, sink: singleSink,
			req: func() *http.Request {
				req := withBearer(httptest.NewRequest(http.MethodPost, sessions, nil), "pat-token")
				req.Header.Set(cluster.HeaderSSHGateway, open.Encode())
				return req
			}(),
			want: &auditlog.Caller{Kind: "operator", ID: "operator"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.sink.reset()
			rec := httptest.NewRecorder()
			tc.srv.Handler().ServeHTTP(rec, tc.req)
			want := 0
			if tc.want != nil {
				want = 1
				if tc.wantSSH {
					want = 2
				}
			}
			got := tc.sink.waitRecords(t, want)
			var call, ssh []auditlog.Event
			for _, ev := range got {
				if ev.Ref == auditlog.RefSSH {
					ssh = append(ssh, ev)
				} else {
					call = append(call, ev)
				}
			}
			if tc.want == nil {
				if len(got) != 0 || rec.Code != http.StatusForbidden {
					t.Fatalf("status %d wrote %+v, want a 403 and no record", rec.Code, got)
				}
				return
			}
			if len(call) != 1 || !reflect.DeepEqual(call[0].Caller, tc.want) {
				t.Fatalf("status %d records %+v: want one call record naming %+v", rec.Code, got, tc.want)
			}
			if (tc.wantSSH && len(ssh) != 1) || (!tc.wantSSH && len(ssh) != 0) {
				t.Fatalf("ssh records = %+v, want one: %v", ssh, tc.wantSSH)
			}
			if tc.wantSSH && !reflect.DeepEqual(ssh[0].Caller, tc.want) {
				t.Fatalf("ssh record caller = %+v, want %+v", ssh[0].Caller, tc.want)
			}
			if tc.req.Header.Get("X-Aerol-Ssh-Gateway") != "" || tc.req.Header.Get("X-Aerol-Ssh-Gateway-Mac") != "" {
				t.Fatal("the loopback attestation was left on the request for the handler and the toolbox to see")
			}
		})
	}
}

// TestSSHGatewayCallChecks drives sshGatewayCall directly, below
// clusterControlHeaderGuard and the principal split, so each of its own
// checks is pinned even where the layers above already refuse the request:
// a forward with no verified certificate and a cluster marker on a call
// that is not a forward are never believed.
func TestSSHGatewayCallChecks(t *testing.T) {
	operator := controlplane.OperatorAccess()
	open := auditlog.SSHGatewayCall{SandboxID: "sb-1", Open: true, Session: "default"}
	routed := func(req *http.Request, pattern string) *http.Request {
		req.Pattern = pattern
		req.SetPathValue("id", "sb-1")
		return req
	}
	cases := []struct {
		name string
		req  *http.Request
		want bool
	}{
		{name: "the gateway's own call, method-qualified pattern", want: true,
			req: routed(gatewayRequest(http.MethodPost, "/v1/sandboxes/sb-1/sessions", open), "POST /v1/sandboxes/{id}/sessions")},
		{name: "a forward with no verified certificate",
			req: func() *http.Request {
				req := routed(httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-1/sessions", nil), "/v1/sandboxes/{id}/sessions")
				req.Header.Set(cluster.HeaderForwarded, "1")
				req.Header.Set(cluster.HeaderSSHGateway, open.Encode())
				return req
			}()},
		{name: "a cluster marker on a call that is not a forward",
			req: func() *http.Request {
				req := routed(httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-1/sessions", nil), "/v1/sandboxes/{id}/sessions")
				req.TLS = peerTLS("edge-1")
				req.Header.Set(cluster.HeaderSSHGateway, open.Encode())
				return req
			}()},
		{name: "a route with no sandbox id",
			req: func() *http.Request {
				req := gatewayRequest(http.MethodGet, "/v1/sandboxes", open)
				req.Pattern = "/v1/sandboxes/{id}/sessions"
				return req
			}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := sshGatewayCall(tc.req, operator)
			if ok != tc.want || (ok && got != open) {
				t.Fatalf("sshGatewayCall = %+v, %v; want %v", got, ok, tc.want)
			}
		})
	}
}
