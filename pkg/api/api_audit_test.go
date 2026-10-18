package api

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// recSink is the audit writer the api-record tests read back.
type recSink struct {
	mu  sync.Mutex
	evs []auditlog.Event
}

func (s *recSink) Emit(ev auditlog.Event) {
	s.mu.Lock()
	s.evs = append(s.evs, ev)
	s.mu.Unlock()
}

// records returns the api and auth_denied records written so far.
func (s *recSink) records() []auditlog.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []auditlog.Event
	for _, ev := range s.evs {
		if ev.Kind == auditlog.KindAPI || ev.Kind == auditlog.KindAuthDenied {
			out = append(out, ev)
		}
	}
	return out
}

func (s *recSink) reset() {
	s.mu.Lock()
	s.evs = nil
	s.mu.Unlock()
}

// waitRecords returns the records once at least n have arrived (or after 5 s).
// The service writes them on its audit writer goroutine, so an MCP tool's
// result can reach the client before the inner call's record lands in the
// sink. It then waits a moment longer so a test that wants exactly n still
// sees any extra record.
func (s *recSink) waitRecords(t *testing.T, n int) []auditlog.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(s.records()) < n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	return s.records()
}

// auditServer is a single-node API server over a real store whose audit
// records land in a recSink.
func auditServer(t *testing.T, svcCfg config.Config, sandboxes ...*models.Sandbox) (*Server, *recSink, *service.Service) {
	t.Helper()
	st := storeWith(t, "audit", sandboxes...)
	svc := service.New(svcCfg, discardLogger(), st, nil, nil, nil, nil, nil, nil)
	sink := &recSink{}
	svc.UseAuditSinkForTest(sink)
	srv := NewServer(discardLogger(), svc, nil, nil, config.Config{IdentityEnabled: true}, "pat-token", nil,
		WithCredentialAuthenticator(controlplane.PrincipalToken, stubTokens()))
	return srv, sink, svc
}

func do(t *testing.T, srv *Server, method, path, bearer, body string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "198.51.100.7:5000"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// TestAPIRecordPerRoute is the record-per-route table (§5.9): which calls
// write an api record under the default SB_AUDIT_API_RECORDS=mutations,
// with the route pattern as ref, the sandbox the path names, and
// request.target for the snapshot, egress profile, WASM module, JS bundle
// and template routes (token routes arrive with T3).
func TestAPIRecordPerRoute(t *testing.T) {
	srv, sink, _ := auditServer(t, config.Config{})
	cases := []struct {
		name, method, path, bearer, body string
		header                           map[string]string
		// wantRef "" means no record.
		wantRef, wantSandbox, wantTarget string
		wantCaller                       string
	}{
		{name: "sandbox mutation", method: "POST", path: "/v1/sandboxes/sb-1/stop", bearer: "pat-token",
			wantRef: "POST /v1/sandboxes/{id}/stop", wantSandbox: "sb-1", wantCaller: "operator"},
		{name: "sandbox delete", method: "DELETE", path: "/v1/sandboxes/sb-1", bearer: "avm_payments",
			wantRef: "DELETE /v1/sandboxes/{id}", wantSandbox: "sb-1", wantCaller: "tok_7Hq2"},
		{name: "plain read: not recorded by default", method: "GET", path: "/v1/sandboxes/sb-1", bearer: "pat-token"},
		{name: "toolbox read is recorded: files can hold secrets", method: "GET", path: "/v1/sandboxes/sb-1/toolbox/files/download", bearer: "pat-token",
			wantRef: "GET /v1/sandboxes/{id}/toolbox/{path...}", wantSandbox: "sb-1", wantTarget: "files/download", wantCaller: "operator"},
		{name: "port", method: "POST", path: "/v1/sandboxes/sb-1/ports/8080", bearer: "pat-token",
			wantRef: "POST /v1/sandboxes/{id}/ports/{port}", wantSandbox: "sb-1", wantTarget: "8080", wantCaller: "operator"},
		{name: "snapshot delete names the snapshot", method: "DELETE", path: "/v1/snapshots/snap-7", bearer: "pat-token",
			wantRef: "DELETE /v1/snapshots/{id}", wantTarget: "snap-7", wantCaller: "operator"},
		{name: "egress profile put names the profile", method: "PUT", path: "/v1/egress-profiles/corp-egress", bearer: "pat-token", body: `{}`,
			wantRef: "PUT /v1/egress-profiles/{name}", wantTarget: "corp-egress", wantCaller: "operator"},
		{name: "egress profile delete", method: "DELETE", path: "/v1/egress-profiles/corp-egress", bearer: "pat-token",
			wantRef: "DELETE /v1/egress-profiles/{name}", wantTarget: "corp-egress", wantCaller: "operator"},
		{name: "wasm module delete names the module", method: "DELETE", path: "/v1/wasm-modules/mod-1", bearer: "pat-token",
			wantRef: "DELETE /v1/wasm-modules/{id}", wantTarget: "mod-1", wantCaller: "operator"},
		{name: "js bundle delete names the bundle", method: "DELETE", path: "/v1/js-bundles/bun-1", bearer: "pat-token",
			wantRef: "DELETE /v1/js-bundles/{id}", wantTarget: "bun-1", wantCaller: "operator"},
		{name: "template delete names the template", method: "DELETE", path: "/v1/templates/tpl-1", bearer: "pat-token",
			wantRef: "DELETE /v1/templates/{id}", wantTarget: "tpl-1", wantCaller: "operator"},
		{name: "template rebuild", method: "POST", path: "/v1/templates/tpl-1/rebuild", bearer: "pat-token",
			wantRef: "POST /v1/templates/{id}/rebuild", wantTarget: "tpl-1", wantCaller: "operator"},
		{name: "audit verify", method: "POST", path: "/v1/audit/verify", bearer: "pat-token",
			wantRef: "POST /v1/audit/verify", wantCaller: "operator"},
		{name: "snapshot read: not recorded by default", method: "GET", path: "/v1/snapshots/snap-7", bearer: "pat-token"},
		{name: "e2b delete", method: "DELETE", path: "/e2b/sandboxes/sb-2", header: map[string]string{"X-API-KEY": "pat-token"},
			wantRef: "DELETE /e2b/sandboxes/{id}", wantSandbox: "sb-2", wantCaller: "operator"},
		{name: "daytona delete", method: "DELETE", path: "/daytona/sandbox/sb-3", bearer: "pat-token",
			wantRef: "DELETE /daytona/sandbox/{idOrName}", wantSandbox: "sb-3", wantCaller: "operator"},
		{name: "daytona toolbox", method: "POST", path: "/daytona/toolbox/sb-3/process/execute", bearer: "pat-token", body: `{"command":"ls"}`,
			wantRef: "POST /daytona/toolbox/{id}/{path...}", wantSandbox: "sb-3", wantTarget: "process/execute", wantCaller: "operator"},
		{name: "runloop shutdown, route named like a pattern", method: "POST", path: "/runloop/v1/devboxes/sb-4/shutdown", bearer: "pat-token",
			wantRef: "POST /runloop/v1/devboxes/{id}/shutdown", wantSandbox: "sb-4", wantCaller: "operator"},
		{name: "runloop snapshot delete names the snapshot", method: "POST", path: "/runloop/v1/devboxes/disk_snapshots/snap-9/delete", bearer: "pat-token",
			wantRef: "POST /runloop/v1/devboxes/disk_snapshots/{id}/delete", wantTarget: "snap-9", wantCaller: "operator"},
		{name: "cluster.internal writes no record (7.2)", method: "GET", path: "/v1/cluster/internal/placements", bearer: "pat-token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink.reset()
			rec := do(t, srv, tc.method, tc.path, tc.bearer, tc.body, tc.header)
			got := sink.records()
			if tc.wantRef == "" {
				if len(got) != 0 {
					t.Fatalf("status %d wrote %d records, want none: %+v", rec.Code, len(got), got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("status %d wrote %d records, want 1: %+v", rec.Code, len(got), got)
			}
			ev := got[0]
			if ev.Kind != auditlog.KindAPI || ev.Ref != tc.wantRef || ev.SandboxID != tc.wantSandbox {
				t.Fatalf("record = kind %q ref %q sandbox %q, want api %q %q", ev.Kind, ev.Ref, ev.SandboxID, tc.wantRef, tc.wantSandbox)
			}
			if ev.Request == nil || ev.Request.Target != tc.wantTarget || ev.Request.Status != rec.Code || ev.Request.Method != tc.method {
				t.Fatalf("request = %+v, want target %q status %d", ev.Request, tc.wantTarget, rec.Code)
			}
			if ev.Result != auditlog.APIResultForStatus(rec.Code) {
				t.Fatalf("result %q for status %d", ev.Result, rec.Code)
			}
			if ev.Caller == nil || ev.Caller.ID != tc.wantCaller {
				t.Fatalf("caller = %+v, want %s", ev.Caller, tc.wantCaller)
			}
			if ev.CorrelationID == "" {
				t.Fatal("record without a correlation id")
			}
		})
	}
}

// durableRecSink is a recSink that also takes durable records, so a test
// can see which calls waited for disk.
type durableRecSink struct {
	recSink
	durable []string
}

func (s *durableRecSink) EmitDurable(ev auditlog.Event) error {
	s.mu.Lock()
	s.durable = append(s.durable, ev.Ref)
	s.mu.Unlock()
	s.Emit(ev)
	return nil
}

// TestAPIRecordTokenRoutes is the token half of the request.target table
// (finding 7.1, needed by D7's access review): a create names the token it
// minted and the role and team it carries, never the secret; a revoke names
// the token it revoked; a list is always recorded and names none. With
// SB_AUDIT_API_DURABLE the create and the revoke wait for disk.
func TestAPIRecordTokenRoutes(t *testing.T) {
	st := storeWith(t, "tokens")
	svc := service.New(config.Config{IdentityEnabled: true, AuditAPIDurable: true}, discardLogger(), st, nil, nil, nil, nil, nil, nil)
	sink := &durableRecSink{}
	svc.UseAuditSinkForTest(sink)
	srv := NewServer(discardLogger(), svc, nil, nil, config.Config{IdentityEnabled: true}, "pat-token", nil)

	rec := do(t, srv, "POST", "/v1/tokens", "pat-token", `{"name":"ci-admin","role":"admin","team":"*","expires_in":"30d"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	var created models.CreatedAPIToken
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || !strings.HasPrefix(created.ID, "tok_") {
		t.Fatalf("create body: %v %s", err, rec.Body.String())
	}
	do(t, srv, "GET", "/v1/tokens", "pat-token", "", nil)
	if rec := do(t, srv, "DELETE", "/v1/tokens/"+created.ID, "pat-token", "", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body.String())
	}

	got := sink.records()
	if len(got) != 3 {
		t.Fatalf("token calls wrote %d records, want 3: %+v", len(got), got)
	}
	create, list, revoke := got[0], got[1], got[2]
	if create.Ref != "POST /v1/tokens" || create.Request.Target != created.ID || create.Request.Status != http.StatusCreated ||
		create.Request.Grant == nil || *create.Request.Grant != (auditlog.Grant{Role: "admin", Team: "*"}) || create.Caller.ID != "operator" {
		t.Fatalf("create record = %+v (request %+v)", create, create.Request)
	}
	if raw, _ := json.Marshal(create); strings.Contains(string(raw), created.Token) {
		t.Fatal("the create record carries the token's secret")
	}
	if list.Ref != "GET /v1/tokens" || list.Request.Target != "" || list.Request.Grant != nil {
		t.Fatalf("list record = %+v (request %+v)", list, list.Request)
	}
	if revoke.Ref != "DELETE /v1/tokens/{id}" || revoke.Request.Target != created.ID || revoke.Request.Status != http.StatusNoContent {
		t.Fatalf("revoke record = %+v (request %+v)", revoke, revoke.Request)
	}
	if want := []string{"POST /v1/tokens", "DELETE /v1/tokens/{id}"}; !slices.Equal(sink.durable, want) {
		t.Fatalf("durable records = %v, want %v", sink.durable, want)
	}
}

// TestAPIRecordAllReads: SB_AUDIT_API_RECORDS=all records plain GETs too,
// and off records nothing at all (no hook is installed).
func TestAPIRecordAllReadsAndOff(t *testing.T) {
	all, sink, _ := auditServer(t, config.Config{AuditAPIRecords: config.AuditAPIRecordsAll})
	do(t, all, "GET", "/v1/snapshots/snap-7", "pat-token", "", nil)
	if got := sink.records(); len(got) != 1 || got[0].Request.Target != "snap-7" || got[0].Ref != "GET /v1/snapshots/{id}" {
		t.Fatalf("all: %+v", got)
	}
	off, offSink, _ := auditServer(t, config.Config{AuditAPIRecords: config.AuditAPIRecordsOff})
	if off.audit != nil {
		t.Fatal("records off must install no hook")
	}
	do(t, off, "POST", "/v1/sandboxes/sb-1/stop", "pat-token", "", nil)
	do(t, off, "POST", "/v1/sandboxes/sb-1/stop", "", "", nil)
	if got := offSink.records(); len(got) != 0 {
		t.Fatalf("off wrote %+v", got)
	}
}

// TestAPIRecordDenied: a 403 is an api record with result denied, naming
// the caller, whatever the method (finding 2.3); a refused team header is
// the same, since the credential itself verified.
func TestAPIRecordDenied(t *testing.T) {
	srv, sink, _ := auditServer(t, config.Config{})
	cases := []struct {
		name, method, path string
		header             map[string]string
		wantStatus         int
		wantRef            string
	}{
		{"viewer stops a sandbox", "POST", "/v1/sandboxes/sb-1/stop", nil, http.StatusForbidden, "POST /v1/sandboxes/{id}/stop"},
		{"viewer reads a file (a GET)", "GET", "/v1/sandboxes/sb-1/toolbox/files", nil, http.StatusForbidden, "GET /v1/sandboxes/{id}/toolbox/{path...}"},
		{"viewer on * names a team", "GET", "/v1/sandboxes", map[string]string{HeaderTeam: "payments"}, http.StatusForbidden, "GET /v1/sandboxes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink.reset()
			rec := do(t, srv, tc.method, tc.path, "avm_fleet", "", tc.header)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			got := sink.records()
			if len(got) != 1 || got[0].Result != auditlog.APIResultDenied || got[0].Ref != tc.wantRef ||
				got[0].Caller == nil || got[0].Caller.ID != "tok_7Hq2" || got[0].Request.Status != tc.wantStatus {
				t.Fatalf("records = %+v", got)
			}
		})
	}
	// A bad team header is a 400 from a verified credential: also denied.
	sink.reset()
	if rec := do(t, srv, "GET", "/v1/sandboxes", "avm_payments", "", map[string]string{HeaderTeam: "Bad Team"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad team header = %d", rec.Code)
	}
	if got := sink.records(); len(got) != 1 || got[0].Result != auditlog.APIResultDenied || got[0].Request.Status != http.StatusBadRequest {
		t.Fatalf("bad team header records = %+v", got)
	}
	// The PAT on a cluster-internal route without a peer certificate is
	// refused, and still writes nothing: cluster.internal is never recorded.
	sink.reset()
	if rec := do(t, srv, "GET", "/v1/cluster/internal/placements", "pat-token", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("internal route = %d", rec.Code)
	}
	if got := sink.records(); len(got) != 0 {
		t.Fatalf("cluster.internal refusal recorded: %+v", got)
	}
}

// TestAuthDeniedRateLimit: a refused credential writes one auth_denied
// record per source address per minute; the next record says how many
// 401s it stands for. A spray cannot fill the disk.
func TestAuthDeniedRateLimit(t *testing.T) {
	srv, sink, _ := auditServer(t, config.Config{})
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	srv.authDenied.now = func() time.Time { return now }
	from := func(addr, bearer string) int {
		req := httptest.NewRequest("POST", "/v1/sandboxes/sb-1/stop", nil)
		req.RemoteAddr = addr
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < 5; i++ {
		if code := from("203.0.113.9:4000", "wrong"); code != http.StatusUnauthorized {
			t.Fatalf("code %d", code)
		}
	}
	from("203.0.113.10:4000", "avm_expired")
	got := sink.records()
	if len(got) != 2 {
		t.Fatalf("auth_denied records = %d, want one per address: %+v", len(got), got)
	}
	first := got[0]
	if first.Kind != auditlog.KindAuthDenied || first.Caller != nil || first.Request.Source != "203.0.113.9" ||
		first.Ref != "POST /v1/sandboxes/{id}/stop" || first.Reason != "rejected" || first.Dropped != 0 {
		t.Fatalf("first auth_denied = %+v (request %+v)", first, first.Request)
	}
	if got[1].Request.Source != "203.0.113.10" || got[1].Reason != string(controlplane.RejectExpired) {
		t.Fatalf("second = %+v", got[1])
	}
	now = now.Add(time.Minute)
	from("203.0.113.9:4000", "")
	got = sink.records()
	if len(got) != 3 || got[2].Dropped != 4 || got[2].Reason != "missing" {
		t.Fatalf("after the window: %+v", got)
	}
}

func TestAuthDeniedLimiterBounds(t *testing.T) {
	l := newAuthDeniedLimiter()
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return now }
	for i := 0; i < authDeniedMaxSources; i++ {
		if ok, _ := l.admit("10.0.0." + strings.Repeat("x", i%7) + string(rune(i))); !ok {
			t.Fatalf("source %d refused below the cap", i)
		}
	}
	if ok, _ := l.admit("192.0.2.1"); ok {
		t.Fatal("a new source past the cap was recorded")
	}
	now = now.Add(time.Minute)
	if ok, n := l.admit("192.0.2.1"); !ok || n != 1 {
		t.Fatalf("after the sweep: %v %d", ok, n)
	}
	if got := tcpPeerAddress(&http.Request{RemoteAddr: "pipe"}); got != "pipe" {
		t.Fatalf("source of a portless address = %q", got)
	}
}

// forwardingCluster is the edge's view in the edge-skip test: a peer owns
// the sandbox, and ForwardHTTP does what the real reverse-proxy Director
// does (StampForward on the outbound request, whose context is the
// inbound one), then delivers the request to the owner over "mTLS".
type forwardingCluster struct {
	*cluster.Noop
	owner *Server
	fail  bool
}

func (c *forwardingCluster) AuditCallerWritesAllowed() bool { return true }
func (c *forwardingCluster) OwnerOf(string) (cluster.OwnerInfo, error) {
	return cluster.OwnerInfo{NodeID: "owner-1", InternalURL: "https://owner-1.internal"}, nil
}
func (c *forwardingCluster) ForwardHTTP(_ cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	out := r.Clone(r.Context())
	access, _ := controlplane.AccessFromContext(r.Context())
	cluster.StampForward(out, access)
	if c.fail {
		auditlog.MarkForwardFailed(r.Context())
		http.Error(w, "cluster: forward to https://owner-1.internal failed: connection refused", http.StatusBadGateway)
		return
	}
	// The network hop: the owner sees the wire, not the edge's context.
	out = out.WithContext(context.Background())
	out.TLS = peerTLS("edge-1")
	out.Header.Set(cluster.PeerNodeIDHeader, "edge-1")
	c.owner.Handler().ServeHTTP(w, out)
}

// TestAPIRecordEdgeSkipsOnForward is UC-273's unit half: a call the edge
// forwards is recorded once, by the owner that ran it, naming the caller
// and the edge as via; the edge writes nothing. A forward that fails
// before reaching the owner is recorded by the edge.
func TestAPIRecordEdgeSkipsOnForward(t *testing.T) {
	ownerStore := storeWith(t, "owner", ownedSandbox("sb-owned", "payments"))
	ownerSvc := service.New(config.Config{EnableCluster: true}, discardLogger(), ownerStore, nil, nil, nil, nil, nil, nil)
	ownerSink := &recSink{}
	ownerSvc.UseAuditSinkForTest(ownerSink)
	ownerSvc.AttachCluster(&openGateCluster{peerSideCluster{Noop: cluster.NewNoop("owner-1", "", ""), edge: "edge-1"}})
	tokens := WithCredentialAuthenticator(controlplane.PrincipalToken, stubTokens())
	clusterCfg := config.Config{IdentityEnabled: true, EnableCluster: true}
	owner := NewServer(discardLogger(), ownerSvc, nil, nil, clusterCfg, "pat-token", nil, tokens)

	edgeSvc := service.New(config.Config{EnableCluster: true}, discardLogger(), storeWith(t, "edge"), nil, nil, nil, nil, nil, nil)
	edgeSink := &recSink{}
	edgeSvc.UseAuditSinkForTest(edgeSink)
	fc := &forwardingCluster{Noop: cluster.NewNoop("edge-1", "", ""), owner: owner}
	edgeSvc.AttachCluster(fc)
	edge := NewServer(discardLogger(), edgeSvc, nil, nil, clusterCfg, "pat-token", nil, tokens)

	rec := do(t, edge, "POST", "/v1/sandboxes/sb-owned/stop", "avm_payments", "", map[string]string{"X-Correlation-ID": "corr-273"})
	if got := edgeSink.records(); len(got) != 0 {
		t.Fatalf("the edge recorded a call it forwarded: %+v", got)
	}
	got := ownerSink.records()
	if len(got) != 1 {
		t.Fatalf("owner records = %d, want 1 (status %d): %+v", len(got), rec.Code, got)
	}
	ev := got[0]
	want := &auditlog.Caller{Kind: "token", ID: "tok_7Hq2", Name: "ci-deploy", Team: "payments", Via: "edge-1"}
	if !reflect.DeepEqual(ev.Caller, want) || ev.SandboxID != "sb-owned" || ev.NodeID != "owner-1" ||
		ev.CorrelationID != "corr-273" || ev.OwnerRef != "team:payments" || ev.IncarnationID != "inc-sb-owned" {
		t.Fatalf("owner record = %+v caller %+v", ev, ev.Caller)
	}

	fc.fail = true
	rec = do(t, edge, "POST", "/v1/sandboxes/sb-owned/stop", "avm_payments", "", nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("failed forward = %d", rec.Code)
	}
	got = edgeSink.records()
	if len(got) != 1 || got[0].Request.Status != http.StatusBadGateway || got[0].Result != auditlog.APIResultError || got[0].NodeID != "edge-1" {
		t.Fatalf("edge record of a failed forward = %+v", got)
	}
}

// TestAPIRecordOnePerMCPToolCall: the outer /mcp request writes nothing;
// the tool's inner API call writes one record, attributed to the MCP
// caller, with surface mcp.
func TestAPIRecordOnePerMCPToolCall(t *testing.T) {
	st := storeWith(t, "mcp")
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-00000000000000aa", Name: "agent", Image: "alpine", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeIsolate, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	svc := service.New(config.Config{}, discardLogger(), st, nil, nil, caddy.New(config.Config{HTTPClientTimeout: time.Second}), nil, nil, nil)
	sink := &recSink{}
	svc.UseAuditSinkForTest(sink)
	srv := httptest.NewServer(NewServer(discardLogger(), svc, nil, nil, config.Config{MCPEnabled: true, MCPRateLimit: 100}, "pat-token", nil).Handler())
	defer srv.Close()
	transport := &mcp.StreamableClientTransport{
		Endpoint:   srv.URL + "/mcp?sandbox=agent",
		HTTPClient: &http.Client{Transport: bearerTransport{"pat-token"}},
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cs.Close()
	if got := sink.records(); len(got) != 0 {
		t.Fatalf("the MCP session setup wrote records: %+v", got)
	}
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "expose_port", Arguments: map[string]any{"port": 8080}})
	if err != nil {
		t.Fatal(err)
	}
	got := sink.waitRecords(t, 1)
	if len(got) != 1 {
		t.Fatalf("one tool call wrote %d records, want 1: %+v (tool result %+v)", len(got), got, res.Content[0])
	}
	ev := got[0]
	if ev.Ref != "POST /v1/sandboxes/{id}/ports/{port}" || ev.Request.Surface != auditlog.SurfaceMCP || ev.Caller == nil || ev.Caller.ID != "operator" || ev.SandboxID != "sb-00000000000000aa" {
		t.Fatalf("tool call record = %+v (request %+v)", ev, ev.Request)
	}
}

// recordCall runs h behind recordRoute the way Route does for an allowed
// call, with the route pattern and path values the mux would have set.
func recordCall(srv *Server, perm controlplane.Permission, pattern string, values map[string]string, req *http.Request, w http.ResponseWriter, h http.Handler) {
	req.Pattern = pattern
	for k, v := range values {
		req.SetPathValue(k, v)
	}
	access := controlplane.OperatorAccess()
	req = req.WithContext(controlplane.ContextWithAccess(req.Context(), access))
	srv.recordRoute(w, req, apihttp.RouteCall{Permission: perm, Access: access, HasAccess: true, Allowed: true}, h)
}

// TestAPIRecordExecDigest: an exec body is hashed as the handler reads it,
// never buffered; with SB_AUDIT_EXEC_COMMAND=full the argv is recorded
// too, never the environment.
func TestAPIRecordExecDigest(t *testing.T) {
	body := `{"command":["sh","-c","echo hi"],"env":{"API_KEY":"sk-secret"}}`
	sum := sha256.Sum256([]byte(body))
	readAll := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})
	pattern := "POST /v1/sandboxes/{id}/toolbox/{path...}"
	values := map[string]string{"id": "sb-1", "path": "process/execute"}
	for _, tc := range []struct {
		name     string
		cfg      config.Config
		handler  http.Handler
		wantSum  string
		wantArgv []string
	}{
		{"digest only by default", config.Config{}, readAll, hex.EncodeToString(sum[:]), nil},
		{"full adds the argv, not the env", config.Config{AuditExecCommand: config.AuditExecCommandFull}, readAll, hex.EncodeToString(sum[:]), []string{"sh", "-c", "echo hi"}},
		{"a body the handler never read has no digest", config.Config{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }), "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, sink, _ := auditServer(t, tc.cfg)
			req := httptest.NewRequest("POST", "/v1/sandboxes/sb-1/toolbox/process/execute", strings.NewReader(body))
			recordCall(srv, controlplane.PermSandboxExec, pattern, values, req, httptest.NewRecorder(), tc.handler)
			got := sink.records()
			if len(got) != 1 || got[0].Request.Digest != tc.wantSum || !slices.Equal(got[0].Request.Argv, tc.wantArgv) {
				t.Fatalf("records = %+v", got)
			}
			if strings.Contains(strings.Join(got[0].Request.Argv, " "), "sk-secret") {
				t.Fatal("the environment reached the record")
			}
		})
	}

	t.Run("argv shapes", func(t *testing.T) {
		cases := map[string][]string{
			`{"argv":["ls","-l"]}`:               {"ls", "-l"},
			`{"cmd":"python","args":["-c","1"]}`: {"python", "-c", "1"},
			`{"command":"echo hi"}`:              {"echo hi"},
			`{"command":""}`:                     nil,
			`{"env":{"A":"b"}}`:                  nil,
			`not json`:                           nil,
			`{"command":{"nested":"object"}}`:    nil,
		}
		for raw, want := range cases {
			d := newDigestBody(io.NopCloser(strings.NewReader(raw)), nil, true)
			_, _ = io.Copy(io.Discard, d)
			if got := d.argv(); !slices.Equal(got, want) {
				t.Errorf("argv(%s) = %q, want %q", raw, got, want)
			}
		}
		big := newDigestBody(io.NopCloser(strings.NewReader(`{"command":"`+strings.Repeat("a", execArgvCaptureMax)+`"}`)), nil, true)
		_, _ = io.Copy(io.Discard, big)
		if big.argv() != nil {
			t.Error("a body cut at the capture cap must yield no argv")
		}
		var nilBody *digestBody
		if nilBody.digest() != "" || nilBody.argv() != nil {
			t.Error("nil digest body")
		}
	})

	t.Run("a forwarded call stops hashing on the edge", func(t *testing.T) {
		srv, sink, _ := auditServer(t, config.Config{})
		req := httptest.NewRequest("POST", "/v1/sandboxes/sb-1/toolbox/process/execute", strings.NewReader(body))
		forwarder := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auditlog.MarkForwarded(r.Context())
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		})
		var hashed *digestBody
		recordCall(srv, controlplane.PermSandboxExec, pattern, values, req, httptest.NewRecorder(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hashed = r.Body.(*digestBody)
			forwarder.ServeHTTP(w, r)
		}))
		if len(sink.records()) != 0 || hashed == nil || hashed.n != 0 {
			t.Fatalf("records %d, hashed bytes %d: the edge must neither record nor hash a forwarded call", len(sink.records()), hashed.n)
		}
	})
}

// hijackWriter is a ResponseWriter whose connection can be taken over.
type hijackWriter struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (h *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn)), nil
}

// TestAPIRecordStreamsRecordedAtUpgrade: a WebSocket session is recorded
// at the upgrade (status 101) and a streamed response at its first flush,
// while they run, not when they end; and only once.
func TestAPIRecordStreamsRecordedAtUpgrade(t *testing.T) {
	srv, sink, _ := auditServer(t, config.Config{})
	pattern := "/v1/sandboxes/{id}/sessions/{path...}"
	values := map[string]string{"id": "sb-1", "path": "default/attach"}

	server, client := net.Pipe()
	defer client.Close()
	recordedDuringSession := 0
	ws := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		recordedDuringSession = len(sink.records())
		_ = conn.Close()
	})
	recordCall(srv, controlplane.PermSandboxExec, pattern, values, httptest.NewRequest("GET", "/v1/sandboxes/sb-1/sessions/default/attach", nil),
		&hijackWriter{ResponseRecorder: httptest.NewRecorder(), conn: server}, ws)
	got := sink.records()
	if recordedDuringSession != 1 || len(got) != 1 || got[0].Request.Status != http.StatusSwitchingProtocols {
		t.Fatalf("during %d, after %+v: want one record with 101, written at the upgrade", recordedDuringSession, got)
	}

	sink.reset()
	stream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("data: 1\n\n"))
		w.(http.Flusher).Flush()
		recordedDuringSession = len(sink.records())
		w.(http.Flusher).Flush()
	})
	recordCall(srv, controlplane.PermSandboxExec, pattern, values, httptest.NewRequest("GET", "/v1/sandboxes/sb-1/sessions/default/logs", nil), httptest.NewRecorder(), stream)
	if got := sink.records(); recordedDuringSession != 1 || len(got) != 1 || got[0].Request.Status != http.StatusAccepted {
		t.Fatalf("stream: during %d, after %+v", recordedDuringSession, got)
	}

	sink.reset()
	switching := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusContinue) // informational: not the status
		w.WriteHeader(http.StatusSwitchingProtocols)
	})
	recordCall(srv, controlplane.PermSandboxExec, pattern, values, httptest.NewRequest("GET", "/v1/sandboxes/sb-1/sessions/x", nil), httptest.NewRecorder(), switching)
	if got := sink.records(); len(got) != 1 || got[0].Request.Status != http.StatusSwitchingProtocols {
		t.Fatalf("101 via WriteHeader: %+v", got)
	}

	// No hijacker underneath: the error reaches the handler, nothing is
	// recorded early, and the call is recorded when it returns.
	sink.reset()
	rw := &recordingWriter{ResponseWriter: httptest.NewRecorder(), early: func(int) { t.Fatal("recorded early on a failed hijack") }}
	if _, _, err := rw.Hijack(); err == nil {
		t.Fatal("hijack on a recorder succeeded")
	}
	if rw.Unwrap() == nil || rw.statusCode() != http.StatusOK {
		t.Fatal("recordingWriter defaults")
	}
}

// TestAPIRecordNotesFromHandlers: a create learns its sandbox id and a
// handler may name the object it created; both reach the record.
func TestAPIRecordNotesFromHandlers(t *testing.T) {
	srv, sink, _ := auditServer(t, config.Config{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auditlog.NoteSandboxIdentity(r.Context(), "sb-new", "inc-new", "team:payments")
		auditlog.NoteTarget(r.Context(), "tok_new")
		w.WriteHeader(http.StatusCreated)
	})
	recordCall(srv, controlplane.PermSandboxWrite, "POST /v1/sandboxes", nil, httptest.NewRequest("POST", "/v1/sandboxes", nil), httptest.NewRecorder(), h)
	got := sink.records()
	if len(got) != 1 || got[0].SandboxID != "sb-new" || got[0].IncarnationID != "inc-new" || got[0].OwnerRef != "team:payments" ||
		got[0].Request.Target != "tok_new" || got[0].Request.Status != http.StatusCreated {
		t.Fatalf("records = %+v", got)
	}
}

// TestAPIRecordPanickingHandler: a handler that panics still made the
// call; it is recorded (500, or the status already sent) and the panic
// still reaches net/http.
func TestAPIRecordPanickingHandler(t *testing.T) {
	for _, tc := range []struct {
		name   string
		before func(http.ResponseWriter)
		want   int
	}{
		{"before any status", func(http.ResponseWriter) {}, http.StatusInternalServerError},
		{"after the status (a proxy aborting mid-body)", func(w http.ResponseWriter) { w.WriteHeader(http.StatusOK) }, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, sink, _ := auditServer(t, config.Config{})
			func() {
				defer func() {
					if p := recover(); p != http.ErrAbortHandler {
						t.Fatalf("recovered %v, want the handler's own panic", p)
					}
				}()
				recordCall(srv, controlplane.PermSandboxWrite, "POST /v1/sandboxes/{id}/stop", map[string]string{"id": "sb-1"},
					httptest.NewRequest("POST", "/v1/sandboxes/sb-1/stop", nil), httptest.NewRecorder(),
					http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { tc.before(w); panic(http.ErrAbortHandler) }))
			}()
			if got := sink.records(); len(got) != 1 || got[0].Request.Status != tc.want {
				t.Fatalf("records = %+v, want one with status %d", got, tc.want)
			}
		})
	}
}

// TestAPIRecordClusterInternalNeverRecorded (findings 7.1, 7.2): node to
// node control traffic is not a caller's action. Neither an allowed nor a
// refused cluster.internal call writes a record.
func TestAPIRecordClusterInternalNeverRecorded(t *testing.T) {
	srv, sink, _ := auditServer(t, config.Config{AuditAPIRecords: config.AuditAPIRecordsAll})
	ran := false
	recordCall(srv, controlplane.PermClusterInternal, "POST /v1/cluster/internal/apply", nil, httptest.NewRequest("POST", "/v1/cluster/internal/apply", nil), httptest.NewRecorder(),
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran = true }))
	srv.recordRoute(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/cluster/internal/apply", nil), apihttp.RouteCall{Permission: controlplane.PermClusterInternal}, nil)
	if !ran || len(sink.records()) != 0 {
		t.Fatalf("ran %v, records %+v", ran, sink.records())
	}
}

func TestDescribeRoute(t *testing.T) {
	req := func(pattern, method string, values map[string]string) *http.Request {
		r := httptest.NewRequest(method, "/", nil)
		r.Pattern = pattern
		for k, v := range values {
			r.SetPathValue(k, v)
		}
		return r
	}
	cases := []struct {
		name string
		r    *http.Request
		want routeDesc
	}{
		{"no pattern", req("", "GET", nil), routeDesc{route: ""}},
		{"method-less pattern", req("/v1/sandboxes/{id}/toolbox/{path...}", "POST", map[string]string{"id": "sb", "path": "a/b"}),
			routeDesc{route: "/v1/sandboxes/{id}/toolbox/{path...}", sandboxID: "sb", target: "a/b"}},
		{"sandbox delete", req("DELETE /v1/sandboxes/{id}", "DELETE", map[string]string{"id": "sb"}),
			routeDesc{route: "/v1/sandboxes/{id}", sandboxID: "sb", deletesSandbox: true}},
		{"sub-resource delete is not a sandbox delete", req("DELETE /v1/sandboxes/{id}/ports/{port}", "DELETE", map[string]string{"id": "sb", "port": "80"}),
			routeDesc{route: "/v1/sandboxes/{id}/ports/{port}", sandboxID: "sb", target: "80"}},
		{"fleet route naming a sandbox", req("GET /v1/cluster/sandboxes/{id}/secret-holders", "GET", map[string]string{"id": "sb"}),
			routeDesc{route: "/v1/cluster/sandboxes/{id}/secret-holders", sandboxID: "sb"}},
		{"node id is a target", req("POST /v1/cluster/nodes/{id}/drain", "POST", map[string]string{"id": "n2"}),
			routeDesc{route: "/v1/cluster/nodes/{id}/drain", target: "n2"}},
		{"unbound wildcard", req("DELETE /v1/snapshots/{id}", "DELETE", nil), routeDesc{route: "/v1/snapshots/{id}"}},
	}
	for _, c := range cases {
		if got := describeRoute(c.r); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
	if shouldRecordCall(httptest.NewRequest("OPTIONS", "/", nil), controlplane.PermSandboxWrite, service.APIAuditPolicy{Enabled: true}) {
		t.Error("OPTIONS is a read")
	}
	if !shouldRecordCall(httptest.NewRequest("GET", "/", nil), controlplane.PermTokenRead, service.APIAuditPolicy{Enabled: true}) {
		t.Error("token listing is always recorded")
	}
}

// TestSSHGatewayServiceRecordsSessions pins that the service the daemon
// hands the SSH gateway can write the session record.
func TestSSHGatewayServiceRecordsSessions(t *testing.T) {
	var svc any = (*service.Service)(nil)
	if _, ok := svc.(interface {
		RecordSSHSession(context.Context, string, string)
	}); !ok {
		t.Fatal("*service.Service no longer records SSH sessions")
	}
}
