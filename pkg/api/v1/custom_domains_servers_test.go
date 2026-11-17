package v1

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/clustercreate"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A worker or gateway sends a domain attach, and a create with
// custom_domains, to a server; the owner's half a server sent here, and a
// create with no custom_domains, stay here.
func TestCustomDomainCallsGoToServers(t *testing.T) {
	for _, role := range []string{config.NodeRoleWorker, config.NodeRoleIngress} {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		svc := service.New(config.Config{EnableCluster: true, NodeRole: role}, logger, nil, nil, nil, nil, nil, nil, nil)
		rec := &forwardRecorder{Noop: cluster.NewNoop("self-1", "http://self-1", "")}
		svc.AttachCluster(rec)
		mux := http.NewServeMux()
		RegisterRoutes(mux, Deps{Service: svc, Logger: logger, Auth: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), controlplane.OperatorAccess())))
			})
		}})
		call := func(path, body string, headers map[string]string) (int, bool) {
			sent := len(rec.sent)
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer operator")
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			rr := httptest.NewRecorder()
			func() {
				defer func() { _ = recover() }()
				mux.ServeHTTP(rr, req)
			}()
			return rr.Code, len(rec.sent) > sent
		}
		if code, sent := call("/v1/sandboxes/sb-1/custom-domains", `{"hostname":"app.customer.com"}`, nil); !sent || code != http.StatusTeapot || rec.sent[len(rec.sent)-1] != "once POST /v1/sandboxes/sb-1/custom-domains" {
			t.Errorf("%s attach: %d sent=%v %v", role, code, sent, rec.sent)
		}
		if _, sent := call("/v1/sandboxes/sb-1/custom-domains", `{"hostname":"app.customer.com"}`, map[string]string{cluster.HeaderForwarded: "1"}); sent {
			t.Errorf("%s: the owner's half of an attach went back to a server", role)
		}
		if code, sent := call("/v1/sandboxes", `{"image":"alpine","custom_domains":["app.customer.com"]}`, nil); !sent || code != http.StatusTeapot || rec.sent[len(rec.sent)-1] != "once POST /v1/sandboxes" {
			t.Errorf("%s create with custom domains: %d sent=%v %v", role, code, sent, rec.sent)
		}
		// A keyed create replays on a retry, so it may go to the next server
		// after a 5xx.
		if _, sent := call("/v1/sandboxes", `{"image":"alpine","custom_domains":["app.customer.com"]}`, map[string]string{clustercreate.HeaderIdempotencyKey: "k-1"}); !sent || rec.sent[len(rec.sent)-1] != "POST /v1/sandboxes" {
			t.Errorf("%s keyed create: sent=%v %v", role, sent, rec.sent)
		}
		if _, sent := call("/v1/sandboxes", `{"image":"alpine","custom_domains":["app.customer.com"]}`, map[string]string{clustercreate.HeaderTarget: "self-1", clustercreate.HeaderID: "sb-1"}); sent {
			t.Errorf("%s: the owner's half of a create went back to a server", role)
		}
		if _, sent := call("/v1/sandboxes", `{"image":"alpine"}`, nil); sent {
			t.Errorf("%s: a create with no custom domains went to a server", role)
		}
	}
}

// binderCluster is a server's cluster for the attach wrapper: it knows
// sb-1 (team payments) and records binds and releases.
type binderCluster struct {
	*cluster.Noop
	p       cluster.Placement
	bound   []string
	removed []string
}

func (c *binderCluster) PlacementOf(id string) (cluster.Placement, bool) {
	return c.p, id == c.p.SandboxID
}
func (c *binderCluster) IsClusterHostname(string) bool { return false }
func (c *binderCluster) AddCustomDomainForIncarnation(_ context.Context, id, inc, host string) error {
	c.bound = append(c.bound, id+"/"+inc+"/"+host)
	return nil
}
func (c *binderCluster) RemoveCustomDomain(_ context.Context, id, host string) error {
	c.removed = append(c.removed, id+"/"+host)
	return nil
}

type txtView map[string][]string

func (v txtView) LookupTXT(_ context.Context, name string) ([]string, error) {
	if txt, ok := v[name]; ok {
		return txt, nil
	}
	return nil, errors.New("no such host")
}

func binderServer(t *testing.T) (*handlers, *binderCluster) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer,
		CustomDomainVerifyPrefix: "_aerolvm", CustomDomainVerifyValuePrefix: "aerolvm="}, logger, nil, nil, nil, nil, nil, nil, nil)
	c := &binderCluster{Noop: cluster.NewNoop("srv-1", "http://srv-1", ""),
		p: cluster.Placement{SandboxID: "sb-1", IncarnationID: "inc-1", OwnerRef: "team:payments"}}
	svc.AttachCluster(c)
	svc.SetDNSResolver(txtView{"_aerolvm.app.customer.com": {models.CustomDomainTXTValue("aerolvm=", "", "app.customer.com")}})
	return &handlers{deps: Deps{Service: svc, Logger: logger}}, c
}

// A server binds the caller's proven name, then serves the call; a name it
// bound is released when the owner refuses the attach, and kept when the
// outcome is unknown.
func TestServerBindsTheAttachFirst(t *testing.T) {
	run := func(h *handlers, body string, forwarded bool, ownerStatus int) (int, bool, bool) {
		called, marked := false, false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			_, marked = cluster.CustomDomainsBoundFromContext(r.Context())
			raw, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(raw), "hostname") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if ownerStatus == 0 {
				// A body with no WriteHeader: the implicit 200.
				_, _ = w.Write([]byte(`{"hostname":"app.customer.com"}`))
				return
			}
			w.WriteHeader(ownerStatus)
		})
		mux := http.NewServeMux()
		mux.Handle("POST /v1/sandboxes/{id}/custom-domains", h.bindCustomDomainFirst(next))
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-1/custom-domains", strings.NewReader(body))
		req = req.WithContext(controlplane.ContextWithAccess(req.Context(), controlplane.OperatorAccess()))
		if forwarded {
			req.Header.Set(cluster.HeaderForwarded, "1")
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr.Code, called, marked
	}
	const attach = `{"hostname":"app.customer.com"}`
	for _, tc := range []struct {
		name        string
		body        string
		forwarded   bool
		owner       int
		wantCode    int
		wantBound   int
		wantRemoved int
		wantMarked  bool
	}{
		{name: "the owner takes it", body: attach, owner: http.StatusCreated, wantCode: http.StatusCreated, wantBound: 1, wantMarked: true},
		{name: "the owner answers with a body only", body: attach, owner: 0, wantCode: http.StatusOK, wantBound: 1, wantMarked: true},
		{name: "the owner refuses it", body: attach, owner: http.StatusConflict, wantCode: http.StatusConflict, wantBound: 1, wantRemoved: 1, wantMarked: true},
		{name: "the outcome is unknown", body: attach, owner: http.StatusBadGateway, wantCode: http.StatusBadGateway, wantBound: 1, wantMarked: true},
		{name: "the owner's half", body: attach, forwarded: true, owner: http.StatusCreated, wantCode: http.StatusCreated},
		{name: "no proof", body: `{"hostname":"none.customer.com"}`, owner: http.StatusCreated, wantCode: http.StatusForbidden},
		{name: "a bad body", body: `{`, owner: http.StatusCreated, wantCode: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, c := binderServer(t)
			code, called, marked := run(h, tc.body, tc.forwarded, tc.owner)
			if code != tc.wantCode || len(c.bound) != tc.wantBound || len(c.removed) != tc.wantRemoved || marked != tc.wantMarked {
				t.Fatalf("code %d called %v marked %v bound %v removed %v", code, called, marked, c.bound, c.removed)
			}
			if tc.wantCode == http.StatusForbidden && called {
				t.Fatal("the call went on without a proof")
			}
		})
	}
	// A worker binds nothing.
	h, c := binderServer(t)
	h.deps.Service = service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker}, h.deps.Logger, nil, nil, nil, nil, nil, nil, nil)
	h.deps.Service.AttachCluster(c)
	if code, _, marked := run(h, attach, false, http.StatusCreated); code != http.StatusCreated || marked || len(c.bound) != 0 {
		t.Fatalf("worker: code %d marked %v bound %v", code, marked, c.bound)
	}
}

// The create router's hook on a server binds a create's custom domains to
// its reservation; none without custom domains or off a server.
func TestBindCreateCustomDomainsHook(t *testing.T) {
	h, c := binderServer(t)
	if h.bindCreateCustomDomains(models.CreateSandboxRequest{Image: "alpine"}) != nil {
		t.Fatal("a hook for a create with no custom domains")
	}
	hook := h.bindCreateCustomDomains(models.CreateSandboxRequest{Image: "alpine", CustomDomains: []string{"app.customer.com"}})
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	req = req.WithContext(controlplane.ContextWithAccess(req.Context(), controlplane.OperatorAccess()))
	next, ok := hook(httptest.NewRecorder(), req, "sb-9", "inc-9")
	if !ok || len(c.bound) != 1 || c.bound[0] != "sb-9/inc-9/app.customer.com" {
		t.Fatalf("ok %v bound %v", ok, c.bound)
	}
	if b, marked := cluster.CustomDomainsBoundFromContext(next.Context()); !marked || !b.Covers("sb-9", "app.customer.com") {
		t.Fatal("the create goes on unmarked")
	}
	tenant := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	tenant = tenant.WithContext(controlplane.ContextWithAccess(tenant.Context(),
		controlplane.TokenAccess("tok_x", "x", controlplane.RoleRunner, "payments", time.Time{})))
	rr := httptest.NewRecorder()
	if _, ok := hook(rr, tenant, "sb-9", "inc-9"); ok || rr.Code != http.StatusForbidden {
		t.Fatalf("a team caller with no TXT record of its own: ok %v code %d", ok, rr.Code)
	}
	worker, _ := binderServer(t)
	worker.deps.Service = service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker}, worker.deps.Logger, nil, nil, nil, nil, nil, nil, nil)
	if worker.bindCreateCustomDomains(models.CreateSandboxRequest{CustomDomains: []string{"app.customer.com"}}) != nil {
		t.Fatal("a worker's hook")
	}
}

// A call a worker or gateway sent on to this server makes this server its
// edge: it binds, and routes the call on to the owner; a call a server sent
// is the owner's half.
func TestServerIsTheEdgeForACallSentOn(t *testing.T) {
	sentBy := func(role string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-1/custom-domains", strings.NewReader(`{"hostname":"app.customer.com"}`))
		req = req.WithContext(controlplane.ContextWithAccess(req.Context(), controlplane.OperatorAccess()))
		req.Header.Set(cluster.HeaderForwarded, "1")
		names := []string{"node:p1"}
		if role != "" {
			names = append(names, "role:"+role)
		}
		cert := &x509.Certificate{DNSNames: names}
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
		return req
	}
	for _, tc := range []struct {
		role      string
		wantBound bool
	}{
		{controlplane.NodeRoleWorker, true},
		{controlplane.NodeRoleIngress, true},
		{controlplane.NodeRoleServer, false},
	} {
		h, c := binderServer(t)
		var forwarded string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			forwarded = r.Header.Get(cluster.HeaderForwarded)
			w.WriteHeader(http.StatusCreated)
		})
		mux := http.NewServeMux()
		mux.Handle("POST /v1/sandboxes/{id}/custom-domains", h.bindCustomDomainFirst(next))
		mux.ServeHTTP(httptest.NewRecorder(), sentBy(tc.role))
		if (len(c.bound) == 1) != tc.wantBound || (forwarded == "") != tc.wantBound {
			t.Errorf("sent on by a %s: bound %v, forward marker %q", tc.role, c.bound, forwarded)
		}
	}
	// Not a server: nothing changes.
	h, _ := binderServer(t)
	h.deps.Service = service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker}, h.deps.Logger, nil, nil, nil, nil, nil, nil, nil)
	if r := sentBy(controlplane.NodeRoleIngress); h.asEdge(r) != r {
		t.Fatal("a worker made itself the edge")
	}
	// No verified certificate: not sent on by a node.
	h, _ = binderServer(t)
	plain := sentBy(controlplane.NodeRoleIngress)
	plain.TLS = nil
	if h.asEdge(plain) != plain {
		t.Fatal("a call with no certificate taken as sent on")
	}
}

// On a server, the attach route binds the name before the call goes on.
func TestAttachRouteBindsOnAServer(t *testing.T) {
	h, c := binderServer(t)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: h.deps.Service, Logger: h.deps.Logger, Auth: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), controlplane.OperatorAccess())))
		})
	}})
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-1/custom-domains", strings.NewReader(`{"hostname":"app.customer.com"}`))
	req.Header.Set("Authorization", "Bearer operator")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	// This test server has custom domains off, so the owner's half answers
	// 412 and the name the route bound is released again.
	if len(c.bound) != 1 || len(c.removed) != 1 || rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("code %d bound %v removed %v: %s", rr.Code, c.bound, c.removed, rr.Body.String())
	}
}

// routingBinder is a server whose placement picks another node: it records
// the create forward it would send.
type routingBinder struct {
	*binderCluster
	forwarded []*http.Request
}

func (c *routingBinder) SelectPlacementForCreate(capacity.Request, string, int) (cluster.PlacementTarget, []string, error) {
	return cluster.PlacementTarget{NodeID: "wkr-2", APIURL: "http://wkr-2", InternalURL: "https://wkr-2:7002"}, nil, nil
}

func (c *routingBinder) ForwardHTTP(_ cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	c.forwarded = append(c.forwarded, r)
	w.WriteHeader(http.StatusCreated)
}

// A create with custom domains a gateway sent on to this server: the
// server binds the names to the reservation, then sends the create to the
// owner as the create's edge, with the names it bound.
func TestCreateSentOnBindsAndRoutes(t *testing.T) {
	h, bc := binderServer(t)
	c := &routingBinder{binderCluster: bc}
	h.deps.Service.AttachCluster(c)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: h.deps.Service, Logger: h.deps.Logger, Auth: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), controlplane.OperatorAccess())))
		})
	}})
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20","allow_public_traffic":true,"custom_domains":["app.customer.com"]}`))
	req.Header.Set("Authorization", "Bearer operator")
	req.Header.Set(cluster.HeaderForwarded, "1")
	cert := &x509.Certificate{DNSNames: []string{"node:gw-1", "role:" + controlplane.NodeRoleIngress}}
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated || len(c.forwarded) != 1 || len(bc.bound) != 1 {
		t.Fatalf("code %d forwarded %d bound %v: %s", rr.Code, len(c.forwarded), bc.bound, rr.Body.String())
	}
	out := c.forwarded[0]
	if out.Header.Get(cluster.HeaderForwarded) != "" {
		t.Fatal("the create went on carrying the gateway's forward marker")
	}
	b, ok := cluster.CustomDomainsBoundFromContext(out.Context())
	if !ok || !b.Covers(out.Header.Get(clustercreate.HeaderID), "app.customer.com") {
		t.Fatalf("the create went on without the names bound: %+v %v", b, ok)
	}
}
