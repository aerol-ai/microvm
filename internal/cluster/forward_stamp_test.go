package cluster

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

func teamToken(team string) controlplane.Access {
	return controlplane.Access{
		Identity:  controlplane.Identity{OwnerRef: controlplane.TeamOwnerRef(team)},
		Role:      controlplane.RoleRunner,
		Principal: controlplane.Principal{Kind: controlplane.PrincipalToken, ID: "tok_7Hq2", Name: "ci-deploy"},
	}
}

// TestStampForward pins what every forward carries: the forwarded marker,
// the team a team-bound credential resolved to (never a team for the PAT, a
// node, a managed account or a fleet binding), and the request's
// correlation id.
func TestStampForward(t *testing.T) {
	oidc := teamToken("checkout")
	oidc.Principal = controlplane.Principal{Kind: controlplane.PrincipalOIDC, ID: "oidc:okta:00u1", Name: "ana@acme.com"}
	fleetToken := controlplane.Access{Fleet: true, Role: controlplane.RoleViewer, Principal: controlplane.Principal{Kind: controlplane.PrincipalToken, ID: "tok_fleet"}}
	managed := controlplane.Access{
		Identity:  controlplane.Identity{OwnerRef: "team:looks-like-a-team"},
		Role:      controlplane.RoleRunner,
		Principal: controlplane.Principal{Kind: controlplane.PrincipalControlPlane, ID: "controlplane:ext-1"},
	}
	cases := []struct {
		name        string
		access      controlplane.Access
		correlation string
		wantTeam    string
	}{
		{"team-bound avm_ token", teamToken("payments"), "", "payments"},
		{"team-bound OIDC token with a correlation id", oidc, "corr-42", "checkout"},
		{"fleet-bound token has no team to select", fleetToken, "", ""},
		{"operator", controlplane.OperatorAccess(), "corr-op", ""},
		{"node", controlplane.NodeAccess("n3"), "", ""},
		{"managed account is never a team", managed, "", ""},
		{"no access at all", controlplane.Access{}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := auditlog.ContextWithCorrelationID(context.Background(), tc.correlation)
			out, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://peer/v1/sandboxes", nil)
			if err != nil {
				t.Fatal(err)
			}
			StampForward(out, tc.access)
			if got := out.Header.Get(HeaderForwarded); got != "1" {
				t.Fatalf("%s = %q, want 1", HeaderForwarded, got)
			}
			if got := out.Header.Get(HeaderTeam); got != tc.wantTeam {
				t.Fatalf("%s = %q, want %q", HeaderTeam, got, tc.wantTeam)
			}
			if got := out.Header.Get(HeaderCorrelationID); got != tc.correlation {
				t.Fatalf("%s = %q, want %q", HeaderCorrelationID, got, tc.correlation)
			}
		})
	}

	t.Run("nil request and nil header map", func(t *testing.T) {
		StampForward(nil, teamToken("payments"))
		out := &http.Request{}
		StampForward(out, teamToken("payments"))
		if out.Header.Get(HeaderForwarded) != "1" || out.Header.Get(HeaderTeam) != "payments" {
			t.Fatalf("headers = %v", out.Header)
		}
	})

	t.Run("the resolved team replaces whatever the caller sent", func(t *testing.T) {
		out := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
		out.Header.Set(HeaderTeam, "payments")
		StampForward(out, teamToken("payments"))
		if got := out.Header.Values(HeaderTeam); len(got) != 1 || got[0] != "payments" {
			t.Fatalf("team values = %v, want exactly [payments]", got)
		}
	})
}

// TestStampForwardPATOrigin is the forwarded-PAT origin rule's sending half
// (plans/identity-and-access.md §5.11): a forward of an operator-token call
// says where the edge accepted the PAT, an unknown origin says public (the
// value an owner under host scope refuses), and no other credential carries
// the marker, even one copied from the inbound request.
func TestStampForwardPATOrigin(t *testing.T) {
	cases := []struct {
		name   string
		access controlplane.Access
		origin string // what the API edge recorded; "" = nothing
		stale  string // a marker already on the outbound request
		want   string
	}{
		{name: "operator from a loopback peer", access: controlplane.OperatorAccess(), origin: PATOriginHost, want: PATOriginHost},
		{name: "operator from the public side", access: controlplane.OperatorAccess(), origin: PATOriginPublic, want: PATOriginPublic},
		{name: "operator with no recorded origin is public", access: controlplane.OperatorAccess(), want: PATOriginPublic},
		{name: "an unknown origin value is public", access: controlplane.OperatorAccess(), origin: "somewhere", want: PATOriginPublic},
		{name: "node acting for itself", access: controlplane.NodeAccess("n3"), origin: PATOriginHost, want: PATOriginHost},
		{name: "a stale public marker is replaced", access: controlplane.OperatorAccess(), origin: PATOriginHost, stale: PATOriginPublic, want: PATOriginHost},
		{name: "a token carries no origin", access: teamToken("payments"), origin: PATOriginHost, want: ""},
		{name: "a stale marker never rides on a token", access: teamToken("payments"), stale: PATOriginHost, want: ""},
		{name: "no access carries no origin", access: controlplane.Access{}, stale: PATOriginHost, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.origin != "" {
				ctx = ContextWithPATOrigin(ctx, tc.origin)
			}
			out, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://peer/v1/sandboxes", nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.stale != "" {
				out.Header.Set(HeaderPATOrigin, tc.stale)
			}
			StampForward(out, tc.access)
			if got := out.Header.Values(HeaderPATOrigin); (tc.want == "" && len(got) != 0) || (tc.want != "" && (len(got) != 1 || got[0] != tc.want)) {
				t.Fatalf("%s = %v, want %q", HeaderPATOrigin, got, tc.want)
			}
		})
	}
	if got := PATOriginFromContext(context.Background()); got != "" {
		t.Fatalf("an empty context has origin %q", got)
	}
}

// TestForwardHTTPStampsTheForward drives the reverse-proxy Director behind
// ForwardHTTP over a real node-bound mTLS hop: the owner receives the
// caller's own credential untouched plus the StampForward markers, taken
// from the inbound request's context.
func TestForwardHTTPStampsTheForward(t *testing.T) {
	seen := make(chan http.Header, 1)
	srv, client := newNodeBoundForwardServer(t, "edge-1", "owner-1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	c := newForwardingCluster(t, client.Transport)
	c.nodeID = "edge-1"

	in := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1", nil)
	in.Header.Set("Authorization", "Bearer avm_payments")
	ctx := controlplane.ContextWithAccess(in.Context(), teamToken("payments"))
	ctx = auditlog.ContextWithCorrelationID(ctx, "corr-fwd")
	in = in.WithContext(ctx)

	rr := httptest.NewRecorder()
	c.ForwardHTTP(Endpoint{NodeID: "owner-1", InternalURL: srv.URL}, rr, in)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("forward status = %d body %s", rr.Code, rr.Body.String())
	}
	h := <-seen
	want := map[string]string{
		"Authorization":     "Bearer avm_payments",
		HeaderForwarded:     "1",
		HeaderTeam:          "payments",
		HeaderCorrelationID: "corr-fwd",
		PeerNodeIDHeader:    "edge-1",
	}
	for name, value := range want {
		if got := h.Get(name); got != value {
			t.Errorf("owner saw %s = %q, want %q", name, got, value)
		}
	}
}

// TestForwardMarksTheEdgeRecord is the regression test for the api-record
// forward dedupe (plans/identity-and-access.md §5.9): the reverse-proxy
// Director marks the edge's call state forwarded, so only the owner records
// the call; a forward that never reaches the owner (a wrong peer
// certificate here, the 502 path) also marks it failed, so the edge records
// the failure instead. Fan-out clients reach the same mark through
// StampForward itself.
func TestForwardMarksTheEdgeRecord(t *testing.T) {
	srv, client := newNodeBoundForwardServer(t, "edge-1", "owner-1", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	c := newForwardingCluster(t, client.Transport)
	c.nodeID = "edge-1"
	forward := func(target Endpoint) (*auditlog.CallState, int) {
		ctx, st := auditlog.ContextWithCallState(controlplane.ContextWithAccess(context.Background(), teamToken("payments")))
		in := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-1/stop", nil).WithContext(ctx)
		rr := httptest.NewRecorder()
		c.ForwardHTTP(target, rr, in)
		return st, rr.Code
	}
	st, code := forward(Endpoint{NodeID: "owner-1", InternalURL: srv.URL})
	if code != http.StatusNoContent || !st.Forwarded() || st.ForwardFailed() {
		t.Fatalf("reached owner: code %d forwarded %v failed %v", code, st.Forwarded(), st.ForwardFailed())
	}
	st, code = forward(Endpoint{NodeID: "owner-2", InternalURL: srv.URL})
	if code != http.StatusBadGateway || !st.Forwarded() || !st.ForwardFailed() {
		t.Fatalf("failed forward: code %d forwarded %v failed %v", code, st.Forwarded(), st.ForwardFailed())
	}

	// A fan-out client builds a fresh request on the inbound context.
	ctx, fan := auditlog.ContextWithCallState(context.Background())
	out, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://peer/v1/sandboxes", nil)
	if err != nil {
		t.Fatal(err)
	}
	StampForward(out, controlplane.OperatorAccess())
	if !fan.Forwarded() {
		t.Fatal("StampForward did not mark the fan-out's call state")
	}
}
