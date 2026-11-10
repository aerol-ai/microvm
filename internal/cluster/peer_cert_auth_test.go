package cluster

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// The internal listener vouches for the peer it checked, and only after
// every check passed.
func TestInternalServerMarksTheCheckedPeer(t *testing.T) {
	pool, tlsCert, err := generateTestCertForNode("node-test")
	if err != nil {
		t.Fatal(err)
	}
	ct := &ClusterTLS{nodeCert: tlsCert, caPool: pool}
	srv, err := startInternalServer("127.0.0.1:0", ct, func(context.Context, []byte) error { return nil }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	live := true
	srv.SetPeerAuthorizer(func(string) bool { return live })
	var seen string
	var marked bool
	srv.SetExtraHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, marked = InternalPeerFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: ct.clientConfig()}}
	get := func() int {
		resp, err := client.Get("https://" + srv.Addr() + "/v1/cluster/internal/drained-nodes")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(); code != http.StatusNoContent || !marked || seen != "node-test" {
		t.Fatalf("live peer = %d marked %v %q", code, marked, seen)
	}
	live, marked = false, false
	if code := get(); code != http.StatusForbidden || marked {
		t.Fatalf("peer out of membership = %d, handler ran %v", code, marked)
	}
}

// The context marks round-trip, and are absent on a plain context.
func TestPeerCertAuthContextMarks(t *testing.T) {
	ctx := context.Background()
	if _, ok := InternalPeerFromContext(ctx); ok || LocalCallerFromContext(ctx) {
		t.Fatal("a plain context carries a mark")
	}
	if _, ok := InternalPeerFromContext(ContextWithInternalPeer(ctx, "")); ok {
		t.Fatal("an empty peer id counted as a mark")
	}
	if id, ok := InternalPeerFromContext(ContextWithInternalPeer(ctx, "n1")); !ok || id != "n1" {
		t.Fatalf("peer mark = %q %v", id, ok)
	}
	if !LocalCallerFromContext(ContextWithLocalCaller(ctx)) {
		t.Fatal("local caller mark lost")
	}
}

// StampForward drops a local tool's credential and says the edge speaks
// for the call; any other forward keeps its credential and loses a
// marker copied from the inbound request.
func TestStampForwardCaller(t *testing.T) {
	mk := func(ctx context.Context) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1", bytes.NewReader(nil)).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer token")
		req.Header.Set("X-API-KEY", "token")
		req.Header.Set(HeaderCaller, CallerNode)
		return req
	}
	local := mk(ContextWithLocalCaller(context.Background()))
	StampForward(local, controlplane.OperatorAccess())
	if local.Header.Get("Authorization") != "" || local.Header.Get("X-API-KEY") != "" || local.Header.Get(HeaderCaller) != CallerNode {
		t.Fatalf("local caller forward = %v", local.Header)
	}
	user := mk(context.Background())
	StampForward(user, controlplane.OperatorAccess())
	if user.Header.Get("Authorization") != "Bearer token" || user.Header.Get(HeaderCaller) != "" {
		t.Fatalf("user forward = %v", user.Header)
	}
}

// A node joined without the PAT sends none on its own peer calls.
func TestNodeWithoutThePATSendsNoBearer(t *testing.T) {
	cfg := config.Config{PATToken: "own-token", PATTokenSHA256: []string{config.PATSHA256("cluster-pat")}}
	if u := newUpgradeNode(cfg, "w1", false, nil); u.patToken != "" {
		t.Fatalf("upgrade node bearer = %q", u.patToken)
	}
	cfg.PATToken = "cluster-pat"
	if u := newUpgradeNode(cfg, "w1", false, nil); u.patToken != "cluster-pat" {
		t.Fatalf("a node that holds the PAT lost it: %q", u.patToken)
	}
}
