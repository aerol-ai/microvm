package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/clustercreate"
	"github.com/aerol-ai/microvm/pkg/sandboxtoken"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// signingServerCluster is a server's cluster with the signing record, one
// placement and an identity key set.
type signingServerCluster struct {
	*cluster.Noop
	rec  *cluster.ServerSigning
	p    cluster.Placement
	keys cloudidentity.KeySet
}

func (c *signingServerCluster) ServerSigningRecord() (cluster.ServerSigning, bool) {
	if c.rec == nil {
		return cluster.ServerSigning{}, false
	}
	return *c.rec, true
}
func (c *signingServerCluster) ServerSigningAllowed() bool { return true }
func (c *signingServerCluster) IsLeader() bool             { return true }
func (c *signingServerCluster) WriteServerSigning(_ context.Context, w cluster.ServerSigningWrite) (cluster.ServerSigning, error) {
	if c.rec == nil {
		rec := w.Signing
		c.rec = &rec
	}
	return *c.rec, nil
}
func (c *signingServerCluster) PlacementOf(id string) (cluster.Placement, bool) {
	return c.p, id == c.p.SandboxID
}
func (c *signingServerCluster) ReadIdentity(context.Context, cluster.IdentityReadRequest) (cluster.IdentityReadResponse, error) {
	keys := c.keys.Clone()
	return cluster.IdentityReadResponse{Keys: &keys}, nil
}

func signingHandlers(t *testing.T, on bool) (*handlers, *signingServerCluster) {
	t.Helper()
	ciph, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(config.Config{EnableCluster: true}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil, nil, ciph, nil, nil)
	c := &signingServerCluster{Noop: cluster.NewNoop("srv-1", "http://srv-1", ""),
		p:    cluster.Placement{SandboxID: "sb-1", OwnerNodeID: "wkr-1", OwnerRef: "team:a"},
		keys: cloudidentity.KeySet{Generation: 1, Keys: []cloudidentity.KeyRecord{{ID: "k1", SealedPrivate: []byte("sealed"), PublicJWK: json.RawMessage(`{}`)}}}}
	svc.AttachCluster(c)
	if on {
		if err := svc.UpkeepServerSigning(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	return &handlers{deps: Deps{Service: svc, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}, c
}

// The feed answers a server's public keys; the sign route signs only for
// the sandbox's owner node; the identity read gives a worker no sealed key
// once servers sign.
func TestServerSigningRoutes(t *testing.T) {
	h, _ := signingHandlers(t, true)
	rr := httptest.NewRecorder()
	h.clusterInternalSigningKeys(rr, asRolePeer(httptest.NewRequest(http.MethodGet, cluster.PublicInternalSigningKeysPath, nil), "wkr-1", cluster.JoinRoleWorker))
	var feed cluster.SigningKeys
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &feed) != nil || feed.SinceUnixNano == 0 || len(feed.TokenKeys) == 0 {
		t.Fatalf("feed = %d %s", rr.Code, rr.Body.String())
	}

	now := time.Now()
	claims, _ := json.Marshal(sandboxtoken.Claims{Version: 1, TokenID: "stk_" + strings.Repeat("a", 32), SandboxID: "sb-1", Owner: "team:a",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(10 * time.Minute).Unix()})
	sign := func(peer, role string, body []byte) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(cluster.SandboxTokenSignRequest{Claims: body})
		if body == nil {
			raw = []byte("{")
		}
		rr := httptest.NewRecorder()
		h.clusterInternalSandboxTokenSign(rr, asRolePeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalSandboxTokenSignPath, bytes.NewReader(raw)), peer, role))
		return rr
	}
	if rr := sign("wkr-1", cluster.JoinRoleWorker, claims); rr.Code != http.StatusOK {
		t.Fatalf("owner = %d %s", rr.Code, rr.Body.String())
	}
	if rr := sign("wkr-2", cluster.JoinRoleWorker, claims); rr.Code != http.StatusForbidden {
		t.Fatalf("another worker = %d %s", rr.Code, rr.Body.String())
	}
	if rr := sign("wkr-1", cluster.JoinRoleWorker, nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad body = %d", rr.Code)
	}
	if rr := sign("wkr-1", cluster.JoinRoleWorker, []byte(`{"v":1,"zz":1}`)); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad claims = %d", rr.Code)
	}

	read := func(peer, role string) cloudidentity.KeySet {
		rr := httptest.NewRecorder()
		body, _ := json.Marshal(cluster.IdentityReadRequest{Keys: true})
		h.clusterInternalIdentityRead(rr, asRolePeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalIdentityReadPath, bytes.NewReader(body)), peer, role))
		var resp cluster.IdentityReadResponse
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &resp) != nil || resp.Keys == nil {
			t.Fatalf("read = %d %s", rr.Code, rr.Body.String())
		}
		return *resp.Keys
	}
	if keys := read("wkr-1", cluster.JoinRoleWorker); len(keys.Keys[0].SealedPrivate) != 0 {
		t.Fatal("a worker read a sealed key")
	}
	off, _ := signingHandlers(t, false)
	h = off
	if keys := read("wkr-1", cluster.JoinRoleWorker); string(keys.Keys[0].SealedPrivate) != "sealed" {
		t.Fatal("before servers sign, a worker reads the keys it signs with")
	}
	if rr := sign("wkr-1", cluster.JoinRoleWorker, claims); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("sign with no record = %d", rr.Code)
	}
}

// Once servers sign, a create with a cloud identity is one a server
// places; one a server already placed here, or with no identity, is not.
func TestIdentityCreateGoesToServer(t *testing.T) {
	on, _ := signingHandlers(t, true)
	off, _ := signingHandlers(t, false)
	req := func(body, target string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, PathPrefix+"/sandboxes", strings.NewReader(body))
		if target != "" {
			r.Header.Set(clustercreate.HeaderTarget, target)
		}
		return r
	}
	withID := `{"image":"alpine","identity":{"role_tag":"deploy"}}`
	for name, tc := range map[string]struct {
		h    *handlers
		r    *http.Request
		want bool
	}{
		"identity, servers sign":  {on, req(withID, ""), true},
		"identity, before":        {off, req(withID, ""), false},
		"placed here by a server": {on, req(withID, "wkr-1"), false},
		"no identity":             {on, req(`{"image":"alpine"}`, ""), false},
		"a null identity":         {on, req(`{"image":"alpine","identity":null}`, ""), false},
		"not JSON":                {on, req(`{`, ""), false},
	} {
		if got := tc.h.identityCreateGoesToServer(tc.r); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
		// The handler still reads the whole body after the check.
		if b, _ := io.ReadAll(tc.r.Body); len(b) == 0 {
			t.Errorf("%s: body consumed", name)
		}
	}
}
