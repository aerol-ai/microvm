package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/sandboxtoken"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
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
func (c *signingServerCluster) ServerSigningGate(bool) cluster.ServerSigningGate {
	return cluster.ServerSigningGate{Allowed: true}
}
func (c *signingServerCluster) IsLeader() bool { return true }
func (c *signingServerCluster) WriteServerSigning(_ context.Context, w cluster.ServerSigningWrite, _ bool) (cluster.ServerSigning, error) {
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

// feedCluster is a worker's cluster: the feed says whether servers sign.
type feedCluster struct {
	*cluster.Noop
	since int64
	reads int
}

func (c *feedCluster) FetchSigningKeys(context.Context) (cluster.SigningKeys, error) {
	c.reads++
	return cluster.SigningKeys{SinceUnixNano: c.since}, nil
}

func (c *feedCluster) SignSandboxToken(context.Context, cluster.SandboxTokenSignRequest) (cluster.SandboxTokenSignResponse, error) {
	return cluster.SandboxTokenSignResponse{}, errors.New("not here")
}

func (c *feedCluster) SignIdentityToken(context.Context, cluster.IdentityTokenSignRequest) (cluster.IdentityTokenSignResponse, error) {
	return cluster.IdentityTokenSignResponse{}, errors.New("not here")
}

// Once servers sign, a create with a cloud identity that reaches a worker
// is one a server places; one a server already placed here, or with no
// identity, is not, and only a create with one reads the signing mode.
func TestIdentityCreateGoesToServer(t *testing.T) {
	worker := func(since int64) (*handlers, *feedCluster) {
		svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil, nil, nil, nil, nil)
		c := &feedCluster{Noop: cluster.NewNoop("wkr-1", "http://wkr-1", ""), since: since}
		svc.AttachCluster(c)
		return &handlers{deps: Deps{Service: svc}}, c
	}
	on, onFeed := worker(5)
	off, _ := worker(0)
	req := func(target string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, PathPrefix+"/sandboxes", nil)
		if target != "" {
			r.Header.Set(clustercreate.HeaderTarget, target)
		}
		return r
	}
	withID := models.CreateSandboxRequest{Image: "alpine", Identity: &models.IdentityRequest{RoleTag: "deploy"}}
	for name, tc := range map[string]struct {
		h    *handlers
		r    *http.Request
		req  models.CreateSandboxRequest
		want bool
	}{
		"identity, servers sign":  {on, req(""), withID, true},
		"identity, before":        {off, req(""), withID, false},
		"placed here by a server": {on, req("wkr-1"), withID, false},
		"no identity":             {on, req(""), models.CreateSandboxRequest{Image: "alpine"}, false},
	} {
		if got := tc.h.createGoesToServer(tc.r, tc.req); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
	fresh, freshFeed := worker(5)
	if fresh.createGoesToServer(req(""), models.CreateSandboxRequest{Image: "alpine"}); freshFeed.reads != 0 {
		t.Fatal("a create with no identity read the signing mode")
	}
	if !fresh.createGoesToServer(req(""), withID) || freshFeed.reads != 1 {
		t.Fatalf("a create with an identity read the mode %d times", freshFeed.reads)
	}
	_ = onFeed
}

// signingLeaderStub is a leading server for the operator's signing calls:
// the upgrade stub's routing and a signing record the gate holds back.
type signingLeaderStub struct {
	*upgradeStub
	rec    *cluster.ServerSigning
	forced bool
}

func (c *signingLeaderStub) ServerSigningRecord() (cluster.ServerSigning, bool) {
	if c.rec == nil {
		return cluster.ServerSigning{}, false
	}
	return *c.rec, true
}
func (c *signingLeaderStub) ServerSigningGate(force bool) cluster.ServerSigningGate {
	g := cluster.ServerSigningGate{ActiveFV: cluster.ServerSigningFSMOpsVersion, Waiting: []string{"wkr-quiet"}, Allowed: force}
	if !force {
		g.Reason = "these members report a version below 22, or none: wkr-quiet"
	}
	return g
}
func (c *signingLeaderStub) IsLeader() bool { return true }
func (c *signingLeaderStub) WriteServerSigning(_ context.Context, w cluster.ServerSigningWrite, force bool) (cluster.ServerSigning, error) {
	switch {
	case w.EndOldTokens:
		c.rec.OldTokensEndUnixNano = c.rec.SinceUnixNano + 1
	case c.rec == nil:
		c.forced = force
		rec := w.Signing
		c.rec = &rec
	}
	return *c.rec, nil
}

// The operator sees why servers do not sign yet and who holds it back,
// starts it anyway, and ends the old tokens; each call is audited.
func TestServerSigningOperatorRoutes(t *testing.T) {
	ciph, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(config.Config{EnableCluster: true}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil, nil, ciph, nil, nil)
	stub := &signingLeaderStub{upgradeStub: newUpgradeStub()}
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	call := func(method, path string) (int, upgradewire.ServerSigningStatus, string) {
		rr := httptest.NewRecorder()
		h.clusterServerSigning(rr, httptest.NewRequest(method, path, nil))
		var out upgradewire.ServerSigningStatus
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out, rr.Body.String()
	}
	code, st, _ := call(http.MethodGet, upgradewire.ClusterUpgradeSigningPath)
	if code != http.StatusOK || st.On || !strings.Contains(st.Blocked, "wkr-quiet") || len(st.Waiting) != 1 || st.NeedsFSMOpsVersion != cluster.ServerSigningFSMOpsVersion {
		t.Fatalf("status before = %d %+v", code, st)
	}
	if code, _, body := call(http.MethodPost, upgradewire.ClusterUpgradeSigningEndOldTokensPath); code != http.StatusConflict || !strings.Contains(body, "server_signing_off") {
		t.Fatalf("end before servers sign = %d %s", code, body)
	}
	code, st, _ = call(http.MethodPost, upgradewire.ClusterUpgradeSigningStartPath)
	if code != http.StatusOK || !st.On || st.Since == nil || st.Blocked != "" || !stub.forced {
		t.Fatalf("start = %d %+v forced %v", code, st, stub.forced)
	}
	code, st, _ = call(http.MethodPost, upgradewire.ClusterUpgradeSigningEndOldTokensPath)
	if code != http.StatusOK || st.OldTokensEnd == nil || !st.OldTokensEnd.After(*st.Since) {
		t.Fatalf("end = %d %+v", code, st)
	}
	// Not in cluster mode: the upgrade routes' 409.
	single := &handlers{deps: Deps{Service: service.New(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil, nil, ciph, nil, nil)}}
	rr := httptest.NewRecorder()
	single.clusterServerSigning(rr, httptest.NewRequest(http.MethodGet, upgradewire.ClusterUpgradeSigningPath, nil))
	if rr.Code != http.StatusConflict {
		t.Fatalf("single node = %d", rr.Code)
	}
}
