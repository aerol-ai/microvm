package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/sandboxtoken"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// signingServer is a server's cluster: the FSM's signing record, its
// placements, and whether it leads.
type signingServer struct {
	*cluster.Noop
	mu         sync.Mutex
	rec        *cluster.ServerSigning
	allowed    bool
	leader     bool
	placements map[string]cluster.Placement
	writes     int
}

func newSigningServer(id string) *signingServer {
	return &signingServer{Noop: cluster.NewNoop(id, "http://"+id, ""), allowed: true, leader: true, placements: map[string]cluster.Placement{}}
}

func (c *signingServer) ServerSigningRecord() (cluster.ServerSigning, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rec == nil {
		return cluster.ServerSigning{}, false
	}
	return *c.rec, true
}

func (c *signingServer) ServerSigningAllowed() bool { return c.allowed }
func (c *signingServer) IsLeader() bool             { return c.leader }

func (c *signingServer) WriteServerSigning(_ context.Context, w cluster.ServerSigningWrite) (cluster.ServerSigning, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	switch {
	case c.rec == nil && len(w.Expect) == 0:
		rec := w.Signing
		c.rec = &rec
	case c.rec != nil && len(w.Expect) > 0 && string(w.Expect) == string(c.rec.Sealed):
		c.rec.Sealed = w.Signing.Sealed
	case c.rec != nil && len(w.Expect) == 0:
	default:
		return cluster.ServerSigning{}, cluster.ErrServerSigningConflict
	}
	return *c.rec, nil
}

func (c *signingServer) PlacementOf(id string) (cluster.Placement, bool) {
	p, ok := c.placements[id]
	return p, ok
}

// signingWorker is a worker's cluster: the feed and the two sign calls go
// to server, as the named node.
type signingWorker struct {
	*cluster.Noop
	server   *Service
	feedErr  error
	signErr  error
	fetches  int
	asServer bool
	// rewrite, when set, changes the claims on the way to the server, as a
	// server that signs something else would.
	rewrite func(sandboxtoken.Claims) sandboxtoken.Claims
}

func (c *signingWorker) FetchSigningKeys(context.Context) (cluster.SigningKeys, error) {
	c.fetches++
	if c.feedErr != nil {
		return cluster.SigningKeys{}, c.feedErr
	}
	return c.server.SigningKeysFeed()
}

func (c *signingWorker) SignSandboxToken(ctx context.Context, req cluster.SandboxTokenSignRequest) (cluster.SandboxTokenSignResponse, error) {
	if c.signErr != nil {
		return cluster.SandboxTokenSignResponse{}, c.signErr
	}
	if c.rewrite != nil {
		var claims sandboxtoken.Claims
		if err := json.Unmarshal(req.Claims, &claims); err != nil {
			return cluster.SandboxTokenSignResponse{}, err
		}
		req.Claims, _ = json.Marshal(c.rewrite(claims))
	}
	return c.server.SignSandboxTokenFor(ctx, c.SelfNodeID(), c.asServer, req.Claims)
}

func (c *signingWorker) SignIdentityToken(ctx context.Context, req cluster.IdentityTokenSignRequest) (cluster.IdentityTokenSignResponse, error) {
	resp, err := c.server.SignIdentityTokenFor(ctx, c.SelfNodeID(), c.asServer, req)
	if errors.Is(err, ErrIdentityRoleRemoved) {
		return resp, cluster.ErrIdentityRoleGone
	}
	return resp, err
}

// signingPair is a server and a worker of one cluster: one server key ring,
// the server's record written by its upkeep.
func signingPair(t *testing.T) (server, worker *Service, srv *signingServer, wk *signingWorker, st *store.Store) {
	t.Helper()
	server, _, _ = testTokenService(t, time.Hour)
	worker, st, _ = testTokenService(t, time.Hour)
	worker.cipher = server.cipher
	server.cfg.EnableCluster, worker.cfg.EnableCluster = true, true
	srv = newSigningServer("srv-1")
	server.AttachCluster(srv)
	wk = &signingWorker{Noop: cluster.NewNoop("wkr-1", "http://wkr-1", ""), server: server}
	worker.AttachCluster(wk)
	return server, worker, srv, wk, st
}

func turnOnServerSigning(t *testing.T, server *Service, at time.Time) {
	t.Helper()
	server.serverSigning.now = func() time.Time { return at.Add(-serverSigningLead) }
	if err := server.UpkeepServerSigning(context.Background()); err != nil {
		t.Fatalf("upkeep: %v", err)
	}
}

// The leader writes the record once the active version allows it, sealed
// with the ring; Since lies serverSigningLead ahead; a ring rotation
// reseals it; another server writes nothing.
func TestUpkeepServerSigning(t *testing.T) {
	server, _, srv, _, _ := signingPair(t)
	ctx := context.Background()
	srv.allowed = false
	if err := server.UpkeepServerSigning(ctx); err != nil || srv.rec != nil {
		t.Fatalf("before the version: %v %+v", err, srv.rec)
	}
	srv.allowed = true
	now := time.Unix(1_800_000_000, 0)
	server.serverSigning.now = func() time.Time { return now }
	if err := server.UpkeepServerSigning(ctx); err != nil || srv.rec == nil {
		t.Fatalf("upkeep: %v", err)
	}
	if srv.rec.SinceUnixNano != now.Add(serverSigningLead).UnixNano() {
		t.Fatalf("since %d", srv.rec.SinceUnixNano)
	}
	if seed, err := server.cipher.DecryptWithAAD(srv.rec.Sealed, serverSigningAAD); err != nil || len(seed) != secrets.ServerSeedSize {
		t.Fatalf("seed: %v", err)
	}
	if err := server.UpkeepServerSigning(ctx); err != nil || srv.writes != 1 {
		t.Fatalf("a second pass wrote: %d %v", srv.writes, err)
	}
	follower, _, _ := testTokenService(t, time.Hour)
	follower.cipher = server.cipher
	fsrv := newSigningServer("srv-2")
	fsrv.leader = false
	follower.AttachCluster(fsrv)
	if err := follower.UpkeepServerSigning(ctx); err != nil || fsrv.writes != 0 {
		t.Fatal("a follower wrote")
	}
	// Rotate the ring: the record moves onto the new key, Since kept.
	before := append([]byte(nil), srv.rec.Sealed...)
	rotateTestRing(t, server.cipher)
	if err := server.UpkeepServerSigning(ctx); err != nil || string(srv.rec.Sealed) == string(before) || srv.rec.SinceUnixNano != now.Add(serverSigningLead).UnixNano() {
		t.Fatalf("reseal: %v", err)
	}
}

// rotateTestRing makes a new current key, keeping the old one to open with.
func rotateTestRing(t *testing.T, c *secrets.Cipher) {
	t.Helper()
	old := c.CurrentKeyID()
	keys := []secrets.RingKey{{ID: old}, {ID: old + 1, Key: []byte(strings.Repeat("k", 32)), Current: true}}
	if err := c.SetRing(keys); err != nil {
		t.Fatalf("SetRing: %v", err)
	}
}

// A server signs a sandbox token with the servers' key once servers sign,
// and every node checks it; a token signed with the ring counts only if it
// was issued before Since.
func TestSandboxTokensOnceServersSign(t *testing.T) {
	server, worker, srv, wk, st := signingPair(t)
	ctx := teamCtx("payments")
	seedTokenSandbox(t, st, "sb-1", "team:payments", models.SandboxStatusStarted)
	srv.placements["sb-1"] = cluster.Placement{SandboxID: "sb-1", OwnerNodeID: "wkr-1", OwnerRef: "team:payments"}
	base := time.Unix(1_800_000_000, 0)
	setSandboxTokenClock(t, base)

	// Before: the worker signs with the ring, everyone checks it.
	legacy, err := worker.IssueSandboxToken(ctx, "sb-1", models.CreateSandboxTokenRequest{ExpiresIn: "30m"})
	if err != nil {
		t.Fatal(err)
	}
	if c, err := server.VerifySandboxToken(legacy.Token); err != nil || c.KeyID&secrets.ServerKeyIDBit != 0 {
		t.Fatalf("legacy before = %+v %v", c, err)
	}

	// The record: Since is a minute from now.
	turnOnServerSigning(t, server, base.Add(time.Minute))
	worker.serverSigning.mirror = nil
	signed, err := worker.IssueSandboxToken(ctx, "sb-1", models.CreateSandboxTokenRequest{ExpiresIn: "30m"})
	if err != nil {
		t.Fatalf("issue through a server: %v", err)
	}
	for name, svc := range map[string]*Service{"server": server, "worker": worker} {
		c, err := svc.VerifySandboxToken(signed.Token)
		if err != nil || c.KeyID&secrets.ServerKeyIDBit == 0 || c.SandboxID != "sb-1" {
			t.Fatalf("%s checks the server-signed token: %+v %v", name, c, err)
		}
		// The ring token issued before Since still counts.
		if _, err := svc.VerifySandboxToken(legacy.Token); err != nil {
			t.Fatalf("%s: legacy issued before Since = %v", name, err)
		}
	}
	// A ring token issued at or after Since does not, wherever it is checked.
	setSandboxTokenClock(t, base.Add(2*time.Minute))
	late, _, err := sandboxtoken.Sign(worker.cipher, sandboxtoken.Claims{TokenID: mustTokenID(t), SandboxID: "sb-1", Owner: "team:payments",
		IssuedAt: base.Add(2 * time.Minute).Unix(), ExpiresAt: base.Add(30 * time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	for name, svc := range map[string]*Service{"server": server, "worker": worker} {
		if _, err := svc.VerifySandboxToken(late); !errors.Is(err, sandboxtoken.ErrInvalidSignature) {
			t.Fatalf("%s: a ring token issued after Since = %v", name, err)
		}
	}
	// A worker that cannot read the feed takes no ring token, and issues none.
	worker.serverSigning.mirror = nil
	wk.feedErr = errors.New("server tier down")
	if _, err := worker.VerifySandboxToken(legacy.Token); !errors.Is(err, sandboxtoken.ErrInvalidSignature) {
		t.Fatalf("legacy with no feed = %v", err)
	}
	if _, err := worker.IssueSandboxToken(ctx, "sb-1", models.CreateSandboxTokenRequest{ExpiresIn: "30m"}); !errors.Is(err, ErrSandboxTokensUnavailable) {
		t.Fatalf("issue with no feed = %v", err)
	}
}

func mustTokenID(t *testing.T) string {
	t.Helper()
	id, err := sandboxtoken.NewTokenID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A server signs only for the sandbox's owner node, only the owner the
// sandbox has, issued now, for no longer than it allows.
func TestSignSandboxTokenForChecks(t *testing.T) {
	server, _, srv, _, _ := signingPair(t)
	ctx := context.Background()
	base := time.Unix(1_800_000_000, 0)
	setSandboxTokenClock(t, base)
	claims := func(mut func(*sandboxtoken.Claims)) []byte {
		c := sandboxtoken.Claims{Version: 1, TokenID: mustTokenID(t), SandboxID: "sb-1", Owner: "team:payments",
			IssuedAt: base.Unix(), ExpiresAt: base.Add(30 * time.Minute).Unix()}
		if mut != nil {
			mut(&c)
		}
		raw, _ := jsonMarshal(c)
		return raw
	}
	if _, err := server.SignSandboxTokenFor(ctx, "wkr-1", false, claims(nil)); !errors.Is(err, ErrServerSigningOff) {
		t.Fatalf("no record = %v", err)
	}
	turnOnServerSigning(t, server, base)
	srv.placements["sb-1"] = cluster.Placement{SandboxID: "sb-1", OwnerNodeID: "wkr-1", OwnerRef: "team:payments"}
	srv.placements["sb-gone"] = cluster.Placement{SandboxID: "sb-gone", OwnerNodeID: "wkr-1", State: cluster.PlacementStateDeleting}
	for name, tc := range map[string]struct {
		peer   string
		server bool
		raw    []byte
		want   error
	}{
		"its owner":               {"wkr-1", false, claims(nil), nil},
		"a server":                {"srv-2", true, claims(nil), nil},
		"another node":            {"wkr-2", false, claims(nil), ErrSignNotOwner},
		"no peer":                 {"", false, claims(nil), ErrSignNotOwner},
		"another owner":           {"wkr-1", false, claims(func(c *sandboxtoken.Claims) { c.Owner = "team:other" }), ErrSignNotOwner},
		"an unknown sandbox":      {"wkr-1", false, claims(func(c *sandboxtoken.Claims) { c.SandboxID = "sb-x" }), store.ErrNotFound},
		"a sandbox being deleted": {"wkr-1", false, claims(func(c *sandboxtoken.Claims) { c.SandboxID = "sb-gone" }), store.ErrNotFound},
		"issued in the future":    {"wkr-1", false, claims(func(c *sandboxtoken.Claims) { c.IssuedAt += 120; c.ExpiresAt += 120 }), ErrSandboxTokenInvalid},
		"issued long ago":         {"wkr-1", false, claims(func(c *sandboxtoken.Claims) { c.IssuedAt -= 120 }), ErrSandboxTokenInvalid},
		"lives too long":          {"wkr-1", false, claims(func(c *sandboxtoken.Claims) { c.ExpiresAt = c.IssuedAt + 7200 }), ErrSandboxTokenInvalid},
		"an unknown field":        {"wkr-1", false, []byte(`{"v":1,"x":1}`), ErrSandboxTokenInvalid},
		"no token id":             {"wkr-1", false, claims(func(c *sandboxtoken.Claims) { c.TokenID = "" }), ErrSandboxTokenInvalid},
	} {
		resp, err := server.SignSandboxTokenFor(ctx, tc.peer, tc.server, tc.raw)
		if tc.want == nil {
			if err != nil || resp.KeyID&secrets.ServerKeyIDBit == 0 {
				t.Errorf("%s: %+v %v", name, resp, err)
			}
			continue
		}
		if !errors.Is(err, tc.want) {
			t.Errorf("%s = %v, want %v", name, err, tc.want)
		}
	}
}

// The feed mirror reads the servers once, refreshes in the background,
// and reads again for a key it does not know at most once a window.
func TestSigningKeyMirror(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	reads := 0
	feed := cluster.SigningKeys{SinceUnixNano: 5, TokenKeys: map[uint32][]byte{secrets.ServerKeyIDBit | 1: make([]byte, 32), 7: make([]byte, 32), secrets.ServerKeyIDBit | 2: []byte("short")}}
	var fail error
	m := &signingKeyMirror{fetch: func(context.Context) (cluster.SigningKeys, error) { reads++; return feed, fail }, now: func() time.Time { return now }}
	known, since, pub := m.state(secrets.ServerKeyIDBit | 1)
	if !known || since != 5 || pub == nil || reads != 1 {
		t.Fatalf("first read: %v %d %v %d", known, since, pub, reads)
	}
	if m.keys[7] != nil || m.keys[secrets.ServerKeyIDBit|2] != nil {
		t.Fatal("kept a ring id or a short key")
	}
	m.state(secrets.ServerKeyIDBit | 9)
	m.state(secrets.ServerKeyIDBit | 9)
	if reads != 1 {
		t.Fatalf("unknown key inside the window read %d times", reads)
	}
	now = now.Add(signingKeysRetryWait)
	m.state(secrets.ServerKeyIDBit | 9)
	if reads != 2 {
		t.Fatalf("unknown key after the window: %d reads", reads)
	}
	// A server behind the others (Since 0) never takes the mode back.
	feed.SinceUnixNano = 0
	now = now.Add(signingKeysRetryWait)
	if _, since, _ := m.state(secrets.ServerKeyIDBit | 9); since != 5 {
		t.Fatalf("since went back to %d", since)
	}
	// A failed read keeps what is known.
	fail = errors.New("down")
	now = now.Add(signingKeysRetryWait)
	if known, since, _ := m.state(secrets.ServerKeyIDBit | 9); !known || since != 5 {
		t.Fatal("a failed read lost the state")
	}
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// The cutover is exact: a token signed with the ring and issued in the
// second before Since counts, one issued at Since does not.
func TestRingTokensAroundTheCutover(t *testing.T) {
	server, worker, _, _, _ := signingPair(t)
	since := time.Unix(1_800_000_100, 0)
	turnOnServerSigning(t, server, since)
	ring := func(iat time.Time) string {
		raw, _, err := sandboxtoken.Sign(worker.cipher, sandboxtoken.Claims{TokenID: mustTokenID(t), SandboxID: "sb-1", Owner: "team:a",
			IssuedAt: iat.Unix(), ExpiresAt: iat.Add(10 * time.Minute).Unix()})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	setSandboxTokenClock(t, since.Add(time.Minute))
	before, at := ring(since.Add(-time.Second)), ring(since)
	for name, svc := range map[string]*Service{"server": server, "worker": worker} {
		if _, err := svc.VerifySandboxToken(before); err != nil {
			t.Errorf("%s: issued the second before Since = %v", name, err)
		}
		if _, err := svc.VerifySandboxToken(at); !errors.Is(err, sandboxtoken.ErrInvalidSignature) {
			t.Errorf("%s: issued at Since = %v", name, err)
		}
	}
}

// A brief server outage does not stop tokens already issued: a worker that
// has read the feed keeps checking them with what it read. Only a worker
// that never read it (it restarted during the outage) refuses them until
// the servers answer, and then takes them again.
func TestTokensAcrossAServerOutage(t *testing.T) {
	server, worker, srv, wk, st := signingPair(t)
	seedTokenSandbox(t, st, "sb-1", "team:payments", models.SandboxStatusStarted)
	srv.placements["sb-1"] = cluster.Placement{SandboxID: "sb-1", OwnerNodeID: "wkr-1", OwnerRef: "team:payments"}
	base := time.Unix(1_800_000_000, 0)
	setSandboxTokenClock(t, base)
	old, err := worker.IssueSandboxToken(teamCtx("payments"), "sb-1", models.CreateSandboxTokenRequest{ExpiresIn: "30m"})
	if err != nil {
		t.Fatal(err)
	}
	turnOnServerSigning(t, server, base.Add(time.Minute))
	worker.serverSigning.mirror = nil
	signed, err := worker.IssueSandboxToken(teamCtx("payments"), "sb-1", models.CreateSandboxTokenRequest{ExpiresIn: "30m"})
	if err != nil {
		t.Fatal(err)
	}
	// The servers go away; the worker's copy of the feed is still good.
	wk.feedErr = errors.New("server tier down")
	worker.serverSigning.mirror.fetchedAt = time.Time{}
	for name, tok := range map[string]string{"server-signed": signed.Token, "ring-signed before Since": old.Token} {
		if _, err := worker.VerifySandboxToken(tok); err != nil {
			t.Errorf("during the outage, %s = %v", name, err)
		}
	}
	// A worker that restarted during the outage knows nothing yet.
	worker.serverSigning.mirror = nil
	for name, tok := range map[string]string{"server-signed": signed.Token, "ring-signed before Since": old.Token} {
		if _, err := worker.VerifySandboxToken(tok); !errors.Is(err, sandboxtoken.ErrInvalidSignature) {
			t.Errorf("restarted during the outage, %s = %v", name, err)
		}
	}
	// The servers answer again (after the retry wait): both work.
	wk.feedErr = nil
	worker.serverSigning.mirror.triedAt = time.Time{}
	for name, tok := range map[string]string{"server-signed": signed.Token, "ring-signed before Since": old.Token} {
		if _, err := worker.VerifySandboxToken(tok); err != nil {
			t.Errorf("after the outage, %s = %v", name, err)
		}
	}
}

// The owner hands out only a token for the claims it asked for: one a
// server signed for other claims is refused.
func TestOwnerRefusesATokenForOtherClaims(t *testing.T) {
	server, worker, srv, wk, st := signingPair(t)
	seedTokenSandbox(t, st, "sb-1", "team:payments", models.SandboxStatusStarted)
	srv.placements["sb-1"] = cluster.Placement{SandboxID: "sb-1", OwnerNodeID: "wkr-1", OwnerRef: "team:payments"}
	base := time.Unix(1_800_000_000, 0)
	setSandboxTokenClock(t, base)
	turnOnServerSigning(t, server, base.Add(time.Minute))
	wk.rewrite = func(c sandboxtoken.Claims) sandboxtoken.Claims {
		c.TokenID = mustTokenID(t)
		return c
	}
	if _, err := worker.IssueSandboxToken(teamCtx("payments"), "sb-1", models.CreateSandboxTokenRequest{ExpiresIn: "30m"}); err == nil {
		t.Fatal("the owner handed out a token for other claims")
	}
	wk.rewrite = nil
	if _, err := worker.IssueSandboxToken(teamCtx("payments"), "sb-1", models.CreateSandboxTokenRequest{ExpiresIn: "30m"}); err != nil {
		t.Fatalf("the claims it asked for: %v", err)
	}
	wk.signErr = errors.New("no server answered")
	if _, err := worker.IssueSandboxToken(teamCtx("payments"), "sb-1", models.CreateSandboxTokenRequest{ExpiresIn: "30m"}); err == nil {
		t.Fatal("issued with no server to sign")
	}
}
