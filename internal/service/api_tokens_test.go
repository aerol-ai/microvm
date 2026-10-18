package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
)

// tokenSvcNow is the service's token clock in these tests. It follows the
// real clock (to the second, as the store keeps it) rather than a fixed date:
// some cases hand a minted token to an authenticator that reads the real
// clock, and a fixed date turns those into failures the day it passes.
var tokenSvcNow = time.Now().UTC().Truncate(time.Second)

func newTokenService(t *testing.T, identityOn bool) *Service {
	t.Helper()
	svc := &Service{
		cfg:    config.Config{IdentityEnabled: identityOn, TokenMaxTTL: 365 * 24 * time.Hour},
		store:  openSealTestStore(t),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	svc.apiTokenClock = func() time.Time { return tokenSvcNow }
	return svc
}

func adminCtx() context.Context {
	return controlplane.ContextWithAccess(context.Background(), controlplane.OperatorAccess())
}

func createReq(name, role, team, ttl string) models.CreateAPITokenRequest {
	return models.CreateAPITokenRequest{Name: name, Role: role, Team: team, ExpiresIn: ttl}
}

// TestCreateAPITokenValidation is the input table (§5.4, finding 3.6): every
// refusal is ErrAPITokenInvalid naming the field, and auditor or admin
// bound to one team is refused (Role.RequiresFleet).
func TestCreateAPITokenValidation(t *testing.T) {
	svc := newTokenService(t, true)
	svc.cfg.TokenMaxTTL = 90 * 24 * time.Hour
	cases := []struct {
		name string
		req  models.CreateAPITokenRequest
		want string
	}{
		{"empty name", createReq("", "runner", "payments", "30d"), "name"},
		{"bad name", createReq("ci deploy", "runner", "payments", "30d"), "name"},
		{"long name", createReq(strings.Repeat("a", 65), "runner", "payments", "30d"), "name"},
		{"no role", createReq("ci", "", "payments", "30d"), "role"},
		{"bad role", createReq("ci", "owner", "payments", "30d"), "role"},
		{"no team", createReq("ci", "runner", "", "30d"), "team is required"},
		{"bad team", createReq("ci", "runner", "Payments", "30d"), "team must be"},
		{"auditor on one team", createReq("ci", "auditor", "payments", "30d"), "role auditor must be bound to every team"},
		{"admin on one team", createReq("ci", "admin", "payments", "30d"), "role admin must be bound to every team"},
		{"no expiry", createReq("ci", "runner", "payments", ""), "expires_in is required"},
		{"bad expiry", createReq("ci", "runner", "payments", "forever"), "expires_in must be"},
		{"negative expiry", createReq("ci", "runner", "payments", "-1h"), "expires_in must be"},
		{"over the max", createReq("ci", "runner", "payments", "91d"), "longer than this server's maximum of 2160h0m0s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateAPIToken(adminCtx(), tc.req)
			if !errors.Is(err, ErrAPITokenInvalid) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want invalid naming %q", err, tc.want)
			}
		})
	}
	// The default cap applies when the config has none.
	svc.cfg.TokenMaxTTL = 0
	if _, err := svc.CreateAPIToken(adminCtx(), createReq("ci", "runner", "payments", "366d")); !errors.Is(err, ErrAPITokenInvalid) {
		t.Fatalf("default cap: %v", err)
	}
	if svc.tokenMaxTTL() != 365*24*time.Hour {
		t.Fatal("the default cap is 365 days")
	}
}

// TestAPITokenLifecycleSingleNode: on a single node a create is stored in
// SQLite and in memory, the plaintext is returned once and authenticates,
// a duplicate name is 409, revoke is idempotent, and a restart loads the
// tokens back.
func TestAPITokenLifecycleSingleNode(t *testing.T) {
	svc := newTokenService(t, true)
	ctx := adminCtx()
	if err := svc.StartAPITokens(context.Background()); err != nil {
		t.Fatal(err)
	}
	created, err := svc.CreateAPIToken(ctx, createReq(" ci-deploy ", " runner ", "payments", "90d"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Token, identitywire.APITokenPrefix) || created.ID == "" || created.Team != "payments" ||
		created.CreatedBy != "operator" || !created.ExpiresAt.Equal(tokenSvcNow.Add(90*24*time.Hour)) || created.Expired {
		t.Fatalf("created = %+v", created)
	}
	tok, err := identitywire.ParseAPIToken(created.Token)
	if err != nil || tok.ID != created.ID {
		t.Fatalf("the returned token parses to its id: %+v %v", tok, err)
	}
	// Only the hash is stored.
	rows, _ := svc.store.ListAPITokens(context.Background())
	if len(rows) != 1 || bytes.Contains(rows[0].SecretHash, []byte(tok.Secret)) {
		t.Fatal("the store holds the hash, never the secret")
	}
	// The token authenticates through the request-path index.
	auth := identity.NewTokenAuthenticator(svc.APITokenLookup(), nil)
	access, matched, err := auth.Authenticate(httptest.NewRequest("GET", "/v1/sandboxes", nil), created.Token)
	if err != nil || !matched || access.Principal.ID != created.ID || access.Team() != "payments" {
		t.Fatalf("authenticate the new token: %+v %v %v", access, matched, err)
	}
	// Idempotency: the same create again is a 409 and returns no secret.
	if _, err := svc.CreateAPIToken(ctx, createReq("ci-deploy", "viewer", "payments", "30d")); !errors.Is(err, ErrAPITokenNameTaken) {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := svc.CreateAPIToken(ctx, createReq("ci-deploy", "viewer", "checkout", "30d")); err != nil {
		t.Fatalf("same name, other team: %v", err)
	}
	list, err := svc.ListAPITokens(ctx)
	if err != nil || len(list.Tokens) != 2 {
		t.Fatalf("list = %+v %v", list, err)
	}
	// A restart loads what is stored.
	restarted := &Service{cfg: svc.cfg, store: svc.store}
	if err := restarted.StartAPITokens(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, found, fresh := restarted.APITokenLookup().LookupToken(created.ID); !found || !fresh {
		t.Fatal("a restart loads the tokens into memory")
	}
	// Revoke: immediate, and 204 again when already gone.
	for i := 0; i < 2; i++ {
		if err := svc.RevokeAPIToken(ctx, created.ID); err != nil {
			t.Fatalf("revoke %d: %v", i, err)
		}
	}
	if _, found, _ := svc.APITokenLookup().LookupToken(created.ID); found {
		t.Fatal("a revoke takes effect at once on a single node")
	}
	if _, _, err := auth.Authenticate(httptest.NewRequest("GET", "/", nil), created.Token); err == nil {
		t.Fatal("a revoked token must be refused")
	}
	if err := svc.RevokeAPIToken(ctx, "avm_not-an-id"); !errors.Is(err, ErrAPITokenInvalid) {
		t.Fatalf("a malformed id is refused, never silently revoked: %v", err)
	}
	// Listing flags expired tokens without removing them.
	svc.apiTokenClock = func() time.Time { return tokenSvcNow.Add(31 * 24 * time.Hour) }
	list, _ = svc.ListAPITokens(ctx)
	if len(list.Tokens) != 1 || !list.Tokens[0].Expired {
		t.Fatalf("expired flag: %+v", list.Tokens)
	}
}

func TestAPITokenCreator(t *testing.T) {
	if got := apiTokenCreator(context.Background()); got != "system:daemon" {
		t.Fatalf("no caller = %q", got)
	}
	if got := apiTokenCreator(controlplane.ContextWithSystemCaller(context.Background(), "bootstrap")); got != "system:bootstrap" {
		t.Fatalf("system caller = %q", got)
	}
	admin := controlplane.TokenAccess("tok_7Hq2aBcDeFgH", "root", controlplane.RoleAdmin, controlplane.FleetTeam, tokenSvcNow)
	if got := apiTokenCreator(controlplane.ContextWithAccess(context.Background(), admin)); got != "tok_7Hq2aBcDeFgH" {
		t.Fatalf("token caller = %q", got)
	}
}

// repeatReader serves the same bytes again and again: every token minted
// from it is identical, the way a broken entropy source would mint them.
type repeatReader struct{ chunk []byte }

func (r repeatReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		n += copy(p[n:], r.chunk)
	}
	return n, nil
}

// TestCreateAPITokenIDCollision: a colliding id is re-minted, and an
// entropy source that only ever repeats fails the create without writing.
func TestCreateAPITokenIDCollision(t *testing.T) {
	svc := newTokenService(t, true)
	ctx := adminCtx()
	same := bytes.Repeat([]byte{7}, 64)
	other := bytes.Repeat([]byte{9}, 64)
	svc.apiTokenEntropy = bytes.NewReader(append(append(append([]byte{}, same...), same...), other...))
	first, err := svc.CreateAPIToken(ctx, createReq("one", "runner", "payments", "1d"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.CreateAPIToken(ctx, createReq("two", "runner", "payments", "1d"))
	if err != nil || second.ID == first.ID {
		t.Fatalf("collision re-mint: %+v %v", second, err)
	}
	svc.apiTokenEntropy = repeatReader{chunk: same}
	if _, err := svc.CreateAPIToken(ctx, createReq("three", "runner", "payments", "1d")); !errors.Is(err, ErrAPITokensUnavailable) {
		t.Fatalf("endless collisions: %v", err)
	}
	svc.apiTokenEntropy = bytes.NewReader(nil)
	if _, err := svc.CreateAPIToken(ctx, createReq("four", "runner", "payments", "1d")); err == nil || !strings.Contains(err.Error(), "mint") {
		t.Fatalf("no entropy: %v", err)
	}
	if list, _ := svc.ListAPITokens(ctx); len(list.Tokens) != 2 {
		t.Fatalf("failed creates wrote nothing: %d tokens", len(list.Tokens))
	}
}

func TestAPITokenSweepSingleNode(t *testing.T) {
	svc := newTokenService(t, true)
	ctx := adminCtx()
	old, _ := svc.CreateAPIToken(ctx, createReq("old", "viewer", "payments", "1d"))
	recent, _ := svc.CreateAPIToken(ctx, createReq("recent", "viewer", "payments", "10d"))
	// 32 days on: "old" expired 31 days ago, "recent" 22 days ago.
	svc.apiTokenClock = func() time.Time { return tokenSvcNow.Add(32 * 24 * time.Hour) }
	if n := svc.SweepExpiredAPITokens(ctx); n != 1 {
		t.Fatalf("swept %d, want 1", n)
	}
	if _, found, _ := svc.APITokenLookup().LookupToken(old.ID); found {
		t.Fatal("the swept token leaves memory too")
	}
	list, _ := svc.ListAPITokens(ctx)
	if len(list.Tokens) != 1 || list.Tokens[0].ID != recent.ID || !list.Tokens[0].Expired {
		t.Fatalf("an expired token stays listed for 30 days: %+v", list.Tokens)
	}
	_ = svc.store.Close()
	if n := svc.SweepExpiredAPITokens(ctx); n != 0 {
		t.Fatal("a failed sweep deletes nothing")
	}
	if _, err := svc.CreateAPIToken(ctx, createReq("late", "viewer", "payments", "1d")); err == nil {
		t.Fatal("a create on a broken store fails")
	}
	if err := svc.RevokeAPIToken(ctx, recent.ID); err == nil {
		t.Fatal("a revoke on a broken store fails")
	}
	if _, err := svc.ListAPITokens(ctx); err == nil {
		t.Fatal("a list on a broken store fails")
	}
}

// fakeTokenCluster stands in for the replicated store: a Raft server when
// server is true (LookupToken, sweep), otherwise a worker (the feed).
type fakeTokenCluster struct {
	*cluster.Noop
	mu       sync.Mutex
	rows     map[string]identity.TokenRecord
	writes   []cluster.APITokenWriteRequest
	writeErr []error // popped one per write
	listErr  error
	swept    int
}

func (f *fakeTokenCluster) WriteAPIToken(_ context.Context, req cluster.APITokenWriteRequest) (cluster.APITokenWriteResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, req)
	if len(f.writeErr) > 0 {
		err := f.writeErr[0]
		f.writeErr = f.writeErr[1:]
		if err != nil {
			return cluster.APITokenWriteResponse{}, err
		}
	}
	if req.Delete {
		delete(f.rows, req.ID)
		return cluster.APITokenWriteResponse{}, nil
	}
	rec := req.Token
	rec.Version = uint64(len(f.writes))
	f.rows[rec.ID] = rec
	return cluster.APITokenWriteResponse{Token: rec}, nil
}

func (f *fakeTokenCluster) ListAPITokens(context.Context) ([]identity.TokenRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []identity.TokenRecord
	for _, r := range f.rows {
		out = append(out, r)
	}
	return out, nil
}

type fakeTokenServer struct{ *fakeTokenCluster }

func (f fakeTokenServer) LookupToken(id string) (identity.TokenRecord, bool, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rows[id]
	return r, ok, true
}

func (f fakeTokenServer) SweepExpiredAPITokens(context.Context, time.Time) (int, error) {
	f.swept++
	return 1, nil
}

type fakeTokenWorker struct{ *fakeTokenCluster }

func (f fakeTokenWorker) FetchTokenChanges(context.Context, uint64) ([]byte, error) {
	return nil, identity.ErrTokensUnchanged
}

func (f fakeTokenWorker) FetchTokenPage(context.Context, string, int) ([]byte, error) {
	recs, _ := f.ListAPITokens(context.Background())
	return json.Marshal(identity.TokenPage{Tokens: recs, Version: 1})
}

func newFakeTokenCluster() *fakeTokenCluster {
	return &fakeTokenCluster{Noop: cluster.NewNoop("node-a", "http://node-a", ""), rows: map[string]identity.TokenRecord{}}
}

// TestAPITokenClusterBackend: in a cluster only the hash is proposed, the
// FSM's verdicts keep their meaning, and anything else is a 503 with the
// recovery hint.
func TestAPITokenClusterBackend(t *testing.T) {
	fc := newFakeTokenCluster()
	server := fakeTokenServer{fc}
	svc := newTokenService(t, true)
	svc.cfg.EnableCluster = true
	svc.cluster = server
	ctx := adminCtx()
	created, err := svc.CreateAPIToken(ctx, createReq("ci", "runner", "payments", "30d"))
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := identitywire.ParseAPIToken(created.Token)
	raw, _ := json.Marshal(fc.writes[0])
	if bytes.Contains(raw, []byte(tok.Secret)) || len(fc.writes[0].Token.SecretHash) != 32 {
		t.Fatal("the write proposes the hash, never the secret")
	}
	if svc.APITokenLookup() != identity.TokenLookup(server) {
		t.Fatal("a Raft server reads its own FSM")
	}
	if n := svc.SweepExpiredAPITokens(ctx); n != 1 || fc.swept != 1 {
		t.Fatalf("cluster sweep = %d (calls %d)", n, fc.swept)
	}

	cases := []struct {
		name string
		errs []error
		want error
	}{
		{"name taken", []error{cluster.ErrAPITokenNameTaken}, ErrAPITokenNameTaken},
		{"rolling upgrade", []error{cluster.ErrClusterVersion}, ErrAPITokenClusterVersion},
		{"leader lost", []error{errors.New("leadership lost while committing log")}, ErrAPITokensUnavailable},
		{"invalid", []error{identity.ErrInvalidTokenRecord}, ErrAPITokenInvalid},
	}
	for _, tc := range cases {
		fc.writeErr = tc.errs
		if _, err := svc.CreateAPIToken(ctx, createReq("x-"+strings.ReplaceAll(tc.name, " ", "-"), "runner", "payments", "1d")); !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	fc.writeErr = []error{cluster.ErrAPITokenIDTaken, nil}
	if _, err := svc.CreateAPIToken(ctx, createReq("retry", "runner", "payments", "1d")); err != nil {
		t.Fatalf("an id collision is re-minted: %v", err)
	}
	fc.writeErr = []error{errors.New("no leader")}
	if err := svc.RevokeAPIToken(ctx, created.ID); !errors.Is(err, ErrAPITokensUnavailable) {
		t.Fatalf("revoke without a leader: %v", err)
	}
	if err := svc.RevokeAPIToken(ctx, created.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	fc.listErr = errors.New("server tier down")
	if _, err := svc.ListAPITokens(ctx); !errors.Is(err, ErrAPITokensUnavailable) {
		t.Fatalf("list: %v", err)
	}
}

// TestStartAPITokensModes: identity off does nothing at all (L8); a worker
// starts its mirror and reads it; a cluster node with no replicated store
// refuses every token as stale rather than checking a node-local list.
func TestStartAPITokensModes(t *testing.T) {
	off := newTokenService(t, false)
	_ = off.store.Close() // any load would now fail
	if err := off.StartAPITokens(context.Background()); err != nil {
		t.Fatalf("identity off must not touch the store: %v", err)
	}

	broken := newTokenService(t, true)
	_ = broken.store.Close()
	if err := broken.StartAPITokens(context.Background()); err == nil {
		t.Fatal("a single node that cannot load its tokens fails the boot")
	}

	fc := newFakeTokenCluster()
	_, rec := func() (identitywire.APIToken, identity.TokenRecord) {
		tok, _ := identitywire.NewAPIToken(nil)
		h := tok.SecretHash()
		return tok, identity.TokenRecord{ID: tok.ID, Name: "w", Role: controlplane.RoleViewer, ExpiresAt: tokenSvcNow.Add(time.Hour), SecretHash: h[:]}
	}()
	fc.rows[rec.ID] = rec
	worker := newTokenService(t, true)
	worker.cfg.EnableCluster = true
	worker.cfg.IdentitySyncInterval = time.Hour
	worker.cluster = fakeTokenWorker{fc}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := worker.StartAPITokens(ctx); err != nil {
		t.Fatal(err)
	}
	if worker.apiTokenMirror == nil || worker.APITokenLookup() != identity.TokenLookup(worker.apiTokenMirror) {
		t.Fatal("a worker reads its token mirror")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, found, fresh := worker.APITokenLookup().LookupToken(rec.ID); found && fresh {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the mirror never synced")
		}
		time.Sleep(10 * time.Millisecond)
	}

	bare := newTokenService(t, true)
	bare.cfg.EnableCluster = true
	bare.cluster = cluster.NewNoop("n", "http://n", "")
	if err := bare.StartAPITokens(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, fresh := bare.APITokenLookup().LookupToken(rec.ID); fresh {
		t.Fatal("no replicated store: never fresh")
	}
	if _, err := bare.CreateAPIToken(adminCtx(), createReq("x", "runner", "payments", "1d")); !errors.Is(err, ErrAPITokensUnavailable) {
		t.Fatalf("create without a replicated store: %v", err)
	}
	if _, err := bare.ListAPITokens(adminCtx()); !errors.Is(err, ErrAPITokensUnavailable) {
		t.Fatalf("list without a replicated store: %v", err)
	}
	if err := bare.RevokeAPIToken(adminCtx(), rec.ID); !errors.Is(err, ErrAPITokensUnavailable) {
		t.Fatalf("revoke without a replicated store: %v", err)
	}
}

// The sweep loop runs once at start and stops with its context.
func TestRunAPITokenSweepStops(t *testing.T) {
	svc := newTokenService(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.runAPITokenSweep(ctx, time.Millisecond); close(done) }()
	time.Sleep(5 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the sweep loop did not stop")
	}
	if svc.apiTokenNow().IsZero() {
		t.Fatal("clock")
	}
	plain := &Service{}
	if time.Since(plain.apiTokenNow()) > time.Minute {
		t.Fatal("the default clock is time.Now")
	}
}

// TestAPITokenGauge is aerolvm_api_tokens{key=<role>} (§5.15): unexpired
// tokens by role on a node that holds the store, every role published
// (zeros included), recounted on its tick; a worker publishes nothing.
func TestAPITokenGauge(t *testing.T) {
	svc := newTokenService(t, true)
	if svc.apiTokenCounter() == nil {
		t.Fatal("a single node counts its own tokens")
	}
	ctx := adminCtx()
	for _, req := range []models.CreateAPITokenRequest{
		createReq("ci-a", "runner", "payments", "30d"),
		createReq("ci-b", "runner", "checkout", "30d"),
		createReq("scrape", "viewer", "*", "30d"),
	} {
		if _, err := svc.CreateAPIToken(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	// One more that has already expired: it is listed but not live.
	svc.apiTokenSet.Put(identity.TokenRecord{ID: "tok_expired", Role: controlplane.RoleAdmin, ExpiresAt: tokenSvcNow.Add(-time.Minute)})

	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.runAPITokenGauge(runCtx, svc.apiTokenCounter(), time.Millisecond); close(done) }()
	want := map[string]string{"viewer": "1", "runner": "2", "auditor": "0", "admin": "0"}
	deadline := time.Now().Add(5 * time.Second)
	for {
		ok := true
		for role, n := range want {
			if v := apiTokensByRole.Get(role); v == nil || v.String() != n {
				ok = false
			}
		}
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("aerolvm_api_tokens = %s, want %v", apiTokensByRole.String(), want)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	worker := newTokenService(t, true)
	worker.cfg.EnableCluster = true
	worker.cluster = fakeTokenWorker{newFakeTokenCluster()}
	if worker.apiTokenCounter() != nil {
		t.Fatal("a worker holds only a mirror and publishes no token count")
	}

	server := newTokenService(t, true)
	server.cfg.EnableCluster = true
	server.cluster = countingTokenServer{Noop: cluster.NewNoop("node-s", "http://node-s", "")}
	counter := server.apiTokenCounter()
	if counter == nil || counter.CountAPITokens(tokenSvcNow)[controlplane.RoleAuditor] != 3 {
		t.Fatal("a Raft server counts its FSM's tokens")
	}
}

// countingTokenServer stands in for a Raft server's CountAPITokens.
type countingTokenServer struct{ *cluster.Noop }

func (countingTokenServer) CountAPITokens(time.Time) map[controlplane.Role]int {
	return map[controlplane.Role]int{controlplane.RoleAuditor: 3}
}
