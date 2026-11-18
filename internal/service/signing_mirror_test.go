package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/sandboxtoken"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// ageMirror makes the worker's copy of the feed d old.
func ageMirror(t *testing.T, worker *Service, d time.Duration) {
	t.Helper()
	m := worker.serverSigning.mirror
	if m == nil {
		t.Fatal("no mirror")
	}
	m.mu.Lock()
	m.fetchedAt = time.Now().Add(-d)
	m.triedAt = time.Time{}
	m.mu.Unlock()
}

// A check made while the mirror's read is in flight waits for that read,
// and is answered from it.
func TestMirrorChecksWaitForTheReadInFlight(t *testing.T) {
	kid := secrets.ServerKeyIDBit | 1
	feed := cluster.SigningKeys{SinceUnixNano: 5, TokenKeys: map[uint32][]byte{kid: make([]byte, 32)}}
	started, release := make(chan struct{}), make(chan struct{})
	var reads atomic.Int32
	m := &signingKeyMirror{fetch: func(context.Context) (cluster.SigningKeys, error) {
		if reads.Add(1) == 1 {
			close(started)
		}
		<-release
		return feed, nil
	}}
	done := make(chan struct{})
	go func() { m.view(kid); close(done) }()
	<-started
	answered := make(chan mirrorView, 1)
	go func() { answered <- m.view(kid) }()
	select {
	case <-answered:
		t.Fatal("a check answered before the read in flight ended")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-done
	if v := <-answered; !v.mode.known || v.key == nil {
		t.Fatalf("the waiting check got %+v", v)
	}
	if n := reads.Load(); n != 1 {
		t.Fatalf("%d reads for two checks", n)
	}
}

// A waiting check gives up after the read's own timeout.
func TestMirrorWaitIsBounded(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	m := &signingKeyMirror{fetch: func(ctx context.Context) (cluster.SigningKeys, error) {
		<-block
		return cluster.SigningKeys{}, ctx.Err()
	}}
	m.inflight = make(chan struct{})
	start := time.Now()
	if v := m.view(0); v.mode.known {
		t.Fatalf("answered %+v with nothing read", v)
	}
	if d := time.Since(start); d < signingKeysFetchTimeout || d > signingKeysFetchTimeout+3*time.Second {
		t.Fatalf("waited %v", d)
	}
}

// A copy that says servers do not sign and is older than half the lead is
// read again before it answers: the record may be there now.
func TestStaleCopyIsReadAgainAfterTheRecord(t *testing.T) {
	server, worker, srv, _, st := signingPair(t)
	seedTokenSandbox(t, st, "sb-1", "team:a", models.SandboxStatusStarted)
	srv.placements["sb-1"] = cluster.Placement{SandboxID: "sb-1", OwnerNodeID: "wkr-1", OwnerRef: "team:a"}
	base := time.Unix(1_800_000_000, 0)
	setSandboxTokenClock(t, base)
	if _, err := worker.IssueSandboxToken(teamCtx("a"), "sb-1", models.CreateSandboxTokenRequest{ExpiresIn: "30m"}); err != nil {
		t.Fatal(err)
	}
	turnOnServerSigning(t, server, base.Add(time.Minute))
	ageMirror(t, worker, signingKeysStaleOff)
	now := base.Add(10 * time.Minute)
	setSandboxTokenClock(t, now)
	ring, _, _ := sandboxtoken.Sign(worker.cipher, sandboxtoken.Claims{TokenID: mustTokenID(t), SandboxID: "sb-1", Owner: "team:a",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix()})
	if _, err := worker.VerifySandboxToken(ring); !errors.Is(err, sandboxtoken.ErrInvalidSignature) {
		t.Fatalf("a ring token issued after Since, on an idle worker = %v", err)
	}
	ageMirror(t, worker, signingKeysStaleOff)
	worker.serverSigning.mirror.since = 0
	issued, err := worker.IssueSandboxToken(teamCtx("a"), "sb-1", models.CreateSandboxTokenRequest{ExpiresIn: "30m"})
	if err != nil {
		t.Fatal(err)
	}
	if c, err := server.VerifySandboxToken(issued.Token); err != nil || c.KeyID&secrets.ServerKeyIDBit == 0 {
		t.Fatalf("the idle worker's next token: %+v %v", c, err)
	}
	// The same stale copy on an owner sends no SSH key to a node.
	ageMirror(t, worker, signingKeysStaleOff)
	worker.serverSigning.mirror.since = 0
	if worker.KeepsSSHKeyFrom(false) {
		t.Fatal("an owner whose copy predates the record sends a node the SSH key")
	}
	// A copy younger than half the lead answers as it is.
	worker.serverSigning.mirror = nil
	turnOffSigningFor(t, worker)
	if !worker.KeepsSSHKeyFrom(false) {
		t.Fatal("a fresh copy that says servers do not sign was not taken")
	}
}

// An idle worker in a cluster whose servers do not sign reads the feed
// again, finds them still not signing, and goes on as before: it signs
// tokens itself and takes new ones.
func TestStaleCopyReadAgainWhileServersDoNotSign(t *testing.T) {
	server, worker, _, wk, st := signingPair(t)
	seedTokenSandbox(t, st, "sb-1", "team:a", models.SandboxStatusStarted)
	setSandboxTokenClock(t, time.Now())
	if _, err := worker.IssueSandboxToken(teamCtx("a"), "sb-1", models.CreateSandboxTokenRequest{ExpiresIn: "30m"}); err != nil {
		t.Fatal(err)
	}
	ageMirror(t, worker, 10*time.Minute)
	before := wk.fetches
	tok, err := worker.IssueSandboxToken(teamCtx("a"), "sb-1", models.CreateSandboxTokenRequest{ExpiresIn: "30m"})
	if err != nil {
		t.Fatalf("an idle worker could not sign while servers do not: %v", err)
	}
	if wk.fetches != before+1 {
		t.Fatalf("the stale copy was not read again: %d reads", wk.fetches-before)
	}
	if _, err := server.VerifySandboxToken(tok.Token); err != nil {
		t.Fatalf("its token = %v", err)
	}
}

// turnOffSigningFor gives worker a fresh copy that says servers do not sign.
func turnOffSigningFor(t *testing.T, worker *Service) {
	t.Helper()
	m := worker.signingMirror(worker.Cluster().(signingFeedCluster))
	m.mu.Lock()
	m.known, m.since, m.fetchedAt, m.triedAt = true, 0, time.Now(), time.Now()
	m.mu.Unlock()
}

// A stale copy that says servers do not sign, with no server answering,
// assumes they may have taken over at the earliest they could have: older
// ring tokens still count, newer ones and the SSH bridge's old rule do not,
// and nothing is signed with the ring.
func TestStaleCopyWithNoServerAssumesServersMaySign(t *testing.T) {
	_, worker, _, wk, st := signingPair(t)
	seedTokenSandbox(t, st, "sb-1", "team:a", models.SandboxStatusStarted)
	turnOffSigningFor(t, worker)
	ageMirror(t, worker, 10*time.Minute)
	read := worker.serverSigning.mirror.fetchedAt
	wk.feedErr = errors.New("no server answers")
	earliest := read.Add(signingKeysStaleOff)
	ring := func(iat time.Time) string {
		raw, _, _ := sandboxtoken.Sign(worker.cipher, sandboxtoken.Claims{TokenID: mustTokenID(t), SandboxID: "sb-1", Owner: "team:a",
			IssuedAt: iat.Unix(), ExpiresAt: iat.Add(30 * time.Minute).Unix()})
		return raw
	}
	setSandboxTokenClock(t, earliest.Add(time.Minute))
	if _, err := worker.VerifySandboxToken(ring(earliest.Add(-time.Second))); err != nil {
		t.Fatalf("a ring token from before servers could have signed = %v", err)
	}
	if _, err := worker.VerifySandboxToken(ring(earliest.Add(time.Second))); !errors.Is(err, sandboxtoken.ErrInvalidSignature) {
		t.Fatalf("a ring token from after = %v", err)
	}
	if !worker.ServerSigningOn() || worker.KeepsSSHKeyFrom(false) {
		t.Fatal("the stale copy still answers that servers do not sign")
	}
	if _, err := worker.IssueSandboxToken(teamCtx("a"), "sb-1", models.CreateSandboxTokenRequest{ExpiresIn: "30m"}); err == nil {
		t.Fatal("issued a token with no server to sign it")
	}
}

// An owner that cannot tell whether servers sign (it restarted while no
// server answered) serves no key-less bridged SSH call and sends no key.
func TestSSHBridgeGateWhenTheModeIsUnknown(t *testing.T) {
	server, worker, _, wk, st := signingPair(t)
	ctx := context.Background()
	authorized, _ := testSSHKey(t)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-ssh", Image: "alpine", Status: models.SandboxStatusStarted, SSHPublicKey: authorized,
		CPU: 1, MemoryMB: 64, DiskGB: 1, OSUser: "root", CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatal(err)
	}
	turnOnServerSigning(t, server, now)
	worker.serverSigning.mirror = nil
	wk.feedErr = errors.New("no server answers")
	if err := worker.CheckSSHBridgeKey(ctx, "sb-ssh", ""); !errors.Is(err, ErrSSHBridgeKey) {
		t.Fatalf("a key-less bridged call with the mode unknown = %v", err)
	}
	if worker.KeepsSSHKeyFrom(false) {
		t.Fatal("the SSH key went to a node with the mode unknown")
	}
}

// The operator ends old tokens: a ring token issued before Since, even one
// backdated to just before it, stops counting on servers at once and on
// workers once they read the feed.
func TestEndingOldTokens(t *testing.T) {
	server, worker, srv, _, st := signingPair(t)
	ctx := context.Background()
	since := time.Unix(1_800_000_000, 0)
	setSandboxTokenClock(t, since.Add(-10*time.Minute))
	seedTokenSandbox(t, st, "sb-old", "team:a", models.SandboxStatusStarted)
	turnOnServerSigning(t, server, since)
	row, err := st.Get(ctx, "sb-old")
	if err != nil {
		t.Fatal(err)
	}
	now := since.Add(59 * time.Minute)
	setSandboxTokenClock(t, now)
	iat := since.Add(-time.Second)
	old, _, err := sandboxtoken.Sign(worker.cipher, sandboxtoken.Claims{TokenID: mustTokenID(t), SandboxID: "sb-old", Owner: "team:a",
		IssuedAt: iat.Unix(), ExpiresAt: iat.Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	// Until the operator ends them, such a token counts until it expires:
	// the window is Since plus the token max TTL.
	for name, svc := range map[string]*Service{"server": server, "worker": worker} {
		if c, err := svc.VerifySandboxToken(old); err != nil || c.CheckNotBefore(row.TokensNotBefore) != nil {
			t.Fatalf("%s before the end: %v", name, err)
		}
	}
	if _, err := worker.EndOldSandboxTokens(ctx); !errors.Is(err, ErrServerSigningNotLeader) {
		t.Fatalf("a worker ended old tokens: %v", err)
	}
	srv.leader = false
	if _, err := server.EndOldSandboxTokens(ctx); !errors.Is(err, ErrServerSigningNotLeader) || srv.rec.OldTokensEndUnixNano != 0 {
		t.Fatalf("a server that does not lead ended old tokens: %v", err)
	}
	if _, err := server.StartServerSigning(ctx); !errors.Is(err, ErrServerSigningNotLeader) {
		t.Fatalf("a server that does not lead started signing: %v", err)
	}
	srv.leader = true
	srv.endAt = now.UnixNano()
	rec, err := server.EndOldSandboxTokens(ctx)
	if err != nil || rec.OldTokensEndUnixNano != now.UnixNano() {
		t.Fatalf("end: %+v %v", rec, err)
	}
	if _, err := server.VerifySandboxToken(old); !errors.Is(err, sandboxtoken.ErrInvalidSignature) {
		t.Fatalf("server after the end = %v", err)
	}
	worker.serverSigning.mirror.refresh()
	if _, err := worker.VerifySandboxToken(old); !errors.Is(err, sandboxtoken.ErrInvalidSignature) {
		t.Fatalf("worker after the end = %v", err)
	}
	// Server-signed tokens still count.
	srv.placements["sb-old"] = cluster.Placement{SandboxID: "sb-old", OwnerNodeID: "wkr-1", OwnerRef: "team:a"}
	signed, err := worker.IssueSandboxToken(teamCtx("a"), "sb-old", models.CreateSandboxTokenRequest{ExpiresIn: "30m"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.VerifySandboxToken(signed.Token); err != nil {
		t.Fatalf("a server-signed token after the end = %v", err)
	}
	// Ending them twice keeps the first time; before servers sign there is
	// nothing to end.
	srv.endAt = now.Add(time.Hour).UnixNano()
	if again, err := server.EndOldSandboxTokens(ctx); err != nil || again.OldTokensEndUnixNano != now.UnixNano() {
		t.Fatalf("again: %+v %v", again, err)
	}
	fresh, _, _ := testTokenService(t, time.Hour)
	fresh.cfg.EnableCluster = true
	fresh.AttachCluster(newSigningServer("srv-9"))
	if _, err := fresh.EndOldSandboxTokens(ctx); !errors.Is(err, ErrServerSigningOff) {
		t.Fatalf("before servers sign = %v", err)
	}
}

// The operator's start writes the record past the gate's list of members;
// the upkeep alone waits, and logs why.
func TestStartServerSigningPastTheGate(t *testing.T) {
	server, worker, srv, _, _ := signingPair(t)
	ctx := context.Background()
	srv.allowed, srv.waiting = false, []string{"wkr-quiet"}
	if err := server.UpkeepServerSigning(ctx); err != nil || srv.rec != nil {
		t.Fatalf("the upkeep wrote past the gate: %v", err)
	}
	if server.serverSigning.heldReason == "" {
		t.Fatal("the leader did not log why it waits")
	}
	if _, err := worker.StartServerSigning(ctx); !errors.Is(err, ErrServerSigningNotLeader) {
		t.Fatalf("a worker started it: %v", err)
	}
	rec, err := server.StartServerSigning(ctx)
	if err != nil || srv.rec == nil || !srv.forced || rec.SinceUnixNano == 0 {
		t.Fatalf("start: %+v %v forced %v", rec, err, srv.forced)
	}
	again, err := server.StartServerSigning(ctx)
	if err != nil || string(again.Sealed) != string(rec.Sealed) {
		t.Fatalf("a second start wrote another record: %v", err)
	}
	r, g, on, err := server.ServerSigningStatus()
	if err != nil || !on || r.SinceUnixNano != rec.SinceUnixNano || len(g.Waiting) != 1 {
		t.Fatalf("status: %+v %+v %v %v", r, g, on, err)
	}
	if _, _, _, err := worker.ServerSigningStatus(); !errors.Is(err, ErrServerSigningNotLeader) {
		t.Fatalf("a worker's status: %v", err)
	}
}

// A worker reads the feed from boot, on a ticker, so its copy is fresh
// before the first check needs it.
func TestWorkerReadsTheFeedFromBoot(t *testing.T) {
	_, worker, _, wk, _ := signingPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	worker.StartServerSigningUpkeep(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for {
		m := worker.serverSigning.mirror
		if m != nil {
			m.mu.Lock()
			known := m.known
			m.mu.Unlock()
			if known {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the worker did not read the feed at boot")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if wk.fetches < 1 {
		t.Fatalf("fetches = %d", wk.fetches)
	}
	single, _, _ := testTokenService(t, time.Hour)
	single.StartServerSigningUpkeep(context.Background())
	if single.serverSigning.mirror != nil {
		t.Fatal("a single node started a mirror")
	}
}

// The signing mode a create at a worker edge reads (only one with a cloud
// identity or a platform volume reads it): a fresh copy answers from
// memory.
func BenchmarkSigningModeFromAFreshCopy(b *testing.B) {
	m := &signingKeyMirror{fetch: func(context.Context) (cluster.SigningKeys, error) {
		return cluster.SigningKeys{SinceUnixNano: 5}, nil
	}}
	m.view(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !m.view(0).mode.on {
			b.Fatal("off")
		}
	}
}

// A server cut off from the leader answers neither the feed nor a sign
// call: its view stopped when it lost contact. The node tries the next
// server; the leader is never cut off from itself.
func TestACutOffServerAnswersNoSigningCall(t *testing.T) {
	h, _, srv, _ := identityPair(t)
	ctx := context.Background()
	h.allow(t, "payments", "deploy", "runner")
	if err := h.svc.EnsureIdentityKeysReady(ctx); err != nil {
		t.Fatal(err)
	}
	turnOnServerSigning(t, h.svc, time.Now())
	srv.placements["sb-1"] = cluster.Placement{SandboxID: "sb-1", OwnerNodeID: "wkr-1", OwnerRef: "team:payments",
		Spec: &models.CreateSandboxRequest{Identity: &models.IdentityRequest{RoleTag: "deploy"}}}
	setSandboxTokenClock(t, time.Now())
	claims := func() []byte {
		raw, _ := jsonMarshal(sandboxtoken.Claims{Version: 1, TokenID: mustTokenID(t), SandboxID: "sb-1", Owner: "team:payments",
			IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(10 * time.Minute).Unix()})
		return raw
	}
	srv.mu.Lock()
	srv.stale = true
	srv.mu.Unlock()
	if _, err := h.svc.SigningKeysFeed(); !errors.Is(err, cluster.ErrStalePlacementView) {
		t.Fatalf("feed from a cut-off server = %v", err)
	}
	if _, err := h.svc.SignSandboxTokenFor(ctx, "wkr-1", false, claims()); !errors.Is(err, cluster.ErrStalePlacementView) {
		t.Fatalf("token sign on a cut-off server = %v", err)
	}
	if _, err := h.svc.SignIdentityTokenFor(ctx, "wkr-1", false, cluster.IdentityTokenSignRequest{SandboxID: "sb-1"}); !errors.Is(err, cluster.ErrStalePlacementView) {
		t.Fatalf("identity sign on a cut-off server = %v", err)
	}
	srv.mu.Lock()
	srv.stale = false
	srv.mu.Unlock()
	if feed, err := h.svc.SigningKeysFeed(); err != nil || feed.SinceUnixNano == 0 {
		t.Fatalf("feed once in contact = %+v %v", feed, err)
	}
	if _, err := h.svc.SignSandboxTokenFor(ctx, "wkr-1", false, claims()); err != nil {
		t.Fatalf("token sign once in contact = %v", err)
	}
	if _, err := h.svc.SignIdentityTokenFor(ctx, "wkr-1", false, cluster.IdentityTokenSignRequest{SandboxID: "sb-1"}); err != nil {
		t.Fatalf("identity sign once in contact = %v", err)
	}
}

// In a cluster whose servers' certificates name no role, the feed answers
// that servers do not sign (cluster.Agent.FetchSigningKeys), on every
// read: a worker goes on signing and checking tokens itself, through every
// refresh, as before this release.
func TestTokensWhereEveryServerNamesNoRole(t *testing.T) {
	server, worker, _, wk, st := signingPair(t)
	seedTokenSandbox(t, st, "sb-1", "team:a", models.SandboxStatusStarted)
	setSandboxTokenClock(t, time.Now())
	for i := 0; i < 3; i++ {
		tok, err := worker.IssueSandboxToken(teamCtx("a"), "sb-1", models.CreateSandboxTokenRequest{ExpiresIn: "30m"})
		if err != nil {
			t.Fatalf("pass %d: issue = %v", i, err)
		}
		for name, svc := range map[string]*Service{"worker": worker, "server": server} {
			c, err := svc.VerifySandboxToken(tok.Token)
			if err != nil || c.KeyID&secrets.ServerKeyIDBit != 0 {
				t.Fatalf("pass %d: %s checks %+v %v", i, name, c, err)
			}
		}
		ageMirror(t, worker, 10*time.Minute)
	}
	if wk.fetches < 3 {
		t.Fatalf("the worker read the feed %d times", wk.fetches)
	}
}
