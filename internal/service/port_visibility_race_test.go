package service

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Races between a token gate (A2) and the writers that can open a port
// around it: the port route, a custom domain's route, toolboxd's /proxy
// allowlist (route_gate.go). The Review923 tests are the reproducers from
// review 2 of the token-gated ports, unchanged but for helper names.

// A reconcile pass that read the row while the port was public resumes after
// an expose made it "token". Its old copy must not put the direct route back.
func TestReview923StaleReconcileMustNotReopenGatedPort(t *testing.T) {
	svc, _, w, id := newGateHarness(t)
	ctx := context.Background()
	if _, err := svc.ExposePort(ctx, id, 3000, "http"); err != nil {
		t.Fatal(err)
	}
	stale, err := svc.store.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", "token"); err != nil {
		t.Fatal(err)
	}
	// Reconcile already read stale before expose completed and now resumes.
	if err := svc.syncExposedPortRoute(ctx, stale, stale.ExposedPorts[0]); err != nil {
		t.Fatal(err)
	}
	current, _ := svc.store.Get(ctx, id)
	if portTokenGated(current, 3000) && w.shape(3000) != "ingress" {
		t.Fatalf("security regression: store is token-gated, route is %q", w.shape(3000))
	}
}

// pauseAt makes the first route-gate read at stage stop until the returned
// release is called, and returns a channel closed once it has stopped.
func pauseAt(svc *Service, stage string) (stopped <-chan struct{}, release func()) {
	stop := make(chan struct{})
	rel := make(chan struct{})
	var once atomic.Bool
	svc.testAfterRouteGateRead = func(got string) {
		if got != stage || !once.CompareAndSwap(false, true) {
			return
		}
		close(stop)
		<-rel
	}
	var relOnce sync.Once
	return stop, func() { relOnce.Do(func() { close(rel) }) }
}

func waitForT(t *testing.T, what string, cond func() bool) {
	t.Helper()
	if !waitFor(5*time.Second, cond) {
		t.Fatalf("timed out waiting for %s", what)
	}
}

// Every entry point that writes a port route from a row read earlier (start,
// reconcile and start events share syncExposedPortRoute; the stop/wake and
// lifecycle paths call upsertExposedPortRoute; the serverless force pass
// calls installHTTPPortRoute) reads the gate from the store. A port with no
// row yet (a first public expose writes its route first) keeps the answer of
// the copy it was handed.
func TestStalePortRouteWritersReadTheCurrentGate(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		write func(svc *Service, sb *models.Sandbox, p models.ExposedPort) error
	}{
		{"start, reconcile, start event", func(svc *Service, sb *models.Sandbox, p models.ExposedPort) error {
			return svc.syncExposedPortRoute(ctx, sb, p)
		}},
		{"stop and wake paths, lifecycle flip", func(svc *Service, sb *models.Sandbox, p models.ExposedPort) error {
			return svc.upsertExposedPortRoute(ctx, sb, p)
		}},
		{"serverless force pass", func(svc *Service, sb *models.Sandbox, p models.ExposedPort) error {
			return svc.installHTTPPortRoute(ctx, sb, p.Port)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, w, id := newGateHarness(t)
			if _, err := svc.ExposePort(ctx, id, 3000, "http"); err != nil {
				t.Fatal(err)
			}
			stale, _ := svc.store.Get(ctx, id)
			if _, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityToken); err != nil {
				t.Fatal(err)
			}
			if err := tc.write(svc, stale, *findExposure(stale, 3000)); err != nil {
				t.Fatal(err)
			}
			if got := w.shape(3000); got != "ingress" {
				t.Fatalf("an old public copy wrote the %q route for a gated port", got)
			}

			// The reverse: an old gated copy after the gate was lifted
			// writes the direct route the store now asks for.
			gatedCopy, _ := svc.store.Get(ctx, id)
			if _, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityPublic); err != nil {
				t.Fatal(err)
			}
			if err := tc.write(svc, gatedCopy, *findExposure(gatedCopy, 3000)); err != nil {
				t.Fatal(err)
			}
			if got := w.shape(3000); got != "direct" {
				t.Fatalf("an old gated copy wrote the %q route for a public port", got)
			}

			// No row: the copy decides.
			unstored := *gatedCopy
			unstored.ExposedPorts = []models.ExposedPort{
				{SandboxID: id, Port: 5000, Protocol: "http", Visibility: models.ExposedPortVisibilityToken},
				{SandboxID: id, Port: 6000, Protocol: "http"},
			}
			for _, p := range unstored.ExposedPorts {
				if err := tc.write(svc, &unstored, p); err != nil {
					t.Fatal(err)
				}
			}
			if w.shape(5000) != "ingress" || w.shape(6000) != "direct" {
				t.Fatalf("unstored ports: 5000 %q, 6000 %q", w.shape(5000), w.shape(6000))
			}
			if n := svc.httpRouteLocks.keys(); n != 0 {
				t.Fatalf("%d port route locks left after every write returned", n)
			}
		})
	}
}

// A writer that read "public" and still holds the port's route lock delays
// the gating expose's route write until it is done, so the expose's write is
// the last one. Without the lock the old direct write lands after the wake
// route and reopens the port.
func TestPortRouteWriteFromAnOldReadLandsBeforeTheGate(t *testing.T) {
	ctx := context.Background()
	svc, _, w, id := newGateHarness(t)
	if _, err := svc.ExposePort(ctx, id, 3000, "http"); err != nil {
		t.Fatal(err)
	}
	stale, _ := svc.store.Get(ctx, id)
	stopped, release := pauseAt(svc, gateReadPortRoute)
	defer release()

	staleDone := make(chan error, 1)
	go func() { staleDone <- svc.syncExposedPortRoute(ctx, stale, *findExposure(stale, 3000)) }()
	<-stopped // read "public"; holds the lock

	exposeDone := make(chan error, 1)
	go func() {
		_, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityToken)
		exposeDone <- err
	}()
	key := portLockKey{id: id, port: 3000}
	waitForT(t, "the expose's route write to wait for the lock", func() bool { return svc.httpRouteLocks.refs(key) == 2 })
	if sb, _ := svc.store.Get(ctx, id); !portTokenGated(sb, 3000) {
		t.Fatal("expose has not stored the gate before its route write")
	}
	release()
	if err := <-staleDone; err != nil {
		t.Fatal(err)
	}
	if err := <-exposeDone; err != nil {
		t.Fatal(err)
	}
	if got := w.shape(3000); got != "ingress" {
		t.Fatalf("route after an old public write raced the gate: %q", got)
	}
}

// If the gate cannot be read, no route is written: not the direct one, which
// may be the open way in.
func TestPortRouteNotWrittenWhenTheGateCannotBeRead(t *testing.T) {
	ctx := context.Background()
	svc, _, w, id := newGateHarness(t)
	sb, _ := svc.store.Get(ctx, id)
	p := models.ExposedPort{SandboxID: id, Port: 5000, Protocol: "http"}
	sb.ExposedPorts = append(sb.ExposedPorts, p)
	_ = svc.store.Close()
	if err := svc.syncExposedPortRoute(ctx, sb, p); err == nil || !strings.Contains(err.Error(), "visibility of port 5000") {
		t.Fatalf("route write with an unreadable store = %v", err)
	}
	if got := w.shape(5000); got != "" {
		t.Fatalf("a route was written without the gate: %q", got)
	}
}

// An allowlist push from a row read before the gate leaves the gated port
// off: the push reads the ports itself.
func TestAllowlistPushFromAnOldRowKeepsTheGate(t *testing.T) {
	ctx := context.Background()
	svc, rt, _, id := newGateHarness(t)
	if _, err := svc.ExposePort(ctx, id, 3000, "http"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExposePort(ctx, id, 4000, "http"); err != nil {
		t.Fatal(err)
	}
	stale, _ := svc.store.Get(ctx, id)
	if _, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityToken); err != nil {
		t.Fatal(err)
	}
	svc.syncAllowedPorts(ctx, stale) // reconcile / start event resuming
	if got := lastAllowed(rt); len(got) != 1 || got[0] != 4000 {
		t.Fatalf("allowlist after an old row's push = %v, want [4000]", got)
	}

	// A failed read pushes nothing rather than the old copy.
	pushes := len(rt.pushes)
	_ = svc.store.Close()
	svc.syncAllowedPorts(ctx, stale)
	if len(rt.pushes) != pushes {
		t.Fatalf("pushed %v with the ports unreadable", lastAllowed(rt))
	}
}

// A push that read the port while public and still holds the sandbox's
// allowlist lock delays the gating expose's push, so the expose's push is
// the last one and the gated port ends up off the allowlist.
func TestAllowlistPushFromAnOldReadLandsBeforeTheGate(t *testing.T) {
	ctx := context.Background()
	svc, rt, _, id := newGateHarness(t)
	if _, err := svc.ExposePort(ctx, id, 3000, "http"); err != nil {
		t.Fatal(err)
	}
	stale, _ := svc.store.Get(ctx, id)
	stopped, release := pauseAt(svc, gateReadAllowlist)
	defer release()

	staleDone := make(chan struct{})
	go func() { svc.syncAllowedPorts(ctx, stale); close(staleDone) }()
	<-stopped // read [3000]; holds the lock

	exposeDone := make(chan error, 1)
	go func() {
		_, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityToken)
		exposeDone <- err
	}()
	waitForT(t, "the expose's push to wait for the lock", func() bool { return svc.allowlistLocks.refs(id) == 2 })
	release()
	<-staleDone
	if err := <-exposeDone; err != nil {
		t.Fatal(err)
	}
	if got := lastAllowed(rt); len(got) != 0 {
		t.Fatalf("allowlist after an old push raced the gate = %v, want none", got)
	}
	if n := svc.allowlistLocks.keys(); n != 0 {
		t.Fatalf("%d allowlist locks left", n)
	}
}

// Without a store (bare &Service{} literals) the copy decides; nothing
// panics.
func TestRouteGateWithoutAStore(t *testing.T) {
	ctx := context.Background()
	s := &Service{}
	sb := &models.Sandbox{ID: "sb", ExposedPorts: []models.ExposedPort{{Port: 1, Visibility: models.ExposedPortVisibilityToken}}}
	if gated, err := s.portGatedNow(ctx, sb, 1); err != nil || !gated {
		t.Fatalf("portGatedNow = %v, %v", gated, err)
	}
}
