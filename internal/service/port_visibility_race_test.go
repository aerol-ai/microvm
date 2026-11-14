package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/caddy"
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

// blockingTXTResolver parks the first TXT lookup until release closes, so a
// test can act while AddCustomDomain waits on DNS.
type blockingTXTResolver struct {
	entered chan struct{}
	release chan struct{}
	value   string
}

func (r *blockingTXTResolver) LookupTXT(context.Context, string) ([]string, error) {
	close(r.entered)
	<-r.release
	return []string{r.value}, nil
}

// A custom domain checked the port while it was public and then waited on
// DNS; meanwhile the port became "token". The domain must be refused.
func TestReview923CustomDomainMustNotRaceTokenGate(t *testing.T) {
	svc, _, _, id := newGateHarness(t)
	ctx := context.Background()
	svc.cfg.EnableCustomDomains = true
	const hostname = "app.acme.test"
	dns := &blockingTXTResolver{entered: make(chan struct{}), release: make(chan struct{}), value: models.CustomDomainTXTValue(svc.cfg.CustomDomainVerifyValuePrefix, customDomainProofToken(ctx, ""), hostname)}
	svc.dnsResolver = dns
	done := make(chan error, 1)
	go func() { done <- svc.AddCustomDomain(ctx, id, hostname, 3000) }()
	<-dns.entered
	_, gateErr := svc.ExposePortWithVisibility(ctx, id, 3000, "http", "token")
	close(dns.release)
	domainErr := <-done
	if gateErr != nil {
		t.Fatal(gateErr)
	}
	if domainErr == nil {
		t.Fatal("gated port and ungated custom domain were both accepted concurrently")
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

func exposedPortRefs(svc *Service, id string, port int) int {
	return svc.portLocks.refs(portLockKey{id: id, port: port})
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

// domainRouteWriter is a gateRouteWriter that also records the custom
// hostnames that have a route, and can fail sandbox route writes after
// writing the leaves (as Caddy's leaf-by-leaf write can).
type domainRouteWriter struct {
	gateRouteWriter
	leaves         map[string]int
	failSandboxRte error
}

func (w *domainRouteWriter) UpsertSandboxRoute(_ context.Context, _, _ string, _ int, customs []caddy.CustomHostnameRoute) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.leaves == nil {
		w.leaves = map[string]int{}
	}
	for _, c := range customs {
		w.leaves[c.Hostname] = c.TargetPort
	}
	return w.failSandboxRte
}

func (w *domainRouteWriter) DeleteCustomDomainHTTPRoute(_ context.Context, _, hostname string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.leaves, hostname)
	return nil
}

func (w *domainRouteWriter) leaf(hostname string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.leaves[hostname]
	return ok
}

// proofTXTResolver answers every lookup with the owner-less TXT proof for
// the hostname asked about.
type proofTXTResolver struct{ namePrefix, valuePrefix string }

func (r proofTXTResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	host := strings.TrimPrefix(name, r.namePrefix+".")
	return []string{models.CustomDomainTXTValue(r.valuePrefix, "", host)}, nil
}

// newDomainGateHarness is newGateHarness with custom domains on, a resolver
// that proves every hostname, and a writer that records domain routes.
func newDomainGateHarness(t *testing.T) (*Service, *recordingRuntime, *domainRouteWriter, string) {
	t.Helper()
	svc, rt, _, id := newGateHarness(t)
	svc.cfg.EnableCustomDomains = true
	svc.dnsResolver = proofTXTResolver{namePrefix: svc.cfg.CustomDomainVerifyPrefix, valuePrefix: svc.cfg.CustomDomainVerifyValuePrefix}
	w := &domainRouteWriter{}
	svc.setRouteWriter(w)
	return svc, rt, w, id
}

// An expose to "token" that arrives while an attach is between its check and
// its insert waits, then sees the domain and is refused. Without the port
// lock it would see no domain, and both would be accepted.
func TestTokenGateWaitsForACustomDomainAttach(t *testing.T) {
	ctx := context.Background()
	svc, _, w, id := newDomainGateHarness(t)
	const hostname = "app.acme.test"
	stopped, release := pauseAt(svc, gateReadDomainAttach)
	defer release()

	attachDone := make(chan error, 1)
	go func() { attachDone <- svc.AddCustomDomain(ctx, id, hostname, 3000) }()
	<-stopped // checked "public"; holds the port

	gateDone := make(chan error, 1)
	go func() {
		_, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityToken)
		gateDone <- err
	}()
	waitForT(t, "the expose to wait for the attach", func() bool { return exposedPortRefs(svc, id, 3000) == 2 })
	release()
	if err := <-attachDone; err != nil {
		t.Fatal(err)
	}
	if err := <-gateDone; !errors.Is(err, ErrTokenVisibilityConflict) {
		t.Fatalf("expose to token after the attach = %v, want the conflict", err)
	}
	sb, _ := svc.store.Get(ctx, id)
	if portTokenGated(sb, 3000) || !w.leaf(hostname) {
		t.Fatalf("after attach then gate: gated=%v, domain route=%v", portTokenGated(sb, 3000), w.leaf(hostname))
	}
}

// A failed attach removes its row and the route leaf it may have written; a
// failed retry of an attached domain leaves it attached.
func TestCustomDomainAttachRollbackRemovesItsLeaf(t *testing.T) {
	ctx := context.Background()
	svc, _, w, id := newDomainGateHarness(t)
	w.failSandboxRte = errors.New("caddy down")
	if err := svc.AddCustomDomain(ctx, id, "new.acme.test", 3000); err == nil {
		t.Fatal("attach succeeded with the route write failing")
	}
	if sb, _ := svc.store.Get(ctx, id); len(sb.CustomDomains) != 0 || w.leaf("new.acme.test") {
		t.Fatalf("a failed attach left row %v, leaf %v", sb.CustomDomains, w.leaf("new.acme.test"))
	}

	w.failSandboxRte = nil
	if err := svc.AddCustomDomain(ctx, id, "kept.acme.test", 3000); err != nil {
		t.Fatal(err)
	}
	w.failSandboxRte = errors.New("caddy down")
	if err := svc.AddCustomDomain(ctx, id, "kept.acme.test", 3000); err == nil {
		t.Fatal("re-add succeeded with the route write failing")
	}
	if sb, _ := svc.store.Get(ctx, id); len(sb.CustomDomains) != 1 || !w.leaf("kept.acme.test") {
		t.Fatalf("a failed re-add detached the domain: rows %v, leaf %v", sb.CustomDomains, w.leaf("kept.acme.test"))
	}
}

// A route write from a row read while a domain dialed the port cannot put
// the domain's route back after the domain was removed and the port gated.
func TestStaleSandboxRouteDoesNotRestoreARemovedDomain(t *testing.T) {
	ctx := context.Background()
	svc, _, w, id := newDomainGateHarness(t)
	const hostname = "app.acme.test"
	if err := svc.AddCustomDomain(ctx, id, hostname, 3000); err != nil {
		t.Fatal(err)
	}
	stale, _ := svc.store.Get(ctx, id)
	if err := svc.RemoveCustomDomain(ctx, id, hostname); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityToken); err != nil {
		t.Fatal(err)
	}
	if err := svc.syncSandboxPublicRoute(ctx, stale); err != nil { // reconcile resuming
		t.Fatal(err)
	}
	if w.leaf(hostname) {
		t.Fatal("an old row put back a removed domain's route to a gated port")
	}
}

// A route writer that read the domain and still holds the sandbox's domain
// route lock delays the remove, whose route delete then comes last.
// Without the lock the old write lands after the delete and the leaf
// outlives its row.
func TestCustomDomainRemoveWaitsForAnInflightRouteWrite(t *testing.T) {
	ctx := context.Background()
	svc, _, w, id := newDomainGateHarness(t)
	const hostname = "app.acme.test"
	if err := svc.AddCustomDomain(ctx, id, hostname, 3000); err != nil {
		t.Fatal(err)
	}
	stale, _ := svc.store.Get(ctx, id)
	stopped, release := pauseAt(svc, gateReadCustomDomains)
	defer release()

	writeDone := make(chan error, 1)
	go func() { writeDone <- svc.syncSandboxPublicRoute(ctx, stale) }()
	<-stopped // read the domain; holds the lock

	removeDone := make(chan error, 1)
	go func() { removeDone <- svc.RemoveCustomDomain(ctx, id, hostname) }()
	waitForT(t, "the remove to wait for the route write", func() bool { return svc.customDomainRouteLocks.refs(id) == 2 })
	if sb, _ := svc.store.Get(ctx, id); len(sb.CustomDomains) != 1 {
		t.Fatal("the remove deleted the row while a route write held what it read")
	}
	release()
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if err := <-removeDone; err != nil {
		t.Fatal(err)
	}
	if w.leaf(hostname) {
		t.Fatal("a removed domain's route outlived its row")
	}
	if n := svc.customDomainRouteLocks.keys(); n != 0 {
		t.Fatalf("%d domain route locks left", n)
	}
}

// A remove whose re-sync fails has already deleted the detached leaf.
func TestCustomDomainRemoveDeletesTheLeafEvenIfTheSyncFails(t *testing.T) {
	ctx := context.Background()
	svc, _, w, id := newDomainGateHarness(t)
	const hostname = "app.acme.test"
	if err := svc.AddCustomDomain(ctx, id, hostname, 3000); err != nil {
		t.Fatal(err)
	}
	w.failSandboxRte = errors.New("caddy down")
	if err := svc.RemoveCustomDomain(ctx, id, hostname); err == nil {
		t.Fatal("remove succeeded with the route write failing")
	}
	if w.leaf(hostname) {
		t.Fatal("a failed re-sync left the detached domain's route")
	}
}

// Defense in depth: were a domain row and a gate on its port both stored,
// the route writer still writes no route for that domain. A domain on a
// public port is written as before. A failed read writes nothing.
func TestSandboxRouteSkipsADomainOnAGatedPort(t *testing.T) {
	ctx := context.Background()
	svc, _, w, id := newDomainGateHarness(t)
	if err := svc.AddCustomDomain(ctx, id, "open.acme.test", 4000); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.AddCustomDomain(ctx, id, "gated.acme.test", 3000); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.UpsertPort(ctx, models.ExposedPort{SandboxID: id, Port: 3000, Protocol: "http", CreatedAt: time.Now().UTC(), Visibility: models.ExposedPortVisibilityToken}); err != nil {
		t.Fatal(err)
	}
	sb, _ := svc.store.Get(ctx, id)
	if err := svc.syncSandboxPublicRoute(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if w.leaf("gated.acme.test") || !w.leaf("open.acme.test") {
		t.Fatalf("leaves = %v, want only open.acme.test", w.leaves)
	}

	_ = svc.store.Close()
	w.leaves = nil
	if err := svc.syncSandboxPublicRoute(ctx, sb); err == nil || w.leaves != nil {
		t.Fatalf("route write with unreadable domains = %v, leaves %v", err, w.leaves)
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
	if got, err := s.withCurrentCustomDomains(ctx, sb); err != nil || got != sb {
		t.Fatalf("withCurrentCustomDomains = %v, %v", got, err)
	}
	if hasPortCustomDomain(sb) {
		t.Fatal("a sandbox with no domains has a port domain")
	}
}
