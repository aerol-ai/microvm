package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// held reports whether a create of id holds its lease.
func (l *createLeases) held(id string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.leases[id] != nil
}

func TestCreateLeases(t *testing.T) {
	const wait = time.Minute
	t.Run("free id is taken at once; release frees it once", func(t *testing.T) {
		var l createLeases
		release, err := l.acquire(t.Context(), "sb-1", nil, wait)
		if err != nil || !l.held("sb-1") {
			t.Fatalf("acquire = %v, held %v", err, l.held("sb-1"))
		}
		other, err := l.acquire(t.Context(), "sb-2", []string{"hmac:0:aa"}, wait)
		if err != nil {
			t.Fatalf("another id = %v", err)
		}
		release()
		release() // once
		if l.held("sb-1") || !l.held("sb-2") {
			t.Fatal("a release freed the wrong lease")
		}
		other()
	})

	t.Run("a different keyed request is refused without waiting", func(t *testing.T) {
		var l createLeases
		release, _ := l.acquire(t.Context(), "sb-1", []string{"hmac:0:aa"}, wait)
		defer release()
		if _, err := l.acquire(t.Context(), "sb-1", []string{"hmac:0:bb"}, wait); !errors.Is(err, errCreateLeaseKeyMismatch) {
			t.Fatalf("different request = %v, want errCreateLeaseKeyMismatch", err)
		}
	})

	t.Run("a waiter gets the lease when the holder gives it back", func(t *testing.T) {
		tests := []struct {
			name           string
			holder, waiter []string
		}{
			{name: "same request", holder: []string{"hmac:0:aa"}, waiter: []string{"hmac:0:aa"}},
			{name: "unkeyed holder", holder: nil, waiter: []string{"hmac:0:aa"}},
			{name: "unkeyed waiter", holder: []string{"hmac:0:aa"}, waiter: nil},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var l createLeases
				release, _ := l.acquire(t.Context(), "sb-1", tt.holder, wait)
				got := make(chan error, 1)
				go func() {
					r, err := l.acquire(t.Context(), "sb-1", tt.waiter, wait)
					if err == nil {
						r()
					}
					got <- err
				}()
				select {
				case err := <-got:
					t.Fatalf("the waiter returned %v while the lease was held", err)
				case <-time.After(20 * time.Millisecond):
				}
				release()
				if err := <-got; err != nil {
					t.Fatalf("waiter = %v", err)
				}
			})
		}
	})

	t.Run("waiters run one at a time", func(t *testing.T) {
		var l createLeases
		var running, most int
		var mu sync.Mutex
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				release, err := l.acquire(t.Context(), "sb-1", []string{"hmac:0:aa"}, wait)
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				running++
				most = max(most, running)
				mu.Unlock()
				time.Sleep(time.Millisecond)
				mu.Lock()
				running--
				mu.Unlock()
				release()
			}()
		}
		wg.Wait()
		if most != 1 {
			t.Fatalf("%d creates of one id held the lease at once", most)
		}
	})

	t.Run("the wait gives up at its bound or with its context", func(t *testing.T) {
		var l createLeases
		release, _ := l.acquire(t.Context(), "sb-1", nil, wait)
		defer release()
		if _, err := l.acquire(t.Context(), "sb-1", nil, 10*time.Millisecond); !errors.Is(err, ErrCreateInProgress) {
			t.Fatalf("expired wait = %v, want ErrCreateInProgress", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := l.acquire(ctx, "sb-1", nil, wait); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled wait = %v, want context.Canceled", err)
		}
		if !l.held("sb-1") {
			t.Fatal("a waiter that gave up took the holder's lease")
		}
	})
}

func TestCreateLeaseWait(t *testing.T) {
	tests := []struct {
		name    string
		timeout int
		test    time.Duration
		want    time.Duration
	}{
		{name: "the create timeout bounds it", timeout: 120, want: 120*time.Second + createRollbackTimeout + createLeaseWaitSlack},
		{name: "no create timeout: the default", timeout: 0, want: defaultCreateLeaseWait + createRollbackTimeout + createLeaseWaitSlack},
		{name: "a test override", timeout: 120, test: time.Second, want: time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{testCreateLeaseWait: tt.test}
			s.cfg.CreateSandboxTimeoutSeconds = tt.timeout
			if got := s.createLeaseWait(); got != tt.want {
				t.Fatalf("createLeaseWait = %v, want %v", got, tt.want)
			}
		})
	}
}

// idNamedRuntime models what makes a duplicate create dangerous: a runtime
// instance is named by its sandbox ID, so a second create of an ID whose
// instance exists fails with ErrSandboxContainerExists, as Docker's 409 does.
// The first create of an ID can be held, and any create can be failed.
type idNamedRuntime struct {
	*recordingRuntime
	mu       sync.Mutex
	names    map[string]bool
	creates  int
	hold     chan struct{} // when non-nil, the first create waits on it
	entered  chan struct{} // closed when the first create is held
	held     bool
	failNext error
}

func newIDNamedRuntime(hold bool) *idNamedRuntime {
	rt := &idNamedRuntime{recordingRuntime: &recordingRuntime{}, names: map[string]bool{}, entered: make(chan struct{})}
	if hold {
		rt.hold = make(chan struct{})
	}
	return rt
}

func (n *idNamedRuntime) Create(ctx context.Context, req models.CreateSandboxRequest, id, token string, binds []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	n.mu.Lock()
	n.creates++
	if n.names[id] {
		n.mu.Unlock()
		return nil, docker.ErrSandboxContainerExists
	}
	n.names[id] = true
	first := !n.held
	n.held = true
	failErr := n.failNext
	n.failNext = nil
	n.mu.Unlock()
	if first && n.hold != nil {
		close(n.entered)
		<-n.hold
	}
	if failErr != nil {
		n.mu.Lock()
		delete(n.names, id)
		n.mu.Unlock()
		return nil, failErr
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.recordingRuntime.Create(ctx, req, id, token, binds)
}

func (n *idNamedRuntime) Destroy(ctx context.Context, sb *models.Sandbox) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if sb != nil {
		delete(n.names, sb.ID)
	}
	return n.recordingRuntime.Destroy(ctx, sb)
}

func (n *idNamedRuntime) createCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.creates
}

// leaseHarness is a service on a idNamedRuntime with a mount root the test can
// see, and a sentinel standing for the first create's mounts: a duplicate's
// rollback that tears down rootDir/<id> removes it.
type leaseHarness struct {
	svc      *Service
	rt       *idNamedRuntime
	admitter *capacity.Admitter
	sentinel string
}

func newLeaseHarness(t *testing.T, id string, hold bool) *leaseHarness {
	t.Helper()
	rt := newIDNamedRuntime(hold)
	svc, _, admitter := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	root := filepath.Join(t.TempDir(), "mounts")
	mgr, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{RootDir: root, CredDir: filepath.Join(t.TempDir(), "cred"), WaitTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Close)
	svc.mounts = mgr
	sentinel := filepath.Join(root, id, "0", "first-create")
	if err := os.MkdirAll(filepath.Dir(sentinel), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sentinel, []byte("mounted"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &leaseHarness{svc: svc, rt: rt, admitter: admitter, sentinel: sentinel}
}

// assertOneReservation checks the admitter holds exactly one create's worth:
// the first create's reservation, neither released nor doubled.
func (h *leaseHarness) assertOneReservation(t *testing.T, when string) {
	t.Helper()
	snap := h.admitter.Snapshot()
	if snap.SandboxesActive != 1 || snap.ReservedCPU != models.DefaultCPU || snap.ReservedMemoryMB != models.DefaultMemoryMB {
		t.Fatalf("%s: admission active=%d cpu=%v mem=%d, want one sandbox at cpu=%v mem=%d",
			when, snap.SandboxesActive, snap.ReservedCPU, snap.ReservedMemoryMB, models.DefaultCPU, models.DefaultMemoryMB)
	}
}

func (h *leaseHarness) assertMountsIntact(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(h.sentinel); err != nil {
		t.Fatalf("the first create's mounts were torn down: %v", err)
	}
}

type createResult struct {
	resp *models.CreateSandboxResponse
	err  error
}

// The reported bug: retries of one Idempotency-Key, same request, reach the
// node while the first create still runs. Before the lease each ran its own
// create, failed on the container name, unmounted the first create's mounts
// and released its reservation. Now they wait and replay the first's sandbox.
func TestConcurrentSameKeyCreatesRunOneCreate(t *testing.T) {
	const id = "sb-lease-same001"
	digests := []string{"hmac:0:aaaa"}
	h := newLeaseHarness(t, id, true)
	req := models.CreateSandboxRequest{Image: "alpine:3.20", CreateRequestDigests: digests}

	first := make(chan createResult, 1)
	go func() {
		resp, err := h.svc.CreateSandboxWithID(keyedCtx("job-1"), req, id)
		first <- createResult{resp, err}
	}()
	<-h.rt.entered
	h.assertOneReservation(t, "first create running")

	const retries = 4
	retried := make(chan createResult, retries)
	for range retries {
		go func() {
			resp, err := h.svc.CreateSandboxWithID(keyedCtx("job-1"), req, id)
			retried <- createResult{resp, err}
		}()
	}
	// The retries are waiting, not creating: no runtime call, no second
	// reservation, the first create's mounts in place.
	time.Sleep(50 * time.Millisecond)
	if got := h.rt.createCount(); got != 1 {
		t.Fatalf("runtime creates while the first runs = %d, want 1", got)
	}
	h.assertOneReservation(t, "retries waiting")
	h.assertMountsIntact(t)

	close(h.rt.hold)
	got := <-first
	if got.err != nil || got.resp.Sandbox.ID != id || got.resp.Replayed {
		t.Fatalf("first create = %+v, %v", got.resp, got.err)
	}
	for range retries {
		r := <-retried
		if r.err != nil || r.resp.Sandbox.ID != id || !r.resp.Replayed {
			t.Fatalf("retry = %+v, %v; want a replay of %s", r.resp, r.err, id)
		}
		if r.resp.ToolboxToken != got.resp.ToolboxToken {
			t.Fatal("a retry answered with another sandbox's credentials")
		}
	}
	if n := h.rt.createCount(); n != 1 {
		t.Fatalf("runtime creates = %d, want exactly 1", n)
	}
	h.assertOneReservation(t, "after every retry")
	h.assertMountsIntact(t)
	if h.svc.createLeases.held(id) {
		t.Fatal("the lease outlived every create")
	}
}

// Same key, different request, while the first create runs: 422 at once,
// before any side effect.
func TestConcurrentSameKeyDifferentRequestRefusedWithoutSideEffects(t *testing.T) {
	const id = "sb-lease-diff001"
	h := newLeaseHarness(t, id, true)
	first := make(chan createResult, 1)
	go func() {
		resp, err := h.svc.CreateSandboxWithID(keyedCtx("job-2"), models.CreateSandboxRequest{Image: "alpine:3.20", CreateRequestDigests: []string{"hmac:0:aaaa"}}, id)
		first <- createResult{resp, err}
	}()
	<-h.rt.entered

	done := make(chan error, 1)
	go func() {
		_, err := h.svc.CreateSandboxWithID(keyedCtx("job-2"), models.CreateSandboxRequest{Image: "alpine:3.21", CreateRequestDigests: []string{"hmac:0:bbbb"}}, id)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, models.ErrIdempotencyKeyReused) {
			t.Fatalf("different request = %v, want ErrIdempotencyKeyReused", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a different request waited for the first create instead of being refused")
	}
	if got := h.rt.createCount(); got != 1 {
		t.Fatalf("runtime creates = %d, want 1", got)
	}
	h.assertOneReservation(t, "after the refusal")
	h.assertMountsIntact(t)
	close(h.rt.hold)
	if r := <-first; r.err != nil {
		t.Fatalf("first create = %v", r.err)
	}
}

// The first create fails and rolls back; the retry that waited for it
// creates afresh and succeeds.
func TestRetryAfterFailedCreateCreatesAfresh(t *testing.T) {
	const id = "sb-lease-fail001"
	h := newLeaseHarness(t, id, true)
	h.rt.failNext = errors.New("image pull timed out")
	req := models.CreateSandboxRequest{Image: "alpine:3.20", CreateRequestDigests: []string{"hmac:0:aaaa"}}

	first := make(chan createResult, 1)
	go func() {
		resp, err := h.svc.CreateSandboxWithID(keyedCtx("job-3"), req, id)
		first <- createResult{resp, err}
	}()
	<-h.rt.entered
	retry := make(chan createResult, 1)
	go func() {
		resp, err := h.svc.CreateSandboxWithID(keyedCtx("job-3"), req, id)
		retry <- createResult{resp, err}
	}()
	time.Sleep(20 * time.Millisecond)
	close(h.rt.hold)

	if r := <-first; r.err == nil {
		t.Fatal("the first create succeeded; the test needs it to fail")
	}
	r := <-retry
	if r.err != nil || r.resp.Sandbox.ID != id || r.resp.Replayed {
		t.Fatalf("retry after the failure = %+v, %v; want a fresh create of %s", r.resp, r.err, id)
	}
	if n := h.rt.createCount(); n != 2 {
		t.Fatalf("runtime creates = %d, want 2 (the failed one, then the retry's)", n)
	}
	h.assertOneReservation(t, "after the retry")
}

// A waiting retry whose client goes away gives up; the create it waited for
// is untouched and finishes.
func TestCancelledWaiterLeavesTheFirstCreateAlone(t *testing.T) {
	tests := []struct {
		name    string
		wait    time.Duration // testCreateLeaseWait; 0 = the default bound
		cancel  bool
		wantErr error
	}{
		{name: "client gone", cancel: true, wantErr: context.Canceled},
		{name: "wait bound reached", wait: 30 * time.Millisecond, wantErr: ErrCreateInProgress},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const id = "sb-lease-cncl001"
			h := newLeaseHarness(t, id, true)
			h.svc.testCreateLeaseWait = tt.wait
			req := models.CreateSandboxRequest{Image: "alpine:3.20", CreateRequestDigests: []string{"hmac:0:aaaa"}}
			first := make(chan createResult, 1)
			go func() {
				resp, err := h.svc.CreateSandboxWithID(keyedCtx("job-4"), req, id)
				first <- createResult{resp, err}
			}()
			<-h.rt.entered

			ctx, cancel := context.WithCancel(keyedCtx("job-4"))
			defer cancel()
			waiter := make(chan error, 1)
			go func() {
				_, err := h.svc.CreateSandboxWithID(ctx, req, id)
				waiter <- err
			}()
			if tt.cancel {
				time.Sleep(20 * time.Millisecond)
				cancel()
			}
			if err := <-waiter; !errors.Is(err, tt.wantErr) {
				t.Fatalf("waiter = %v, want %v", err, tt.wantErr)
			}
			h.assertOneReservation(t, "after the waiter gave up")
			h.assertMountsIntact(t)
			close(h.rt.hold)
			r := <-first
			if r.err != nil || r.resp.Sandbox.ID != id {
				t.Fatalf("first create = %+v, %v", r.resp, r.err)
			}
			if n := h.rt.createCount(); n != 1 {
				t.Fatalf("runtime creates = %d, want 1", n)
			}
			h.assertOneReservation(t, "after the first create")
		})
	}
}

// Defence in depth behind the lease: a create that fails because its ID is
// taken releases nothing it did not make. Before, it released the holder's
// reservation (Admit had overwritten it) and removed rootDir/<id>.
func TestCreateOnATakenIDReleasesOnlyWhatItMade(t *testing.T) {
	const id = "sb-lease-taken01"
	tests := []struct {
		name string
		// held: another holder (the live sandbox, or a create that went
		// around the lease) has the ID's reservation and mounts.
		held          bool
		wantActive    int
		wantSentinel  bool
		wantErrExists bool
	}{
		{name: "the holder's reservation and mounts stay", held: true, wantActive: 1, wantSentinel: true, wantErrExists: true},
		{name: "an orphan instance: this create's own reservation goes", held: false, wantActive: 0, wantSentinel: true, wantErrExists: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newLeaseHarness(t, id, false)
			// The ID's runtime instance exists, as the holder's container
			// does: this create's runtime create collides on the name.
			h.rt.names[id] = true
			if tt.held {
				h.admitter.Reserve(id, capacity.Request{CPU: models.DefaultCPU, MemoryMB: models.DefaultMemoryMB, Runtime: models.RuntimeDocker})
			}
			// createSandbox directly: the path that would run if a caller
			// reached the side effects without CreateSandboxWithID's row
			// check.
			_, err := h.svc.createSandbox(t.Context(), models.CreateSandboxRequest{Image: "alpine:3.20"}, id)
			if tt.wantErrExists && !errors.Is(err, models.ErrSandboxExists) {
				t.Fatalf("create on a taken id = %v, want ErrSandboxExists", err)
			}
			if got := h.admitter.Snapshot().SandboxesActive; got != tt.wantActive {
				t.Fatalf("active reservations = %d, want %d", got, tt.wantActive)
			}
			if tt.held {
				h.assertOneReservation(t, "after the failed create")
			}
			if tt.wantSentinel {
				h.assertMountsIntact(t)
			}
		})
	}
}

// A create whose row insert finds the ID taken replays the stored sandbox
// and leaves the holder's reservation in place.
func TestRowCollisionKeepsTheHoldersReservation(t *testing.T) {
	const id = "sb-lease-row0001"
	h := newLeaseHarness(t, id, false)
	stored, err := h.svc.CreateSandboxWithID(keyedCtx("job-5"), models.CreateSandboxRequest{Image: "alpine:3.20"}, id)
	if err != nil {
		t.Fatal(err)
	}
	h.assertOneReservation(t, "after the first create")
	// The first instance is gone (say, destroyed out of band) but its row
	// stays: this create's runtime create succeeds and its insert collides.
	delete(h.rt.names, id)
	resp, err := h.svc.createSandbox(keyedCtx("job-5"), models.CreateSandboxRequest{Image: "alpine:3.20"}, id)
	if err != nil || !resp.Replayed || resp.Sandbox.ToolboxToken != stored.Sandbox.ToolboxToken {
		t.Fatalf("create on a stored id = %+v, %v; want a replay of the stored row", resp, err)
	}
	h.assertOneReservation(t, "after the collision")
	h.assertMountsIntact(t)
}

// failingUpsertWriter refuses the route upsert, as an unreachable Caddy does.
type failingUpsertWriter struct{ recordingRouteWriter }

func (f *failingUpsertWriter) UpsertSandboxRoute(context.Context, string, string, int, []caddy.CustomHostnameRoute) error {
	f.rec("UpsertSandboxRoute")
	return errors.New("caddy unreachable")
}

// A create that fails on a row collision undoes its own route and puts the
// stored sandbox's back; any other failure only deletes.
func TestRollbackCreatePublicRoutes(t *testing.T) {
	const id = "sb-lease-route01"
	public, private := true, false
	tests := []struct {
		name      string
		idTaken   bool
		stored    *bool // AllowPublicTraffic of the row holding the id; nil = no row
		failing   bool
		wantCalls []string
	}{
		{name: "an ordinary failure deletes its route", idTaken: false, stored: &public, wantCalls: []string{"DeleteSandboxRoute"}},
		{name: "a collision with a private sandbox leaves no route", idTaken: true, stored: &private, wantCalls: []string{"DeleteSandboxRoute"}},
		{name: "a collision with a public sandbox puts its route back", idTaken: true, stored: &public, wantCalls: []string{"DeleteSandboxRoute", "UpsertSandboxRoute"}},
		{name: "a route that cannot be put back is logged for reconcile", idTaken: true, stored: &public, failing: true, wantCalls: []string{"DeleteSandboxRoute", "UpsertSandboxRoute"}},
		{name: "no row to restore from", idTaken: true, wantCalls: []string{"DeleteSandboxRoute"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newLeaseHarness(t, id, false)
			if tt.stored != nil {
				if _, err := h.svc.CreateSandboxWithID(t.Context(), models.CreateSandboxRequest{Image: "alpine:3.20", AllowPublicTraffic: tt.stored}, id); err != nil {
					t.Fatal(err)
				}
			}
			var rec *recordingRouteWriter
			if tt.failing {
				w := &failingUpsertWriter{}
				h.svc.routeWriter, rec = w, &w.recordingRouteWriter
			} else {
				rec = &recordingRouteWriter{}
				h.svc.routeWriter = rec
			}
			h.svc.rollbackCreatePublicRoutes(t.Context(), &models.Sandbox{ID: id, ContainerIP: "10.0.0.9"}, tt.idTaken)
			if strings.Join(rec.calls, ",") != strings.Join(tt.wantCalls, ",") {
				t.Fatalf("route calls = %v, want %v", rec.calls, tt.wantCalls)
			}
		})
	}
}
