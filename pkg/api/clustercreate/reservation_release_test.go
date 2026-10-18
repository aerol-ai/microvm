package clustercreate

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// nameReservingCluster models what the release depends on: a reservation
// claims its sandbox name cluster-wide until it is cancelled or promoted, and
// a forwarded create is answered by a target handler the test supplies. It is
// safe for concurrent Prepare calls, unlike clusterStub.
type nameReservingCluster struct {
	*cluster.Noop
	target cluster.PlacementTarget
	// answer is the target node's handling of a forwarded create.
	answer func(c *nameReservingCluster, w http.ResponseWriter, r *http.Request)

	mu         sync.Mutex
	names      map[string]string // name → id of the reservation or sandbox holding it
	placements map[string]cluster.Placement
	nameOf     map[string]string // id → name
	cancels    int
	// clientSawRefusal records, at each cancel, whether the refusal had
	// already reached the client: the release must commit first.
	clientSawRefusal []bool
	client           *httptest.ResponseRecorder
}

func newNameReservingCluster(answer func(*nameReservingCluster, http.ResponseWriter, *http.Request)) *nameReservingCluster {
	return &nameReservingCluster{
		Noop:       cluster.NewNoop("ingress-1", "http://ingress-1", ""),
		target:     cluster.PlacementTarget{NodeID: "worker-z", APIURL: "http://worker-z", InternalURL: "https://worker-z.internal"},
		answer:     answer,
		names:      map[string]string{},
		placements: map[string]cluster.Placement{},
		nameOf:     map[string]string{},
	}
}

func (c *nameReservingCluster) SelectPlacementForCreate(_ capacity.Request, _ string, _ int) (cluster.PlacementTarget, []string, error) {
	return c.target, nil, nil
}

func (c *nameReservingCluster) ReserveOnTarget(_ context.Context, sandboxID string, target cluster.PlacementTarget, redacted *models.CreateSandboxRequest, _ cluster.PlacementSecrets, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	name := redacted.Name
	if holder, ok := c.names[name]; ok && name != "" && holder != sandboxID {
		return cluster.ErrNameConflict
	}
	if _, ok := c.placements[sandboxID]; ok {
		return cluster.ErrReservationConflict
	}
	if name != "" {
		c.names[name] = sandboxID
		c.nameOf[sandboxID] = name
	}
	c.placements[sandboxID] = cluster.Placement{
		SandboxID: sandboxID, OwnerNodeID: target.NodeID, IncarnationID: "inc-" + sandboxID,
		State: cluster.PlacementStateReserved, ExpiresUnix: time.Now().Add(ttl).Unix(),
	}
	return nil
}

func (c *nameReservingCluster) CancelReservation(_ context.Context, sandboxID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cancels++
	if c.client != nil {
		c.clientSawRefusal = append(c.clientSawRefusal, c.client.Body.Len() > 0)
	}
	p, ok := c.placements[sandboxID]
	if !ok || !p.IsReserved() {
		return nil // a cancel never touches a promoted sandbox
	}
	delete(c.placements, sandboxID)
	if name := c.nameOf[sandboxID]; c.names[name] == sandboxID {
		delete(c.names, name)
	}
	delete(c.nameOf, sandboxID)
	return nil
}

func (c *nameReservingCluster) ForwardHTTP(_ cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	c.answer(c, w, r)
}

// promote is the target's successful create: the reservation becomes a
// sandbox that keeps its name.
func (c *nameReservingCluster) promote(sandboxID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.placements[sandboxID]
	p.State = cluster.PlacementStatePlaced
	c.placements[sandboxID] = p
}

func (c *nameReservingCluster) holder(name string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.names[name]
}

func (c *nameReservingCluster) cancelCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cancels
}

// validatingTarget answers like a worker's create: 400 "image is required"
// for a request with no image — without cancelling the reservation itself,
// which is what a worker whose cancel read missed the reservation did, and
// what a refusal before its create handler (an auth 401, a 421) still does —
// and 201 after promoting the reservation otherwise.
func validatingTarget(c *nameReservingCluster, w http.ResponseWriter, r *http.Request) {
	var req models.CreateSandboxRequest
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &req)
	if req.Image == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "image is required")
		return
	}
	id := r.Header.Get(HeaderID)
	c.promote(id)
	apihttp.WriteJSON(w, http.StatusCreated, models.CreateSandboxResponse{Sandbox: models.Sandbox{ID: id, Name: req.Name}})
}

// createThroughRouter is one POST /v1/sandboxes reaching the router.
func createThroughRouter(t *testing.T, c *nameReservingCluster, req models.CreateSandboxRequest, opts PrepareOptions) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	c.mu.Lock()
	c.client = w
	c.mu.Unlock()
	opts.SyncBody = true
	if _, ok := Prepare(w, r, testServiceWithCluster(c), req, apihttp.WriteErrorCode, opts); ok {
		t.Fatal("Prepare ran the create locally; the test routes every create to worker-z")
	}
	return w
}

// TestForwardedCreateRefusalReleasesTheName is the live finding: a create the
// worker refused with 400 "image is required" kept its name reserved for
// ReservationTTL, so the corrected retry got 409 "sandbox name already in use
// cluster-wide" for two minutes and the invalid request resent got 409
// instead of 400.
func TestForwardedCreateRefusalReleasesTheName(t *testing.T) {
	c := newNameReservingCluster(validatingTarget)
	const name = "demo-retry"

	first := createThroughRouter(t, c, models.CreateSandboxRequest{Name: name}, PrepareOptions{})
	if first.Code != http.StatusBadRequest || !strings.Contains(first.Body.String(), "image is required") {
		t.Fatalf("create without an image = %d %s, want 400 image is required", first.Code, first.Body.String())
	}
	if h := c.holder(name); h != "" {
		t.Fatalf("the refused create still holds %q (reservation %s)", name, h)
	}
	for i, saw := range c.clientSawRefusal {
		if saw {
			t.Fatalf("cancel %d ran after the 400 reached the client; an immediate retry could race it", i)
		}
	}

	again := createThroughRouter(t, c, models.CreateSandboxRequest{Name: name}, PrepareOptions{})
	if again.Code != http.StatusBadRequest {
		t.Fatalf("the invalid request resent = %d %s, want 400 again, not 409", again.Code, again.Body.String())
	}

	fixed := createThroughRouter(t, c, models.CreateSandboxRequest{Name: name, Image: "alpine:3.20"}, PrepareOptions{})
	if fixed.Code != http.StatusCreated {
		t.Fatalf("the corrected retry right after the refusal = %d %s, want 201", fixed.Code, fixed.Body.String())
	}
	if h := c.holder(name); h == "" {
		t.Fatal("the created sandbox does not hold its name")
	}

	// The name is the sandbox's now: a duplicate is refused, and its
	// router-side 409 releases nothing.
	before := c.cancelCount()
	dup := createThroughRouter(t, c, models.CreateSandboxRequest{Name: name, Image: "alpine:3.20"}, PrepareOptions{})
	if dup.Code != http.StatusConflict {
		t.Fatalf("a duplicate of a live sandbox = %d, want 409", dup.Code)
	}
	if c.cancelCount() != before {
		t.Fatal("a create refused before any forward cancelled a reservation it never made")
	}
}

// TestForwardedCreateKeepsTheReservationOnServerErrors: a 5xx, a gateway
// failure or a timeout may mean the target is still creating, so the
// reservation stays until the target finishes or the expiry sweep runs, as
// before. Only a 4xx is a verdict.
func TestForwardedCreateKeepsTheReservationOnServerErrors(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			c := newNameReservingCluster(func(_ *nameReservingCluster, w http.ResponseWriter, _ *http.Request) {
				apihttp.WriteError(w, status, "target trouble")
			})
			w := createThroughRouter(t, c, models.CreateSandboxRequest{Name: "demo-5xx", Image: "alpine:3.20"}, PrepareOptions{})
			if w.Code != status {
				t.Fatalf("status = %d, want the target's %d passed through", w.Code, status)
			}
			if c.cancelCount() != 0 || c.holder("demo-5xx") == "" {
				t.Fatalf("a %d released the reservation (cancels %d)", status, c.cancelCount())
			}
			retry := createThroughRouter(t, c, models.CreateSandboxRequest{Name: "demo-5xx", Image: "alpine:3.20"}, PrepareOptions{})
			if retry.Code != http.StatusConflict {
				t.Fatalf("a retry while the reservation stands = %d, want 409 (today's behavior)", retry.Code)
			}
		})
	}
}

// TestForwardedCreateConflictKeepsTheReservation: a target's 409 can follow
// a create that succeeded and then lost its promote to a name race; if that
// retract's destroy failed, the sandbox is still live under the Reserved row,
// and cancelling the row would let ownership replay resurrect it. So a 409
// passes straight through and keeps today's behavior.
func TestForwardedCreateConflictKeepsTheReservation(t *testing.T) {
	c := newNameReservingCluster(func(_ *nameReservingCluster, w http.ResponseWriter, _ *http.Request) {
		apihttp.WriteError(w, http.StatusConflict, "sandbox name already in use cluster-wide")
	})
	w := createThroughRouter(t, c, models.CreateSandboxRequest{Name: "demo-409", Image: "alpine:3.20"}, PrepareOptions{})
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want the target's 409 passed through", w.Code)
	}
	if c.cancelCount() != 0 || c.holder("demo-409") == "" {
		t.Fatalf("a forwarded 409 released the reservation (cancels %d)", c.cancelCount())
	}
}

// TestForwardedCreateRefusalKeepsAnIdempotencyKeyReservation: with an
// Idempotency-Key every replay shares the id, and a replay routes to the
// standing reservation instead of reserving, so the router must not cancel
// it under a replay that may be creating right now.
func TestForwardedCreateRefusalKeepsAnIdempotencyKeyReservation(t *testing.T) {
	c := newNameReservingCluster(validatingTarget)
	w := createThroughRouter(t, c, models.CreateSandboxRequest{Name: "demo-key"}, PrepareOptions{PreferredSandboxID: "sb-00000000000000ab"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want the target's 400", w.Code)
	}
	if c.cancelCount() != 0 || c.holder("demo-key") != "sb-00000000000000ab" {
		t.Fatalf("an Idempotency-Key reservation was released by the router (cancels %d)", c.cancelCount())
	}
}

// TestConcurrentDuplicateCreatesStillRefused: releasing on a refusal must not
// weaken the name guard. Two creates with one name at once: exactly one 201,
// the other 409, and only once the winner's reservation is in place.
func TestConcurrentDuplicateCreatesStillRefused(t *testing.T) {
	for round := 0; round < 20; round++ {
		gate := make(chan struct{})
		c := newNameReservingCluster(func(c *nameReservingCluster, w http.ResponseWriter, r *http.Request) {
			<-gate // the winner's create is in flight while the loser tries
			validatingTarget(c, w, r)
		})
		var wg sync.WaitGroup
		codes := make([]int, 2)
		for i := range codes {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				raw, _ := json.Marshal(models.CreateSandboxRequest{Name: "demo-race", Image: "alpine:3.20"})
				r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", bytes.NewReader(raw))
				rec := httptest.NewRecorder()
				Prepare(rec, r, testServiceWithCluster(c), models.CreateSandboxRequest{Name: "demo-race", Image: "alpine:3.20"}, apihttp.WriteErrorCode, PrepareOptions{SyncBody: true})
				codes[i] = rec.Code
			}(i)
		}
		// Let the loser reach its reservation while the winner is held.
		deadline := time.Now().Add(5 * time.Second)
		for c.holder("demo-race") == "" && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(5 * time.Millisecond)
		close(gate)
		wg.Wait()
		created, conflicts := 0, 0
		for _, code := range codes {
			switch code {
			case http.StatusCreated:
				created++
			case http.StatusConflict:
				conflicts++
			}
		}
		if created != 1 || conflicts != 1 {
			t.Fatalf("round %d: statuses %v, want exactly one 201 and one 409", round, codes)
		}
		if c.cancelCount() != 0 {
			t.Fatalf("round %d: a duplicate refused by the name guard cancelled a reservation", round)
		}
	}
}

// TestRejectionHold covers the writer's edges: what it holds, what it lets
// through, and how a release behaves.
func TestRejectionHold(t *testing.T) {
	t.Run("a 2xx streams through at once", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h := &rejectionHold{ResponseWriter: rec}
		_, _ = h.Write([]byte("ok")) // an implicit 200
		h.Flush()
		if rec.Code != http.StatusOK || rec.Body.String() != "ok" || !rec.Flushed || h.rejected() {
			t.Fatalf("code %d body %q flushed %v rejected %v", rec.Code, rec.Body.String(), rec.Flushed, h.rejected())
		}
		h.WriteHeader(http.StatusTeapot) // a second status is ignored
		if h.rejected() {
			t.Fatal("a later WriteHeader changed the verdict")
		}
		if h.Unwrap() != rec {
			t.Fatal("Unwrap does not return the client writer")
		}
	})

	t.Run("a 4xx is held until release, flushes included", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h := &rejectionHold{ResponseWriter: rec}
		h.Header().Set("Content-Type", "application/json")
		h.WriteHeader(http.StatusUnauthorized)
		_, _ = h.Write([]byte(`{"error":"unauthorized"}`))
		h.Flush()
		if rec.Body.Len() != 0 || rec.Flushed {
			t.Fatalf("the refusal leaked before release: %q flushed %v", rec.Body.String(), rec.Flushed)
		}
		if !h.rejected() {
			t.Fatal("a 401 is not a refusal")
		}
		h.release()
		h.release() // idempotent
		if rec.Code != http.StatusUnauthorized || rec.Body.String() != `{"error":"unauthorized"}` || rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("released %d %q %v", rec.Code, rec.Body.String(), rec.Header())
		}
	})

	t.Run("a 1xx goes straight through ahead of a held refusal", func(t *testing.T) {
		log := &statusLog{ResponseRecorder: httptest.NewRecorder()}
		h := &rejectionHold{ResponseWriter: log}
		h.WriteHeader(http.StatusEarlyHints)
		h.WriteHeader(http.StatusForbidden)
		if len(log.statuses) != 1 || log.statuses[0] != http.StatusEarlyHints {
			t.Fatalf("statuses before release = %v, want only the 103", log.statuses)
		}
		h.release()
		if len(log.statuses) != 2 || log.statuses[1] != http.StatusForbidden {
			t.Fatalf("statuses after release = %v, want 103 then 403", log.statuses)
		}
	})

	t.Run("a 409 streams through and is not a refusal", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h := &rejectionHold{ResponseWriter: rec}
		h.WriteHeader(http.StatusConflict)
		_, _ = h.Write([]byte("taken"))
		if rec.Code != http.StatusConflict || rec.Body.String() != "taken" || h.rejected() {
			t.Fatalf("code %d body %q rejected %v, want a pass-through 409", rec.Code, rec.Body.String(), h.rejected())
		}
	})

	t.Run("an oversized refusal is let through", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h := &rejectionHold{ResponseWriter: rec}
		h.WriteHeader(http.StatusBadRequest)
		big := bytes.Repeat([]byte("x"), maxHeldRejectionBytes)
		_, _ = h.Write(big[:10])
		_, _ = h.Write(big)
		if rec.Code != http.StatusBadRequest || rec.Body.Len() != 10+len(big) {
			t.Fatalf("code %d, %d bytes through, want all %d", rec.Code, rec.Body.Len(), 10+len(big))
		}
		h.release()
		if rec.Body.Len() != 10+len(big) {
			t.Fatal("a release after the overflow wrote the body twice")
		}
	})
}

// statusLog records every status written, 1xx included, which
// httptest.ResponseRecorder collapses into its first.
type statusLog struct {
	*httptest.ResponseRecorder
	statuses []int
}

func (l *statusLog) WriteHeader(status int) { l.statuses = append(l.statuses, status) }
