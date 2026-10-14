package daytona

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

type daytonaForwardCluster struct {
	*cluster.Noop
	target          cluster.PlacementTarget
	reservedID      string
	reservedReq     *models.CreateSandboxRequest
	forwardedTarget string
	forwardedID     string
	forwardedBody   []byte
}

func (c *daytonaForwardCluster) SelectPlacement(capacity.Request) (cluster.PlacementTarget, error) {
	return c.target, nil
}

func (c *daytonaForwardCluster) SelectPlacementWithCandidates(capacity.Request) (cluster.PlacementTarget, []cluster.Member, error) {
	return c.target, []cluster.Member{{NodeID: c.target.NodeID, APIURL: c.target.APIURL, Alive: true}}, nil
}

// SelectPlacementForCreate is what the create path calls now. Without it the
// embedded Noop answers and the create never leaves the router.
func (c *daytonaForwardCluster) SelectPlacementForCreate(req capacity.Request, sandboxID string, recipientBackups int) (cluster.PlacementTarget, []string, error) {
	target, candidates, err := c.SelectPlacementWithCandidates(req)
	if err != nil {
		return cluster.PlacementTarget{}, nil, err
	}
	if recipientBackups <= 0 {
		return target, nil, nil
	}
	return target, cluster.SelectSecretRecipients(sandboxID, candidates, target.NodeID, recipientBackups), nil
}

func (c *daytonaForwardCluster) ReserveOnTarget(_ context.Context, sandboxID string, _ cluster.PlacementTarget, redacted *models.CreateSandboxRequest, _ cluster.PlacementSecrets, _ time.Duration) error {
	c.reservedID = sandboxID
	c.reservedReq = redacted
	return nil
}

func (c *daytonaForwardCluster) ForwardHTTP(_ cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	c.forwardedTarget = r.Header.Get("X-Cluster-Create-Target")
	c.forwardedID = r.Header.Get("X-Cluster-Create-ID")
	c.forwardedBody, _ = io.ReadAll(r.Body)
	w.WriteHeader(http.StatusAccepted)
}

func (c *daytonaForwardCluster) AttachInternalHandler(http.Handler) {}

func TestCreateSandboxClusterForwardBuildsOnTargetNotRouter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &daytonaForwardCluster{
		Noop:   cluster.NewNoop("router", "http://router", ""),
		target: cluster.PlacementTarget{NodeID: "worker-a", APIURL: "http://worker-a:21212"},
	}
	svc.AttachCluster(fakeCluster)
	builder := &fakeImageBuilder{}
	h := newHandlers(Deps{
		Service: withBuilder(svc, builder),
		Logger:  logger,
	})

	body := `{"name":"sdk-build","buildInfo":{"dockerfileContent":"FROM alpine\nRUN echo target"}}`
	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.createSandbox(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}
	if len(builder.builds) != 0 {
		t.Fatalf("router built %d images; build must happen only on selected worker", len(builder.builds))
	}
	if fakeCluster.forwardedTarget != "worker-a" || fakeCluster.forwardedID == "" || fakeCluster.forwardedID != fakeCluster.reservedID {
		t.Fatalf("forward headers target=%q id=%q reserved=%q", fakeCluster.forwardedTarget, fakeCluster.forwardedID, fakeCluster.reservedID)
	}
	if fakeCluster.reservedReq == nil || fakeCluster.reservedReq.Name != "sdk-build" {
		t.Fatalf("reserved request = %+v, want Daytona name carried for cluster-wide uniqueness", fakeCluster.reservedReq)
	}
	// The forwarded request must carry the original wire body so the target
	// re-translates it; an empty body would 400/502 on the worker (B2).
	if !strings.Contains(string(fakeCluster.forwardedBody), "sdk-build") {
		t.Fatalf("forwarded body = %q, want the original Daytona create body", fakeCluster.forwardedBody)
	}
}

type daytonaOwnerForwardCluster struct {
	*cluster.Noop
	owner         cluster.OwnerInfo
	ownerErr      error
	nameID        string
	nameOwner     cluster.OwnerInfo
	nameErr       error
	forwarded     bool
	forwardedPeer string
}

func (c *daytonaOwnerForwardCluster) OwnerOf(string) (cluster.OwnerInfo, error) {
	if c.ownerErr != nil {
		return cluster.OwnerInfo{}, c.ownerErr
	}
	return c.owner, nil
}

func (c *daytonaOwnerForwardCluster) OwnerOfName(string, string) (string, cluster.OwnerInfo, error) {
	if c.nameErr != nil {
		return "", cluster.OwnerInfo{}, c.nameErr
	}
	return c.nameID, c.nameOwner, nil
}

func (c *daytonaOwnerForwardCluster) ForwardHTTP(target cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	c.forwarded = true
	if target.InternalURL != "" {
		c.forwardedPeer = target.InternalURL
	} else {
		c.forwardedPeer = target.APIURL
	}
	w.WriteHeader(http.StatusAccepted)
}

func TestClusterForwardWrapResolvesDaytonaNameToOwner(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &daytonaOwnerForwardCluster{
		Noop:      cluster.NewNoop("router", "http://router", ""),
		ownerErr:  cluster.ErrUnknownSandbox,
		nameID:    "sb-named",
		nameOwner: cluster.OwnerInfo{NodeID: "worker-a", APIURL: "http://worker-a:21212"},
	}
	svc.AttachCluster(fakeCluster)
	h := newHandlers(Deps{Service: svc, Logger: logger})

	localCalled := false
	wrapped := h.clusterForwardWrap("idOrName", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		localCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/named", nil)
	req.SetPathValue("idOrName", "named")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}
	if localCalled {
		t.Fatal("local handler ran on router; name-owned request must forward to owner")
	}
	if !fakeCluster.forwarded || fakeCluster.forwardedPeer != "http://worker-a:21212" {
		t.Fatalf("forwarded=%v peer=%q, want worker API URL", fakeCluster.forwarded, fakeCluster.forwardedPeer)
	}
}

func TestClusterForwardWrapReturnsGoneForOrphanedDaytonaPlacement(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&daytonaOwnerForwardCluster{
		Noop:     cluster.NewNoop("router", "http://router", ""),
		ownerErr: cluster.ErrOrphaned,
	})
	h := newHandlers(Deps{Service: svc, Logger: logger})

	wrapped := h.clusterForwardWrap("idOrName", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("local handler ran for orphaned placement")
	}))
	req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/sb-orphan", nil)
	req.SetPathValue("idOrName", "sb-orphan")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusGone {
		t.Fatalf("status = %d, want %d; body=%q", rr.Code, http.StatusGone, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "placement orphaned") {
		t.Fatalf("body = %q, want orphaned error", rr.Body.String())
	}
}

// Placement must be told the runtime: a WASM-labeled create produces a
// placement request with the WASM runtime so the scheduler picks a node with
// WASM support, instead of scoring it as docker (B4).
func TestClusterPlacementRequestCarriesWasmRuntime(t *testing.T) {
	h := newHandlers(Deps{}) // nil service: no snapshot/module lookup, label path
	labels := map[string]string{"runtime": "wasm", "module_ref": "python:3.12"}
	name := "wasm-box"
	out, err := h.clusterPlacementRequest(context.Background(), createSandboxRequest{Name: &name, Labels: &labels})
	if err != nil || out.Runtime != models.RuntimeWasm || out.ModuleRef != "python:3.12" {
		t.Fatalf("placement request = %+v, %v; want wasm runtime + module ref", out, err)
	}

	// A plain (docker) create leaves the runtime unset, as before.
	dockerOut, err := h.clusterPlacementRequest(context.Background(), createSandboxRequest{Name: &name})
	if err != nil || dockerOut.Runtime != "" {
		t.Fatalf("docker placement request runtime = %q, %v; want empty", dockerOut.Runtime, err)
	}

	// A WASM label with no module ref is a bad request, surfaced at placement.
	badLabels := map[string]string{"runtime": "wasm"}
	if _, err := h.clusterPlacementRequest(context.Background(), createSandboxRequest{Name: &name, Labels: &badLabels}); err == nil {
		t.Fatal("wasm label without a module ref should fail placement translation")
	}
}

// An Idempotency-Key on the cluster path threads into the reservation id, so a
// retry reserves the same id (ErrReservationConflict routes to the existing
// placement) instead of placing a second sandbox. Without the key the reserved
// id is freshly minted each call. On the pre-fix code Prepare always minted a
// fresh id, so the same-key reservations would differ — this test fails there.
func TestDaytonaCreateClusterForwardIdempotencyKeyFixesReservedID(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	env := newDaytonaContractEnv(t)
	fakeCluster := &daytonaForwardCluster{
		Noop:   cluster.NewNoop("router", "http://router", ""),
		target: cluster.PlacementTarget{NodeID: "worker-a", APIURL: "http://worker-a:21212"},
	}
	env.service.AttachCluster(fakeCluster)
	h := &handlers{deps: Deps{Service: env.service, Logger: logger}}

	post := func(key string) string {
		fakeCluster.reservedID = ""
		req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(`{"snapshot":"alpine:3.20"}`))
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		rr := httptest.NewRecorder()
		h.createSandbox(rr, req)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (forwarded); body=%s", rr.Code, rr.Body.String())
		}
		if fakeCluster.reservedID == "" {
			t.Fatalf("no reservation recorded for key %q", key)
		}
		return fakeCluster.reservedID
	}

	withKey1 := post("key-xyz")
	withKey2 := post("key-xyz")
	if withKey1 != withKey2 {
		t.Fatalf("same key reserved different ids %q vs %q", withKey1, withKey2)
	}
	if noKey := post(""); noKey == withKey1 {
		t.Fatalf("keyless create reused the keyed reservation id %q", noKey)
	}
}
