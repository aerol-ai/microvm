package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeGateway records the egress API calls sandboxd makes.
type fakeGateway struct {
	mu           sync.Mutex
	attached     map[string]egress.Spec
	detached     []string
	blocked      map[string]egress.BlockReason
	synced       [][]egress.Spec
	tokens       []egress.SyncToken
	tok          egress.SyncToken
	tokErr       error
	bridges      []egress.Bridge
	attachErr    error
	readyErr     error
	events       chan egress.Event
	probeRes     egress.ProbeResult
	probeErr     error
	control      []netip.AddrPort
	controlCalls int
	learned      map[string]json.RawMessage
	learnedErr   error
	forgotten    []string
	inspectCA    []egress.InspectCA
	inspectErr   error
	retained     []string
	retains      int
}

func newFakeGateway() *fakeGateway {
	return &fakeGateway{attached: map[string]egress.Spec{}, blocked: map[string]egress.BlockReason{}}
}

func (f *fakeGateway) Attach(_ context.Context, s egress.Spec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.attachErr != nil {
		return f.attachErr
	}
	f.attached[s.ID] = s
	return nil
}
func (f *fakeGateway) Update(ctx context.Context, s egress.Spec) error { return f.Attach(ctx, s) }
func (f *fakeGateway) Detach(_ context.Context, id string, _ netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detached = append(f.detached, id)
	delete(f.attached, id)
	return nil
}
func (f *fakeGateway) SetBlocked(_ context.Context, id string, r egress.BlockReason, on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if on {
		f.blocked[id] |= r
	} else {
		f.blocked[id] &^= r
	}
	return nil
}
func (f *fakeGateway) SyncToken(context.Context) (egress.SyncToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tok, f.tokErr
}
func (f *fakeGateway) Sync(_ context.Context, specs []egress.Spec, tok egress.SyncToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.synced = append(f.synced, specs)
	f.tokens = append(f.tokens, tok)
	return nil
}
func (f *fakeGateway) Ready(context.Context) (egress.ReadyStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return egress.ReadyStatus{Layout: true}, f.readyErr
}
func (f *fakeGateway) SetBridges(_ context.Context, b []egress.Bridge) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bridges = b
	return nil
}
func (f *fakeGateway) Probe(_ context.Context, p egress.ProbeRequest) (egress.ProbeResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p.Begin {
		return egress.ProbeResult{}, f.probeErr
	}
	return f.probeRes, f.probeErr
}
func (f *fakeGateway) Learned(_ context.Context, id string) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.learnedErr != nil {
		return nil, f.learnedErr
	}
	if raw, ok := f.learned[id]; ok {
		return raw, nil
	}
	return json.RawMessage(`{"truncated":false,"entries":[],"cidrs":[],"suggested_allow_out":[],"suggested_profile":null}`), nil
}

func (f *fakeGateway) ForgetLearned(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forgotten = append(f.forgotten, id)
	delete(f.learned, id)
	return nil
}
func (f *fakeGateway) RetainLearned(_ context.Context, ids []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retained = append([]string(nil), ids...)
	f.retains++
	return nil
}
func (f *fakeGateway) SetInspectCA(_ context.Context, ca egress.InspectCA) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.inspectErr != nil {
		return f.inspectErr
	}
	f.inspectCA = append(f.inspectCA, ca)
	return nil
}
func (f *fakeGateway) SetNodeControl(_ context.Context, eps []netip.AddrPort) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.control = append([]netip.AddrPort(nil), eps...)
	f.controlCalls++
	return nil
}
func (f *fakeGateway) Subscribe(ctx context.Context) (<-chan egress.Event, error) {
	if f.events == nil {
		return nil, egress.ErrUnavailable
	}
	return f.events, nil
}

func (f *fakeGateway) isAttached(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.attached[id]
	return ok
}

// holdRuntime adds the EgressHolder to the recording runtime.
type holdRuntime struct {
	*recordingRuntime
	mu     sync.Mutex
	holds  []string
	unhold []string
}

func (h *holdRuntime) ApplyEgressHold(ip string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.holds = append(h.holds, ip)
	return nil
}

func (h *holdRuntime) ClearEgressHold(ip string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.unhold = append(h.unhold, ip)
	return nil
}

func newEgressHarness(t *testing.T) (*Service, *fakeGateway, *holdRuntime) {
	t.Helper()
	rt := &holdRuntime{recordingRuntime: &recordingRuntime{}}
	svc, _, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	svc.cfg.EgressFQDNEnabled = true
	gw := newFakeGateway()
	// A live (silent) event stream, as a healthy gateway has; without one
	// the subscriber marks the gateway down. Tests that need events replace it.
	gw.events = make(chan egress.Event)
	svc.SetEgressGateway(gw, func(context.Context) []egress.Bridge {
		return []egress.Bridge{{Name: "docker0", GatewayIP: netip.MustParseAddr("172.17.0.1")}}
	})
	return svc, gw, rt
}

func TestCreateHostnamePolicyNeedsGateway(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"pypi.org"}})
	if !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("err = %v, want 501 (no gateway)", err)
	}
	if rt.createCalls != 0 {
		t.Fatal("runtime must not be called")
	}
	svc.cfg.EgressFQDNEnabled = true
	svc.SetEgressGateway(newFakeGateway(), nil)
	svc.cfg.ContainerPrivileged = true
	if _, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"pypi.org"}}); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("privileged node err = %v, want 501 (CEO D18)", err)
	}
}

// TestCreateGatewayModeAttaches covers §5.7: the driver gets the
// driver-facing copy (block-all, no lists), the gateway gets the real
// policy, and the driver block is lifted after the attach.
func TestCreateGatewayModeAttaches(t *testing.T) {
	svc, gw, rt := newEgressHarness(t)
	ctx := context.Background()
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"pypi.org", "10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	req := rt.lastCreateReq
	if !req.NetworkBlockAll || len(req.NetworkAllowOut) != 0 {
		t.Fatalf("driver req = block %v allow %v, want block-all and no lists", req.NetworkBlockAll, req.NetworkAllowOut)
	}
	spec, ok := gw.attached[resp.ID]
	if !ok || !slices.Equal(spec.AllowOut, []string{"pypi.org", "10.0.0.0/8"}) || spec.IP.String() != "10.0.0.2" {
		t.Fatalf("gateway spec = %+v, %v", spec, ok)
	}
	if !slices.Contains(rt.clearNetworkBlockEgresses, "10.0.0.2") {
		t.Fatal("the driver's temporary block must be lifted after the attach")
	}
	if len(gw.synced) != 1 || len(gw.bridges) != 1 {
		t.Fatalf("first attach must bootstrap: synced=%d bridges=%v", len(gw.synced), gw.bridges)
	}
	if resp.NetworkBlockAll || !slices.Contains(resp.NetworkAllowOut, "pypi.org") {
		t.Fatalf("stored row must keep the real policy: %+v", resp.Sandbox)
	}
	if st := svc.EgressStatus(ctx, &resp.Sandbox); st != EgressStatusActive {
		t.Fatalf("egress status = %q", st)
	}
}

func TestCreateGatewayAttachFailureRollsBack(t *testing.T) {
	svc, gw, rt := newEgressHarness(t)
	gw.attachErr = egress.ErrUnavailable
	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"pypi.org"}})
	if !errors.Is(err, ErrEgressGatewayUnavailable) {
		t.Fatalf("err = %v, want ErrEgressGatewayUnavailable (503)", err)
	}
	if len(rt.destroyIDs) == 0 {
		t.Fatal("a failed attach must roll the container back")
	}
	if len(gw.detached) == 0 {
		t.Fatal("rollback must detach from the gateway")
	}
	if slices.Contains(rt.clearNetworkBlockEgresses, "10.0.0.2") {
		t.Fatal("the driver block must never be lifted without an attach")
	}
	if svc.egressStats.attachFailed.Load() == 0 {
		t.Fatal("attach failures must be counted")
	}
}

// TestReplayCreateHoldsInsteadOfFailing: a failover recreate never refuses
// its stored spec; the sandbox comes up held (CEO D16).
func TestReplayCreateHoldsInsteadOfFailing(t *testing.T) {
	svc, gw, rt := newEgressHarness(t)
	gw.attachErr = egress.ErrUnavailable
	ctx := context.WithValue(context.Background(), storedSpecReplayKey{}, true)
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"pypi.org"}})
	if err != nil {
		t.Fatalf("replay must not fail: %v", err)
	}
	st, _ := svc.store.GetEgressState(ctx, resp.ID)
	if st.HoldReason != egressHoldUnavailable {
		t.Fatalf("hold = %q", st.HoldReason)
	}
	if len(rt.holds) != 1 {
		t.Fatal("the hold DROP must be installed")
	}
	if svc.EgressStatus(ctx, &resp.Sandbox) != EgressStatusUnavailable {
		t.Fatal("held for unavailability shows as unavailable")
	}
	// Reconcile retries and releases the hold once the gateway is back.
	gw.attachErr = nil
	row, _ := svc.store.Get(ctx, resp.ID)
	svc.reconcileSandboxEgress(ctx, row)
	if st, _ := svc.store.GetEgressState(ctx, resp.ID); st.HoldReason != "" {
		t.Fatal("a successful attach must release the hold")
	}
	if len(rt.unhold) != 1 || gw.blocked[resp.ID]&egress.BlockHold != 0 {
		t.Fatal("release must lift the hold DROP and the gateway block")
	}
}

func TestStartGatewayModeHoldsOnFailure(t *testing.T) {
	svc, gw, rt := newEgressHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sb := &models.Sandbox{ID: "sb-start", Image: "alpine", Status: models.SandboxStatusStopped, Runtime: models.RuntimeDocker,
		ContainerID: "ctr-start", NetworkAllowOut: []string{"pypi.org"}, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}
	if err := svc.store.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	gw.attachErr = egress.ErrUnavailable
	if _, err := svc.StartSandbox(ctx, sb.ID); err != nil {
		t.Fatalf("start must succeed held: %v", err)
	}
	if !slices.Contains(rt.applyNetworkBlockAllCalls, "10.0.0.3") {
		t.Fatal("start must shut the sandbox before attaching")
	}
	if st, _ := svc.store.GetEgressState(ctx, sb.ID); st.HoldReason == "" {
		t.Fatal("failed attach on start must hold")
	}
}

func TestEventsDetachGatewayMode(t *testing.T) {
	svc, gw, rt := newEgressHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sb := &models.Sandbox{ID: "sb-ev", Image: "alpine", Status: models.SandboxStatusStarted, Runtime: models.RuntimeDocker,
		ContainerIP: "10.0.0.9", NetworkAllowOut: []string{"pypi.org"}, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}
	if err := svc.markSandboxStopped(ctx, sb, docker.DockerEvent{SandboxID: sb.ID, Action: "die", Time: now}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(gw.detached, "sb-ev") || len(rt.unhold) != 1 {
		t.Fatalf("stop must detach and lift the hold DROP: detached=%v unhold=%v", gw.detached, rt.unhold)
	}
}

func TestQuotaMirrorsIntoGateway(t *testing.T) {
	svc, gw, _ := newEgressHarness(t)
	sb := &models.Sandbox{ID: "sb-q", ContainerIP: "10.0.0.10", Runtime: models.RuntimeDocker, NetworkAllowOut: []string{"pypi.org"}}
	svc.applyNetworkQuotaState(context.Background(), sb, false, true)
	if gw.blocked["sb-q"]&egress.BlockQuota == 0 {
		t.Fatal("quota block must be mirrored into @blocked_src (D2)")
	}
	svc.applyNetworkQuotaState(context.Background(), sb, false, false)
	if gw.blocked["sb-q"]&egress.BlockQuota != 0 {
		t.Fatal("quota unblock must clear only the quota reason")
	}
}

func TestEnsureEgressGatewayReadyLatch(t *testing.T) {
	svc, gw, _ := newEgressHarness(t)
	ctx := context.Background()
	gw.readyErr = egress.ErrUnavailable
	if err := svc.EnsureEgressGatewayReady(ctx); err == nil || svc.egressReady.Load() {
		t.Fatal("a failed bootstrap must leave the latch unset")
	}
	gw.readyErr = nil
	for i := 0; i < 3; i++ {
		if err := svc.EnsureEgressGatewayReady(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(gw.synced) != 1 {
		t.Fatalf("latched bootstrap synced %d times, want 1", len(gw.synced))
	}
	if err := svc.ResyncEgressGateway(ctx); err != nil || len(gw.synced) != 2 {
		t.Fatalf("forced resync: %v synced=%d", err, len(gw.synced))
	}
	svc.cfg.EgressFQDNEnabled = false
	if err := svc.EnsureEgressGatewayReady(ctx); !errors.Is(err, egress.ErrUnavailable) {
		t.Fatalf("disabled feature err = %v", err)
	}
	if _, ok := svc.egressGateway().(egress.Noop); !ok {
		t.Fatal("disabled feature must use Noop")
	}
	if svc.ResyncEgressGateway(ctx) != nil {
		t.Fatal("resync is a no-op when disabled")
	}
}

// TestLayoutLostHoldsAndReattaches covers CEO D17 on the sandboxd side.
func TestLayoutLostHoldsAndReattaches(t *testing.T) {
	svc, gw, rt := newEgressHarness(t)
	ctx := context.Background()
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"pypi.org"}})
	if err != nil {
		t.Fatal(err)
	}
	svc.handleEgressEvent(ctx, egress.Event{Kind: "heartbeat", LayoutLostSeen: true, FQDNSandboxes: 1})
	if len(rt.holds) == 0 {
		t.Fatal("table loss must hold every gateway-mode sandbox")
	}
	if st, _ := svc.store.GetEgressState(ctx, resp.ID); st.HoldReason != "" {
		t.Fatal("re-attach after the resync must release the hold")
	}
	if svc.egressStats.layoutLost.Load() != 1 || !gw.isAttached(resp.ID) {
		t.Fatal("layout loss handling")
	}
	svc.cfg.EgressAttributionEnabled = true
	svc.handleEgressEvent(ctx, egress.Event{Kind: "audit", SandboxID: resp.ID, Result: "denied", Reason: "sni_not_allowed", Destination: "evil.example:443"})
	if svc.egressStats.denied.snapshot()["sni_not_allowed"] != 0 {
		t.Fatal("audit events must not count denials; the heartbeat totals do")
	}
	svc.handleEgressEvent(ctx, egress.Event{Kind: "heartbeat", Denied: map[string]uint64{"sni_not_allowed": 1}})
	if svc.egressStats.denied.snapshot()["sni_not_allowed"] != 1 {
		t.Fatal("denials must be counted")
	}
}

func TestConsumeEgressEvents(t *testing.T) {
	svc, gw, _ := newEgressHarness(t)
	gw.events = make(chan egress.Event, 2)
	gw.events <- egress.Event{Kind: "heartbeat", AuditDropped: 7}
	close(gw.events)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	svc.consumeEgressEvents(ctx)
	if svc.egressStats.auditDropped.Load() != 7 {
		t.Fatal("heartbeat not consumed")
	}
}

// TestEgressGatewayReadyAdvertised covers the sandboxd half of CEO D20: the
// capacity snapshot carries readiness, which needs the feature on, the latch
// set and the gateway seen up.
func TestEgressGatewayReadyAdvertised(t *testing.T) {
	svc, _, _ := newEgressHarness(t)
	if svc.EgressGatewayReady() || svc.Capacity().EgressGatewayReady {
		t.Fatal("not ready before the bootstrap")
	}
	if err := svc.EnsureEgressGatewayReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !svc.EgressGatewayReady() || !svc.Capacity().EgressGatewayReady {
		t.Fatal("a synced gateway must be advertised")
	}
	svc.egressStats.gatewayUp.Store(false)
	if svc.EgressGatewayReady() {
		t.Fatal("a gateway seen down must not be advertised")
	}
	svc.egressStats.gatewayUp.Store(true)
	svc.cfg.EgressFQDNEnabled = false
	if svc.EgressGatewayReady() {
		t.Fatal("the feature off means no gateway")
	}
	var nilSvc *Service
	if nilSvc.EgressGatewayReady() {
		t.Fatal("nil service")
	}
}

// TestSuperviseEgressGatewayRecovers: a gateway that was down at startup, or
// whose stream broke, is re-synced without waiting for a create, because in
// a cluster placement sends none to a node that isn't ready.
func TestSuperviseEgressGatewayRecovers(t *testing.T) {
	svc, gw, _ := newEgressHarness(t)
	gw.mu.Lock()
	gw.readyErr = egress.ErrUnavailable
	gw.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		svc.SuperviseEgressGateway(ctx, 5*time.Millisecond)
		close(done)
	}()
	waitFor := func(want bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for svc.EgressGatewayReady() != want {
			if time.Now().After(deadline) {
				t.Fatalf("EgressGatewayReady never became %v", want)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	time.Sleep(20 * time.Millisecond)
	if svc.EgressGatewayReady() {
		t.Fatal("ready while the gateway is down")
	}
	gw.mu.Lock()
	gw.readyErr = nil
	gw.mu.Unlock()
	waitFor(true)
	// The event stream broke: the latch drops and the supervisor re-syncs.
	gw.mu.Lock()
	before := len(gw.synced)
	gw.mu.Unlock()
	svc.egressReady.Store(false)
	waitFor(true)
	gw.mu.Lock()
	after := len(gw.synced)
	gw.mu.Unlock()
	if after <= before {
		t.Fatal("recovery must re-sync the gateway")
	}
	cancel()
	<-done

	// Feature off: it keeps only the policy retry, which needs no gateway,
	// and touches no gateway state; it stops with its context.
	svc.cfg.EgressFQDNEnabled = false
	svc.egressReady.Store(false)
	gw.mu.Lock()
	gw.readyErr = nil
	synced := len(gw.synced)
	gw.mu.Unlock()
	offCtx, offCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer offCancel()
	svc.SuperviseEgressGateway(offCtx, time.Millisecond)
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if svc.egressReady.Load() || len(gw.synced) != synced {
		t.Fatal("with the feature off the supervisor must not bring the gateway up")
	}
}

// TestSuperviseReleasesHoldsOnRecovery: a sandbox held while the gateway was
// down gets its egress back within a supervisor tick of the gateway
// returning, without waiting for the reconcile pass.
func TestSuperviseReleasesHoldsOnRecovery(t *testing.T) {
	svc, _, _ := newEgressHarness(t)
	ctx := context.Background()
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"pypi.org"}})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := svc.store.Get(ctx, resp.ID)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := svc.containerRuntimeForSandbox(sb)
	if err != nil {
		t.Fatal(err)
	}
	svc.holdSandboxEgress(ctx, sb, cr, egressHoldUnavailable)
	if st, _ := svc.store.GetEgressState(ctx, resp.ID); st.HoldReason == "" {
		t.Fatal("setup: sandbox must be held")
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { svc.SuperviseEgressGateway(runCtx, 5*time.Millisecond); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		st, _ := svc.store.GetEgressState(ctx, resp.ID)
		if st.HoldReason == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("hold never lifted after the gateway was ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if svc.egressStats.held.Load() != 0 {
		t.Fatal("held gauge must return to 0")
	}
}

// TestGetShowsEgressStatus (D16): GET carries egress_status for a container
// sandbox in gateway mode, and nothing for other sandboxes or runtimes.
func TestGetShowsEgressStatus(t *testing.T) {
	svc, _, _ := newEgressHarness(t)
	ctx := context.Background()
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"pypi.org"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetSandboxWithOptions(ctx, resp.ID, GetSandboxOptions{})
	if err != nil || got.EgressStatus != EgressStatusActive {
		t.Fatalf("gateway-mode GET egress_status = %q, %v", got.EgressStatus, err)
	}
	plain, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.GetSandboxWithOptions(ctx, plain.ID, GetSandboxOptions{}); got.EgressStatus != "" {
		t.Fatalf("CIDR-only sandbox egress_status = %q", got.EgressStatus)
	}
	wasm := &models.Sandbox{Runtime: models.RuntimeWasm, NetworkAllowOut: []string{"pypi.org"}}
	if svc.EgressStatus(ctx, wasm) != "" || svc.EgressStatus(ctx, nil) != "" {
		t.Fatal("WASM filters in its mediator: no gateway status")
	}
}

// TestEgressWiringRacesReadinessReads: in cluster mode the capacity loop
// polls EgressGatewayReady from before the daemon wires the gateway and its
// self-test (pkg/daemon's cluster tests under -race). Wiring must be safe
// against those reads, and visible to them once done.
func TestEgressWiringRacesReadinessReads(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), &recordingRuntime{})
	svc.cfg.EgressFQDNEnabled = true
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			_ = svc.EgressGatewayReady()
			_ = svc.egressSelfTestPending()
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	svc.SetEgressGateway(newFakeGateway(), nil)
	svc.SetEgressSelfTest(&fakeSelfTestNet{})
	close(stop)
	<-done
	if !svc.egressEnabled() || !svc.egressSelfTestPending() {
		t.Fatal("the wiring must be visible once set")
	}
}
