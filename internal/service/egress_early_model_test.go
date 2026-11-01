package service

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// netModel is the fail-closed contract of a hostname-filtered sandbox as a
// state machine over addresses. Every fake below reports each transition to
// it, and it checks the contract at that transition, not only at the end:
//
//   - a workload that runs at an address is behind the driver's block-all,
//     or the gateway enforces for that address; never neither;
//   - an address goes back to the pool only once the gateway holds nothing
//     for it and its rules are gone (the next sandbox there gets only its
//     own policy).
//
// A violation is recorded with the event history that led to it.
type netModel struct {
	mu         sync.Mutex
	blocked    map[string]bool
	attached   map[string]string // address -> sandbox the gateway enforces for
	running    map[string]bool
	claimed    map[string]string // address -> sandbox holding the slot
	events     []string
	violations []string
	// lateBlock allows a workload to start before its block-all (a driver
	// that broke the contract, which the service must then shut).
	lateBlock bool
	// unrestricted are the addresses of sandboxes created without rules,
	// which run open by design (the contract is for restricted ones).
	unrestricted map[string]bool
}

func newNetModel() *netModel {
	return &netModel{blocked: map[string]bool{}, attached: map[string]string{}, running: map[string]bool{}, claimed: map[string]string{}, unrestricted: map[string]bool{}}
}

func (m *netModel) eventLocked(format string, args ...any) {
	m.events = append(m.events, fmt.Sprintf(format, args...))
}

func (m *netModel) violateLocked(format string, args ...any) {
	m.violations = append(m.violations, fmt.Sprintf(format, args...)+"\n    after: "+strings.Join(m.events, " → "))
}

func (m *netModel) openLocked(ip string) bool {
	return m.running[ip] && !m.blocked[ip] && m.attached[ip] == "" && !m.unrestricted[ip]
}

// unrestrict marks ip as an unrestricted sandbox's until it is freed.
func (m *netModel) unrestrict(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventLocked("unrestricted %s", ip)
	m.unrestricted[ip] = true
}

func (m *netModel) event(format string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventLocked(format, args...)
}

func (m *netModel) claim(id, ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventLocked("claim %s %s", id, ip)
	if owner := m.claimed[ip]; owner != "" && owner != id {
		m.violateLocked("address %s handed to %s while %s holds it", ip, id, owner)
	}
	m.claimed[ip] = id
}

func (m *netModel) free(id, ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventLocked("free %s %s", id, ip)
	if m.claimed[ip] != id {
		m.violateLocked("address %s freed by %s, held by %q", ip, id, m.claimed[ip])
	}
	if who := m.attached[ip]; who != "" {
		m.violateLocked("address %s freed while the gateway still enforces for %s there", ip, who)
	}
	if m.blocked[ip] {
		m.violateLocked("address %s freed with its block-all still on (the next owner would inherit it)", ip)
	}
	delete(m.claimed, ip)
	delete(m.unrestricted, ip)
}

func (m *netModel) block(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventLocked("block %s", ip)
	m.blocked[ip] = true
}

func (m *netModel) unblock(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventLocked("unblock %s", ip)
	m.blocked[ip] = false
	if m.openLocked(ip) {
		m.violateLocked("block-all lifted at %s while its workload runs and the gateway doesn't enforce there", ip)
	}
}

func (m *netModel) start(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventLocked("start %s", ip)
	m.running[ip] = true
	if m.openLocked(ip) && !m.lateBlock {
		m.violateLocked("workload started at %s with neither the block-all nor the gateway", ip)
	}
}

func (m *netModel) stop(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventLocked("stop %s", ip)
	delete(m.running, ip)
}

func (m *netModel) attach(id, ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventLocked("attach %s %s", id, ip)
	m.attached[ip] = id
}

func (m *netModel) detach(id, ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventLocked("detach %s %s", id, ip)
	if m.attached[ip] != id {
		return // the gateway checks the address is still the sandbox's (D5)
	}
	delete(m.attached, ip)
	if m.openLocked(ip) {
		m.violateLocked("gateway let go of %s while its workload runs unblocked", ip)
	}
}

// replace is a full Sync: the gateway enforces exactly specs afterwards.
func (m *netModel) replace(specs []egress.Spec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventLocked("sync %d", len(specs))
	m.attached = map[string]string{}
	for _, s := range specs {
		m.attached[s.IP.String()] = s.ID
	}
	for ip := range m.running {
		if m.openLocked(ip) {
			m.violateLocked("a full Sync dropped %s while its workload runs unblocked", ip)
		}
	}
}

// index is the position of the first event with the prefix, -1 if none.
func (m *netModel) index(prefix string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.IndexFunc(m.events, func(e string) bool { return strings.HasPrefix(e, prefix) })
}

func (m *netModel) count(prefix string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.events {
		if strings.HasPrefix(e, prefix) {
			n++
		}
	}
	return n
}

func (m *netModel) assertClean(t *testing.T) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.violations) > 0 {
		t.Fatalf("fail-closed contract broken:\n  %s", strings.Join(m.violations, "\n  "))
	}
}

// assertNothingLeft: no gateway state, no claimed address, no rule.
func (m *netModel) assertNothingLeft(t *testing.T) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for ip, id := range m.attached {
		t.Errorf("gateway still enforces for %s at %s", id, ip)
	}
	for ip, id := range m.claimed {
		t.Errorf("address %s still claimed by %s", ip, id)
	}
	for ip, on := range m.blocked {
		if on {
			t.Errorf("block-all left on %s", ip)
		}
	}
	if t.Failed() {
		t.Logf("events: %s", strings.Join(m.events, " → "))
	}
}

// modelGateway is the fake gateway with its enforcement reported to the
// model (kernel state: it survives a gateway restart until a Sync replaces
// it).
type modelGateway struct {
	*fakeGateway
	m           *netModel
	attachDelay time.Duration
	// beforeAttach may fail or block an Attach (an outage, a restart).
	beforeAttach func(egress.Spec) error
	attachedCh   chan string // receives the sandbox ID of each Attach that landed
}

func newModelGateway(m *netModel) *modelGateway {
	g := &modelGateway{fakeGateway: newFakeGateway(), m: m, attachedCh: make(chan string, 64)}
	g.events = make(chan egress.Event)
	return g
}

func (g *modelGateway) Attach(ctx context.Context, s egress.Spec) error {
	if g.beforeAttach != nil {
		if err := g.beforeAttach(s); err != nil {
			return err
		}
	}
	if g.attachDelay > 0 {
		select {
		case <-time.After(g.attachDelay):
		case <-ctx.Done():
			return fmt.Errorf("%w: %v", egress.ErrUnavailable, ctx.Err())
		}
	}
	if err := g.fakeGateway.Attach(ctx, s); err != nil {
		return err
	}
	g.m.attach(s.ID, s.IP.String())
	select {
	case g.attachedCh <- s.ID:
	default:
	}
	return nil
}

func (g *modelGateway) Detach(ctx context.Context, id string, ip netip.Addr) error {
	_ = g.fakeGateway.Detach(ctx, id, ip)
	g.m.detach(id, ip.String())
	return nil
}

func (g *modelGateway) Sync(ctx context.Context, specs []egress.Spec, tok egress.SyncToken) error {
	if err := g.fakeGateway.Sync(ctx, specs, tok); err != nil {
		return err
	}
	g.mu.Lock()
	g.attached = map[string]egress.Spec{}
	for _, s := range specs {
		g.attached[s.ID] = s
	}
	g.mu.Unlock()
	g.m.replace(specs)
	return nil
}

func (g *modelGateway) attachCount(id string) int {
	return g.m.count("attach " + id + " ")
}

// Runtime shapes. The early ones are the drivers that know a sandbox's
// address before its workload runs (containerd's prepaid netns, Docker's
// pause netns, a Firecracker TAP slot): for the service they are one
// contract, so one fake plays them all, the Firecracker one through the
// Firecracker create path. dockerPlain is Docker without the pause pool: a
// create with rules starts a pause container of its own (pkg/docker
// netns_pause_on_demand.go) and so is early too, which can fail before
// anything is claimed; a create without rules keeps Docker's own IPAM (no
// address until the container runs, which goes with the container).
const (
	shapeContainerd  = "containerd-netns"
	shapeDockerPause = "docker-pause"
	shapeFirecracker = "firecracker-tap"
	shapeDockerPlain = "docker-plain"
)

var earlyShapes = []string{shapeContainerd, shapeDockerPause, shapeFirecracker, shapeDockerPlain}

// hasRules is the driver's test for a create that must be shut before its
// workload runs (a hostname allowlist reaches it as block-all).
func hasRules(req models.CreateSandboxRequest) bool {
	return req.NetworkBlockAll || len(req.NetworkAllowOut) > 0 || len(req.NetworkDenyOut) > 0
}

// modelRuntime follows the driver contract runtime.AddressObserver states,
// in the shape it is told, and reports every transition to the model. A
// slot (and its address) follows the sandbox ID, as the netns and TAP pools
// do, and freed addresses are reused first, so address reuse is exercised.
type modelRuntime struct {
	m     *netModel
	shape string

	mu         sync.Mutex
	slots      map[string]string // sandbox id -> address
	plain      map[string]bool   // sandbox id -> on Docker's own IPAM
	pool       []string          // free addresses, reused last-freed first
	next       int
	containers map[string]*models.SandboxRuntimeState
	destroyed  []string
	// fail injects a failure at a point of Create: "pause" (plain Docker's
	// own pause container can't be started), "before-report",
	// "after-report", "after-start".
	fail map[string]error
	// afterReport runs right after the address is reported (a context
	// cancel, a gateway restart); waitAttach makes the runtime create last
	// at least as long as the gateway attach (a slow build).
	afterReport func(ctx context.Context, ip string)
	waitAttach  chan string
	// finalIP, when set, is the address Create returns (a driver that
	// breaks the contract).
	finalIP func(string) string
}

func newModelRuntime(m *netModel, shape string) *modelRuntime {
	return &modelRuntime{m: m, shape: shape, slots: map[string]string{}, plain: map[string]bool{}, containers: map[string]*models.SandboxRuntimeState{}, fail: map[string]error{}}
}

func (r *modelRuntime) claim(id string) string {
	r.mu.Lock()
	ip, ok := r.slots[id]
	if !ok {
		if n := len(r.pool); n > 0 {
			ip, r.pool = r.pool[n-1], r.pool[:n-1]
		} else {
			r.next++
			ip = fmt.Sprintf("10.77.%d.%d", r.next/250, r.next%250+2)
		}
		r.slots[id] = ip
	}
	r.mu.Unlock()
	r.m.claim(id, ip)
	return ip
}

func (r *modelRuntime) release(id, ip string) {
	r.m.free(id, ip)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.slots[id] == ip {
		delete(r.slots, id)
		r.pool = append(r.pool, ip)
	}
}

// newContainer is NewContainer: false when the sandbox's container exists
// (a duplicate create lost the race).
func (r *modelRuntime) newContainer(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.containers[id]; ok {
		return false
	}
	r.containers[id] = &models.SandboxRuntimeState{SandboxID: id, ContainerID: "ctr-" + id, Status: models.SandboxStatusStarted}
	return true
}

func (r *modelRuntime) dropContainer(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.containers, id)
	r.destroyed = append(r.destroyed, id)
}

func (r *modelRuntime) Create(ctx context.Context, req models.CreateSandboxRequest, id, _ string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	if r.shape == shapeDockerPlain {
		if !hasRules(req) {
			return r.createPlain(ctx, req, id)
		}
		// The pause container is the slot: if it can't start, nothing is
		// claimed and nothing ran.
		if err := r.fail["pause"]; err != nil {
			return nil, err
		}
	}
	ip := r.claim(id)
	if !r.newContainer(id) {
		// Lost to a duplicate: the slot is the winner's, nothing is undone.
		return nil, docker.ErrSandboxContainerExists
	}
	reported, started := false, false
	cleanup := func() {
		if started {
			r.m.stop(ip)
		}
		if reported {
			runtime.NotifyReleasingAddress(ctx, ip)
		}
		r.m.unblock(ip)
		r.dropContainer(id)
		r.release(id, ip)
	}
	if req.NetworkBlockAll {
		r.m.block(ip)
	}
	if err := r.fail["before-report"]; err != nil {
		cleanup()
		return nil, err
	}
	runtime.NotifyAddressKnown(ctx, ip)
	reported = true
	r.m.event("reported %s", ip)
	if r.afterReport != nil {
		r.afterReport(ctx, ip)
	}
	if err := r.fail["after-report"]; err != nil {
		cleanup()
		return nil, err
	}
	if r.waitAttach != nil {
		select {
		case <-r.waitAttach:
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
		}
	}
	if err := ctx.Err(); err != nil {
		cleanup()
		return nil, err
	}
	r.m.start(ip)
	started = true
	if err := r.fail["after-start"]; err != nil {
		cleanup()
		return nil, err
	}
	final := ip
	if r.finalIP != nil {
		final = r.finalIP(ip)
	}
	r.m.event("returned %s", final)
	return &models.SandboxRuntimeState{SandboxID: id, ContainerID: "ctr-" + id, ContainerIP: final, Status: models.SandboxStatusStarted}, nil
}

// createPlain is Docker's own path, for a create without rules: the
// address exists only once the container runs.
func (r *modelRuntime) createPlain(_ context.Context, _ models.CreateSandboxRequest, id string) (*models.SandboxRuntimeState, error) {
	if !r.newContainer(id) {
		return nil, docker.ErrSandboxContainerExists
	}
	ip := r.claim(id)
	r.mu.Lock()
	r.plain[id] = true
	r.mu.Unlock()
	r.m.unrestrict(ip)
	r.m.start(ip)
	r.m.event("returned %s", ip)
	return &models.SandboxRuntimeState{SandboxID: id, ContainerID: "ctr-" + id, ContainerIP: ip, Status: models.SandboxStatusStarted}, nil
}

// Destroy follows the drivers: the workload goes first, the observer is
// told, the rules go while the slot is held, the slot goes last. A sandbox
// on Docker's own IPAM (no rules) has its address go with its container.
func (r *modelRuntime) Destroy(ctx context.Context, sb *models.Sandbox) error {
	if sb == nil {
		return nil
	}
	r.mu.Lock()
	ip, held := r.slots[sb.ID]
	plain := r.plain[sb.ID]
	delete(r.plain, sb.ID)
	r.mu.Unlock()
	if !held {
		r.dropContainer(sb.ID)
		return nil
	}
	if plain {
		r.m.unblock(ip)
		r.m.stop(ip)
		r.dropContainer(sb.ID)
		r.release(sb.ID, ip)
		return nil
	}
	r.m.stop(ip)
	runtime.NotifyReleasingAddress(ctx, ip)
	r.m.unblock(ip)
	if sb.ContainerIP != "" && sb.ContainerIP != ip {
		r.m.unblock(sb.ContainerIP) // the drivers clear the row's address too
	}
	r.dropContainer(sb.ID)
	r.release(sb.ID, ip)
	return nil
}

func (r *modelRuntime) ApplyNetworkBlockAll(ip string) error    { r.m.block(ip); return nil }
func (r *modelRuntime) ClearNetworkBlockEgress(ip string) error { r.m.unblock(ip); return nil }
func (r *modelRuntime) ClearNetworkRules(ip string) error       { r.m.unblock(ip); return nil }
func (r *modelRuntime) ApplyEgressHold(ip string) error         { r.m.event("hold %s", ip); return nil }
func (r *modelRuntime) ClearEgressHold(ip string) error         { r.m.event("unhold %s", ip); return nil }
func (r *modelRuntime) NetRulesEnabled() bool                   { return true }
func (r *modelRuntime) PushAllowedPorts(context.Context, string, string, []int) error {
	return nil
}
func (r *modelRuntime) ApplyNetworkBlockIngress(string) error              { return nil }
func (r *modelRuntime) ClearNetworkBlockIngress(string) error              { return nil }
func (r *modelRuntime) ApplyEgressPolicy(string, []string, []string) error { return nil }
func (r *modelRuntime) ClearEgressPolicy(string, []string, []string) error { return nil }
func (r *modelRuntime) Start(context.Context, string) (*models.SandboxRuntimeState, error) {
	return nil, fmt.Errorf("model runtime: start unsupported")
}
func (r *modelRuntime) Stop(context.Context, string) error { return nil }
func (r *modelRuntime) CreateSnapshot(context.Context, string, string) (string, error) {
	return "", nil
}
func (r *modelRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error { return nil }
func (r *modelRuntime) Inspect(_ context.Context, ref string) (*models.SandboxRuntimeState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, st := range r.containers {
		if ref == id || ref == st.ContainerID {
			cp := *st
			cp.ContainerIP = r.slots[id]
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", runtime.ErrInstanceNotFound, ref)
}
func (r *modelRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]*models.SandboxRuntimeState{}
	for id, st := range r.containers {
		cp := *st
		cp.ContainerIP = r.slots[id]
		out[id] = &cp
	}
	return out, nil
}
func (r *modelRuntime) Ping(context.Context) error                { return nil }
func (r *modelRuntime) RemoveImage(context.Context, string) error { return nil }

var (
	_ runtime.ContainerRuntime = (*modelRuntime)(nil)
	_ runtime.EgressHolder     = (*modelRuntime)(nil)
)

// earlyHarness is a Service whose runtime and gateway report to one model.
type earlyHarness struct {
	svc *Service
	gw  *modelGateway
	rt  *modelRuntime
	m   *netModel
}

func newEarlyHarness(t *testing.T, shape string) *earlyHarness {
	t.Helper()
	m := newNetModel()
	rt := newModelRuntime(m, shape)
	svc, _, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	svc.cfg.EgressFQDNEnabled = true
	// Capacity is not under test, and these tests create many sandboxes.
	svc.admitter = nil
	if shape == shapeFirecracker {
		svc.cfg.EnableFirecracker = true
		svc.SetFirecrackerRuntime(rt)
	}
	gw := newModelGateway(m)
	svc.SetEgressGateway(gw, func(context.Context) []egress.Bridge {
		return []egress.Bridge{{Name: "aerolvm0", GatewayIP: netip.MustParseAddr("10.77.0.1")}}
	})
	return &earlyHarness{svc: svc, gw: gw, rt: rt, m: m}
}

func (h *earlyHarness) request() models.CreateSandboxRequest {
	req := models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"pypi.org"}}
	if h.rt.shape == shapeFirecracker {
		req.Runtime = models.RuntimeFirecracker
	}
	return req
}
