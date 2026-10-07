package service

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/observability"
	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
	"go.opentelemetry.io/otel/attribute"
)

// Hold reasons stored in sandbox_egress.hold_reason (CEO D16).
const (
	egressHoldAttachFailed = "attach_failed"
	// egressHoldApplyFailed: a stored policy change (live PUT, profile
	// re-apply) didn't finish applying, so what is enforced may not be what
	// is stored. The sandbox is shut until a retry applies it (review
	// finding 2).
	egressHoldApplyFailed   = "apply_failed"
	egressHoldUnavailable   = "gateway_unavailable"
	egressHoldLayoutLost    = "layout_lost"
	egressHoldPolicyInvalid = "policy_invalid"
	// egressHoldProfileUnavailable: a referenced profile couldn't be read or
	// is gone. Only the profile re-apply pass lifts it.
	egressHoldProfileUnavailable = "profile_unavailable"
	// egressHoldOrgProfileInvalid: a referenced org profile left the operator
	// file, or its entries pushed the sandbox past the union cap (§5.10
	// PC-3). Only the profile re-apply pass lifts it.
	egressHoldOrgProfileInvalid = "org_profile_invalid"
)

// isProfileHold reports whether only the profile re-apply pass may lift a
// hold: re-attaching the stored list can't fix what the profiles broke.
func isProfileHold(reason string) bool {
	return reason == egressHoldProfileUnavailable || reason == egressHoldOrgProfileInvalid
}

// Egress status shown on GET (egress_status).
const (
	EgressStatusActive      = "active"
	EgressStatusHeld        = "held"
	EgressStatusUnavailable = "unavailable"
)

// egressAttachTimeout bounds one UDS round trip on the create path.
const egressAttachTimeout = 5 * time.Second

// egressCounters are the sandboxd-side egress metrics (P1-12).
type egressCounters struct {
	attachFailed  atomic.Uint64
	held          atomic.Int64
	gatewayUp     atomic.Bool
	lastSync      atomic.Int64 // unix nanos
	lastHeartbeat atomic.Int64
	auditDropped  atomic.Uint64
	fqdnSandboxes atomic.Int64
	proxyConns    atomic.Int64
	proxyConnCap  atomic.Int64
	layoutLost    atomic.Uint64
	denied        reasonCounts
	totals        gatewayTotals
}

// reasonCounts counts this Service's denials by reason, the per-node view
// of aerolvm_egress_denied_total.
type reasonCounts struct {
	mu sync.Mutex
	m  map[string]uint64
}

func (r *reasonCounts) addN(reason string, n uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[string]uint64{}
	}
	r.m[reason] += n
}

func (r *reasonCounts) snapshot() map[string]uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]uint64, len(r.m))
	for k, v := range r.m {
		out[k] = v
	}
	return out
}

// SetEgressGateway wires the gateway client and the bridge discovery. A nil
// api leaves the feature off (Noop).
func (s *Service) SetEgressGateway(api egress.API, bridges func(context.Context) []egress.Bridge) {
	s.egressAPI = api
	s.egressBridges = bridges
	if api != nil {
		activeEgressStats.Store(&s.egressStats)
	}
}

// gatewayBridges lists what the gateway listens on: the container bridges
// the daemon discovers and, when the Firecracker guests have a firewall,
// the TAP pool (Phase 4). ok is false when nothing wires any (tests).
func (s *Service) gatewayBridges(ctx context.Context) (bridges []egress.Bridge, ok bool) {
	if s.egressBridges != nil {
		bridges, ok = s.egressBridges(ctx), true
	}
	if fc, isFC := s.firecracker.(interface{ EgressTapSubnet() (netip.Prefix, bool) }); isFC {
		if subnet, on := fc.EgressTapSubnet(); on {
			bridges, ok = append(bridges, egress.TapPoolBridge(subnet)), true
		}
	}
	return bridges, ok
}

// egressGateway returns the client, or Noop when the feature is off.
func (s *Service) egressGateway() egress.API {
	if s == nil || s.egressAPI == nil || !s.cfg.EgressFQDNEnabled {
		return egress.Noop{}
	}
	return s.egressAPI
}

// egressEnabled reports whether hostname filtering can run on this node:
// the feature is on, a gateway client is wired, and the node is not running
// privileged sandboxes (they hold NET_RAW/NET_ADMIN and could step around
// the gateway, CEO D18).
func (s *Service) egressEnabled() bool {
	return s != nil && s.egressAPI != nil && s.cfg.EgressFQDNEnabled && !s.cfg.ContainerPrivileged
}

// EnsureEgressGatewayReady connects to the gateway and pushes the node's full
// state: the sandbox bridges, then a Sync of every gateway-mode sandbox. Same
// atomic.Bool + mutex single-flight shape as EnsureLayer4Ready; called
// best-effort at daemon start and lazily before the first attach. A failure
// leaves the latch unset.
func (s *Service) EnsureEgressGatewayReady(ctx context.Context) error {
	if !s.egressEnabled() {
		return fmt.Errorf("%w: hostname egress filtering is disabled on this node", egress.ErrUnavailable)
	}
	if s.egressReady.Load() {
		return nil
	}
	s.egressMu.Lock()
	defer s.egressMu.Unlock()
	if s.egressReady.Load() {
		return nil
	}
	if err := s.syncEgressGatewayLocked(ctx); err != nil {
		s.egressStats.gatewayUp.Store(false)
		return err
	}
	s.egressReady.Store(true)
	s.egressStats.gatewayUp.Store(true)
	// Holds persist across sandboxd restarts; seed the gauge the supervisor
	// keys its retries on.
	s.refreshHeldGauge(ctx)
	s.egressSubOnce.Do(func() { go s.consumeEgressEvents(context.WithoutCancel(ctx)) })
	return nil
}

// syncEgressGatewayLocked hands over bridges and replaces the gateway's state
// with the store's. Callers hold egressMu.
func (s *Service) syncEgressGatewayLocked(ctx context.Context) (err error) {
	ctx, span := observability.StartSpan(ctx, "egress.sync")
	defer func() { observability.EndSpan(span, err) }()
	gw := s.egressGateway()
	if _, err := gw.Ready(ctx); err != nil {
		return err
	}
	if bridges, ok := s.gatewayBridges(ctx); ok {
		if err := gw.SetBridges(ctx, bridges); err != nil {
			return fmt.Errorf("egress gateway bridges: %w", err)
		}
	}
	// Before the Sync: an inspect sandbox it re-attaches must never meet a
	// gateway without the CA (it would be refused, not passed through).
	if err := s.resyncEgressCA(ctx); err != nil {
		return err
	}
	// No attach or detach runs between reading the state and the gateway
	// applying it, and the attaches the store doesn't show yet are included.
	s.egressSyncMu.Lock()
	specs, err := s.localEgressSpecs(ctx)
	if err == nil {
		err = gw.Sync(ctx, specs)
	}
	s.egressSyncMu.Unlock()
	if err != nil {
		return err
	}
	// Every full sync asks for a re-test of every bridge: it runs at startup
	// and after a gateway restart, the two times the redirect path may have
	// changed. The supervisor runs it, off any create path. A restarted
	// gateway also needs the control-port guard list again.
	s.requestEgressSelfTests()
	s.egressControlPushed.Store(nil)
	s.egressStats.lastSync.Store(time.Now().UnixNano())
	s.egressStats.fqdnSandboxes.Store(int64(len(specs)))
	return nil
}

// EgressGatewayReady reports whether this node can attach a hostname-filtered
// sandbox right now. It is advertised in the capacity heartbeat, so cluster
// placement sends gateway-mode creates only to nodes where it holds
// (plans/egress-domain-filtering.md CEO D20). Two atomic loads: it runs on
// every heartbeat and every /v1/capacity read.
func (s *Service) EgressGatewayReady() bool {
	return s.egressEnabled() && s.egressReady.Load() && s.egressStats.gatewayUp.Load() &&
		!s.egressSelfTestFailed() && !s.egressSelfTestPending()
}

// SuperviseEgressGateway re-runs the gateway bootstrap whenever the latch is
// down (at startup before the gateway is up, and after its event stream
// breaks on a gateway restart), and re-attaches held sandboxes once it is
// back. The lazy retry on create is not enough in
// cluster mode, where placement stops sending gateway-mode creates to a node
// that isn't ready, so nothing else would bring it back. One atomic load per
// tick while ready; logs only when the failure changes.
func (s *Service) SuperviseEgressGateway(ctx context.Context, interval time.Duration) {
	if !s.egressEnabled() {
		return
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	lastErr := ""
	for {
		if !s.egressReady.Load() {
			msg := ""
			if err := s.EnsureEgressGatewayReady(ctx); err != nil {
				msg = err.Error()
			}
			switch {
			case msg != "" && msg != lastErr:
				s.logger.Warn("egress gateway not ready; hostname-filtered creates are refused here until it is", "error", msg)
			case msg == "" && lastErr != "":
				s.logger.Info("egress gateway ready")
			}
			lastErr = msg
		}
		s.retryEgressSelfTests(ctx, false)
		s.syncNodeControl(ctx)
		if s.EgressGatewayReady() && s.egressStats.held.Load() > 0 {
			s.retryEgressHolds(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.egressSelfTestKick():
			s.retryEgressSelfTests(ctx, true)
		}
	}
}

// ResyncEgressGateway forces a full Sync (gateway restart, table loss).
func (s *Service) ResyncEgressGateway(ctx context.Context) error {
	if !s.egressEnabled() {
		return nil
	}
	s.egressMu.Lock()
	defer s.egressMu.Unlock()
	err := s.syncEgressGatewayLocked(ctx)
	s.egressReady.Store(err == nil)
	s.egressStats.gatewayUp.Store(err == nil)
	return err
}

// localEgressSpecs builds a Spec for every started gateway-mode sandbox on
// this node, with its current block reasons.
func (s *Service) localEgressSpecs(ctx context.Context) ([]egress.Spec, error) {
	rows, err := s.store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list sandboxes for egress sync: %w", err)
	}
	holds, err := s.store.ListEgressHolds(ctx)
	if err != nil {
		return nil, err
	}
	var specs []egress.Spec
	started := map[string]netip.Addr{}
	for _, sb := range rows {
		if sb.Status != models.SandboxStatusStarted || sb.ContainerIP == "" {
			continue
		}
		if ip, err := netip.ParseAddr(sb.ContainerIP); err == nil {
			started[sb.ID] = ip
		}
		spec, ok := s.egressSpecFor(sb, holds[sb.ID] != "")
		if !ok {
			continue
		}
		spec.Secrets = s.egressSecrets(ctx, sb)
		spec.Pid = s.egressPid(ctx, sb)
		specs = append(specs, spec)
	}
	return s.egressInflight.merge(specs, started, time.Now()), nil
}

// sandboxPolicy compiles a stored sandbox's egress policy.
func sandboxPolicy(sb *models.Sandbox) (*egresspolicy.Policy, error) {
	return egresspolicy.Compile(egresspolicy.Spec{AllowOut: sb.NetworkAllowOut, DenyOut: sb.NetworkDenyOut, BlockAll: sb.NetworkBlockAll,
		Mode: egresspolicy.Mode(sb.NetworkEgressMode), MaxHostnames: egresspolicy.MaxUnionHostnames})
}

// isGatewayMode reports whether a stored sandbox runs in gateway mode:
// hostname rules (or, in Phase 2, learn mode / profiles) and not block-all.
func isGatewayMode(sb *models.Sandbox) bool {
	if sb == nil || sb.NetworkBlockAll {
		return false
	}
	pol, err := sandboxPolicy(sb)
	return err == nil && pol.GatewayMode()
}

// egressSpecFor builds the gateway Spec for a gateway-mode sandbox.
func (s *Service) egressSpecFor(sb *models.Sandbox, held bool) (egress.Spec, bool) {
	if !isGatewayMode(sb) {
		return egress.Spec{}, false
	}
	ip, err := netip.ParseAddr(sb.ContainerIP)
	if err != nil {
		return egress.Spec{}, false
	}
	spec := egress.Spec{ID: sb.ID, IP: ip, AllowOut: sb.NetworkAllowOut, DenyOut: sb.NetworkDenyOut,
		Learn: sb.NetworkEgressMode == models.NetworkEgressModeLearn, Rules: egressRuleSpecs(sb.NetworkEgressRules)}
	if sb.NetworkQuotaExceeded && sb.NetworkBytesOutLimit > 0 && sb.NetworkBytesOut >= sb.NetworkBytesOutLimit {
		spec.Blocked |= egress.BlockQuota
	}
	if held {
		spec.Blocked |= egress.BlockHold
	}
	return spec, true
}

// attachSandboxEgress puts a started gateway-mode sandbox under the gateway
// and lifts the driver's temporary block-all. The driver installed that DROP
// at create (the driver-facing copy) so the sandbox was shut until now; on any
// failure it stays shut and the sandbox is held (CEO D16).
func (s *Service) attachSandboxEgress(ctx context.Context, sb *models.Sandbox, cr runtime.ContainerRuntime) (err error) {
	ctx, span := observability.StartSpan(ctx, "egress.attach", attribute.String("sandbox_id", sb.ID))
	defer func() { observability.EndSpan(span, err) }()
	ctx, cancel := context.WithTimeout(ctx, egressAttachTimeout)
	defer cancel()
	spec, ok := s.egressSpecFor(sb, false)
	if !ok {
		return nil
	}
	spec.Secrets = s.egressSecrets(ctx, sb)
	spec.Pid = s.egressPid(ctx, sb)
	if err := s.EnsureEgressGatewayReady(ctx); err != nil {
		s.egressStats.recordAttachFailed()
		return err
	}
	s.kickEgressSelfTest()
	s.egressSyncMu.RLock()
	err = s.egressGateway().Attach(ctx, spec)
	if err == nil {
		s.egressInflight.put(spec)
	}
	s.egressSyncMu.RUnlock()
	if err != nil {
		s.egressStats.recordAttachFailed()
		if errors.Is(err, egress.ErrUnavailable) || errors.Is(err, egress.ErrVersionMismatch) {
			s.egressReady.Store(false)
		}
		return err
	}
	if err := s.releaseEgressHold(ctx, sb, cr); err != nil {
		return err
	}
	// The driver's block-all DROP has done its job; quota and real block-all
	// keep their own DROPs (applyNetworkQuotaState, NetworkBlockAll).
	if !sb.NetworkBlockAll && !sb.NetworkQuotaExceeded {
		if err := cr.ClearNetworkBlockEgress(sb.ContainerIP); err != nil {
			return fmt.Errorf("lift driver block after egress attach: %w", err)
		}
	}
	return nil
}

// holdSandboxEgress records and enforces the fail-closed hold: the store
// row, the hold DROP in the host firewall, and the gateway's blocked bit for
// the redirect path (S3). Each layer alone keeps the sandbox shut, so every
// step is best-effort after the first.
func (s *Service) holdSandboxEgress(ctx context.Context, sb *models.Sandbox, cr runtime.ContainerRuntime, reason string) {
	now := time.Now().UTC()
	if err := s.store.SetEgressHold(ctx, sb.ID, reason, now); err != nil {
		s.logger.Warn("egress: persist hold failed", "sandbox_id", sb.ID, "reason", reason, "error", err)
	}
	if holder, ok := cr.(runtime.EgressHolder); ok && sb.ContainerIP != "" {
		if err := holder.ApplyEgressHold(sb.ContainerIP); err != nil {
			s.logger.Warn("egress: install hold DROP failed", "sandbox_id", sb.ID, "error", err)
		}
	}
	if err := s.egressGateway().SetBlocked(ctx, sb.ID, egress.BlockHold, true); err != nil && !errors.Is(err, egress.ErrNotAttached) {
		s.logger.Warn("egress: gateway hold failed", "sandbox_id", sb.ID, "error", err)
	}
	s.refreshHeldGauge(ctx)
	s.logger.Warn("egress: sandbox held", "sandbox_id", sb.ID, "reason", reason)
}

// releaseEgressHold lifts a hold after a successful attach. Nothing else
// lifts one.
func (s *Service) releaseEgressHold(ctx context.Context, sb *models.Sandbox, cr runtime.ContainerRuntime) error {
	st, err := s.store.GetEgressState(ctx, sb.ID)
	if err != nil {
		return err
	}
	if st.HoldReason == "" {
		return nil
	}
	if holder, ok := cr.(runtime.EgressHolder); ok && sb.ContainerIP != "" {
		if err := holder.ClearEgressHold(sb.ContainerIP); err != nil {
			return fmt.Errorf("lift egress hold DROP: %w", err)
		}
	}
	if err := s.egressGateway().SetBlocked(ctx, sb.ID, egress.BlockHold, false); err != nil && !errors.Is(err, egress.ErrNotAttached) {
		return err
	}
	if err := s.store.ClearEgressHold(ctx, sb.ID, time.Now().UTC()); err != nil {
		return err
	}
	s.refreshHeldGauge(ctx)
	return nil
}

// retryEgressHolds re-attaches held, running sandboxes once the gateway is
// ready, so a hold from a gateway outage lifts within one supervisor tick
// rather than on the next reconcile pass. An invalid stored policy can never
// attach and is left for its owner to replace; stopped sandboxes re-attach
// on start.
func (s *Service) retryEgressHolds(ctx context.Context) {
	holds, err := s.store.ListEgressHolds(ctx)
	if err != nil {
		return
	}
	for id, reason := range holds {
		// An invalid stored policy and an unresolvable profile can't be fixed
		// by re-attaching the stored list; their owners lift those holds.
		if reason == egressHoldPolicyInvalid || isProfileHold(reason) {
			continue
		}
		sb, err := s.store.Get(ctx, id)
		if err != nil || sb.Status != models.SandboxStatusStarted {
			continue
		}
		if reason == egressHoldApplyFailed {
			if err := s.reapplyStoredPolicy(ctx, id); err != nil {
				s.logger.Debug("egress: held policy still not applied", "sandbox_id", id, "error", err)
			}
			continue
		}
		s.reconcileSandboxEgress(ctx, sb)
	}
	s.refreshHeldGauge(ctx)
}

// endGaugeBatch closes a batch opened with egressGaugeBatch.Add(1) and runs
// the one gauge refresh the batch deferred.
func (s *Service) endGaugeBatch(ctx context.Context) {
	if s.egressGaugeBatch.Add(-1) == 0 && s.egressGaugeDirty.Swap(false) {
		s.refreshHeldGauge(ctx)
	}
}

// refreshHeldGauge recounts the held sandboxes. Inside a batch (a table-loss
// recovery holds and re-attaches every gateway sandbox) the recount is
// deferred to the batch's end: per sandbox it would be quadratic.
func (s *Service) refreshHeldGauge(ctx context.Context) {
	if s.egressGaugeBatch.Load() > 0 {
		s.egressGaugeDirty.Store(true)
		return
	}
	if holds, err := s.store.ListEgressHolds(ctx); err == nil {
		s.egressStats.held.Store(int64(len(holds)))
	}
}

// shutStoppedGuest blocks a stopped gateway-mode Firecracker guest's IP.
// The guest keeps its slot (and IP) while stopped, a full gateway Sync drops
// stopped sandboxes, and Start resumes the VM before it re-attaches, so
// without this a restart in between would leave a resumed guest unfiltered
// until the attach. Start lifts it when the policy no longer needs it
// (liftStartedGuest). Best effort: the attach on Start still shuts it.
func (s *Service) shutStoppedGuest(rt runtime.Runtime, sb *models.Sandbox) {
	if !isGatewayMode(sb) || sb.ContainerIP == "" {
		return
	}
	cr, ok := runtime.AsContainerRuntime(rt)
	if !ok {
		return
	}
	if err := cr.ApplyNetworkBlockAll(sb.ContainerIP); err != nil {
		s.logger.Warn("egress: stopped guest not shut; it is shut again on start", "sandbox_id", sb.ID, "error", err)
	}
}

// liftStartedGuest lifts shutStoppedGuest's block from a Firecracker guest
// whose policy changed, while it was stopped, to one without a block.
func (s *Service) liftStartedGuest(rt runtime.Runtime, sb *models.Sandbox) error {
	if !s.isFirecrackerSandbox(sb) || sb.NetworkBlockAll || isGatewayMode(sb) || sb.ContainerIP == "" {
		return nil
	}
	cr, ok := runtime.AsContainerRuntime(rt)
	if !ok {
		return nil
	}
	if err := cr.ClearNetworkBlockEgress(sb.ContainerIP); err != nil && !errors.Is(err, models.ErrRuntimeNotImplemented) {
		return err
	}
	return nil
}

// detachSandboxEgress removes a sandbox from the gateway. The gateway checks
// the IP still belongs to it (D5), so a late call after IP reuse is safe.
func (s *Service) detachSandboxEgress(ctx context.Context, sb *models.Sandbox, ip string) {
	if !s.egressEnabled() || ip == "" {
		return
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, egressAttachTimeout)
	defer cancel()
	s.egressSyncMu.RLock()
	defer s.egressSyncMu.RUnlock()
	s.egressInflight.drop(sb.ID)
	if err := s.egressGateway().Detach(ctx, sb.ID, addr); err != nil {
		s.logger.Warn("egress: detach failed (gateway Sync will drop it)", "sandbox_id", sb.ID, "error", err)
	}
}

// settleEgressAttach marks a create's or start's attach as covered by its
// store row, once that row is written.
func (s *Service) settleEgressAttach(id string) { s.egressInflight.drop(id) }

// setEgressQuotaBlock mirrors a quota block into the gateway's @blocked_src
// for a gateway-mode sandbox (eng re-review D2).
func (s *Service) setEgressQuotaBlock(ctx context.Context, sb *models.Sandbox, on bool) {
	if !s.egressEnabled() || !isGatewayMode(sb) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, egressAttachTimeout)
	defer cancel()
	if err := s.egressGateway().SetBlocked(ctx, sb.ID, egress.BlockQuota, on); err != nil && !errors.Is(err, egress.ErrNotAttached) {
		s.logger.Warn("egress: quota block not mirrored to the gateway", "sandbox_id", sb.ID, "on", on, "error", err)
	}
}

// EgressStatus reports a sandbox's egress status for GET: "" for a sandbox
// outside gateway mode and not held, otherwise active, held or unavailable.
// A hold shows on every runtime: a policy that failed to apply, or profiles
// that can't be resolved, hold WASM, isolate and CIDR sandboxes too.
func (s *Service) EgressStatus(ctx context.Context, sb *models.Sandbox) string {
	if sb == nil || !hasEgressConfig(sb) {
		return ""
	}
	gw := models.RuntimeUsesEgressGateway(sb.Runtime) && isGatewayMode(sb)
	if st, err := s.store.GetEgressState(ctx, sb.ID); err == nil && st.HoldReason != "" {
		switch st.HoldReason {
		case egressHoldUnavailable, egressHoldLayoutLost, egressHoldProfileUnavailable:
			// A failover replay whose profiles this node can't resolve runs
			// block-all, held, until they can (CEO D11): no policy of the
			// owner's is in force.
			return EgressStatusUnavailable
		}
		return EgressStatusHeld
	}
	if gw {
		return EgressStatusActive
	}
	return ""
}

// hasEgressConfig reports whether a sandbox has any egress setting, so a
// sandbox with none skips the egress state read.
func hasEgressConfig(sb *models.Sandbox) bool {
	return sb.NetworkBlockAll || len(sb.NetworkAllowOut) > 0 || len(sb.NetworkDenyOut) > 0 ||
		sb.NetworkEgressMode != "" || len(sb.NetworkEgressRules) > 0 || len(sb.EgressProfiles) > 0
}

// consumeEgressEvents streams gateway events into the audit log and metrics,
// resubscribing with backoff while the gateway is away.
func (s *Service) consumeEgressEvents(ctx context.Context) {
	sub, ok := s.egressAPI.(interface {
		Subscribe(context.Context) (<-chan egress.Event, error)
	})
	if !ok {
		return
	}
	backoff := time.Second
	for ctx.Err() == nil {
		events, err := sub.Subscribe(ctx)
		if err != nil {
			s.egressStats.gatewayUp.Store(false)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		for ev := range events {
			s.handleEgressEvent(ctx, ev)
		}
		// The stream broke: the gateway restarted or went away. Its state
		// may be a snapshot behind ours, so re-sync once it is back.
		s.egressReady.Store(false)
	}
}

// handleEgressEvent records one gateway event.
func (s *Service) handleEgressEvent(ctx context.Context, ev egress.Event) {
	switch ev.Kind {
	case "audit":
		// Audit only: denials are counted from the heartbeat's totals,
		// which stay exact when the audit ring drops events. A learn-mode
		// connection is open egress by design, so the audit says so on
		// every one of them (CEO D2).
		reason := ev.Reason
		if ev.Mode == string(egress.ModeLearn) && ev.Result == "allowed" {
			reason = egressAuditReasonLearnMode
		}
		s.emitEgressDecision(ev.SandboxID, "tcp", ev.Destination, ev.Result == "allowed", reason)
	case "heartbeat":
		s.egressStats.gatewayUp.Store(true)
		s.egressStats.lastHeartbeat.Store(time.Now().UnixNano())
		s.egressStats.observeHeartbeat(ev)
		s.egressStats.fqdnSandboxes.Store(int64(ev.FQDNSandboxes))
		s.egressStats.proxyConns.Store(int64(ev.ProxyConns))
		s.egressStats.proxyConnCap.Store(int64(ev.ProxyConnCap))
		s.observeGatewayOperator(ev.OperatorHash)
		if ev.LayoutLostSeen {
			s.onEgressLayoutLost(ctx)
		}
	}
}

// onEgressLayoutLost answers a lost nft table (CEO D17): every gateway-mode
// sandbox is held (its host-firewall hold DROP covers the window), then a
// full Sync re-applies the gateway state and successful attaches release
// the holds.
func (s *Service) onEgressLayoutLost(ctx context.Context) {
	// One recovery at a time: heartbeats keep reporting the loss until the
	// gateway sees this recovery's Sync succeed.
	if !s.egressRecovering.CompareAndSwap(false, true) {
		return
	}
	defer s.egressRecovering.Store(false)
	s.egressStats.recordLayoutLost()
	s.egressGaugeBatch.Add(1)
	defer s.endGaugeBatch(ctx)
	rows, err := s.store.List(ctx)
	if err != nil {
		return
	}
	for _, sb := range rows {
		if sb.Status != models.SandboxStatusStarted || !isGatewayMode(sb) {
			continue
		}
		if cr, err := s.containerRuntimeForSandbox(sb); err == nil {
			s.holdSandboxEgress(ctx, sb, cr, egressHoldLayoutLost)
		}
	}
	if err := s.ResyncEgressGateway(ctx); err != nil {
		s.logger.Error("egress: re-sync after table loss failed; sandboxes stay held", "error", err)
		return
	}
	for _, sb := range rows {
		if sb.Status != models.SandboxStatusStarted || !isGatewayMode(sb) {
			continue
		}
		if cr, err := s.containerRuntimeForSandbox(sb); err == nil {
			if err := s.attachSandboxEgress(ctx, sb, cr); err != nil {
				s.logger.Warn("egress: re-attach after table loss failed; sandbox stays held", "sandbox_id", sb.ID, "error", err)
			}
		}
	}
}

// egressAuditReasonLearnMode marks an allowed connection a learn-mode
// sandbox made.
const egressAuditReasonLearnMode = "learn_mode"

// emitEgressDecision writes a gateway decision into the hash-chained audit
// log: allowed connections as success, denials as failure with the reason.
func (s *Service) emitEgressDecision(sandboxID, network, destination string, allowed bool, reason string) {
	if s == nil || !s.cfg.EgressAttributionEnabled {
		return
	}
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return
	}
	sink := s.secretAuditSink()
	if sink == nil {
		return
	}
	result, why := secretAuditResultSuccess, secretAuditReasonOK
	if !allowed {
		result, why = secretAuditResultFailure, reason
	} else if reason == egressAuditReasonLearnMode {
		why = reason
	}
	actor := s.auditActor()
	incarnationID, ownerRef := s.auditIdentityFor(sandboxID)
	sink.Emit(SecretAuditEvent{
		Time:          time.Now().UTC(),
		Actor:         actor,
		SandboxID:     sandboxID,
		Result:        result,
		Reason:        why,
		NodeID:        actor,
		Kind:          secretAuditKindEgress,
		Destination:   strings.TrimSpace(destination),
		Network:       network,
		IncarnationID: incarnationID,
		OwnerRef:      ownerRef,
	})
}

// reconcileSandboxEgress retries the attach of a held gateway-mode sandbox;
// the hold lifts only when the attach succeeds (CEO D16).
func (s *Service) reconcileSandboxEgress(ctx context.Context, sb *models.Sandbox) {
	if !s.egressEnabled() || sb.ContainerIP == "" {
		return
	}
	st, err := s.store.GetEgressState(ctx, sb.ID)
	if err != nil || st.HoldReason == "" {
		return
	}
	cr, err := s.containerRuntimeForSandbox(sb)
	if err != nil {
		return
	}
	if err := s.attachSandboxEgress(ctx, sb, cr); err != nil {
		s.logger.Debug("egress: held sandbox still not attachable", "sandbox_id", sb.ID, "reason", st.HoldReason, "error", err)
	}
}
