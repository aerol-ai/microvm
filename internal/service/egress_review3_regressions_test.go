package service

// Regression tests from the third review of PR #622: each reproduces a
// finding against the reviewed head (7935cfe6) and passes with its fix.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestPartialTransitionThenAnotherPolicyTearsDownBoth(t *testing.T) {
	svc, gw, rt := newPolicyHarness(t)
	ctx := context.Background()
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"8.8.8.0/24"}})
	rt.liftErr = errors.New("temporary failure lifting swap DROP")
	if _, err := svc.UpdateNetworkPolicy(ctx, sb.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"pypi.org"}}); !errors.Is(err, ErrEgressApplyFailedHeld) {
		t.Fatalf("setup: %v", err)
	}
	if !gw.isAttached(sb.ID) {
		t.Fatal("setup: intermediate gateway was not installed")
	}
	rt.liftErr = nil
	if _, err := svc.UpdateNetworkPolicy(ctx, sb.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"1.1.1.0/24"}}); err != nil {
		t.Fatal(err)
	}
	st, _ := svc.store.GetEgressState(ctx, sb.ID)
	if gw.isAttached(sb.ID) && st.HoldReason == "" {
		t.Fatal("successful CIDR policy left intermediate pypi.org gateway attached and unheld")
	}
}

func TestPersistedApplyHoldRetriesAfterRestart(t *testing.T) {
	svc, _, _ := newPolicyHarness(t)
	svc.cfg.EgressFQDNEnabled = false
	svc.wasm = newMediator()
	sb := seedPolicySandbox(t, svc, models.Sandbox{ID: "persisted-wasm", Runtime: models.RuntimeWasm, NetworkAllowOut: []string{"pypi.org"}})
	// State on daemon boot: durable hold, zero in-memory metrics, no gateway.
	if err := svc.store.SetEgressHold(context.Background(), sb.ID, egressHoldApplyFailed, time.Now()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	svc.SuperviseEgressGateway(ctx, time.Millisecond)
	st, err := svc.store.GetEgressState(context.Background(), sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st.HoldReason != "" {
		t.Fatalf("persisted hold never retried after restart without gateway: %s", st.HoldReason)
	}
}

type detachFailingGateway struct{ *fakeGateway }

func (g *detachFailingGateway) Detach(context.Context, string, netip.Addr) error {
	return errors.New("gateway detach transaction failed")
}

func TestCrossModeDetachFailureHolds(t *testing.T) {
	svc, gw, rt := newPolicyHarness(t)
	svc.SetEgressGateway(&detachFailingGateway{gw}, nil)
	ctx := context.Background()
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}})
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	_, err := svc.UpdateNetworkPolicy(ctx, sb.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"8.8.8.0/24"}})
	st, _ := svc.store.GetEgressState(ctx, sb.ID)
	if err == nil && st.HoldReason == "" && gw.isAttached(sb.ID) {
		t.Fatal("PUT acknowledged CIDR policy despite failed detach; old hostname gateway is still open")
	}
}

type newerHoldSyncGateway struct {
	*fakeGateway
	real                  *egress.Gateway
	beforeSync            func()
	rejectRepair, syncing bool
	exposed               bool
	id                    string
}

func (g *newerHoldSyncGateway) Attach(_ context.Context, s egress.Spec) error {
	return g.real.Attach(s)
}
func (g *newerHoldSyncGateway) SetBlocked(_ context.Context, id string, r egress.BlockReason, on bool) error {
	if g.syncing && g.rejectRepair {
		return errors.New("gateway repair RPC failed")
	}
	return g.real.SetBlocked(id, r, on)
}
func (g *newerHoldSyncGateway) SyncToken(context.Context) (egress.SyncToken, error) {
	return g.real.SyncToken(), nil
}
func (g *newerHoldSyncGateway) Sync(_ context.Context, ss []egress.Spec, tok egress.SyncToken) error {
	if g.beforeSync != nil {
		g.beforeSync()
	}
	if err := g.real.SyncFrom(tok, ss); err != nil {
		return err
	}
	if g.beforeSync != nil {
		g.exposed = !g.real.IsBlocked(g.id)
		g.syncing = true
	}
	return nil
}
func TestFullSyncNeverDropsANewerHold(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "repair-succeeds", true: "repair-fails"}[reject], func(t *testing.T) {
			svc, fake, rt := newPolicyHarness(t)
			real := egress.New(egress.Options{Backend: egress.NewMemBackend()})
			if err := real.Bootstrap(); err != nil {
				t.Fatal(err)
			}
			gw := &newerHoldSyncGateway{fakeGateway: fake, real: real, rejectRepair: reject}
			svc.SetEgressGateway(gw, nil)
			ctx := context.Background()
			sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}})
			gw.id = sb.ID
			if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
				t.Fatal(err)
			}
			gw.beforeSync = func() { svc.holdUnapplied(ctx, sb, egressHoldProfileUnavailable) }
			err := svc.ResyncEgressGateway(ctx)
			if gw.exposed {
				t.Errorf("full Sync cleared newer hold before repair (final blocked=%v, Sync error=%v)", real.IsBlocked(sb.ID), err)
			}
			if reject && !real.IsBlocked(sb.ID) && err == nil {
				t.Error("failed repair leaves durable hold unenforced but full Sync returns success")
			}
		})
	}
}

func TestUnreadableHoldKeepsMediatorsShut(t *testing.T) {
	for _, kind := range []string{models.RuntimeWasm, models.RuntimeIsolate} {
		t.Run(kind, func(t *testing.T) {
			svc, _, _ := newPolicyHarness(t)
			m := newMediator()
			svc.wasm, svc.isolate = m, m
			sb := seedPolicySandbox(t, svc, models.Sandbox{Runtime: kind, NetworkAllowOut: []string{"pypi.org"}})
			svc.holdUnapplied(context.Background(), sb, egressHoldProfileUnavailable)
			if !m.blocked[sb.ID] {
				t.Fatal("setup: not held")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if kind == models.RuntimeWasm {
				svc.applyNetworkQuotaState(ctx, sb, false, false)
			} else {
				_ = svc.applyIsolatePolicy(ctx, sb)
			}
			st, err := svc.store.GetEgressState(context.Background(), sb.ID)
			if err != nil {
				t.Fatal(err)
			}
			if st.HoldReason != "" && !m.blocked[sb.ID] {
				t.Fatal("canceled hold lookup was treated as unheld and reopened mediator despite durable profile hold")
			}
		})
	}
}

type interleavingReleaseRuntime struct {
	*policyRuntime
	beforeClear func()
}

func (r *interleavingReleaseRuntime) ClearEgressHold(ip string) error {
	r.beforeClear()
	return r.policyRuntime.ClearEgressHold(ip)
}

func TestGatewayReleaseKeepsAConcurrentStrongerHold(t *testing.T) {
	svc, gw, rt := newPolicyHarness(t)
	ctx := context.Background()
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}})
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	svc.holdUnapplied(ctx, sb, egressHoldAttachFailed)
	// A profile pass raises a stronger hold on another goroutine after the
	// gateway release read the weaker reason, before its host-rule removal
	// and record clear. Without serialization the hold completes in the
	// window and the release erases it; with it, the hold waits for the
	// release and lands on top (the wait below gives it the window).
	done := make(chan struct{})
	releasing := &interleavingReleaseRuntime{policyRuntime: rt, beforeClear: func() {
		go func() { svc.holdUnapplied(ctx, sb, egressHoldProfileUnavailable); close(done) }()
		select {
		case <-done:
		case <-time.After(200 * time.Millisecond):
		}
	}}
	if err := svc.releaseEgressHold(ctx, sb, releasing, gatewayHolds...); err != nil {
		t.Fatal(err)
	}
	<-done
	st, _ := svc.store.GetEgressState(ctx, sb.ID)
	gw.mu.Lock()
	blocked := gw.blocked[sb.ID]&egress.BlockHold != 0
	gw.mu.Unlock()
	if st.HoldReason != egressHoldProfileUnavailable || !blocked {
		t.Fatalf("gateway release erased concurrent stronger hold: persisted=%q, gateway blocked=%v", st.HoldReason, blocked)
	}
}

// flakyBlocksGateway fails block writes while fail is set, and detaches
// while detachErr is nil.
type flakyBlocksGateway struct {
	*fakeGateway
	fail      bool
	detachErr error
}

func (g *flakyBlocksGateway) SetBlocked(ctx context.Context, id string, r egress.BlockReason, on bool) error {
	if g.fail {
		return fmt.Errorf("%w: gateway write failed", egress.ErrUnavailable)
	}
	return g.fakeGateway.SetBlocked(ctx, id, r, on)
}

func (g *flakyBlocksGateway) Detach(ctx context.Context, id string, ip netip.Addr) error {
	if g.detachErr != nil {
		return g.detachErr
	}
	return g.fakeGateway.Detach(ctx, id, ip)
}

// TestFailedBlockWriteStaysPendingAndFailsTheSync (review 3 finding 1): a
// hold whose gateway write fails is retried from the record until it lands,
// and a full Sync fails while it hasn't, so the gateway isn't reported
// ready on a state missing the hold.
func TestFailedBlockWriteStaysPendingAndFailsTheSync(t *testing.T) {
	ctx := context.Background()
	svc, fake, rt := newPolicyHarness(t)
	gw := &flakyBlocksGateway{fakeGateway: fake}
	svc.SetEgressGateway(gw, nil)
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}})
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	gw.fail = true
	svc.holdUnapplied(ctx, sb, egressHoldProfileUnavailable)
	if ids := svc.egressBlocksPending.list(); len(ids) != 1 || ids[0] != sb.ID {
		t.Fatalf("pending = %v", ids)
	}
	if err := svc.ResyncEgressGateway(ctx); err == nil {
		t.Fatal("a full Sync must fail while a block write is still pending")
	}
	gw.fail = false
	if err := svc.ResyncEgressGateway(ctx); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	blocked := fake.blocked[sb.ID]&egress.BlockHold != 0
	since := fake.tokens[len(fake.tokens)-1]
	fake.mu.Unlock()
	if !blocked || len(svc.egressBlocksPending.list()) != 0 {
		t.Fatalf("the pending hold must land: blocked=%v pending=%v", blocked, svc.egressBlocksPending.list())
	}
	if since != fake.tok {
		t.Fatalf("the Sync must carry the block gen read before its snapshot: %d", since)
	}
	// The supervisor's retry lands a write that failed outside a Sync.
	gw.fail = true
	svc.setEgressQuotaBlock(ctx, &models.Sandbox{ID: sb.ID, ContainerIP: policyIP, NetworkAllowOut: []string{"pypi.org"}}, true)
	gw.fail = false
	if err := svc.retryPendingBlocks(ctx); err != nil || len(svc.egressBlocksPending.list()) != 0 {
		t.Fatalf("retry: %v %v", err, svc.egressBlocksPending.list())
	}
	// A block gen that can't be read fails the Sync before anything changes.
	fake.mu.Lock()
	fake.tokErr = egress.ErrUnavailable
	n := len(fake.synced)
	fake.mu.Unlock()
	if err := svc.ResyncEgressGateway(ctx); err == nil {
		t.Fatal("no block gen, no Sync")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.synced) != n {
		t.Fatal("a Sync without a block gen must not be sent")
	}
}

// TestHeldSandboxAttachesShut: whatever the hold's class, an attach carries
// it, so the gateway never serves a held sandbox between the attach and a
// later block write; only a gateway hold is lifted by the attach itself.
func TestHeldSandboxAttachesShut(t *testing.T) {
	ctx := context.Background()
	svc, fake, rt := newPolicyHarness(t)
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}})
	if err := svc.recordHoldOnly(ctx, sb.ID, egressHoldProfileUnavailable); err != nil {
		t.Fatal(err)
	}
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	spec := fake.attached[sb.ID]
	fake.mu.Unlock()
	if spec.Blocked&egress.BlockHold == 0 {
		t.Fatal("a profile-held sandbox must attach with the hold block")
	}
	if st, _ := svc.store.GetEgressState(ctx, sb.ID); st.HoldReason != egressHoldProfileUnavailable {
		t.Fatalf("the attach lifted a profile hold: %q", st.HoldReason)
	}
}

// TestDetachFailureHoldsUntilTheRetryDetaches (review 3 finding 4): leaving
// gateway mode needs the detach acknowledged; until it is the sandbox is
// held and the record still names the gateway, so the supervisor's retry
// detaches it and only then releases the hold.
func TestDetachFailureHoldsUntilTheRetryDetaches(t *testing.T) {
	ctx := context.Background()
	svc, fake, rt := newPolicyHarness(t)
	gw := &flakyBlocksGateway{fakeGateway: fake, detachErr: fmt.Errorf("%w: detach failed", egress.ErrUnavailable)}
	svc.SetEgressGateway(gw, nil)
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}})
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateNetworkPolicy(ctx, sb.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"8.8.8.0/24"}}); !errors.Is(err, ErrEgressApplyFailedHeld) {
		t.Fatalf("err = %v", err)
	}
	st, _ := svc.store.GetEgressState(ctx, sb.ID)
	if st.HoldReason != egressHoldApplyFailed || st.Installed == nil || !st.Installed.Gateway {
		t.Fatalf("state = %+v", st)
	}
	if !fake.isAttached(sb.ID) {
		t.Fatal("setup: the failed detach must leave the attachment")
	}
	gw.detachErr = nil
	if err := svc.reapplyStoredPolicy(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	// Finished: the record goes (what is installed is what the stored
	// policy installs).
	st, _ = svc.store.GetEgressState(ctx, sb.ID)
	if fake.isAttached(sb.ID) || st.HoldReason != "" || st.Installed != nil {
		t.Fatalf("after the retry: attached=%v state=%+v", fake.isAttached(sb.ID), st)
	}
}

// TestInstalledRecordIsBounded: each failed transition to a new target adds
// at most one CIDR rule set; past the bound a new target is refused before
// the stored policy changes, and one success narrows the record.
func TestInstalledRecordIsBounded(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newPolicyHarness(t)
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"8.8.8.0/24"}})
	var inst store.InstalledEgress
	for i := range maxInstalledCIDR {
		inst.CIDR = append(inst.CIDR, store.CIDRRules{Allow: []string{fmt.Sprintf("10.%d.0.0/16", i)}})
	}
	if err := svc.store.SetInstalledEgress(ctx, sb.ID, inst, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateNetworkPolicy(ctx, sb.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"1.1.1.0/24"}}); err == nil {
		t.Fatal("a new target past the bound must be refused")
	}
	if got, _ := svc.store.Get(ctx, sb.ID); !slices.Equal(got.NetworkAllowOut, []string{"8.8.8.0/24"}) {
		t.Fatalf("the refused PUT changed the stored policy: %v", got.NetworkAllowOut)
	}
	// A target already in the record isn't new: it applies, and the
	// finished transition clears the record.
	if _, err := svc.UpdateNetworkPolicy(ctx, sb.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"10.3.0.0/16"}}); err != nil {
		t.Fatal(err)
	}
	if st, _ := svc.store.GetEgressState(ctx, sb.ID); st.Installed != nil {
		t.Fatalf("installed = %+v", st.Installed)
	}
}
