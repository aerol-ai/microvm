package service

// Early gateway attach: a hostname-filtered create's attach starts as soon
// as the runtime knows the sandbox's address, so it overlaps the rest of
// the runtime create instead of following it (plans/egress-domain-filtering.md
// §8.2 budgets: svc_egress_join ≤ 2 ms p50).
//
// A driver that fixes the address before the workload runs (containerd's
// prepaid netns, Docker's pause netns, a Firecracker TAP slot) installs the
// request's rules on it (for a gateway-mode create, the block-all) and
// reports it through runtime.AddressObserver. The create then runs the
// gateway half of the attach (attachGateway) while the runtime builds and
// starts the workload. When the runtime create returns, finish checks the
// address is the one reported, joins the attach, and lifts the driver's
// block (liftDriverBlock) alongside the row persist, as the late attach
// always did. A driver that learns the address only from the finished
// create (Docker's own IPAM, a warm-pool adopt) reports nothing, and the
// create attaches afterwards exactly as before.
//
// Why the sandbox is never open:
//   - the workload never runs without the block-all: the driver installs it
//     before it reports the address, and reports before the workload starts;
//   - the block lifts only in finish, after the gateway's Attach for that
//     exact address succeeded and the runtime confirmed the address; a
//     create that fails earlier leaves the block on;
//   - so at every moment the sandbox is behind the block-all, the gateway,
//     or both.
//
// Rollback rule (pr-review.md §4). An early attach is undone (a gateway
// Detach) before its address can reach another sandbox:
//   - by the driver's ReleasingAddress call on every path that gives the
//     address back (a failed create's cleanup, a rollback's Destroy), after
//     the workload is gone and before the slot is freed;
//   - by the create itself when the runtime create failed without the
//     driver calling it;
//   - never while another create of the same sandbox holds the same attach
//     (concurrent duplicates) or a stored row has taken it over (that
//     create committed). egressCreateLocks orders that check and the detach
//     against a duplicate's attach.
// A Detach that fails is queued (egressDetachPending) and retried every
// supervisor tick, as a destroy's is.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/observability"
	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
	"go.opentelemetry.io/otel/attribute"
)

// errEgressAddressMismatch: the runtime created the sandbox at an address
// other than the one it reported early. The gateway enforces for the
// reported one, so the create fails.
var errEgressAddressMismatch = errors.New("egress: the runtime created the sandbox at another address than it reported")

// egressCreateHolds counts, per sandbox, the creates holding an early
// attach: normally none or one, two only for concurrent duplicates of one
// sandbox ID. Callers hold egressCreateLocks for the sandbox.
type egressCreateHolds struct {
	mu sync.Mutex
	n  map[string]int
}

func (h *egressCreateHolds) hold(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.n == nil {
		h.n = map[string]int{}
	}
	h.n[id]++
}

// drop releases one hold and reports whether none is left.
func (h *egressCreateHolds) drop(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.n[id] > 1 {
		h.n[id]--
		return false
	}
	delete(h.n, id)
	return true
}

func (h *egressCreateHolds) count(id string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.n[id]
}

// earlyEgressAttach is one create's early attach. It is the create's
// runtime.AddressObserver.
type earlyEgressAttach struct {
	s   *Service
	ctx context.Context
	cr  runtime.ContainerRuntime
	sb  models.Sandbox // the create's policy; ContainerIP is set once reported

	once sync.Once
	mu   sync.Mutex
	ip   string
	at   time.Time // when the address was reported
	done chan struct{}
	// Written before done closes; read after it.
	attached, held bool
	err            error
	took           time.Duration
	// settled: the hold this create took is dropped (committed or undone).
	settled bool
}

var _ runtime.AddressObserver = (*earlyEgressAttach)(nil)

func (s *Service) newEarlyEgressAttach(ctx context.Context, cr runtime.ContainerRuntime, sb models.Sandbox) *earlyEgressAttach {
	return &earlyEgressAttach{s: s, ctx: ctx, cr: cr, sb: sb}
}

// AddressKnown starts the gateway half of the attach for ip.
func (e *earlyEgressAttach) AddressKnown(ip string) {
	e.once.Do(func() {
		// The hold is taken before the attach exists, under the lock an
		// undo takes for its check and Detach: a duplicate's undo either
		// sees this hold, or finishes its Detach before this Attach.
		unlock := e.s.egressCreateLocks.lock(e.sb.ID)
		e.s.egressCreateHolds.hold(e.sb.ID)
		unlock()
		e.mu.Lock()
		e.ip, e.at, e.done = ip, time.Now(), make(chan struct{})
		e.mu.Unlock()
		sb := e.sb
		sb.ContainerIP = ip
		go e.run(&sb)
	})
}

func (e *earlyEgressAttach) run(sb *models.Sandbox) {
	defer close(e.done)
	start := time.Now()
	ctx, span := observability.StartSpan(e.ctx, "egress.attach", attribute.String("sandbox_id", sb.ID), attribute.String("egress.attach.phase", "early"))
	stages := e.s.newAttachStages(ctx, span)
	ctx, cancel := context.WithTimeout(ctx, egressAttachTimeout)
	defer cancel()
	attached, held, err := e.s.attachGateway(ctx, sb, stages)
	observability.EndSpan(span, err)
	e.attached, e.held, e.err, e.took = attached, held, err, time.Since(start)
}

// reported returns the address the runtime reported, if it did.
func (e *earlyEgressAttach) reported() (string, bool) {
	if e == nil {
		return "", false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.ip, e.ip != ""
}

// wait joins the gateway half. Callers check reported first.
func (e *earlyEgressAttach) wait() {
	<-e.done
}

// ReleasingAddress undoes the attach before the driver gives ip back.
func (e *earlyEgressAttach) ReleasingAddress(string) { e.undo() }

// undo is the rollback rule above. Idempotent; a no-op before a report.
func (e *earlyEgressAttach) undo() {
	ip, ok := e.reported()
	if !ok {
		return
	}
	e.mu.Lock()
	if e.settled {
		e.mu.Unlock()
		return
	}
	e.settled = true
	e.mu.Unlock()
	// The Attach may still be on the wire: a Detach that overtook it would
	// leave the Attach's state behind.
	e.wait()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(e.ctx), egressAttachTimeout)
	defer cancel()
	unlock := e.s.egressCreateLocks.lock(e.sb.ID)
	defer unlock()
	if !e.s.egressCreateHolds.drop(e.sb.ID) {
		return // a concurrent create of this sandbox holds the same attach
	}
	if owned, err := e.s.store.HasSandbox(ctx, e.sb.ID); err != nil {
		// Unknown: a committed duplicate would be opened by a Detach, so
		// keep the attach (the full Sync drops it once no row names it).
		e.s.logger.Warn("egress: early attach kept; the sandbox row could not be read", "sandbox_id", e.sb.ID, "error", err)
		return
	} else if owned {
		return // a create of this sandbox committed: its row owns the attach
	}
	sb := e.sb
	sb.ContainerIP = ip
	// Even a failed Attach may have reached the gateway (a reply lost to a
	// timeout); a Detach of a sandbox it doesn't have is a no-op.
	e.s.detachSandboxEgress(ctx, &sb, ip)
}

// commit hands the attach to the create's stored row.
func (e *earlyEgressAttach) commit() {
	if _, ok := e.reported(); !ok {
		return
	}
	e.mu.Lock()
	if e.settled {
		e.mu.Unlock()
		return
	}
	e.settled = true
	e.mu.Unlock()
	unlock := e.s.egressCreateLocks.lock(e.sb.ID)
	e.s.egressCreateHolds.drop(e.sb.ID)
	unlock()
}

// end settles the attach when its create returns: a successful create
// commits it, any other exit undoes it (a no-op when a rollback already
// did).
func (e *earlyEgressAttach) end(ok bool) {
	if e == nil {
		return
	}
	if ok {
		e.commit()
		return
	}
	e.undo()
}

// finish completes an early attach once the runtime create returned sb: the
// address must be the reported one, the gateway half must have succeeded,
// and then the driver's block lifts. It returns the attach's total work (the
// two halves, not the wall time between them) for svc_egress_attach.
func (e *earlyEgressAttach) finish(sb *models.Sandbox) (time.Duration, error) {
	ip, _ := e.reported()
	if sb.ContainerIP != ip {
		// The gateway enforces for ip, the sandbox is at sb.ContainerIP,
		// whose rules the driver never installed: shut it before failing.
		if err := e.cr.ApplyNetworkBlockAll(sb.ContainerIP); err != nil {
			e.s.logger.Warn("egress: could not shut a sandbox the runtime moved", "sandbox_id", sb.ID, "ip", sb.ContainerIP, "error", err)
		}
		return 0, fmt.Errorf("%w: reported %q, created at %q", errEgressAddressMismatch, ip, sb.ContainerIP)
	}
	e.wait()
	if e.err != nil || !e.attached {
		// Not attached and no error: not a gateway-mode spec after all
		// (attachSandboxEgress returns the same way); the block stays.
		return e.took, e.err
	}
	start := time.Now()
	ctx, span := observability.StartSpan(e.ctx, "egress.attach", attribute.String("sandbox_id", sb.ID), attribute.String("egress.attach.phase", "finish"))
	stages := e.s.newAttachStages(ctx, span)
	ctx, cancel := context.WithTimeout(ctx, egressAttachTimeout)
	defer cancel()
	err := e.s.liftDriverBlock(ctx, sb, e.cr, e.held, stages)
	observability.EndSpan(span, err)
	return e.took + time.Since(start), err
}

// gatewayReleaser detaches a sandbox from the gateway when its runtime is
// about to give the address back: the runtime.AddressObserver of a destroy
// (DestroySandbox, a reconcile reap, an orphan removal, a create rollback
// with no early attach). The runtime calls it once the workload can no
// longer send, so the Detach opens nothing, and before the slot is free,
// so no other sandbox ever meets this one's gateway state. The terminal
// teardown after the destroy still detaches (a no-op by then) for runtimes
// that free the address inside their own call (Docker's IPAM).
type gatewayReleaser struct {
	s  *Service
	sb *models.Sandbox
	// any detaches without asking the stored policy: an orphan's stub
	// carries none.
	any bool
	ctx context.Context
}

var _ runtime.AddressObserver = gatewayReleaser{}

func (s *Service) gatewayReleaserCtx(ctx context.Context, sb *models.Sandbox, any bool) context.Context {
	if !s.egressEnabled() || sb == nil {
		return ctx
	}
	return runtime.WithAddressObserver(ctx, gatewayReleaser{s: s, sb: sb, any: any, ctx: ctx})
}

func (gatewayReleaser) AddressKnown(string) {}

func (g gatewayReleaser) ReleasingAddress(ip string) {
	if !g.any && !isGatewayMode(g.sb) {
		return
	}
	g.s.detachSandboxEgress(context.WithoutCancel(g.ctx), g.sb, ip)
}

// reportedAt is when the runtime reported the address.
func (e *earlyEgressAttach) reportedAt() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.at
}

// startCreateAttach runs a create's attach alongside its row persist and
// delivers the result on done: the finish of an early attach, or the whole
// attach when the runtime reported no address early. svc_egress_attach is
// the attach's work either way; svc_egress_early, present only on the early
// path, is how long the attach had while the runtime built the sandbox.
func (s *Service) startCreateAttach(ctx context.Context, early *earlyEgressAttach, sb *models.Sandbox, cr runtime.ContainerRuntime, isContainer bool, done chan<- error) {
	timing := createtiming.From(ctx)
	if _, ok := early.reported(); ok {
		timing.RecordStage("svc_egress_early", time.Since(early.reportedAt()))
		go func() {
			took, err := early.finish(sb)
			timing.RecordStage("svc_egress_attach", took)
			done <- err
		}()
		return
	}
	go func() {
		start := time.Now()
		err := ErrEgressGatewayRequired
		if isContainer {
			err = s.attachSandboxEgress(ctx, sb, cr)
		}
		timing.RecordStage("svc_egress_attach", time.Since(start))
		done <- err
	}()
}
