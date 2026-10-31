package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func stageMS(timing *createtiming.CreateTiming, name string) (time.Duration, bool) {
	for _, st := range timing.Stages() {
		if st.Name == name {
			return time.Duration(st.DurMS * float64(time.Millisecond)), true
		}
	}
	return 0, false
}

// TestEarlyAttachOrder: on every runtime that reports the address early,
// the create runs block-all → report → gateway Attach (while the runtime
// is still building) → runtime create returns → block lifted, never
// leaving the sandbox open, and the create waits for (almost) nothing.
// The runtime here takes as long as the gateway's 40 ms Attach.
func TestEarlyAttachOrder(t *testing.T) {
	for _, shape := range earlyShapes {
		t.Run(shape, func(t *testing.T) {
			h := newEarlyHarness(t, shape)
			h.gw.attachDelay = 40 * time.Millisecond
			h.rt.waitAttach = h.gw.attachedCh
			ctx, timing := createtiming.With(context.Background())
			resp, err := h.svc.CreateSandbox(ctx, h.request())
			if err != nil {
				t.Fatal(err)
			}
			h.m.assertClean(t)
			ip := resp.ContainerIP
			order := []string{"block " + ip, "reported " + ip, "attach " + resp.ID + " " + ip, "returned " + ip, "unblock " + ip}
			last := -1
			for _, ev := range order {
				i := h.m.index(ev)
				if i < 0 || i < last {
					t.Fatalf("event %q at %d, want it after %d in order %q\nevents: %v", ev, i, last, order, h.m.events)
				}
				last = i
			}
			if n := h.gw.attachCount(resp.ID); n != 1 {
				t.Fatalf("%d gateway attaches, want 1", n)
			}
			if !h.gw.isAttached(resp.ID) {
				t.Fatal("the gateway must enforce for the created sandbox")
			}
			early, ok := stageMS(timing, "svc_egress_early")
			if !ok || early <= 0 {
				t.Fatalf("svc_egress_early = %v (present %v), want the overlap reported", early, ok)
			}
			join, ok := stageMS(timing, "svc_egress_join")
			if !ok {
				t.Fatal("svc_egress_join missing")
			}
			if join >= h.gw.attachDelay/2 {
				t.Fatalf("svc_egress_join %v: the create still waited for the gateway's %v Attach", join, h.gw.attachDelay)
			}
			if _, ok := stageMS(timing, "svc_egress_attach"); !ok {
				t.Fatal("svc_egress_attach missing")
			}
			if c := h.svc.egressCreateHolds.count(resp.ID); c != 0 {
				t.Fatalf("%d create holds left after a committed create", c)
			}
		})
	}
}

// TestPlainDockerKeepsLateAttach: Docker without the pause pool reports no
// address before the container runs, so its create attaches after the
// runtime create as before, and waits for the Attach (the join this change
// removes elsewhere).
func TestPlainDockerKeepsLateAttach(t *testing.T) {
	h := newEarlyHarness(t, shapeDockerPlain)
	h.gw.attachDelay = 40 * time.Millisecond
	ctx, timing := createtiming.With(context.Background())
	resp, err := h.svc.CreateSandbox(ctx, h.request())
	if err != nil {
		t.Fatal(err)
	}
	h.m.assertClean(t)
	ip := resp.ContainerIP
	if r, a := h.m.index("returned "+ip), h.m.index("attach "+resp.ID); a < r {
		t.Fatalf("plain Docker attached (%d) before its runtime create returned (%d)", a, r)
	}
	if h.m.index("reported") >= 0 {
		t.Fatal("plain Docker must not report an address early")
	}
	if _, ok := stageMS(timing, "svc_egress_early"); ok {
		t.Fatal("svc_egress_early on a late attach")
	}
	if join, _ := stageMS(timing, "svc_egress_join"); join < h.gw.attachDelay/2 {
		t.Fatalf("svc_egress_join %v: a late attach is joined after the persist", join)
	}
}

// TestEarlyAttachFailureLeavesNoGatewayState: whatever step of an early
// attach's create fails, the create fails (or returns the winner of a
// duplicate), the sandbox is never open on the way, and afterwards the
// gateway holds nothing for the address, no rule is left on it, and the
// address went back only after the gateway let go of it.
func TestEarlyAttachFailureLeavesNoGatewayState(t *testing.T) {
	boom := errors.New("injected runtime failure")
	type tc struct {
		name    string
		prep    func(*testing.T, *earlyHarness, context.CancelFunc)
		mutate  func(*models.CreateSandboxRequest)
		wantErr func(error) bool
		// attached: whether the gateway attach landed before the failure
		// ("" when it races the failure).
		attached string
	}
	isBoom := func(err error) bool { return errors.Is(err, boom) }
	cases := []tc{
		{name: "runtime fails before it reports", prep: func(_ *testing.T, h *earlyHarness, _ context.CancelFunc) {
			h.rt.fail["before-report"] = boom
		}, wantErr: isBoom, attached: "no"},
		{name: "runtime fails right after it reports", prep: func(_ *testing.T, h *earlyHarness, _ context.CancelFunc) {
			h.rt.fail["after-report"] = boom
		}, wantErr: isBoom},
		{name: "runtime fails after the workload started", prep: func(_ *testing.T, h *earlyHarness, _ context.CancelFunc) {
			h.rt.waitAttach = h.gw.attachedCh
			h.rt.fail["after-start"] = boom
		}, wantErr: isBoom, attached: "yes"},
		{name: "gateway refuses the attach", prep: func(_ *testing.T, h *earlyHarness, _ context.CancelFunc) {
			h.gw.beforeAttach = func(egress.Spec) error { return fmt.Errorf("%w: refused", egress.ErrUnavailable) }
		}, wantErr: func(err error) bool { return errors.Is(err, ErrEgressGatewayUnavailable) }, attached: "no"},
		{name: "registry seal fails after the attach", prep: func(_ *testing.T, h *earlyHarness, _ context.CancelFunc) {
			h.rt.waitAttach = h.gw.attachedCh
			h.rt.afterReport = func(context.Context, string) { h.svc.cipher.Revoke() }
		}, mutate: func(req *models.CreateSandboxRequest) {
			req.Registry = &models.RegistryAuth{Server: "registry.example", Username: "u", Password: "p"}
		}, wantErr: func(err error) bool { return errors.Is(err, secrets.ErrKeyRevoked) }, attached: "yes"},
		{name: "persist fails after the row (platform attachments)", prep: func(t *testing.T, h *earlyHarness, _ context.CancelFunc) {
			h.rt.waitAttach = h.gw.attachedCh
			forcePlatformAttachmentFailure(t, h.svc)
		}, wantErr: func(err error) bool { return err != nil && strings.Contains(err.Error(), "persist platform") }, attached: "yes"},
		{name: "context cancelled mid-create", prep: func(_ *testing.T, h *earlyHarness, cancel context.CancelFunc) {
			// The runtime builds until the context ends; it ends once the
			// attach has landed.
			h.rt.waitAttach = make(chan string)
			h.rt.afterReport = func(context.Context, string) {
				go func() { <-h.gw.attachedCh; cancel() }()
			}
		}, wantErr: func(err error) bool { return errors.Is(err, context.Canceled) }, attached: "yes"},
		{name: "runtime returns another address than it reported", prep: func(_ *testing.T, h *earlyHarness, _ context.CancelFunc) {
			h.rt.waitAttach = h.gw.attachedCh
			h.rt.finalIP = func(string) string { return "10.77.99.99" }
		}, wantErr: func(err error) bool {
			// 503 like any attach that couldn't be completed, naming why.
			return errors.Is(err, ErrEgressGatewayUnavailable) && strings.Contains(err.Error(), "another address")
		}, attached: "yes"},
	}
	for _, shape := range earlyShapes {
		for _, c := range cases {
			t.Run(shape+"/"+c.name, func(t *testing.T) {
				h := newEarlyHarness(t, shape)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if shape == shapeFirecracker && strings.Contains(c.name, "platform attachments") {
					t.Skip("Firecracker has no platform volumes; its after-row failure is the refused attach, joined after the persist")
				}
				c.prep(t, h, cancel)
				if c.name == "runtime returns another address than it reported" {
					// A sandbox at an address its rules aren't on runs open
					// until the service shuts it: what the model must see is
					// that it does shut it, so its start isn't judged.
					h.m.lateBlock = true
				}
				req := h.request()
				if c.mutate != nil {
					c.mutate(&req)
				}
				resp, err := h.svc.CreateSandbox(ctx, req)
				if err == nil {
					t.Fatalf("create succeeded (%s), want a failure", resp.ID)
				}
				if !c.wantErr(err) {
					t.Fatalf("err = %v", err)
				}
				h.m.assertClean(t)
				h.m.assertNothingLeft(t)
				for id := range h.gw.attached {
					t.Fatalf("gateway entry for %s left", id)
				}
				landed := h.m.index("attach ") >= 0
				if c.attached == "yes" && !landed || c.attached == "no" && landed {
					t.Fatalf("attach landed = %v, want %s (events %v)", landed, c.attached, h.m.events)
				}
				if landed {
					if d, f := h.m.index("detach "), h.m.index("free "); d < 0 || d > f {
						t.Fatalf("detach at %d, free at %d: the gateway must let go before the address is freed", d, f)
					}
				}
				if c.name == "runtime returns another address than it reported" && h.m.index("block 10.77.99.99") < 0 {
					t.Fatal("the address the runtime really used must be shut")
				}
			})
		}
	}
}

// forcePlatformAttachmentFailure makes the create fail right after its row
// is stored (the platform-attachment persist).
func forcePlatformAttachmentFailure(t *testing.T, svc *Service) {
	t.Helper()
	svc.cfg.PlatformVolumes = enabledVolumeService(t).cfg.PlatformVolumes
	svc.cfg.PATToken = "operator-pat"
	tenant, err := svc.volumeTenant(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	svc.testForcePlatformAttachments = []models.VolumeAttachment{{VolumeID: "ghost", Tenant: tenant, Target: "/data"}}
	svc.testVolumeMeta = &scriptedVolumeMeta{putAttachmentsErr: errors.New("put boom")}
}

// TestEarlyAttachDuplicateCreatesConverge: concurrent creates of one
// sandbox ID (a retried cluster create) on a runtime that settles the race
// at its container create: one attach, one sandbox, attached and unblocked,
// never open, however the race goes. Run under -race; 25 rounds per shape.
func TestEarlyAttachDuplicateCreatesConverge(t *testing.T) {
	for _, shape := range []string{shapeContainerd, shapeDockerPause} {
		t.Run(shape, func(t *testing.T) {
			h := newEarlyHarness(t, shape)
			h.gw.attachDelay = 2 * time.Millisecond
			for round := 0; round < 25; round++ {
				id := fmt.Sprintf("sb-dup-%d", round)
				var wg sync.WaitGroup
				errs := make([]error, 3)
				for i := range errs {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						_, errs[i] = h.svc.CreateSandboxWithID(context.Background(), h.request(), id)
					}(i)
				}
				wg.Wait()
				ok := 0
				for _, err := range errs {
					switch {
					case err == nil:
						ok++
					case errors.Is(err, models.ErrSandboxExists):
					default:
						t.Fatalf("round %d: %v", round, err)
					}
				}
				if ok == 0 {
					t.Fatalf("round %d: no create succeeded: %v", round, errs)
				}
				if n := h.gw.attachCount(id); n != 1 {
					t.Fatalf("round %d: %d attaches, want 1", round, n)
				}
				if !h.gw.isAttached(id) {
					t.Fatalf("round %d: the winner is not attached", round)
				}
				if c := h.svc.egressCreateHolds.count(id); c != 0 {
					t.Fatalf("round %d: %d create holds left", round, c)
				}
			}
			h.m.assertClean(t)
		})
	}
}

// TestEarlyUndoKeepsADuplicatesAttach: two creates of one sandbox both hold
// the same early attach (a runtime that doesn't settle duplicates at its
// create). The one that fails must not detach what the other still uses;
// the last one out does, unless a stored row took the attach over.
func TestEarlyUndoKeepsADuplicatesAttach(t *testing.T) {
	h := newEarlyHarness(t, shapeContainerd)
	ctx := context.Background()
	sb := models.Sandbox{ID: "sb-twice", Runtime: models.RuntimeDocker, NetworkAllowOut: []string{"pypi.org"}}
	a := h.svc.newEarlyEgressAttach(ctx, h.rt, sb)
	b := h.svc.newEarlyEgressAttach(ctx, h.rt, sb)
	a.AddressKnown("10.77.5.5")
	b.AddressKnown("10.77.5.5")
	a.AddressKnown("10.77.5.6") // a second report is ignored
	a.wait()
	b.wait()
	if !h.gw.isAttached("sb-twice") {
		t.Fatal("not attached")
	}
	a.undo()
	if !h.gw.isAttached("sb-twice") {
		t.Fatal("an undo detached an attach another create still holds")
	}
	a.undo() // idempotent: it must not drop b's hold
	if h.svc.egressCreateHolds.count("sb-twice") != 1 {
		t.Fatalf("holds = %d, want b's", h.svc.egressCreateHolds.count("sb-twice"))
	}
	b.undo()
	if h.gw.isAttached("sb-twice") {
		t.Fatal("the last undo must detach")
	}

	// A row that took the attach over keeps it.
	c := h.svc.newEarlyEgressAttach(ctx, h.rt, models.Sandbox{ID: "sb-row", Runtime: models.RuntimeDocker, NetworkAllowOut: []string{"pypi.org"}})
	c.AddressKnown("10.77.5.7")
	c.wait()
	now := time.Now().UTC()
	if err := h.svc.store.Create(ctx, &models.Sandbox{ID: "sb-row", Image: "alpine", Status: models.SandboxStatusStarted, ContainerIP: "10.77.5.7",
		Runtime: models.RuntimeDocker, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatal(err)
	}
	c.undo()
	if !h.gw.isAttached("sb-row") {
		t.Fatal("an undo detached an attach a stored row owns")
	}
	// Before any report everything is a no-op.
	d := h.svc.newEarlyEgressAttach(ctx, h.rt, sb)
	d.undo()
	d.commit()
	if _, ok := d.reported(); ok {
		t.Fatal("reported before AddressKnown")
	}
	var nilAttach *earlyEgressAttach
	nilAttach.end(true)
	nilAttach.end(false)
	nilAttach.undo()
	nilAttach.commit()
}

// TestEarlyAttachGatewayRestartBetweenAttachAndFinish: the gateway restarts
// after the early Attach and before the create finishes. Its kernel sets
// keep enforcing, sandboxd's full Sync carries the in-flight attach, and
// the create completes attached; it is never open.
func TestEarlyAttachGatewayRestartBetweenAttachAndFinish(t *testing.T) {
	for _, shape := range earlyShapes {
		t.Run(shape, func(t *testing.T) {
			h := newEarlyHarness(t, shape)
			h.rt.waitAttach = make(chan string, 1)
			var synced []egress.Spec
			h.rt.afterReport = func(ctx context.Context, ip string) {
				go func() {
					id := <-h.gw.attachedCh
					// Restart: the process's memory is gone (the kernel's
					// isn't), the event stream broke, sandboxd re-syncs.
					h.gw.mu.Lock()
					h.gw.attached = map[string]egress.Spec{}
					h.gw.mu.Unlock()
					h.svc.egressReady.Store(false)
					if err := h.svc.EnsureEgressGatewayReady(context.Background()); err != nil {
						t.Errorf("re-sync: %v", err)
					}
					h.gw.mu.Lock()
					synced = slices.Clone(h.gw.synced[len(h.gw.synced)-1])
					h.gw.mu.Unlock()
					h.rt.waitAttach <- id
				}()
			}
			resp, err := h.svc.CreateSandbox(context.Background(), h.request())
			if err != nil {
				t.Fatal(err)
			}
			h.m.assertClean(t)
			if !slices.ContainsFunc(synced, func(s egress.Spec) bool { return s.ID == resp.ID && s.IP.String() == resp.ContainerIP }) {
				t.Fatalf("the full Sync after the restart dropped the in-flight attach: %+v", synced)
			}
			if !h.gw.isAttached(resp.ID) {
				t.Fatal("the sandbox must be attached after the create")
			}
		})
	}
}

// TestEarlyAttachGatewayDownFailsClean: a gateway that is down when the
// address is reported fails the create with 503; the block-all never
// lifts while the workload runs and nothing is left behind.
func TestEarlyAttachGatewayDownFailsClean(t *testing.T) {
	for _, shape := range earlyShapes {
		t.Run(shape, func(t *testing.T) {
			h := newEarlyHarness(t, shape)
			h.gw.readyErr = egress.ErrUnavailable
			h.gw.beforeAttach = func(egress.Spec) error { return egress.ErrUnavailable }
			_, err := h.svc.CreateSandbox(context.Background(), h.request())
			if !errors.Is(err, ErrEgressGatewayUnavailable) {
				t.Fatalf("err = %v, want 503", err)
			}
			h.m.assertClean(t)
			h.m.assertNothingLeft(t)
		})
	}
}

// TestDestroyLetsTheGatewayGoBeforeTheAddress: destroying a sandbox the
// gateway enforces for detaches it after the workload stopped and before
// the runtime frees the address, on every runtime that holds its address
// apart from the workload; plain Docker's address goes with its container
// and the detach follows (unchanged).
func TestDestroyLetsTheGatewayGoBeforeTheAddress(t *testing.T) {
	for _, shape := range append(slices.Clone(earlyShapes), shapeDockerPlain) {
		t.Run(shape, func(t *testing.T) {
			h := newEarlyHarness(t, shape)
			ctx := context.Background()
			resp, err := h.svc.CreateSandbox(ctx, h.request())
			if err != nil {
				t.Fatal(err)
			}
			if err := h.svc.DestroySandbox(ctx, resp.ID); err != nil {
				t.Fatal(err)
			}
			h.m.assertClean(t)
			h.m.assertNothingLeft(t)
			stop, det, free := h.m.index("stop "), h.m.index("detach "+resp.ID), h.m.index("free "+resp.ID)
			if stop < 0 || det < 0 || free < 0 {
				t.Fatalf("stop %d detach %d free %d: %v", stop, det, free, h.m.events)
			}
			if shape == shapeDockerPlain {
				if free > det {
					t.Fatalf("plain Docker: free %d before detach %d expected (the address goes with the container)", free, det)
				}
				return
			}
			if !(stop < det && det < free) {
				t.Fatalf("want stop < detach < free, got %d %d %d: %v", stop, det, free, h.m.events)
			}
		})
	}
}

// TestOrphanRemovalLetsTheGatewayGoFirst: a create that died after its
// early attach leaves a runtime instance with no row; the orphan sweep
// removes it, and the gateway lets go before the address is freed.
func TestOrphanRemovalLetsTheGatewayGoFirst(t *testing.T) {
	h := newEarlyHarness(t, shapeContainerd)
	ctx := context.Background()
	// The dead create: container, address, block-all, an attach, no row.
	ip := h.rt.claim("sb-orphan")
	h.rt.newContainer("sb-orphan")
	h.m.block(ip)
	h.m.start(ip)
	ea := h.svc.newEarlyEgressAttach(ctx, h.rt, models.Sandbox{ID: "sb-orphan", Runtime: models.RuntimeDocker, NetworkAllowOut: []string{"pypi.org"}})
	ea.AddressKnown(ip)
	ea.wait()
	h.svc.cfg.AutoReconcile = true
	if err := h.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	h.m.assertClean(t)
	h.m.assertNothingLeft(t)
	if det, free := h.m.index("detach sb-orphan"), h.m.index("free sb-orphan"); det < 0 || det > free {
		t.Fatalf("detach %d, free %d: %v", det, free, h.m.events)
	}
}

// TestGatewayReleaserScope: a destroy's releaser detaches only a
// gateway-mode sandbox (or any sandbox for an orphan's stub), and is
// absent when the feature is off.
func TestGatewayReleaserScope(t *testing.T) {
	h := newEarlyHarness(t, shapeContainerd)
	ctx := context.Background()
	plain := &models.Sandbox{ID: "sb-plain", ContainerIP: "10.77.6.1"}
	gw := &models.Sandbox{ID: "sb-gw", ContainerIP: "10.77.6.2", NetworkAllowOut: []string{"pypi.org"}}
	runtime.NotifyReleasingAddress(h.svc.gatewayReleaserCtx(ctx, plain, false), plain.ContainerIP)
	runtime.NotifyReleasingAddress(h.svc.gatewayReleaserCtx(ctx, gw, false), gw.ContainerIP)
	runtime.NotifyReleasingAddress(h.svc.gatewayReleaserCtx(ctx, &models.Sandbox{ID: "sb-stub"}, true), "10.77.6.3")
	h.gw.mu.Lock()
	detached := slices.Clone(h.gw.detached)
	h.gw.mu.Unlock()
	if slices.Contains(detached, "sb-plain") || !slices.Contains(detached, "sb-gw") || !slices.Contains(detached, "sb-stub") {
		t.Fatalf("detached %v", detached)
	}
	runtime.NotifyAddressKnown(h.svc.gatewayReleaserCtx(ctx, gw, false), "10.77.6.2") // a destroy has nothing to report
	h.svc.cfg.EgressFQDNEnabled = false
	if runtime.AddressObserverFrom(h.svc.gatewayReleaserCtx(ctx, gw, false)) != nil {
		t.Fatal("no releaser without the feature")
	}
}
