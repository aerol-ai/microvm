package containerd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The clears #1460 moved into giveBack, each pinned on its own (#1460
// review), and the containerd driver's IPOwner (ip_owner.go).

// blockThenFail is single mode's firewall (the Manager, ClearAddress
// included) that puts the park block on, then reports a failure: a park
// that fails after its block is on.
type blockThenFail struct{ *netrules.Manager }

func (f blockThenFail) BlockAllEgress(ip string) error {
	_ = f.Manager.BlockAllEgress(ip)
	return errors.New("the block went on, then the call failed")
}

// liftFails is single mode's firewall refusing the claim's rules step (the
// lift of the park block).
type liftFails struct{ *netrules.Manager }

func (liftFails) LiftBlockAllEgress(string) error { return errors.New("helper unavailable") }

// A park that fails after its block went on gives its slot back with the
// block cleared: the next sandbox given the address would start blocked.
func TestFailedParkClearsItsAddress(t *testing.T) {
	stubToolboxProbe(t)
	hostIPv6(t, true)
	(&specCapture{}).install(t)
	provider, img := newTestImageProvider(t)
	tr := newFakeTransport()
	tr.provider, tr.image = provider, img
	tmp := t.TempDir()
	toolbox := filepath.Join(tmp, "toolboxd")
	if err := os.WriteFile(toolbox, []byte{0}, 0o755); err != nil {
		t.Fatal(err)
	}
	be := &addressMemBackend{netrulesMemBackend: &netrulesMemBackend{}}
	d := New(Config{
		ToolboxBinaryPath: toolbox, ToolboxMountPath: "/.aerol/toolboxd", ToolboxPort: 2280,
		ToolboxWaitTimeout: 2 * time.Second, LogDir: filepath.Join(tmp, "logs"), RunDir: filepath.Join(tmp, "run"),
		ReadyEnabled: true, ReadyDir: shortReadyDir(t), NativeNetnsPool: true,
	}, nil, nil)
	d.SetHostFirewall(blockThenFail{netrules.NewWithBackend(be)})
	d.SetClient(NewTestClient("aerolvm", tr))
	const ip = "10.88.0.82"
	d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/park-blk", ip: ip})
	origWait := parkReadyWaitFn
	parkReadyWaitFn = func(context.Context, *dockerpkg.ParkedListener) error { return nil }
	t.Cleanup(func() { parkReadyWaitFn = origWait })
	_, err := d.parkContainer(context.Background(), "park-blk", containerdpool.Key{Image: "cfg:test", Runtime: models.RuntimeGvisor})
	if err == nil || !strings.Contains(err.Error(), "park egress block") {
		t.Fatalf("park = %v, want the block step's failure", err)
	}
	if left := be.rulesOf(ip); len(left) > 0 {
		t.Fatalf("the failed park left rules on %s: %v", ip, left)
	}
}

// A failed claim whose owner move-back failed but whose container delete
// worked: the slot is still sb-a's, so the discard gives sb-a's address
// back, with the rules the claim put on it. #1460 moved this clear out of
// destroyParked (the park no longer holds the slot) into the discard.
func TestClaimDiscardClearsTheAddressTheIDHolds(t *testing.T) {
	r := newDoubleFailureRig(t, false)
	r.fw.onLift = nil // containerd takes the delete
	be := &addressMemBackend{netrulesMemBackend: &netrulesMemBackend{}}
	r.d.SetHostFirewall(liftFails{netrules.NewWithBackend(be)})
	// The claim's lists, already on the address when its rules step failed.
	if err := r.d.ApplyEgressPolicy(r.parkIP, []string{"10.1.0.0/16"}, []string{"10.2.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	_, err := r.d.tryWarmAdopt(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-a", "tok", nil, models.RuntimeDocker)
	if err == nil || errors.Is(err, errClaimLeftover) || !strings.Contains(err.Error(), "warm adopt failed") {
		t.Fatalf("claim err %v, want a failed claim whose teardown worked", err)
	}
	if r.slotLeft() {
		t.Fatal("setup: the container was meant to go")
	}
	if left := be.rulesOf(r.parkIP); len(left) > 0 {
		t.Fatalf("the discard left the claim's rules on %s: %v", r.parkIP, left)
	}
	if got := r.owner(t, r.parkIP); got != "" {
		t.Fatalf("%s still held by %q", r.parkIP, got)
	}
}

// The free step gives back only the slot at the claim's own address, and
// checks that under the slot's lock: here, after its own check passed,
// sb-a gave that address back, sb-b took it, and sb-a got another one with
// its rules on. The step must leave sb-a's new slot and its rules.
func TestFreeStepMatchesTheAddressUnderTheLock(t *testing.T) {
	ctx := context.Background()
	r := newDoubleFailureRig(t, false)
	r.failClaim(t)
	be := singleModeRules(t, r.d, r.parkIP)
	r.busy.Store(false)
	var y string
	moved := false
	testHookGiveBack = func(owner string) {
		if owner != "sb-a" || moved {
			return
		}
		moved = true
		if err := r.h.Release(ctx, "sb-a"); err != nil {
			t.Error(err)
		}
		if _, x, err := r.h.Provision(ctx, "sb-b"); err != nil || x != r.parkIP {
			t.Errorf("sb-b got %q, %v", x, err)
		}
		var err error
		if _, y, err = r.h.Provision(ctx, "sb-a"); err != nil || y == "" || y == r.parkIP {
			t.Errorf("sb-a got %q, %v", y, err)
		}
		if err := r.d.ApplyNetworkBlockAll(y); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { testHookGiveBack = nil })
	if err := r.retry(t); err != nil {
		t.Fatal(err)
	}
	if !moved {
		t.Fatal("the free step never reached giveBack")
	}
	if len(be.rulesOf(y)) == 0 {
		t.Fatalf("sb-a's new rules on %s were cleared", y)
	}
	if held, _ := r.h.Address(ctx, "sb-a"); held != y {
		t.Fatalf("sb-a holds %q, want %s", held, y)
	}
}

// errHolderReader is a netns handoff whose owner read fails.
type errHolderReader struct{ *fakeNetnsHandoff }

func (errHolderReader) AddressHolder(context.Context, string) (string, bool, error) {
	return "", false, errors.New("store busy")
}

// IPOwner answers from the netns pool's slots: the slot that records the
// address, a park included; an error while a slot is being built with its
// rules folded in (split) and nothing records the address; no view at all
// without the pool.
func TestIPOwner(t *testing.T) {
	ctx := context.Background()
	t.Run("no netns pool", func(t *testing.T) {
		if _, err := New(Config{}, nil, nil).IPOwner(ctx, "10.88.0.2"); !errors.Is(err, sbruntime.ErrNoIPOwnerView) {
			t.Fatalf("err %v", err)
		}
		d := New(Config{}, nil, nil)
		d.SetNetnsHandoff(&fakeNetnsHandoff{})
		if _, err := d.IPOwner(ctx, "10.88.0.2"); !errors.Is(err, sbruntime.ErrNoIPOwnerView) {
			t.Fatalf("a handoff with no owner read: %v", err)
		}
	})
	t.Run("a failed read", func(t *testing.T) {
		d := New(Config{}, nil, nil)
		d.SetNetnsHandoff(errHolderReader{&fakeNetnsHandoff{}})
		if _, err := d.IPOwner(ctx, "10.88.0.2"); err == nil {
			t.Fatal("a failed read gave an owner")
		}
	})
	t.Run("held, parked, free and being built", func(t *testing.T) {
		r := newDoubleFailureRig(t, false)
		d := r.d
		if got, err := d.IPOwner(ctx, r.parkIP); err != nil || got != "park-a" {
			t.Fatalf("parked address: %q %v", got, err)
		}
		if _, ip, err := r.h.Provision(ctx, "sb-x"); err != nil {
			t.Fatal(err)
		} else if got, err := d.IPOwner(ctx, ip); err != nil || got != "sb-x" {
			t.Fatalf("held address: %q %v", got, err)
		}
		if _, err := r.np.Reserve(ctx, "sb-building", time.Now()); err != nil {
			t.Fatal(err)
		}
		d.SetHostFirewall(plainFirewall{r.fw})
		if got, err := d.IPOwner(ctx, "10.88.250.1"); err != nil || got != "" {
			t.Fatalf("single mode, a slot being built: %q %v; want free", got, err)
		}
		d.SetHostFirewall(r.fw) // its rules fold into the build
		if _, err := d.IPOwner(ctx, "10.88.250.1"); !errors.Is(err, errAddressBeingBuilt) {
			t.Fatalf("split, a slot being built: %v", err)
		}
		if got, err := d.IPOwner(ctx, r.parkIP); err != nil || got != "park-a" {
			t.Fatalf("a recorded address while another slot is built: %q %v", got, err)
		}
	})
}
