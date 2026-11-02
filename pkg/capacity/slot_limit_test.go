package capacity

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Regression for the 2026-11-02 single-node-fc density run (m5zn.metal,
// docker engine): 1,023 docker sandboxes started, then every create failed
// with dockerd's "failed to set up container networking" 500, because the
// sandbox bridge holds 1,023 ports and nothing counted them. CPU and memory
// admission still had room, so no create was refused for capacity.

func bridgeLimit(total int) SlotLimit {
	return SlotLimit{Name: SlotPoolDockerBridge, Pool: "docker bridge pool", Runtimes: []string{models.RuntimeDocker, models.RuntimeGvisor}, Total: total}
}

// roomyHost has CPU and memory for thousands of small sandboxes, so the slot
// pool is the only limit a test can hit.
func roomyHost() *Admitter {
	return New(HostInfo{CPUCores: 96, MemoryTotalMB: 384 * 1024, SupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeGvisor, models.RuntimeFirecracker}}, Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1, CPUOverProvisionFactor: 10}, nil)
}

func small(runtime string) Request { return Request{CPU: 0.25, MemoryMB: 128, Runtime: runtime} }

func TestSlotLimitFillsThenRefusesCleanly(t *testing.T) {
	a := roomyHost()
	a.SetSlotLimit(bridgeLimit(3))
	// runc and gVisor share the one bridge.
	for i, rt := range []string{models.RuntimeDocker, models.RuntimeGvisor, models.RuntimeDocker} {
		if err := a.Admit(fmt.Sprintf("sb-%d", i), small(rt)); err != nil {
			t.Fatalf("admit %d (%s): %v", i, rt, err)
		}
	}
	if p, ok := a.SlotPool(); !ok || p.Free != 0 || p.Total != 3 || p.Name != SlotPoolDockerBridge {
		t.Fatalf("SlotPool = %+v %t, want docker_bridge 0 of 3 free", p, ok)
	}
	for _, rt := range []string{models.RuntimeDocker, models.RuntimeGvisor} {
		err := a.Admit("sb-over-"+rt, small(rt))
		if !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("%s past the pool = %v, want a capacity refusal", rt, err)
		}
		if pool, ok := SlotPoolExhausted(err); !ok || pool != "docker bridge pool" {
			t.Fatalf("SlotPoolExhausted(%v) = (%q, %t), want the docker bridge pool", err, pool, ok)
		}
		if !strings.Contains(err.Error(), "network slot reservation exceeded (3+1 > 3 slots)") {
			t.Fatalf("message %q must say which axis ran out", err)
		}
	}
	if got := a.Snapshot().SandboxesActive; got != 3 {
		t.Fatalf("a refused admit reserved anyway: %d active", got)
	}
	// Other runtimes do not use the bridge.
	if err := a.Admit("fc-1", small(models.RuntimeFirecracker)); err != nil {
		t.Fatalf("firecracker on a full bridge: %v", err)
	}
	// Re-admitting a held id (retry, resize) does not take a second slot.
	if err := a.Admit("sb-0", Request{CPU: 1, MemoryMB: 256, Runtime: models.RuntimeDocker}); err != nil {
		t.Fatalf("re-admit of a held id: %v", err)
	}
	// "Is this host accepting at all?" stays yes: placement uses the pool,
	// not can_admit, to skip it for container runtimes.
	if snap := a.Snapshot(); !snap.CanAdmit {
		t.Fatalf("a full bridge turned can_admit off: %v", snap.Reasons)
	}
	if ok, _ := a.CanAdmitRequest(small(models.RuntimeDocker)); ok {
		t.Fatal("dry run on a full bridge says a docker sandbox fits")
	}
	if ok, _ := a.CanAdmitRequest(small(models.RuntimeFirecracker)); !ok {
		t.Fatal("dry run refuses firecracker for a full bridge")
	}
	// Destroy (and stop) release the slot.
	a.Release("sb-1")
	if p, _ := a.SlotPool(); p.Free != 1 {
		t.Fatalf("after a release Free = %d, want 1", p.Free)
	}
	if err := a.Admit("sb-next", small(models.RuntimeGvisor)); err != nil {
		t.Fatalf("admit after a release: %v", err)
	}
}

// A create that fails after admission releases it (service createSandbox's
// releaseAdmission), and a duplicate Release is harmless.
func TestSlotLimitFailedCreateGivesTheSlotBack(t *testing.T) {
	a := roomyHost()
	a.SetSlotLimit(bridgeLimit(1))
	if err := a.Admit("sb-a", small(models.RuntimeDocker)); err != nil {
		t.Fatal(err)
	}
	a.Release("sb-a")
	a.Release("sb-a")
	if p, _ := a.SlotPool(); p.Free != 1 {
		t.Fatalf("Free = %d after the failed create released, want 1", p.Free)
	}
	if err := a.Admit("sb-b", small(models.RuntimeDocker)); err != nil {
		t.Fatalf("the slot did not come back: %v", err)
	}
}

// A restart replays every running sandbox (Reserve, no checks) before or
// after the limit is set; either order must count all of them, and a pool
// replayed past its total refuses until enough are destroyed.
func TestSlotLimitCountsReplayedReservations(t *testing.T) {
	for _, limitFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("limit_first=%t", limitFirst), func(t *testing.T) {
			a := roomyHost()
			if limitFirst {
				a.SetSlotLimit(bridgeLimit(1000))
			}
			for i := 0; i < 1000; i++ {
				rt := models.RuntimeDocker
				if i%4 == 0 {
					rt = models.RuntimeGvisor
				}
				a.Reserve(fmt.Sprintf("sb-%d", i), small(rt))
			}
			a.Reserve("fc-0", small(models.RuntimeFirecracker))
			if !limitFirst {
				a.SetSlotLimit(bridgeLimit(1000))
			}
			if p, _ := a.SlotPool(); p.Free != 0 {
				t.Fatalf("after replaying 1000 sandboxes Free = %d, want 0", p.Free)
			}
			if err := a.Admit("sb-new", small(models.RuntimeDocker)); !errors.Is(err, ErrCapacityExceeded) {
				t.Fatalf("admit after a restart with a full bridge = %v, want a refusal", err)
			}
		})
	}
	// An operator lowering the total below what is running: no negative room.
	a := roomyHost()
	for i := 0; i < 5; i++ {
		a.Reserve(fmt.Sprintf("sb-%d", i), small(models.RuntimeDocker))
	}
	a.SetSlotLimit(bridgeLimit(3))
	if p, _ := a.SlotPool(); p.Free != 0 {
		t.Fatalf("over-full pool Free = %d, want 0", p.Free)
	}
	a.Release("sb-0")
	a.Release("sb-1")
	if err := a.Admit("sb-x", small(models.RuntimeDocker)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("3 of 3 held: admit = %v, want a refusal", err)
	}
	a.Release("sb-2")
	if err := a.Admit("sb-x", small(models.RuntimeDocker)); err != nil {
		t.Fatalf("2 of 3 held: %v", err)
	}
}

func TestSlotLimitOffOrRemoved(t *testing.T) {
	a := roomyHost()
	if _, ok := a.SlotPool(); ok {
		t.Fatal("no limit set, but a pool is reported")
	}
	a.SetSlotLimit(bridgeLimit(1))
	if err := a.Admit("sb-1", small(models.RuntimeDocker)); err != nil {
		t.Fatal(err)
	}
	a.SetSlotLimit(SlotLimit{})
	if _, ok := a.SlotPool(); ok {
		t.Fatal("a removed limit is still reported")
	}
	if err := a.Admit("sb-2", small(models.RuntimeDocker)); err != nil {
		t.Fatalf("admit with the limit removed: %v", err)
	}
	// The caller's runtime slice is not shared with the admitter.
	rts := []string{models.RuntimeDocker}
	a.SetSlotLimit(SlotLimit{Name: SlotPoolDockerBridge, Pool: "p", Runtimes: rts, Total: 9})
	rts[0] = models.RuntimeWasm
	if p, _ := a.SlotPool(); p.Runtimes[0] != models.RuntimeDocker || p.Free != 7 {
		t.Fatalf("SlotPool = %+v, want docker with 7 of 9 free", p)
	}
}

// Warm-pool parks hold a bridge port each. A ready park counts as free room
// (a create adopts or reclaims it), and a real create on a bridge full of
// parks reclaims one, exactly as it does for a full CPU budget; a park never
// reclaims another park.
func TestSlotLimitWarmParks(t *testing.T) {
	a := roomyHost()
	a.SetSlotLimit(bridgeLimit(3))
	gate := &ParkGate{Admitter: a}
	shape := dockerpool.ParkShape{CPU: 0.25, MemoryMB: 128, Runtime: models.RuntimeDocker}
	parked := []string{"p1", "p2"}
	for _, id := range parked {
		if err := gate.ParkReservation(id, shape); err != nil {
			t.Fatal(err)
		}
	}
	if p, _ := a.SlotPool(); p.Free != 1 {
		t.Fatalf("Free = %d with two parks still spawning, want 1", p.Free)
	}
	for _, id := range parked {
		gate.MarkParkReady(id, true)
	}
	if p, _ := a.SlotPool(); p.Free != 3 {
		t.Fatalf("Free = %d with two ready parks, want 3", p.Free)
	}
	var calls []int
	a.AddParkReclaimer(func(slots int) int {
		calls = append(calls, slots)
		freed := 0
		for freed < slots && len(parked) > 0 {
			gate.ReleasePark(parked[0])
			parked = parked[1:]
			freed++
		}
		return freed
	})
	if err := a.Admit("sb-1", small(models.RuntimeDocker)); err != nil {
		t.Fatal(err)
	}
	if gate.CanPark(shape) {
		t.Fatal("the refill gate would park on a full bridge")
	}
	if err := gate.ParkReservation("p3", shape); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("a park on a full bridge = %v, want a refusal without reclaim", err)
	}
	if len(calls) != 0 {
		t.Fatalf("a park reclaimed another park: %v", calls)
	}
	if err := a.Admit("sb-2", small(models.RuntimeGvisor)); err != nil {
		t.Fatalf("a real create on a bridge full of ready parks = %v, want it to reclaim one", err)
	}
	if len(calls) != 1 || calls[0] != 1 {
		t.Fatalf("reclaim calls = %v, want one call for one slot", calls)
	}
	if p, _ := a.SlotPool(); p.Free != 1 {
		t.Fatalf("Free = %d after the reclaim, want 1 (one ready park left)", p.Free)
	}
	// A park that is no longer ready (acquired by an adopting create) is
	// not room.
	gate.MarkParkReady("p2", false)
	if p, _ := a.SlotPool(); p.Free != 0 {
		t.Fatalf("Free = %d with the last park acquired, want 0", p.Free)
	}
	if err := a.Admit("sb-3", small(models.RuntimeDocker)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("no ready park to reclaim: admit = %v, want a refusal", err)
	}
}

func TestAsNetworkSlotExhausted(t *testing.T) {
	const pool = "docker bridge pool"
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"dockerd bridge full", errors.New(`start container: docker API POST /containers/c1/start failed with status 500: {"message":"failed to set up container networking: adding interface veth1a2b3c to bridge docker0 failed: exchange full"}`), true},
		{"iproute2 spelling", errors.New("RTNETLINK answers: Exchange full"), true},
		{"cni bridge plugin", errors.New(`provision netns: cni add: plugin type="bridge" failed (add): failed to connect "veth9" to bridge aerolvm0: exchange full`), true},
		{"dockerd ipam", errors.New("failed to set up container networking: no available IPv4 addresses on this network's address pools: bridge (8c1f)"), true},
		{"libnetwork ipam sentinel", errors.New("no available addresses on this pool"), true},
		{"cni host-local", errors.New("failed to allocate for range 0: no IP addresses available in range set: 10.88.0.1-10.88.255.254"), true},
		{"other start failure", errors.New("start container: docker API POST /containers/c1/start failed with status 500: OCI runtime create failed"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsNetworkExhaustion(tc.err); got != tc.want {
				t.Fatalf("IsNetworkExhaustion = %t, want %t", got, tc.want)
			}
			got := AsNetworkSlotExhausted(pool, tc.err)
			if !tc.want {
				if got != tc.err {
					t.Fatalf("a non-network error was rewritten: %v", got)
				}
				return
			}
			if !errors.Is(got, ErrCapacityExceeded) || !errors.Is(got, tc.err) {
				t.Fatalf("%v must be a capacity refusal that keeps its cause", got)
			}
			if name, ok := SlotPoolExhausted(got); !ok || name != pool {
				t.Fatalf("SlotPoolExhausted = (%q, %t)", name, ok)
			}
			if !strings.HasPrefix(got.Error(), "docker bridge pool: no free slot (host capacity exceeded): ") || !strings.HasSuffix(got.Error(), tc.err.Error()) {
				t.Fatalf("message %q must lead with the pool and keep the cause", got)
			}
		})
	}
	// Already a capacity refusal: not wrapped twice.
	already := fmt.Errorf("x: %w: exchange full", NewSlotPoolExhausted(pool))
	if got := AsNetworkSlotExhausted(pool, already); got != already {
		t.Fatalf("a capacity refusal was wrapped again: %v", got)
	}
}

// Parks already ready when the limit is set (a pool refilled before boot
// wiring finished) are counted as held and as free room.
func TestSetSlotLimitRecountsReadyParks(t *testing.T) {
	a := roomyHost()
	gate := &ParkGate{Admitter: a}
	if err := gate.ParkReservation("p1", dockerpool.ParkShape{CPU: 0.25, MemoryMB: 128, Runtime: models.RuntimeDocker}); err != nil {
		t.Fatal(err)
	}
	gate.MarkParkReady("p1", true)
	a.Reserve("sb-1", small(models.RuntimeDocker))
	a.SetSlotLimit(bridgeLimit(2))
	if p, _ := a.SlotPool(); p.Free != 1 {
		t.Fatalf("Free = %d, want 1 (two held, one of them a ready park)", p.Free)
	}
}
