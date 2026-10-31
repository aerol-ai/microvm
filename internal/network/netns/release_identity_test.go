package netns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/store"
)

// These are the regression tests for the live leak on cluster-3-mixed-gvisor
// (UC-336 churn soak: iptables-save grew 445 -> 1135 lines on one node, with
// 147 distinct "aerol-netns-<N>" ids left in the nat table). They only use API
// that exists on origin/main, so they can be run against it to show the bug.

// recordingHost is a real *Host over the in-memory CNI runner, with the netns
// create/delete seams recorded so a test can compare ADD and DEL identities.
type recordingHost struct {
	*Host
	runner *cni.FakeRunner

	mu      sync.Mutex
	created []string
	deleted []string
}

func newRecordingHost(t *testing.T) *recordingHost {
	t.Helper()
	r := &recordingHost{runner: cni.NewFakeRunner()}
	r.Host = &Host{
		Runner:    r.runner,
		NetnsRoot: "/run/netns",
		mkdir:     func(string, os.FileMode) error { return nil },
		addNetns: func(_ context.Context, name string) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.created = append(r.created, name)
			return nil
		},
		delNetns: func(_ context.Context, name string) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.deleted = append(r.deleted, name)
			return nil
		},
		loopbackUp: func(context.Context, string) error { return nil },
	}
	return r
}

func (r *recordingHost) deletedNames() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.deleted...)
}

// assertDelMatchesAdd fails unless the one CNI DEL and netns delete used the
// same container id, netns path and netns name as the one CNI ADD.
func assertDelMatchesAdd(t *testing.T, r *recordingHost, wantName string) {
	t.Helper()
	adds, dels := r.runner.Adds(), r.runner.Dels()
	if len(adds) != 1 || len(dels) != 1 {
		t.Fatalf("want exactly one CNI ADD and one DEL, got adds=%+v dels=%+v", adds, dels)
	}
	if adds[0].ContainerID != wantName {
		t.Fatalf("CNI ADD container id = %q, want %q", adds[0].ContainerID, wantName)
	}
	if dels[0].ContainerID != adds[0].ContainerID {
		t.Fatalf("CNI DEL container id %q != ADD container id %q: the host-local lease and the "+
			"ipMasq chain are keyed by container id, so this DEL leaks both", dels[0].ContainerID, adds[0].ContainerID)
	}
	if dels[0].Netns != adds[0].Netns {
		t.Fatalf("CNI DEL netns %q != ADD netns %q", dels[0].Netns, adds[0].Netns)
	}
	deleted := r.deletedNames()
	found := false
	for _, n := range deleted {
		if n == wantName {
			found = true
		}
	}
	if !found {
		t.Fatalf("netns %q was never deleted (deleted: %v): `ip netns del` targeted the wrong name", wantName, deleted)
	}
}

// A prewarmed slot is realized as "aerol-netns-N" and later claimed by a
// sandbox. Before the fix Release ran CNI DEL and `ip netns del` under the
// sandbox id, so the lease, the masquerade chain and the netns all survived.
func TestReleaseDeletesClaimedPooledSlotUnderAddIdentity(t *testing.T) {
	p := testPool(t, 2)
	r := newRecordingHost(t)
	ctx := context.Background()
	if err := p.Prewarm(ctx, r.Host, time.Unix(1, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	h := NewRuntimeHandoff(p, r.Host)
	path, ip, err := h.Provision(ctx, "sb-claim")
	if err != nil || path != "/run/netns/aerol-netns-0" || ip == "" {
		t.Fatalf("provision should hit the prewarmed slot: path=%q ip=%q err=%v", path, ip, err)
	}
	if err := h.Release(ctx, "sb-claim"); err != nil {
		t.Fatal(err)
	}
	assertDelMatchesAdd(t, r, "aerol-netns-0")
}

// A warm-park slot is realized under the park id, then the adopting sandbox
// takes it over by ReassignOwner. DEL must still use the park id.
func TestReleaseDeletesReassignedParkSlotUnderAddIdentity(t *testing.T) {
	p := testPool(t, 2)
	r := newRecordingHost(t)
	ctx := context.Background()
	h := NewRuntimeHandoff(p, r.Host)
	if _, _, err := h.Provision(ctx, "park-7"); err != nil {
		t.Fatal(err)
	}
	if err := h.ReassignOwner(ctx, "park-7", "sb-adopted"); err != nil {
		t.Fatal(err)
	}
	if err := h.Release(ctx, "sb-adopted"); err != nil {
		t.Fatal(err)
	}
	assertDelMatchesAdd(t, r, "park-7")
}

// The same, when the park itself sat on a prewarmed slot.
func TestReleaseDeletesReassignedPooledParkSlotUnderAddIdentity(t *testing.T) {
	p := testPool(t, 2)
	r := newRecordingHost(t)
	ctx := context.Background()
	if err := p.Prewarm(ctx, r.Host, time.Unix(1, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	h := NewRuntimeHandoff(p, r.Host)
	if _, _, err := h.Provision(ctx, "park-8"); err != nil {
		t.Fatal(err)
	}
	if err := h.ReassignOwner(ctx, "park-8", "sb-adopted-8"); err != nil {
		t.Fatal(err)
	}
	if err := h.Release(ctx, "sb-adopted-8"); err != nil {
		t.Fatal(err)
	}
	assertDelMatchesAdd(t, r, "aerol-netns-0")
}

// The cold path names the netns after the sandbox; that must not change.
func TestReleaseColdBuiltSlotKeepsSandboxIdentity(t *testing.T) {
	p := testPool(t, 2)
	r := newRecordingHost(t)
	ctx := context.Background()
	h := NewRuntimeHandoff(p, r.Host)
	if _, _, err := h.Provision(ctx, "sb-cold"); err != nil {
		t.Fatal(err)
	}
	if err := h.Release(ctx, "sb-cold"); err != nil {
		t.Fatal(err)
	}
	assertDelMatchesAdd(t, r, "sb-cold")
}

// A failed host teardown must not return the slot to the free pool: its
// lease, NAT chain and netns are still on the node, and handing it out again
// either fails ADD (host-local refuses a second lease for the same id) or
// stacks a second set of rules. Before the fix Release dropped the error and
// freed the slot anyway.
func TestReleaseRemoveFailureKeepsSlotOutOfPool(t *testing.T) {
	p := testPool(t, 1)
	host := NewFakeHost()
	ctx := context.Background()
	h := NewRuntimeHandoff(p, host)
	if _, _, err := h.Provision(ctx, "sb-fail"); err != nil {
		t.Fatal(err)
	}
	host.SetRemoveError(errors.New("cni del: exit status 1"))
	_ = h.Release(ctx, "sb-fail")

	stats, err := p.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Free != 0 {
		t.Fatalf("slot went back to the free pool after a failed teardown: %+v", stats)
	}
	if _, _, err := h.Provision(ctx, "sb-next"); !errors.Is(err, store.ErrNoFreeContainerNetnsSlot) {
		t.Fatalf("the half-torn-down slot was handed to the next sandbox (err=%v)", err)
	}
	if got, _ := p.Get(ctx, "sb-fail"); got != nil {
		t.Fatalf("the destroyed sandbox still owns a slot: %+v", got)
	}
}

// cniNode models what the CNI v1.5.1 bridge + host-local plugins leave on a
// node, keyed the way the real plugins key it:
//   - host-local lease: by container id; a second ADD for an id that still
//     holds a lease fails ("duplicate allocation is not allowed").
//   - ipMasq chain + POSTROUTING jump: by container id; the plugin's DEL only
//     tears them down for addresses still present on eth0 at DEL time.
//   - eth0 + its address: inside the netns at the ADD's netns path.
//
// stripAddr models gVisor: runsc moves the address into its netstack and
// deletes it from eth0 when the sandbox starts.
type cniNode struct {
	mu     sync.Mutex
	netns  map[string]bool            // mounted netns names
	eth0   map[string]*nodeLink       // netns path -> container interface
	leases map[string]string          // container id -> ip
	masq   map[string]map[string]bool // container id -> POSTROUTING sources
	next   int
}

type nodeLink struct {
	ip      string
	hasAddr bool
}

func newCNINode() *cniNode {
	return &cniNode{netns: map[string]bool{}, eth0: map[string]*nodeLink{}, leases: map[string]string{}, masq: map[string]map[string]bool{}}
}

func (n *cniNode) Add(_ context.Context, path, id string) (cni.Result, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.netns[filepath.Base(path)] {
		return cni.Result{}, fmt.Errorf("failed to open netns %q", path)
	}
	if n.eth0[path] != nil {
		return cni.Result{}, errors.New("container veth name provided (eth0) already exists")
	}
	if ip, ok := n.leases[id]; ok {
		return cni.Result{}, fmt.Errorf("%s has been allocated to %s, duplicate allocation is not allowed", ip, id)
	}
	n.next++
	ip := fmt.Sprintf("10.88.%d.%d", n.next/250, n.next%250+2)
	n.leases[id] = ip
	n.eth0[path] = &nodeLink{ip: ip, hasAddr: true}
	if n.masq[id] == nil {
		n.masq[id] = map[string]bool{}
	}
	n.masq[id][ip] = true
	return cni.Result{IP4: ip}, nil
}

func (n *cniNode) Del(_ context.Context, path, id string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.leases, id)
	if !n.netns[filepath.Base(path)] {
		return nil
	}
	link := n.eth0[path]
	delete(n.eth0, path)
	if link != nil && link.hasAddr {
		delete(n.masq, id)
	}
	return nil
}

// TeardownIPMasq models cni.ExecRunner's teardown: remove the id's chain and
// its jumps whatever eth0 looks like. Unused (and harmless) on origin/main.
func (n *cniNode) TeardownIPMasq(_ context.Context, id, _ string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.masq, id)
	return nil
}

func (n *cniNode) stripAddr(path string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if l := n.eth0[path]; l != nil {
		l.hasAddr = false
	}
}

func (n *cniNode) host() *Host {
	return &Host{
		Runner:    n,
		NetnsRoot: "/run/netns",
		mkdir:     func(string, os.FileMode) error { return nil },
		addNetns: func(_ context.Context, name string) error {
			n.mu.Lock()
			defer n.mu.Unlock()
			n.netns[name] = true
			return nil
		},
		delNetns: func(_ context.Context, name string) error {
			n.mu.Lock()
			defer n.mu.Unlock()
			delete(n.netns, name)
			delete(n.eth0, filepath.Join("/run/netns", name))
			return nil
		},
		loopbackUp: func(context.Context, string) error { return nil },
	}
}

// leftovers lists node state not owned by a slot that is still pooled (a
// pooled slot legitimately holds a lease, a chain and a netns).
func (n *cniNode) leftovers(pooled map[string]bool) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for id := range n.leases {
		if !pooled[id] {
			out = append(out, "lease:"+id)
		}
	}
	for id := range n.masq {
		if !pooled[id] {
			out = append(out, "masq:"+id)
		}
	}
	for name := range n.netns {
		if !pooled[name] {
			out = append(out, "netns:"+name)
		}
	}
	sort.Strings(out)
	return out
}

// TestChurnLeavesNoCNIState replays the UC-336 churn (create -> destroy with
// the warm refiller running, runc and gVisor sandboxes interleaved, a few in
// flight at once) against the plugin model and checks that nothing is left
// behind. On origin/main every claimed prewarmed slot leaked its lease and
// NAT chain, and every gVisor sandbox leaked its NAT chain.
func TestChurnLeavesNoCNIState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		gvisor func(i int) bool
	}{
		{name: "runc", gvisor: func(int) bool { return false }},
		{name: "gvisor", gvisor: func(int) bool { return true }},
		{name: "mixed", gvisor: func(i int) bool { return i%2 == 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := newCNINode()
			p := testPool(t, 64)
			host := node.host()
			h := NewRuntimeHandoff(p, host)
			r := NewRefiller(p, host, 4, time.Hour)
			ctx := context.Background()
			const cycles, inFlight = 120, 3
			var live []string
			for i := 0; i < cycles; i++ {
				r.refillOnce(ctx)
				id := fmt.Sprintf("sb-%03d", i)
				path, _, err := h.Provision(ctx, id)
				if err != nil {
					t.Fatalf("cycle %d: provision: %v", i, err)
				}
				if tc.gvisor(i) {
					node.stripAddr(path)
				}
				live = append(live, id)
				if len(live) > inFlight {
					if err := h.Release(ctx, live[0]); err != nil {
						t.Fatalf("cycle %d: release: %v", i, err)
					}
					live = live[1:]
				}
			}
			for _, id := range live {
				if err := h.Release(ctx, id); err != nil {
					t.Fatal(err)
				}
			}
			r.refillOnce(ctx)

			pooledRows, err := p.st.ListContainerNetnsSlotsByState(ctx, store.NetnsSlotStatePooled)
			if err != nil {
				t.Fatal(err)
			}
			pooled := map[string]bool{}
			for _, row := range pooledRows {
				pooled[row.SlotID] = true
			}
			if left := node.leftovers(pooled); len(left) > 0 {
				t.Fatalf("%d CNI objects outlived their sandboxes after %d cycles (first: %v)", len(left), cycles, left[:min(len(left), 6)])
			}
			stats, _ := p.Stats(ctx)
			if stats.Pooled != 4 {
				t.Fatalf("refiller should be back at depth 4, stats=%+v", stats)
			}
		})
	}
}

// A node upgraded from an affected binary already has slots whose lease was
// leaked under the slot's own id. host-local refuses every later ADD for that
// id, so on origin/main the refiller failed on the same lowest free slot each
// tick forever. A failed prewarm now clears the slot's own leftovers, so the
// next attempt succeeds.
func TestPrewarmHealsSlotWithLeakedLease(t *testing.T) {
	node := newCNINode()
	node.leases["aerol-netns-0"] = "10.88.9.9"
	node.masq["aerol-netns-0"] = map[string]bool{"10.88.9.9": true}
	p := testPool(t, 1)
	host := node.host()
	ctx := context.Background()
	if err := p.Prewarm(ctx, host, time.Unix(1, 0).UTC()); err == nil {
		t.Fatal("first prewarm must fail on the leaked lease (duplicate allocation)")
	}
	if err := p.Prewarm(ctx, host, time.Unix(2, 0).UTC()); err != nil {
		t.Fatalf("second prewarm must succeed once the leftover lease is released: %v", err)
	}
	stats, _ := p.Stats(ctx)
	if stats.Pooled != 1 {
		t.Fatalf("stats=%+v, want the slot pooled", stats)
	}
	if ip := node.leases["aerol-netns-0"]; ip == "10.88.9.9" {
		t.Fatal("the leaked lease is still held")
	}
}

// adoptFailHost realizes with an empty IP so the store rejects MarkRealized.
type adoptFailHost struct{ *FakeHost }

func (a *adoptFailHost) Realize(ctx context.Context, slot Slot) (string, string, error) {
	path, _, err := a.FakeHost.Realize(ctx, slot)
	return path, "", err
}

// Build failing after a successful Realize (MarkRealized or Adopt error) must
// tear the realized netns down and free the slot. On origin/main the deferred
// teardown read the slot variable that the failed MarkRealized had just set
// to nil, and panicked.
func TestBuildFailureAfterRealizeTearsDownWithoutPanic(t *testing.T) {
	p := testPool(t, 1)
	host := &adoptFailHost{FakeHost: NewFakeHost()}
	if _, err := NewBuilder(p, host).Build(context.Background(), "sb-bad"); err == nil {
		t.Fatal("want build failure")
	}
	if host.RemovedCount() != 1 || host.RealizedCount() != 0 {
		t.Fatalf("realized netns not torn down: removed=%d realized=%d", host.RemovedCount(), host.RealizedCount())
	}
	stats, _ := p.Stats(context.Background())
	if stats.Free != 1 {
		t.Fatalf("slot not freed: %+v", stats)
	}
}

// A duplicate create for the same sandbox that reaches Build after the first
// one adopted the slot must get that slot back. On origin/main it re-realized:
// `ip netns add` reused the live netns, CNI ADD failed (eth0 exists /
// duplicate lease), and the rollback deleted the live netns and freed the
// running sandbox's slot.
func TestDuplicateBuildReturnsAdoptedSlotWithoutTouchingIt(t *testing.T) {
	node := newCNINode()
	p := testPool(t, 2)
	host := node.host()
	ctx := context.Background()
	first, err := NewBuilder(p, host).Build(ctx, "sb-dup")
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewBuilder(p, host).Build(ctx, "sb-dup")
	if err != nil {
		t.Fatalf("duplicate build: %v", err)
	}
	if second.SlotID != first.SlotID || second.NetnsPath != first.NetnsPath || second.ContainerIP != first.ContainerIP {
		t.Fatalf("duplicate build got %+v, want %+v", second, first)
	}
	if !node.netns["sb-dup"] {
		t.Fatal("the running sandbox's netns was deleted")
	}
	if got, _ := p.Get(ctx, "sb-dup"); got == nil || got.State != store.NetnsSlotStateAdopted {
		t.Fatalf("the running sandbox lost its slot: %+v", got)
	}
}

// Same, racing: concurrent duplicate Provisions for one sandbox. A loser may
// fail cleanly at Reserve (the sandbox_id unique index), or wait and get the
// winner's slot; it must never tear down the winner's netns.
func TestConcurrentDuplicateProvisionKeepsWinnerIntact(t *testing.T) {
	node := newCNINode()
	p := testPool(t, 4)
	h := NewRuntimeHandoff(p, node.host())
	ctx := context.Background()
	var wg sync.WaitGroup
	paths := make([]string, 4)
	errs := make([]error, 4)
	for i := range paths {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			paths[i], _, errs[i] = h.Provision(ctx, "sb-race")
		}(i)
	}
	wg.Wait()
	ok := 0
	for i := range paths {
		if errs[i] != nil {
			continue
		}
		ok++
		if paths[i] != "/run/netns/sb-race" {
			t.Fatalf("provision %d: path=%q", i, paths[i])
		}
	}
	if ok == 0 {
		t.Fatalf("no provision succeeded: %v", errs)
	}
	if !node.netns["sb-race"] || len(node.leases) != 1 {
		t.Fatalf("want the winner's netns and one lease intact, got netns=%v leases=%v (errs=%v)", node.netns, node.leases, errs)
	}
	if got, _ := p.Get(ctx, "sb-race"); got == nil || got.State != store.NetnsSlotStateAdopted {
		t.Fatalf("winner lost its slot: %+v", got)
	}
}
