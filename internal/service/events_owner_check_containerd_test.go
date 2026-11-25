package service

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/netns"
	"github.com/aerol-ai/microvm/internal/runtime"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A late stop or destroy event on the containerd engine (P0-6, the
// containerd driver's IPOwner). Sandbox A's destroy failed after it gave
// its address back (Destroy lets the address go either way, and the row
// stays for the retry), and A's die event comes late. Meanwhile sandbox B
// is being created on the same address. In privilege mode split B's rules
// go on inside its namespace build, before its slot row records the
// address, so the store alone sees no holder and the late event cleared
// B's rules.

// memRuleBackend is an in-memory netrules backend.
type memRuleBackend struct{ rules []string }

func memRuleKey(table, chain string, spec []string) string {
	return strings.Join(append([]string{table, chain}, spec...), "|")
}
func (m *memRuleBackend) EnsureInputChain(string) error { return nil }
func (m *memRuleBackend) Exists(table, chain string, spec ...string) (bool, error) {
	return slices.Contains(m.rules, memRuleKey(table, chain, spec)), nil
}
func (m *memRuleBackend) Insert(table, chain string, _ int, spec ...string) error {
	m.rules = append(m.rules, memRuleKey(table, chain, spec))
	return nil
}
func (m *memRuleBackend) Delete(table, chain string, spec ...string) error {
	i := slices.Index(m.rules, memRuleKey(table, chain, spec))
	if i < 0 {
		return errors.New("No chain/target/match by that name")
	}
	m.rules = slices.Delete(m.rules, i, i+1)
	return nil
}
func (m *memRuleBackend) on(ip string) int {
	n := 0
	for _, r := range m.rules {
		if strings.Contains(r, "|"+ip+"|") {
			n++
		}
	}
	return n
}

// foldingFirewall is privilege mode split's firewall as the driver sees it:
// a create's rules go on with its namespace build (FoldsIntoBuild).
type foldingFirewall struct{ cntr.HostFirewall }

func (foldingFirewall) ApplyCreateRules(context.Context, string, string, bool, []string, []string) error {
	return nil
}
func (foldingFirewall) FoldsIntoBuild() bool  { return true }
func (foldingFirewall) ClearsOnRelease() bool { return true }

// containerdOwnerRig is a service whose sandboxes run on a real containerd
// driver over the service's own store: its netns pool, and a firewall over
// the in-memory backend.
type containerdOwnerRig struct {
	svc  *Service
	pool *netns.Pool
	h    *netns.RuntimeHandoff
	d    *cntr.Driver
	be   *memRuleBackend
}

func newContainerdOwnerRig(t *testing.T, split bool) *containerdOwnerRig {
	t.Helper()
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	pool := netns.New(st)
	for _, id := range []string{"slot-1", "slot-2"} {
		if err := st.SeedContainerNetnsSlot(ctx, id, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	r := &containerdOwnerRig{svc: svc, pool: pool, h: netns.NewRuntimeHandoff(pool, netns.NewFakeHost()), be: &memRuleBackend{}}
	rules := netrules.NewWithBackend(r.be)
	r.d = cntr.New(cntr.Config{}, rules, nil)
	if split {
		r.d.SetHostFirewall(foldingFirewall{rules})
	}
	r.d.SetNetnsHandoff(r.h)
	svc.docker = r.d
	return r
}

// leave gives sandbox A an address, its row and its rules, then gives the
// address back as a Destroy whose container delete failed does: the row
// stays.
func (r *containerdOwnerRig) leave(t *testing.T) (*models.Sandbox, string) {
	t.Helper()
	ctx := context.Background()
	_, ip, err := r.h.Provision(ctx, "sb-a")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	a := &models.Sandbox{ID: "sb-a", Image: "img", Status: models.SandboxStatusStarted, ContainerIP: ip,
		Runtime: models.RuntimeDocker, AuditIncarnationID: "inc-sb-a", CreatedAt: now, UpdatedAt: now, LastActiveAt: now}
	if err := r.svc.store.Upsert(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := r.d.ApplyNetworkBlockAll(ip); err != nil {
		t.Fatal(err)
	}
	if err := r.h.Release(ctx, "sb-a"); err != nil {
		t.Fatal(err)
	}
	return a, ip
}

func lateEvent(t *testing.T, svc *Service, a *models.Sandbox, event string) {
	t.Helper()
	ctx := context.Background()
	var err error
	if event == "stop" {
		err = svc.markSandboxStopped(ctx, a, docker.DockerEvent{SandboxID: a.ID, Action: "die", Time: time.Now().UTC()})
	} else {
		err = svc.handleDestroyEvent(ctx, a)
	}
	if err != nil {
		t.Fatalf("%s event: %v", event, err)
	}
}

// B is being built on A's old address with its rules on (split mode), and
// its slot row does not record the address yet: A's late event leaves B's
// rules. Once B's row records the address, the store sees B and a second
// late event leaves them too.
func TestLateEventLeavesTheRulesOfASlotBeingBuilt(t *testing.T) {
	for _, event := range []string{"stop", "destroy"} {
		t.Run(event, func(t *testing.T) {
			ctx := context.Background()
			r := newContainerdOwnerRig(t, true)
			a, ip := r.leave(t)
			// B's build: the slot is reserved, CNI gave it A's old address,
			// and its rules went on with the namespace.
			if _, err := r.pool.Reserve(ctx, "sb-b", time.Now()); err != nil {
				t.Fatal(err)
			}
			if err := r.d.ApplyNetworkBlockAll(ip); err != nil {
				t.Fatal(err)
			}
			rulesOfB := r.be.on(ip)
			lateEvent(t, r.svc, a, event)
			if got := r.be.on(ip); got != rulesOfB {
				t.Fatalf("B's rules on %s: %d left of %d", ip, got, rulesOfB)
			}
			// B's build finishes: its row records the address.
			if _, err := r.pool.MarkRealized(ctx, "sb-b", "/run/netns/b", ip, time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := r.pool.Adopt(ctx, "sb-b", time.Now()); err != nil {
				t.Fatal(err)
			}
			lateEvent(t, r.svc, a, event)
			if got := r.be.on(ip); got != rulesOfB {
				t.Fatalf("after B's build, B's rules on %s: %d left of %d", ip, got, rulesOfB)
			}
		})
	}
}

// Nobody took A's address: A's own late event still clears it, in split
// mode and in single mode, a slot being built for someone else or not
// (single mode's rules go on only once the row records the address).
func TestLateEventStillClearsAnAddressNobodyTook(t *testing.T) {
	for _, tc := range []struct {
		name            string
		split, building bool
	}{
		{name: "split", split: true},
		{name: "single"},
		{name: "single, another slot being built", building: true},
	} {
		for _, event := range []string{"stop", "destroy"} {
			t.Run(tc.name+"/"+event, func(t *testing.T) {
				ctx := context.Background()
				r := newContainerdOwnerRig(t, tc.split)
				a, ip := r.leave(t)
				if tc.building {
					if _, err := r.pool.Reserve(ctx, "sb-b", time.Now()); err != nil {
						t.Fatal(err)
					}
				}
				lateEvent(t, r.svc, a, event)
				if got := r.be.on(ip); got != 0 {
					t.Fatalf("A's rules on %s: %d left", ip, got)
				}
			})
		}
	}
}

// Without its native netns pool the containerd driver has no view of who
// holds an address: the store alone decides, as before IPOwner.
func TestIPHolderWithoutANetnsPoolUsesTheStore(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	d := cntr.New(cntr.Config{}, nil, nil)
	if _, err := d.IPOwner(ctx, "10.88.0.9"); !errors.Is(err, runtime.ErrNoIPOwnerView) {
		t.Fatalf("IPOwner without a pool: %v", err)
	}
	now := time.Now().UTC()
	if err := st.Upsert(ctx, &models.Sandbox{ID: "sb-x", Image: "img", Status: models.SandboxStatusStarted, ContainerIP: "10.88.0.9",
		Runtime: models.RuntimeDocker, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatal(err)
	}
	if holder, known := svc.ipHolder(ctx, d, "10.88.0.9", ""); !known || holder != "sb-x" {
		t.Fatalf("ipHolder = %q, %v; want the store's sb-x", holder, known)
	}
	if holder, known := svc.ipHolder(ctx, d, "10.88.0.10", ""); !known || holder != "" {
		t.Fatalf("ipHolder of a free address = %q, %v", holder, known)
	}
}
