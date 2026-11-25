package containerd

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Follow-ups from the #1451 review (claim_leftovers.go): in single mode an
// address whose holder is gone is cleared of every rule, not only the block
// rules; a retried create that removes the leftover itself ends the
// refusal; and the free step's address check is pinned on its own.

// addressMemBackend is netrulesMemBackend that can clear an address the way
// both real backends do (netrules ClearAddressRules): every rule whose
// source is ip, and every rule with no source whose destination is ip.
type addressMemBackend struct {
	*netrulesMemBackend
}

func (b *addressMemBackend) ClearAddressRules(chains []string, ip string) error {
	kept := b.rules[:0]
	for _, r := range b.rules {
		parts := strings.Split(r, "|")
		if len(parts) > 2 && slices.Contains(chains, parts[1]) && ruleKeyedBy(parts[2:], ip) {
			continue
		}
		kept = append(kept, r)
	}
	b.rules = kept
	return nil
}

// ruleKeyedBy mirrors netrules' addressRuleKeyed.
func ruleKeyedBy(spec []string, ip string) bool {
	var src, dst string
	for i := 0; i+1 < len(spec); i++ {
		switch spec[i] {
		case "-s":
			src = spec[i+1]
		case "-d":
			dst = spec[i+1]
		}
	}
	if src != "" {
		return strings.TrimSuffix(src, "/32") == ip
	}
	return strings.TrimSuffix(dst, "/32") == ip
}

// rulesOf is every rule keyed by ip.
func (b *addressMemBackend) rulesOf(ip string) []string {
	var out []string
	for _, r := range b.rules {
		if parts := strings.Split(r, "|"); len(parts) > 2 && ruleKeyedBy(parts[2:], ip) {
			out = append(out, r)
		}
	}
	return out
}

// singleModeRules gives d a single-mode firewall (netrules.Manager over
// the in-memory backend: no CreateRules, so its release clears nothing)
// and puts the allow and deny lists and the block a failed claim could
// leave on ip, plus another address's list that must stay.
func singleModeRules(t *testing.T, d *Driver, ip string) *addressMemBackend {
	t.Helper()
	be := &addressMemBackend{netrulesMemBackend: &netrulesMemBackend{}}
	d.SetHostFirewall(netrules.NewWithBackend(be))
	if d.clearsOnRelease() {
		t.Fatal("setup: want a firewall whose release does not clear rules")
	}
	if err := d.ApplyEgressPolicy(ip, []string{"10.1.0.0/16"}, []string{"10.2.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	if err := d.ApplyNetworkBlockAll(ip); err != nil {
		t.Fatal(err)
	}
	if err := d.ApplyEgressPolicy(otherIP, []string{"10.3.0.0/16"}, nil); err != nil {
		t.Fatal(err)
	}
	if n := len(be.rulesOf(ip)); n < 3 {
		t.Fatalf("setup: %d rules on %s, want the lists and the block: %v", n, ip, be.rules)
	}
	return be
}

const otherIP = "10.88.0.77"

func requireAddressEmpty(t *testing.T, be *addressMemBackend, ip string) {
	t.Helper()
	if left := be.rulesOf(ip); len(left) > 0 {
		t.Fatalf("rules left on %s: %v", ip, left)
	}
	if len(be.rulesOf(otherIP)) == 0 {
		t.Fatalf("another address's rules were cleared too: %v", be.rules)
	}
}

// The free step in single mode: the address the leftover's namespace still
// holds is cleared of the claim's lists too, not only of its block, before
// the slot goes back to the pool.
func TestClaimLeftoverFreeClearsEveryRuleOfTheAddressInSingleMode(t *testing.T) {
	r := newDoubleFailureRig(t, false)
	r.failClaim(t)
	be := singleModeRules(t, r.d, r.parkIP)
	r.busy.Store(false)
	r.pool.Close()
	requireAddressEmpty(t, be, r.parkIP)
	if r.owner(t, r.parkIP) != "" || r.d.refusesClaimLeftover("sb-a") {
		t.Fatalf("owner %q, remembered %v", r.owner(t, r.parkIP), r.d.refusesClaimLeftover("sb-a"))
	}
}

// destroyParked in single mode: a parked slot's address is cleared of
// every rule once its container is gone.
func TestDestroyParkedClearsEveryRuleOfTheAddressInSingleMode(t *testing.T) {
	d := New(Config{}, nil, nil)
	const ip = "10.88.0.9"
	be := singleModeRules(t, d, ip)
	d.SetNetnsHandoff(&fakeNetnsHandoff{})
	d.SetClient(NewTestClient("aerolvm", newFakeTransport())) // the container is gone
	slot := &containerdpool.ParkedSlot{ID: "park-n", ContainerID: "park-n", ContainerIP: ip}
	if err := d.destroyParked(context.Background(), slot); err != nil {
		t.Fatal(err)
	}
	requireAddressEmpty(t, be, ip)
}

// plainFirewall hides CreateRules and ClearAddress: a single-mode firewall
// whose release clears nothing and that can clear only the rules it is
// named. addressFirewall is the same with ClearAddress.
type plainFirewall struct{ HostFirewall }

type addressFirewall struct {
	HostFirewall
	rec func(format string, args ...any) error
}

func (f addressFirewall) ClearAddress(ip string) error { return f.rec("clear-address %s", ip) }

// The free step's order in single mode (#1451 review check): the container
// first, then the address's rules, then sb-a's slot. With ClearAddress the
// whole address is cleared; a firewall without it clears the block rules,
// as before.
func TestClaimLeftoverFreeClearsRulesBeforeReleaseInSingleMode(t *testing.T) {
	for name, tc := range map[string]struct {
		fw   func(r *doubleFailureRig) HostFirewall
		want string
	}{
		"firewall with ClearAddress": {func(r *doubleFailureRig) HostFirewall { return addressFirewall{r.fw, r.fw.rec} }, "clear-address "},
		"firewall without it":        {func(r *doubleFailureRig) HostFirewall { return plainFirewall{r.fw} }, "clear-block "},
	} {
		t.Run(name, func(t *testing.T) {
			r := newDoubleFailureRig(t, false)
			r.d.SetHostFirewall(tc.fw(r))
			if r.d.clearsOnRelease() {
				t.Fatal("setup: want a firewall whose release does not clear rules")
			}
			r.failClaim(t)
			r.busy.Store(false)
			mark := len(r.fw.recorded())
			r.pool.Close()
			after := r.fw.recorded()[mark:]
			del, clr, rel := slices.Index(after, "delete park-a"), slices.Index(after, tc.want+r.parkIP), slices.Index(after, "release sb-a")
			if del < 0 || clr < del || rel < clr {
				t.Fatalf("retry calls %v: want delete, then %q, then release sb-a", after, tc.want+r.parkIP)
			}
			if r.owner(t, r.parkIP) != "" || r.d.refusesClaimLeftover("sb-a") {
				t.Fatalf("owner %q, remembered %v", r.owner(t, r.parkIP), r.d.refusesClaimLeftover("sb-a"))
			}
		})
	}
}

// The free step's address check on its own: sb-a released the leftover's
// namespace and holds another one now, with no container in it yet (a
// create of it on its way). The step frees only a slot that still has the
// park's address, so it leaves sb-a's new slot and its rules alone.
func TestClaimLeftoverNetnsIsFreedOnlyWhileTheAddressMatches(t *testing.T) {
	ctx := context.Background()
	r := newDoubleFailureRig(t, false)
	r.failClaim(t)
	if err := r.h.Release(ctx, "sb-a"); err != nil {
		t.Fatal(err)
	}
	if _, ip, err := r.h.Provision(ctx, "sb-b"); err != nil || ip != r.parkIP {
		t.Fatalf("sb-b got %s, %v; want the freed %s", ip, err, r.parkIP)
	}
	_, now, err := r.h.Provision(ctx, "sb-a")
	if err != nil || now == "" || now == r.parkIP {
		t.Fatalf("sb-a got %q, %v; want another address than %s", now, err, r.parkIP)
	}
	r.busy.Store(false)
	mark := len(r.fw.recorded())
	if err := r.retry(t); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.fw.recorded()[mark:] {
		if c == "release sb-a" || strings.HasSuffix(c, " "+now) {
			t.Fatalf("retry call %q touched sb-a's new slot %s", c, now)
		}
	}
	if held, err := r.h.Address(ctx, "sb-a"); err != nil || held != now {
		t.Fatalf("sb-a holds %q, %v; want %s", held, err, now)
	}
	if r.d.refusesClaimLeftover("sb-a") {
		t.Fatal("sb-a still remembered")
	}
}

// A retried create that took a warm slot meets the leftover by its label
// and has it removed (service create_leftover.go, Driver.Destroy). Once
// containerd has no container of sb-a, a cold create of it goes on at once,
// instead of waiting for the pool's retry. In single mode the address is
// cleared of every rule, since no row held the claim's lists.
func TestClaimLeftoverIsForgottenWhenARetriedCreateRemovesIt(t *testing.T) {
	stubToolboxProbe(t)
	ctx := context.Background()
	stub := func(r *doubleFailureRig) *models.Sandbox {
		return &models.Sandbox{ID: "sb-a", ContainerID: "park-a", ContainerIP: r.parkIP}
	}
	t.Run("removed", func(t *testing.T) {
		r := newDoubleFailureRig(t, false)
		r.failClaim(t)
		be := singleModeRules(t, r.d, r.parkIP)
		r.busy.Store(false)
		if err := r.d.Destroy(ctx, stub(r)); err != nil {
			t.Fatal(err)
		}
		if r.d.refusesClaimLeftover("sb-a") {
			t.Fatal("sb-a still refused after its leftover was removed")
		}
		requireAddressEmpty(t, be, r.parkIP)
		if r.owner(t, r.parkIP) != "" {
			t.Fatalf("%s still held by %q", r.parkIP, r.owner(t, r.parkIP))
		}
		mark := len(r.fw.recorded())
		// The rig has no image content, so the create stops later and
		// undoes itself; what matters is that it went past the refusal.
		if err := r.coldCreate(t, false); errors.Is(err, errClaimLeftover) {
			t.Fatalf("cold create still refused: %v", err)
		}
		if got := r.fw.recorded()[mark:]; !slices.Contains(got, "provision sb-a") {
			t.Fatalf("calls %v: the create did not go cold", got)
		}
		// sb-a runs again in a slot of its own; the pool's retry still
		// removes the slot's files, and frees nothing of the new sandbox.
		_, held, err := r.h.Provision(ctx, "sb-a")
		if err != nil || held == "" {
			t.Fatalf("sb-a got %q, %v", held, err)
		}
		r.tr.mu.Lock()
		r.tr.containers["sb-a"] = &fakeContainer{id: "sb-a", labels: map[string]string{sandboxIDLabelKey: "sb-a"}}
		r.tr.mu.Unlock()
		mark = len(r.fw.recorded())
		if err := r.retry(t); err != nil {
			t.Fatal(err)
		}
		if got := r.fw.recorded()[mark:]; slices.Contains(got, "release sb-a") {
			t.Fatalf("retry calls %v: freed the new sandbox's slot", got)
		}
		if again, _ := r.h.Address(ctx, "sb-a"); again != held {
			t.Fatalf("sb-a holds %q after the retry, want %s", again, held)
		}
	})
	t.Run("a container of sb-a is still there", func(t *testing.T) {
		r := newDoubleFailureRig(t, false)
		r.failClaim(t)
		r.tr.mu.Lock()
		r.tr.containers["sb-a-other"] = &fakeContainer{id: "sb-a-other", labels: map[string]string{sandboxIDLabelKey: "sb-a"}}
		r.tr.mu.Unlock()
		r.busy.Store(false)
		if err := r.d.Destroy(ctx, stub(r)); err != nil {
			t.Fatal(err)
		}
		if !r.d.refusesClaimLeftover("sb-a") {
			t.Fatal("sb-a forgotten while containerd still lists a container of it")
		}
	})
	t.Run("the removal fails", func(t *testing.T) {
		r := newDoubleFailureRig(t, false)
		r.failClaim(t) // containerd still refuses (busy)
		if err := r.d.Destroy(ctx, stub(r)); err == nil {
			t.Fatal("setup: want the removal to fail")
		}
		if !r.d.refusesClaimLeftover("sb-a") {
			t.Fatal("sb-a forgotten although its leftover may still run")
		}
	})
	t.Run("the list fails", func(t *testing.T) {
		r := newDoubleFailureRig(t, false)
		r.failClaim(t)
		r.busy.Store(false)
		r.tr.mu.Lock()
		r.tr.listErr = errors.New("containerd busy")
		r.tr.mu.Unlock()
		if err := r.d.Destroy(ctx, stub(r)); err != nil {
			t.Fatal(err)
		}
		if !r.d.refusesClaimLeftover("sb-a") {
			t.Fatal("sb-a forgotten without containerd saying it is gone")
		}
	})
}

// forgetSandbox drops every slot of one sandbox and only those.
func TestClaimLeftoversForgetSandbox(t *testing.T) {
	var l claimLeftovers
	l.remember("park-a", "sb-a", "")
	l.remember("park-b", "sb-a", "")
	l.remember("park-c", "sb-c", "")
	l.forgetSandbox("sb-a")
	l.forgetSandbox("sb-none")
	if l.holds("sb-a") || !l.holds("sb-c") || l.n.Load() != 1 {
		t.Fatalf("holds sb-a %v, sb-c %v, n %d", l.holds("sb-a"), l.holds("sb-c"), l.n.Load())
	}
}
