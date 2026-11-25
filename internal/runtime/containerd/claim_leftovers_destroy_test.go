package containerd

import (
	"context"
	"testing"

	cntr "github.com/containerd/containerd/v2/client"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Follow-ups from the #1454 review: Destroy of a failed claim's leftover
// (the service's leftover removal, Driver.Destroy) clears the address
// whatever the removal's outcome, finds the address itself when the
// removal names none, and ends the refusal only after a removal that
// worked.

// leftoverStub is the row-less sandbox the service's leftover removal
// hands Destroy; ip is what its Inspect found ("" for none).
func leftoverStub(ip string) *models.Sandbox {
	return &models.Sandbox{ID: "sb-a", ContainerID: "park-a", ContainerIP: ip}
}

// Destroy of a leftover lets the address go whether or not containerd
// took the delete (as Destroy always has), so it clears every rule of the
// address either way. Only the delete that worked ends the refusal.
func TestClaimLeftoverDestroyClearsTheAddressWhateverTheOutcome(t *testing.T) {
	ctx := context.Background()
	for name, works := range map[string]bool{"the removal works": true, "the removal fails": false} {
		t.Run(name, func(t *testing.T) {
			r := newDoubleFailureRig(t, false)
			r.failClaim(t)
			be := singleModeRules(t, r.d, r.parkIP)
			r.busy.Store(!works) // busy: containerd refuses the delete
			err := r.d.Destroy(ctx, leftoverStub(r.parkIP))
			if (err == nil) != works {
				t.Fatalf("Destroy = %v, want success %v", err, works)
			}
			requireAddressEmpty(t, be, r.parkIP)
			if refused := r.d.refusesClaimLeftover("sb-a"); refused == works {
				t.Fatalf("sb-a still refused: %v, want %v", refused, !works)
			}
		})
	}
}

// When the service's Inspect found no address for the leftover, Destroy
// clears the address the failed claim's slot had, while sb-a still holds
// it. If sb-a no longer holds it, that address may be another sandbox's
// now, and its rules stay.
func TestClaimLeftoverDestroyWithNoAddressUsesTheRemembered(t *testing.T) {
	ctx := context.Background()
	t.Run("sb-a still holds it", func(t *testing.T) {
		r := newDoubleFailureRig(t, false)
		r.failClaim(t)
		be := singleModeRules(t, r.d, r.parkIP)
		r.busy.Store(false)
		if err := r.d.Destroy(ctx, leftoverStub("")); err != nil {
			t.Fatal(err)
		}
		requireAddressEmpty(t, be, r.parkIP)
		if r.owner(t, r.parkIP) != "" || r.d.refusesClaimLeftover("sb-a") {
			t.Fatalf("owner %q, refused %v", r.owner(t, r.parkIP), r.d.refusesClaimLeftover("sb-a"))
		}
	})
	t.Run("another sandbox holds it now", func(t *testing.T) {
		r := newDoubleFailureRig(t, false)
		r.failClaim(t)
		if err := r.h.Release(ctx, "sb-a"); err != nil {
			t.Fatal(err)
		}
		if _, ip, err := r.h.Provision(ctx, "sb-b"); err != nil || ip != r.parkIP {
			t.Fatalf("sb-b got %s, %v; want %s", ip, err, r.parkIP)
		}
		be := singleModeRules(t, r.d, r.parkIP) // sb-b's own rules now
		r.busy.Store(false)
		if err := r.d.Destroy(ctx, leftoverStub("")); err != nil {
			t.Fatal(err)
		}
		if len(be.rulesOf(r.parkIP)) == 0 {
			t.Fatalf("sb-b's rules on %s were cleared", r.parkIP)
		}
	})
}

// A delete containerd refused never ends the refusal, even when the list
// that follows shows no container of sb-a (here the container went between
// the two calls): the list alone does not prove the namespace is free.
func TestClaimLeftoverDestroyFailureNeverForgets(t *testing.T) {
	r := newDoubleFailureRig(t, false)
	r.failClaim(t) // containerd still refuses the delete (busy)
	r.tr.mu.Lock()
	delete(r.tr.containers, "park-a")
	r.tr.mu.Unlock()
	if err := r.d.Destroy(context.Background(), leftoverStub(r.parkIP)); err == nil {
		t.Fatal("setup: want the removal to fail")
	}
	if !r.d.refusesClaimLeftover("sb-a") {
		t.Fatal("sb-a forgotten after a failed removal")
	}
}

// listHookTransport runs onList just before it answers a container list.
type listHookTransport struct {
	*fakeTransport
	onList func()
}

func (l *listHookTransport) listContainers(ctx context.Context, filters ...string) ([]cntr.Container, error) {
	if l.onList != nil {
		l.onList()
	}
	return l.fakeTransport.listContainers(ctx, filters...)
}

// Only the claims remembered before the list are forgotten. A claim of the
// same id that fails while the list runs (its container is one the list
// did not look for) stays remembered.
func TestClaimLeftoverForgetKeepsAClaimThatFailsDuringTheList(t *testing.T) {
	r := newDoubleFailureRig(t, false)
	r.failClaim(t)
	r.busy.Store(false)
	tr := &listHookTransport{fakeTransport: r.tr}
	tr.onList = func() {
		tr.onList = nil
		r.d.claimLeftovers.remember("park-z", "sb-a", "10.88.0.99")
	}
	r.d.SetClient(NewTestClient("aerolvm", tr))
	if err := r.d.Destroy(context.Background(), leftoverStub(r.parkIP)); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.d.claimLeftovers.of("park-a"); ok {
		t.Fatal("park-a, removed before the list, is still remembered")
	}
	if _, ok := r.d.claimLeftovers.of("park-z"); !ok || !r.d.refusesClaimLeftover("sb-a") {
		t.Fatal("a claim that failed during the list was forgotten")
	}
}
