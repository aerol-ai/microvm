package firecracker

import (
	"context"
	"errors"
	"slices"
	"testing"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/models"
)

type fcAddrObserver struct {
	known, released []string
	onKnown         func(ip string)
	onRelease       func(ip string)
}

func (o *fcAddrObserver) AddressKnown(ip string) {
	o.known = append(o.known, ip)
	if o.onKnown != nil {
		o.onKnown(ip)
	}
}
func (o *fcAddrObserver) ReleasingAddress(ip string) {
	o.released = append(o.released, ip)
	if o.onRelease != nil {
		o.onRelease(ip)
	}
}

func gatewayReq() models.CreateSandboxRequest {
	// The driver-facing copy of a hostname-filtered create: block-all.
	return models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1, MemoryMB: 128, NetworkBlockAll: true}
}

// TestCreateReportsGuestAddressBeforeBoot: the guest IP is reported once
// its block-all is on and before the VM starts.
func TestCreateReportsGuestAddressBeforeBoot(t *testing.T) {
	f := newDriverFixture(t)
	rules := &fakeNetRules{}
	f.driver.SetNetRules(rules)
	obs := &fcAddrObserver{onKnown: func(ip string) {
		if !rules.has("block-egress " + ip) {
			t.Error("guest IP reported before its block-all is on")
		}
		if f.vmm.started {
			t.Error("guest IP reported after the VM started")
		}
	}}
	st, err := f.driver.Create(sbruntime.WithAddressObserver(context.Background(), obs), gatewayReq(), "sb-early", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(obs.known, []string{st.ContainerIP}) || len(obs.released) != 0 {
		t.Fatalf("known %v released %v ip %q", obs.known, obs.released, st.ContainerIP)
	}
}

// TestCreateFailureAfterBootLetsTheAddressGoLast: a create that fails once
// the guest booted shuts the VM down, removes its TAP and clears its rules
// before the observer is told, and frees the slot after.
func TestCreateFailureAfterBootLetsTheAddressGoLast(t *testing.T) {
	f := newDriverFixture(t)
	rules := &fakeNetRules{}
	f.driver.SetNetRules(rules)
	boom := errors.New("api socket never came up")
	f.vmm.waitErr = boom
	obs := &fcAddrObserver{onRelease: func(ip string) {
		if !f.vmm.shutdown || f.tapHost.removeCalls == 0 {
			t.Error("observer told before the VM was down and its TAP gone")
		}
		if !rules.has("clear-egress " + ip) {
			t.Error("rules not cleared before the observer let go")
		}
		if f.pool.release != 0 {
			t.Error("slot freed before the observer let go")
		}
	}}
	if _, err := f.driver.Create(sbruntime.WithAddressObserver(context.Background(), obs), gatewayReq(), "sb-fail", "tok", nil); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if len(obs.known) != 1 || !slices.Equal(obs.released, obs.known) || f.pool.release != 1 {
		t.Fatalf("known %v released %v slot releases %d", obs.known, obs.released, f.pool.release)
	}
}

// TestCreateRuleFailureClearsAndReportsNothing: rules that fail to go on
// fail the create before the report, and a partial install is cleared.
func TestCreateRuleFailureClearsAndReportsNothing(t *testing.T) {
	f := newDriverFixture(t)
	rules := &fakeNetRules{err: errors.New("iptables gone")}
	f.driver.SetNetRules(rules)
	obs := &fcAddrObserver{}
	if _, err := f.driver.Create(sbruntime.WithAddressObserver(context.Background(), obs), gatewayReq(), "sb-rule", "tok", nil); err == nil {
		t.Fatal("a refused rule must fail the create")
	}
	if len(obs.known) != 0 || len(obs.released) != 0 || !rules.has("clear-egress ") || f.pool.release != 1 {
		t.Fatalf("known %v released %v calls %v releases %d", obs.known, obs.released, rules.calls, f.pool.release)
	}
}

// TestDestroyLetsTheAddressGoAfterShutdown: Destroy tells the observer once
// the VM is down and before the slot is freed; a VM whose shutdown failed
// may still send, so it keeps its attach (no call) and the error goes back.
func TestDestroyLetsTheAddressGoAfterShutdown(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.SetNetRules(&fakeNetRules{})
	st, err := f.driver.Create(context.Background(), gatewayReq(), "sb-d", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	obs := &fcAddrObserver{onRelease: func(string) {
		if !f.vmm.shutdown || f.pool.release != 0 {
			t.Error("observer told before the VM was down, or after the slot was freed")
		}
	}}
	if err := f.driver.Destroy(sbruntime.WithAddressObserver(context.Background(), obs), &models.Sandbox{ID: "sb-d"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(obs.released, []string{st.ContainerIP}) || f.pool.release != 1 {
		t.Fatalf("released %v slot releases %d", obs.released, f.pool.release)
	}

	g := newDriverFixture(t)
	g.driver.SetNetRules(&fakeNetRules{})
	if _, err := g.driver.Create(context.Background(), gatewayReq(), "sb-stuck", "tok", nil); err != nil {
		t.Fatal(err)
	}
	g.vmm.shutdownErr = errors.New("vmm wedged")
	stuck := &fcAddrObserver{}
	if err := g.driver.Destroy(sbruntime.WithAddressObserver(context.Background(), stuck), &models.Sandbox{ID: "sb-stuck"}); err == nil {
		t.Fatal("a failed shutdown must be returned")
	}
	if len(stuck.released) != 0 {
		t.Fatal("a VM that may still run must keep its attach")
	}
}
