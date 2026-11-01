package docker

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// dockerRuleSet keeps host-firewall rules as strings, so a test can ask
// which address has rules at any moment.
type dockerRuleSet struct {
	mu      sync.Mutex
	rules   []string
	failIns error
}

func (r *dockerRuleSet) key(chain string, spec []string) string {
	return chain + " " + strings.Join(spec, " ") + " "
}
func (r *dockerRuleSet) Exists(_, chain string, spec ...string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Contains(r.rules, r.key(chain, spec)), nil
}
func (r *dockerRuleSet) Insert(_, chain string, _ int, spec ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failIns != nil {
		return r.failIns
	}
	r.rules = append(r.rules, r.key(chain, spec))
	return nil
}
func (r *dockerRuleSet) Delete(_, chain string, spec ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i := slices.Index(r.rules, r.key(chain, spec)); i >= 0 {
		r.rules = slices.Delete(r.rules, i, i+1)
		return nil
	}
	return errors.New("rule does not exist")
}
func (r *dockerRuleSet) EnsureInputChain(string) error { return nil }
func (r *dockerRuleSet) on(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.ContainsFunc(r.rules, func(s string) bool { return strings.Contains(s, " "+ip+" ") })
}

type dockerAddrObserver struct {
	known, released []string
	onKnown         func(ip string)
	onRelease       func(ip string)
}

func (o *dockerAddrObserver) AddressKnown(ip string) {
	o.known = append(o.known, ip)
	if o.onKnown != nil {
		o.onKnown(ip)
	}
}
func (o *dockerAddrObserver) ReleasingAddress(ip string) {
	o.released = append(o.released, ip)
	if o.onRelease != nil {
		o.onRelease(ip)
	}
}

func pauseCreateClient(t *testing.T) (*Client, *netnsFakeDaemon, *dockerRuleSet) {
	t.Helper()
	d := newNetnsFakeDaemon()
	c := newNetnsCreateClient(t, d, true)
	rs := &dockerRuleSet{}
	c.networkRules = netrules.NewWithBackend(rs)
	return c, d, rs
}

func running(d *netnsFakeDaemon, ref string) (exists, isRunning bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := d.byRef(ref)
	return c != nil, c != nil && c.running
}

// TestCreatePauseSlotReportsAddressBeforeStart: on a pause netns the
// request's block-all is on the pause slot's address and the create is
// told that address after the workload container exists and before it
// starts; the late install doesn't run again.
func TestCreatePauseSlotReportsAddressBeforeStart(t *testing.T) {
	c, d, rs := pauseCreateClient(t)
	obs := &dockerAddrObserver{onKnown: func(ip string) {
		if !rs.on(ip) {
			t.Error("address reported before its block-all is on")
		}
		if exists, isRunning := running(d, "sb-early"); !exists || isRunning {
			t.Errorf("reported with the workload container exists=%v running=%v; want created, not started", exists, isRunning)
		}
	}}
	st, err := c.Create(sbruntime.WithAddressObserver(context.Background(), obs), models.CreateSandboxRequest{Image: "img", NetworkBlockAll: true}, "sb-early", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(obs.known, []string{st.ContainerIP}) || len(obs.released) != 0 || !rs.on(st.ContainerIP) {
		t.Fatalf("known %v released %v rules %v", obs.known, obs.released, rs.rules)
	}
	if n := len(rs.rules); n != 2 {
		t.Fatalf("rules %v: want the block-all pair once", rs.rules)
	}
}

// TestCreatePauseSlotFailureLetsGoInOrder: a create that fails after the
// report removes the workload, tells the observer while the pause slot
// still holds the address and the rules are on, then clears the rules,
// then gives the slot up.
func TestCreatePauseSlotFailureLetsGoInOrder(t *testing.T) {
	c, d, rs := pauseCreateClient(t)
	d.mu.Lock()
	d.startErr = true
	d.mu.Unlock()
	obs := &dockerAddrObserver{onRelease: func(ip string) {
		if exists, _ := running(d, "sb-fail"); exists {
			t.Error("observer told before the workload container was removed")
		}
		if exists, _ := running(d, netnsAdoptedName("sb-fail")); !exists {
			t.Error("pause slot gone before the observer let go")
		}
		if !rs.on(ip) {
			t.Error("rules cleared before the observer let go")
		}
	}}
	if _, err := c.Create(sbruntime.WithAddressObserver(context.Background(), obs), models.CreateSandboxRequest{Image: "img", NetworkBlockAll: true}, "sb-fail", "tok", nil); err == nil {
		t.Fatal("create should fail on start")
	}
	if len(obs.known) != 1 || !slices.Equal(obs.released, obs.known) || rs.on(obs.known[0]) {
		t.Fatalf("known %v released %v rules %v", obs.known, obs.released, rs.rules)
	}
	if exists, _ := running(d, netnsAdoptedName("sb-fail")); exists {
		t.Fatal("pause slot leaked")
	}
}

// TestCreatePauseSlotRuleFailureReportsNothing: rules that fail to go on
// fail the create before the report; the workload never starts.
func TestCreatePauseSlotRuleFailureReportsNothing(t *testing.T) {
	c, d, rs := pauseCreateClient(t)
	rs.failIns = errors.New("insert boom")
	obs := &dockerAddrObserver{}
	_, err := c.Create(sbruntime.WithAddressObserver(context.Background(), obs), models.CreateSandboxRequest{Image: "img", NetworkBlockAll: true}, "sb-rule", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "apply network block") {
		t.Fatalf("err = %v", err)
	}
	if len(obs.known) != 0 || len(obs.released) != 0 {
		t.Fatalf("known %v released %v", obs.known, obs.released)
	}
	if exists, _ := running(d, "sb-rule"); exists {
		t.Fatal("workload container left")
	}
}

// TestDestroyOnPauseLetsTheAddressGoLast: a sandbox on a pause netns is
// destroyed workload first, then the observer is told (pause still holding
// the address, rules on), then rules, then the pause container.
func TestDestroyOnPauseLetsTheAddressGoLast(t *testing.T) {
	c, d, rs := pauseCreateClient(t)
	st, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "img", NetworkBlockAll: true}, "sb-d", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	obs := &dockerAddrObserver{onRelease: func(ip string) {
		if exists, _ := running(d, st.ContainerID); exists {
			t.Error("observer told before the workload container was removed")
		}
		if exists, _ := running(d, netnsAdoptedName("sb-d")); !exists || !rs.on(ip) {
			t.Error("pause slot or rules gone before the observer let go")
		}
	}}
	sb := &models.Sandbox{ID: "sb-d", ContainerID: st.ContainerID, ContainerIP: st.ContainerIP}
	if err := c.Destroy(sbruntime.WithAddressObserver(context.Background(), obs), sb); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(obs.released, []string{st.ContainerIP}) || rs.on(st.ContainerIP) {
		t.Fatalf("released %v rules %v", obs.released, rs.rules)
	}
	if exists, _ := running(d, netnsAdoptedName("sb-d")); exists {
		t.Fatal("pause container left")
	}
}

// TestDestroyOnPauseKeepsEverythingWhenTheWorkloadStays: a workload that
// can't be removed keeps its address, rules and attach for the retry.
func TestDestroyOnPauseKeepsEverythingWhenTheWorkloadStays(t *testing.T) {
	c, d, rs := pauseCreateClient(t)
	st, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "img", NetworkBlockAll: true}, "sb-e", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	obs := &dockerAddrObserver{}
	err = c.Destroy(sbruntime.WithAddressObserver(context.Background(), obs), &models.Sandbox{ID: "sb-e", ContainerIP: st.ContainerIP})
	if err == nil || len(obs.released) != 0 || !rs.on(st.ContainerIP) {
		t.Fatalf("err %v released %v rules kept %v", err, obs.released, rs.on(st.ContainerIP))
	}
	if exists, _ := running(d, netnsAdoptedName("sb-e")); !exists {
		t.Fatal("the pause slot must stay while the workload may run")
	}
}

// TestCreatePauseSlotCIDRPolicy: a CIDR policy goes on the pause slot's
// address before the workload starts; one that fails to go on fails the
// create and is cleared.
func TestCreatePauseSlotCIDRPolicy(t *testing.T) {
	c, _, rs := pauseCreateClient(t)
	req := models.CreateSandboxRequest{Image: "img", NetworkAllowOut: []string{"1.1.1.0/24"}}
	obs := &dockerAddrObserver{onKnown: func(ip string) {
		if !rs.on(ip) {
			t.Error("CIDR policy not on before the report")
		}
	}}
	if _, err := c.Create(sbruntime.WithAddressObserver(context.Background(), obs), req, "sb-cidr", "tok", nil); err != nil {
		t.Fatal(err)
	}
	c2, d2, rs2 := pauseCreateClient(t)
	rs2.failIns = errors.New("policy boom")
	if _, err := c2.Create(context.Background(), req, "sb-cidr2", "tok", nil); err == nil || !strings.Contains(err.Error(), "apply egress policy") {
		t.Fatalf("err = %v", err)
	}
	if exists, _ := running(d2, netnsAdoptedName("sb-cidr2")); exists {
		t.Fatal("pause slot leaked")
	}
}

// TestDestroyFallsBackWhenThePauseCannotBeInspected: Destroy can't tell
// whether a pause container holds the address and keeps the rules-first
// order (no observer call); a missing pause is the plain order too.
func TestDestroyFallsBackWhenThePauseCannotBeInspected(t *testing.T) {
	c, d, _ := pauseCreateClient(t)
	inner := d.transport()
	c.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, netnsAdoptedName("sb-x")) {
			return textResponse(http.StatusInternalServerError, "inspect boom"), nil
		}
		return inner(r)
	})
	d.add(&netnsFakeContainer{id: "ctr-x", name: "sb-x", running: true})
	obs := &dockerAddrObserver{}
	if err := c.Destroy(sbruntime.WithAddressObserver(context.Background(), obs), &models.Sandbox{ID: "sb-x", ContainerID: "ctr-x", ContainerIP: "172.30.9.9"}); err != nil {
		t.Fatal(err)
	}
	if len(obs.released) != 0 {
		t.Fatalf("released %v: the plain order has no observer call", obs.released)
	}
	if ok, err := c.hasNetnsPause(context.Background(), "sb-none"); ok || err != nil {
		t.Fatalf("missing pause: %v %v", ok, err)
	}
}
