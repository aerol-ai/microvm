package containerd

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	cntr "github.com/containerd/containerd/v2/client"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ruleSet is a host-firewall backend that keeps rules as strings, so a test
// can ask which address has rules at any moment.
type ruleSet struct {
	mu      sync.Mutex
	rules   []string
	inserts int
	failIns error
}

func (r *ruleSet) key(chain string, spec []string) string {
	return chain + " " + strings.Join(spec, " ")
}

func (r *ruleSet) Exists(_, chain string, spec ...string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Contains(r.rules, r.key(chain, spec)), nil
}

func (r *ruleSet) Insert(_, chain string, _ int, spec ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failIns != nil {
		return r.failIns
	}
	r.inserts++
	r.rules = append(r.rules, r.key(chain, spec))
	return nil
}

func (r *ruleSet) Delete(_, chain string, spec ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i := slices.Index(r.rules, r.key(chain, spec)); i >= 0 {
		r.rules = slices.Delete(r.rules, i, i+1)
		return nil
	}
	return errors.New("rule does not exist")
}

func (r *ruleSet) EnsureInputChain(string) error { return nil }

// on reports whether any rule names ip.
func (r *ruleSet) on(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.ContainsFunc(r.rules, func(s string) bool { return strings.Contains(s, " "+ip+" ") })
}

// addrObserver records the AddressObserver calls and runs a check at each.
type addrObserver struct {
	mu        sync.Mutex
	known     []string
	released  []string
	onKnown   func(ip string)
	onRelease func(ip string)
}

func (o *addrObserver) AddressKnown(ip string) {
	o.mu.Lock()
	o.known = append(o.known, ip)
	o.mu.Unlock()
	if o.onKnown != nil {
		o.onKnown(ip)
	}
}

func (o *addrObserver) ReleasingAddress(ip string) {
	o.mu.Lock()
	o.released = append(o.released, ip)
	o.mu.Unlock()
	if o.onRelease != nil {
		o.onRelease(ip)
	}
}

func earlyDriver(t *testing.T) (*Driver, *fakeTransport, *harnessNetns, *ruleSet) {
	t.Helper()
	stubToolboxProbe(t)
	d := newTestDriver(t)
	tr := newFakeTransport()
	d.SetClient(NewTestClient("aerolvm", tr))
	h := &harnessNetns{path: "/run/netns/sb", ip: "10.88.0.9"}
	d.SetNetnsHandoff(h)
	rs := &ruleSet{}
	d.networkRules = netrules.NewWithBackend(rs)
	return d, tr, h, rs
}

// TestCreateReportsPrepaidAddressBeforeTheWorkload: with the netns pool the
// request's block-all is on the prepaid address and the create is told the
// address before any task exists; the late install doesn't run again.
func TestCreateReportsPrepaidAddressBeforeTheWorkload(t *testing.T) {
	d, tr, h, rs := earlyDriver(t)
	obs := &addrObserver{onKnown: func(ip string) {
		if !rs.on(ip) {
			t.Error("address reported before its block-all is on")
		}
		tr.mu.Lock()
		c := tr.containers["sb"]
		tr.mu.Unlock()
		if c == nil || c.task != nil {
			t.Error("address must be reported after the container exists and before its task")
		}
	}}
	ctx := sbruntime.WithAddressObserver(context.Background(), obs)
	st, err := d.Create(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", ContainerCommand: []string{"sleep"}, NetworkBlockAll: true}, "sb", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(obs.known, []string{"10.88.0.9"}) || len(obs.released) != 0 || st.ContainerIP != "10.88.0.9" {
		t.Fatalf("known %v released %v ip %q", obs.known, obs.released, st.ContainerIP)
	}
	if !rs.on("10.88.0.9") || rs.inserts != 2 {
		t.Fatalf("rules %v (%d inserts): the block-all pair once, kept for the service to lift", rs.rules, rs.inserts)
	}
	if h.released {
		t.Fatal("a committed create must keep its slot")
	}
}

// TestCreateWithoutRulesStillReports: a plain create installs nothing and
// still reports its address (harmless without an observer).
func TestCreateWithoutRulesStillReports(t *testing.T) {
	d, _, _, rs := earlyDriver(t)
	obs := &addrObserver{}
	if _, err := d.Create(sbruntime.WithAddressObserver(context.Background(), obs), models.CreateSandboxRequest{Image: "alpine:3.20", ContainerCommand: []string{"sleep"}}, "sb", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if len(obs.known) != 1 || len(rs.rules) != 0 {
		t.Fatalf("known %v rules %v", obs.known, rs.rules)
	}
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", ContainerCommand: []string{"sleep"}}, "sb2", "tok", nil); err != nil {
		t.Fatalf("no observer: %v", err)
	}
}

// TestCreateFailureAfterReportLetsGoInOrder: a create that fails once the
// address is out kills the workload, tells the observer, clears the rules
// while the slot is held, and frees the slot last.
func TestCreateFailureAfterReportLetsGoInOrder(t *testing.T) {
	d, tr, h, rs := earlyDriver(t)
	boom := errors.New("start boom")
	tr.pendingStartErr = map[string]error{"sb": boom}
	obs := &addrObserver{onRelease: func(ip string) {
		tr.mu.Lock()
		c := tr.containers["sb"]
		tr.mu.Unlock()
		if c == nil || c.task == nil || c.task.status != cntr.Stopped {
			t.Error("observer told before the workload was killed")
		}
		if !rs.on(ip) {
			t.Error("rules cleared before the observer let go")
		}
		if h.released {
			t.Error("slot freed before the observer let go")
		}
	}}
	_, err := d.Create(sbruntime.WithAddressObserver(context.Background(), obs), models.CreateSandboxRequest{Image: "alpine:3.20", ContainerCommand: []string{"sleep"}, NetworkBlockAll: true}, "sb", "tok", nil)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if !slices.Equal(obs.released, []string{"10.88.0.9"}) || rs.on("10.88.0.9") || !h.released {
		t.Fatalf("released %v rules %v slot freed %v", obs.released, rs.rules, h.released)
	}
}

// TestCreateRuleFailureClearsAndReportsNothing: rules that fail to go on
// fail the create before anything is reported; a partial install is
// cleared before the slot goes.
func TestCreateRuleFailureClearsAndReportsNothing(t *testing.T) {
	d, _, h, rs := earlyDriver(t)
	rs.failIns = errors.New("insert boom")
	obs := &addrObserver{}
	_, err := d.Create(sbruntime.WithAddressObserver(context.Background(), obs), models.CreateSandboxRequest{Image: "alpine:3.20", ContainerCommand: []string{"sleep"}, NetworkBlockAll: true}, "sb", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "apply network block") {
		t.Fatalf("err = %v", err)
	}
	if len(obs.known) != 0 || len(obs.released) != 0 || !h.released || rs.on("10.88.0.9") {
		t.Fatalf("known %v released %v slot %v rules %v", obs.known, obs.released, h.released, rs.rules)
	}
}

// TestCreateAddressMismatchFails: a task that comes up at another address
// than the prepaid one runs without its rules; the create fails and lets
// the prepaid address go in order.
func TestCreateAddressMismatchFails(t *testing.T) {
	d, _, h, rs := earlyDriver(t)
	orig := containerIPv4FromTaskFn
	containerIPv4FromTaskFn = func(context.Context, cntr.Task) (string, error) { return "10.88.7.7", nil }
	t.Cleanup(func() { containerIPv4FromTaskFn = orig })
	obs := &addrObserver{}
	_, err := d.Create(sbruntime.WithAddressObserver(context.Background(), obs), models.CreateSandboxRequest{Image: "alpine:3.20", ContainerCommand: []string{"sleep"}, NetworkBlockAll: true}, "sb", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "prepaid address") {
		t.Fatalf("err = %v", err)
	}
	if !slices.Equal(obs.released, []string{"10.88.0.9"}) || !h.released || rs.on("10.88.0.9") {
		t.Fatalf("released %v slot %v rules %v", obs.released, h.released, rs.rules)
	}
}

// TestCreateWithoutPoolKeepsLateRules: without the netns pool there is no
// address before the task, so nothing is reported and the rules go on the
// started task's address, as before.
func TestCreateWithoutPoolKeepsLateRules(t *testing.T) {
	d, _, _, rs := earlyDriver(t)
	d.cfg.NativeNetnsPool = false
	obs := &addrObserver{}
	st, err := d.Create(sbruntime.WithAddressObserver(context.Background(), obs), models.CreateSandboxRequest{Image: "alpine:3.20", ContainerCommand: []string{"sleep"}, NetworkBlockAll: true}, "sb", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.known) != 0 || !rs.on(st.ContainerIP) {
		t.Fatalf("known %v rules %v", obs.known, rs.rules)
	}
}

// TestDestroyKillsBeforeTheAddressGoes: Destroy kills the task, then tells
// the observer (rules still on, slot still held), then clears the rules,
// then frees the slot.
func TestDestroyKillsBeforeTheAddressGoes(t *testing.T) {
	d, tr, h, rs := earlyDriver(t)
	task := &fakeTask{status: cntr.Running}
	tr.containers["sb"] = &fakeContainer{id: "sb", task: task}
	if _, err := d.networkRules.BlockAllEgressReport("10.88.0.9"); err != nil {
		t.Fatal(err)
	}
	obs := &addrObserver{onRelease: func(ip string) {
		if task.status != cntr.Stopped {
			t.Error("observer told before the task was killed")
		}
		if !rs.on(ip) || h.released {
			t.Error("rules or slot gone before the observer let go")
		}
	}}
	sb := &models.Sandbox{ID: "sb", ContainerID: "sb", ContainerIP: "10.88.0.9"}
	if err := d.Destroy(sbruntime.WithAddressObserver(context.Background(), obs), sb); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(obs.released, []string{"10.88.0.9"}) || rs.on("10.88.0.9") || !h.released {
		t.Fatalf("released %v rules %v slot %v", obs.released, rs.rules, h.released)
	}
	if err := d.Destroy(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

// TestDestroyLetsTheAddressGoWhenTheContainerFails: a container containerd
// can't remove still lets the address go (the netns teardown cuts its
// network) and returns the error; one that is gone is not an error.
func TestDestroyLetsTheAddressGoWhenTheContainerFails(t *testing.T) {
	d, tr, h, _ := earlyDriver(t)
	boom := errors.New("load boom")
	tr.loadContainerFn = func(context.Context, string) (cntr.Container, error) { return nil, boom }
	obs := &addrObserver{}
	err := d.Destroy(sbruntime.WithAddressObserver(context.Background(), obs), &models.Sandbox{ID: "sb", ContainerIP: "10.88.0.9"})
	if !errors.Is(err, boom) || len(obs.released) != 1 || !h.released {
		t.Fatalf("err %v released %v slot %v", err, obs.released, h.released)
	}
	tr.loadContainerFn = nil
	h.released = false
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "gone", ContainerIP: "10.88.0.9"}); err != nil || !h.released {
		t.Fatalf("gone container: err %v slot %v", err, h.released)
	}
}

// TestCreateEarlyCIDRPolicy: a CIDR policy goes on the prepaid address
// before the workload too, and one that fails to go on is cleared before
// the slot is freed.
func TestCreateEarlyCIDRPolicy(t *testing.T) {
	d, _, h, rs := earlyDriver(t)
	req := models.CreateSandboxRequest{Image: "alpine:3.20", ContainerCommand: []string{"sleep"}, NetworkAllowOut: []string{"1.1.1.0/24"}}
	obs := &addrObserver{onKnown: func(ip string) {
		if !rs.on(ip) {
			t.Error("CIDR policy not on before the report")
		}
	}}
	if _, err := d.Create(sbruntime.WithAddressObserver(context.Background(), obs), req, "sb", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if len(obs.known) != 1 {
		t.Fatalf("known %v", obs.known)
	}

	d2, _, h2, rs2 := earlyDriver(t)
	rs2.failIns = errors.New("policy boom")
	if _, err := d2.Create(context.Background(), req, "sb", "tok", nil); err == nil || !strings.Contains(err.Error(), "apply egress policy") {
		t.Fatalf("err = %v", err)
	}
	if !h2.released || rs2.on("10.88.0.9") {
		t.Fatalf("slot %v rules %v", h2.released, rs2.rules)
	}
	_ = h
}
