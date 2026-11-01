package ipv6fence

import (
	"bytes"
	"context"
	"errors"
	"expvar"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBackend records what the supervisor installs and answers Check from
// a kernel the test can tamper with.
type fakeBackend struct {
	mu        sync.Mutex
	kernel    []Rule
	applies   int
	checks    int
	applyErr  error
	checkErr  error
	installed bool
}

func (f *fakeBackend) Apply(rules []Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies++
	if f.applyErr != nil {
		return f.applyErr
	}
	f.kernel = append([]Rule(nil), rules...)
	f.installed = true
	return nil
}

func (f *fakeBackend) Check(rules []Rule) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks++
	if f.checkErr != nil {
		return false, f.checkErr
	}
	if !f.installed || len(f.kernel) != len(rules) {
		return false, nil
	}
	for i := range rules {
		if f.kernel[i] != rules[i] {
			return false, nil
		}
	}
	return true, nil
}

func (f *fakeBackend) flush() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kernel, f.installed = nil, false
}

func (f *fakeBackend) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applies, f.checks
}

func (f *fakeBackend) has(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.kernel {
		if r.Name == name {
			return true
		}
	}
	return false
}

func static(spec Spec) func(context.Context) (Spec, error) {
	return func(context.Context) (Spec, error) { return spec, nil }
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time                 { return c.t }
func (c *clock) advance(d time.Duration)        { c.t = c.t.Add(d) }
func newClock() *clock                          { return &clock{t: time.Unix(1000, 0)} }
func testLogger(buf *bytes.Buffer) *slog.Logger { return slog.New(slog.NewTextHandler(buf, nil)) }

func newTestSupervisor(be Backend, buf *bytes.Buffer, c *clock, sources ...Source) *Supervisor {
	s := NewSupervisor(be, testLogger(buf), sources...)
	s.now = c.now
	return s
}

func TestSupervisorBootInstallsAndGates(t *testing.T) {
	be := &fakeBackend{}
	var logs bytes.Buffer
	c := newClock()
	s := newTestSupervisor(be, &logs, c,
		Source{Runtime: "containerd", Spec: static(Spec{Bridges: []string{"aerolvm0"}})},
		Source{Runtime: "firecracker", Spec: static(Spec{Links: []string{"fctap*"}})},
	)
	if err := s.Ready("containerd"); !errors.Is(err, ErrNotSynced) {
		t.Fatalf("Ready before the first sync = %v, want ErrNotSynced", err)
	}
	s.Sync(context.Background(), true)
	for _, rt := range []string{"containerd", "firecracker"} {
		if err := s.Ready(rt); err != nil {
			t.Fatalf("Ready(%s) = %v", rt, err)
		}
	}
	// A runtime with no interface on the node is not this fence's to gate.
	if err := s.Ready("wasm"); err != nil {
		t.Fatalf("Ready(wasm) = %v", err)
	}
	if !be.has("aerolvm0") || !be.has("fctap*") {
		t.Fatalf("kernel = %+v", be.kernel)
	}
	if !strings.Contains(logs.String(), "ipv6 fence installed") {
		t.Fatalf("logs = %s", logs.String())
	}
	if v := ready.Get("firecracker"); v == nil || v.(*expvar.Int).Value() != 1 {
		t.Fatalf("expvar firecracker = %v", v)
	}
	// Nothing changed and nothing is due: no netlink at all.
	a, ck := be.counts()
	s.Sync(context.Background(), false)
	if a2, ck2 := be.counts(); a2 != a || ck2 != ck {
		t.Fatalf("an idle tick touched the kernel: applies %d->%d checks %d->%d", a, a2, ck, ck2)
	}
	var nilSup *Supervisor
	if nilSup.Ready("docker") != nil {
		t.Fatal("a nil supervisor gates nothing")
	}
}

// Fail closed: a fence that cannot be installed refuses every runtime it
// covers, and the next tick retries.
func TestSupervisorInstallFailureRefusesAndRetries(t *testing.T) {
	be := &fakeBackend{applyErr: errors.New("nf_tables: operation not supported")}
	var logs bytes.Buffer
	c := newClock()
	s := newTestSupervisor(be, &logs, c, Source{Runtime: "docker", Spec: static(Spec{Bridges: []string{"docker0"}})})
	s.Sync(context.Background(), true)
	err := s.Ready("docker")
	if err == nil || !strings.Contains(err.Error(), "operation not supported") {
		t.Fatalf("Ready = %v, want the install error", err)
	}
	if v := ready.Get("docker"); v == nil || v.(*expvar.Int).Value() != 0 {
		t.Fatalf("expvar docker = %v", v)
	}
	if !strings.Contains(logs.String(), "creates are refused") {
		t.Fatalf("logs = %s", logs.String())
	}
	be.mu.Lock()
	be.applyErr = nil
	be.mu.Unlock()
	s.Sync(context.Background(), false) // not due, but the last apply failed
	if err := s.Ready("docker"); err != nil {
		t.Fatalf("Ready after recovery = %v", err)
	}
}

// A source that has never answered refuses only its own runtime; one that
// answered before keeps its interfaces in the fence when it stops
// answering, so running sandboxes stay fenced.
func TestSupervisorSourceFailures(t *testing.T) {
	be := &fakeBackend{}
	var logs bytes.Buffer
	c := newClock()
	var mu sync.Mutex
	dockerErr := errors.New("docker: connection refused")
	dockerSpec := func(context.Context) (Spec, error) {
		mu.Lock()
		defer mu.Unlock()
		if dockerErr != nil {
			return Spec{}, dockerErr
		}
		return Spec{Bridges: []string{"docker0"}}, nil
	}
	s := newTestSupervisor(be, &logs, c,
		Source{Runtime: "docker", Spec: dockerSpec},
		Source{Runtime: "firecracker", Spec: static(Spec{Links: []string{"fctap*"}})},
	)
	s.Sync(context.Background(), true)
	if err := s.Ready("docker"); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("Ready(docker) = %v", err)
	}
	if err := s.Ready("firecracker"); err != nil {
		t.Fatalf("Ready(firecracker) = %v", err)
	}
	// dockerd comes up: the next tick asks again (it has no names yet) and
	// adds its bridge.
	mu.Lock()
	dockerErr = nil
	mu.Unlock()
	s.Sync(context.Background(), false)
	if err := s.Ready("docker"); err != nil || !be.has("docker0") {
		t.Fatalf("Ready(docker) = %v, docker0 installed=%v", err, be.has("docker0"))
	}
	// dockerd restarts while the reassert is due: docker0 stays fenced.
	mu.Lock()
	dockerErr = errors.New("docker: restarting")
	mu.Unlock()
	c.advance(ReassertInterval)
	s.Sync(context.Background(), false)
	if err := s.Ready("docker"); err != nil || !be.has("docker0") {
		t.Fatalf("after a failed refresh: Ready(docker) = %v, docker0 installed=%v", err, be.has("docker0"))
	}
	if !strings.Contains(logs.String(), "keeping its last interfaces") {
		t.Fatalf("logs = %s", logs.String())
	}
}

// The reassert: a fence something flushed is put back within one interval,
// and the log says so.
func TestSupervisorReassertRepairs(t *testing.T) {
	be := &fakeBackend{}
	var logs bytes.Buffer
	c := newClock()
	s := newTestSupervisor(be, &logs, c, Source{Runtime: "containerd", Spec: static(Spec{Bridges: []string{"cni0"}})})
	s.Sync(context.Background(), true)
	be.flush() // `nft flush ruleset`, a firewall reload
	c.advance(ReassertInterval - time.Second)
	s.Sync(context.Background(), false)
	if be.has("cni0") {
		t.Fatal("not due yet, yet the fence came back")
	}
	c.advance(time.Second)
	s.Sync(context.Background(), false)
	if !be.has("cni0") {
		t.Fatal("the reassert did not put the fence back")
	}
	if !strings.Contains(logs.String(), "has been put back") {
		t.Fatalf("logs = %s", logs.String())
	}
	if err := s.Ready("containerd"); err != nil {
		t.Fatal(err)
	}
	// A due check that finds it intact does not re-apply.
	a, _ := be.counts()
	c.advance(ReassertInterval)
	s.Sync(context.Background(), false)
	if a2, _ := be.counts(); a2 != a {
		t.Fatalf("an intact fence was re-applied (%d -> %d)", a, a2)
	}
	// A check that errors fails closed and is retried.
	be.mu.Lock()
	be.checkErr = errors.New("netlink: permission denied")
	be.mu.Unlock()
	c.advance(ReassertInterval)
	s.Sync(context.Background(), false)
	if err := s.Ready("containerd"); err == nil {
		t.Fatal("a failed check must refuse creates")
	}
	be.mu.Lock()
	be.checkErr = nil
	be.mu.Unlock()
	s.Sync(context.Background(), false)
	if err := s.Ready("containerd"); err != nil {
		t.Fatalf("after the check recovers: %v", err)
	}
}

// A changed spec (a new bridge) is applied on the next tick.
func TestSupervisorSpecChange(t *testing.T) {
	be := &fakeBackend{}
	var logs bytes.Buffer
	c := newClock()
	var mu sync.Mutex
	name := "aerolvm0"
	s := newTestSupervisor(be, &logs, c, Source{Runtime: "containerd", Spec: func(context.Context) (Spec, error) {
		mu.Lock()
		defer mu.Unlock()
		return Spec{Bridges: []string{name}}, nil
	}})
	s.Sync(context.Background(), true)
	mu.Lock()
	name = "cni0"
	mu.Unlock()
	c.advance(ReassertInterval)
	s.Sync(context.Background(), false)
	if !be.has("cni0") || be.has("aerolvm0") {
		t.Fatalf("kernel = %+v", be.kernel)
	}
}

func TestSupervisorBadSources(t *testing.T) {
	be := &fakeBackend{}
	var logs bytes.Buffer
	s := newTestSupervisor(be, &logs, newClock(),
		Source{Runtime: "nospec"},
		Source{Runtime: "empty", Spec: static(Spec{})},
		Source{Runtime: "invalid", Spec: static(Spec{Bridges: []string{"a/b"}})},
	)
	s.Sync(context.Background(), true)
	for _, rt := range []string{"nospec", "empty", "invalid"} {
		if err := s.Ready(rt); err == nil {
			t.Fatalf("Ready(%s) accepted a source that names no valid interface", rt)
		}
	}
}

func TestSupervisorRun(t *testing.T) {
	be := &fakeBackend{applyErr: errors.New("boot race")}
	s := NewSupervisor(be, nil, Source{Runtime: "docker", Spec: static(Spec{Bridges: []string{"docker0"}})})
	s.Sync(context.Background(), true)
	be.mu.Lock()
	be.applyErr = nil
	be.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx, time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for s.Ready("docker") != nil {
		if time.Now().After(deadline) {
			t.Fatal("Run never retried the failed install")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	// A zero tick falls back to the default and still stops on cancel.
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	s.Run(ctx2, 0)
}
