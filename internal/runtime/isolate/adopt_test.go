package isolate

import (
	"context"
	"errors"
	"net/http"
	"testing"

	pkgisolate "github.com/aerol-ai/microvm/pkg/isolate"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

// adoptingSupervisor hands back the hosts a test says survived.
type adoptingSupervisor struct {
	fakeSupervisor
	groups []AdoptedGroup
	calls  int
}

func (s *adoptingSupervisor) AdoptGroups(context.Context) []AdoptedGroup {
	s.calls++
	return s.groups
}

// refusingResolver resolves every ref but one.
type refusingResolver struct{ refuse string }

func (r refusingResolver) Resolve(ctx context.Context, tenant, ref string) (*jsbundle.Bundle, error) {
	if ref == r.refuse {
		return nil, errors.New("bundle gone")
	}
	return stubResolver{}.Resolve(ctx, tenant, ref)
}

func isoRow(id, tenant string) *models.Sandbox {
	return &models.Sandbox{ID: id, Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStarted, TenantID: tenant,
		ModuleRef: "sha256:abc", ModuleDigest: "abc"}
}

// TestAdoptSandboxesKeepsLiveIsolates: a started sandbox a surviving host
// still holds is registered on that host, under its group key, and a
// request reaches it without a reload; one no host holds is registered for
// a reload; a host whose sandboxes are all gone is stopped.
func TestAdoptSandboxesKeepsLiveIsolates(t *testing.T) {
	live := newFakeGroupHost()
	empty := newFakeGroupHost()
	sup := &adoptingSupervisor{groups: []AdoptedGroup{
		{Key: "warm-1a-3", Host: live, Loaded: []string{"sb-1", "sb-2", "sb-gone", "sb-bad"}},
		{Key: "acme2", Host: empty, Loaded: []string{"sb-destroyed"}},
	}}
	d := New(Config{JailUID: 1000, JailGID: 1000, JailChrootBase: "/srv/jail"}, nil)
	d.SetHostSupervisor(sup)
	d.SetBundleResolver(refusingResolver{refuse: "sha256:refused"})
	bad := isoRow("sb-bad", "acme")
	bad.ModuleRef = "sha256:refused"
	blocked := isoRow("sb-2", "acme")
	blocked.NetworkBlockAll = true
	rows := []*models.Sandbox{
		isoRow("sb-1", "acme"), blocked, bad,
		isoRow("sb-fresh", "other"),
		{ID: "sb-stopped", Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStopped},
		{ID: "sb-wasm", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted},
	}
	report := d.AdoptSandboxes(context.Background(), rows)
	if report.Groups != 1 || report.Adopted != 2 || report.Reloading != 2 {
		t.Fatalf("report = %+v", report)
	}
	if !empty.isStopped() || live.isStopped() {
		t.Fatalf("stopped: live=%v empty=%v", live.isStopped(), empty.isStopped())
	}
	if live.loaded["sb-gone"] || live.loaded["sb-bad"] || !live.loaded["sb-1"] || !live.loaded["sb-2"] {
		t.Fatalf("live host holds %v", live.loaded)
	}
	d.groupsMu.Lock()
	g := d.groups["acme"]
	d.groupsMu.Unlock()
	if g == nil || g.host != live || len(g.members) != 2 {
		t.Fatalf("group acme = %+v", g)
	}
	state, _ := d.Inspect(context.Background(), "sb-2")
	if state == nil || state.Status != models.SandboxStatusStarted || state.ModuleDigest == "" {
		t.Fatalf("adopted state = %+v", state)
	}
	if rec := d.byID["sb-2"]; !rec.egress.BlockAll || rec.needsReload {
		t.Fatalf("adopted record = %+v", rec)
	}
	// The adopted sandbox answers on its old host, with no new spawn.
	req, _ := http.NewRequest(http.MethodGet, "http://isolate/", nil)
	resp, err := d.InvokeHTTP(context.Background(), "sb-1", req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if sup.spawns != 0 {
		t.Fatalf("adopted sandbox spawned a new group (%d spawns)", sup.spawns)
	}
	// A sandbox no host kept is registered for a reload, and its next
	// request spawns a fresh group.
	if rec := d.byID["sb-fresh"]; rec == nil || !rec.needsReload || rec.state.Status != models.SandboxStatusStopped {
		t.Fatalf("reload record = %+v", rec)
	}
	if resp, err := d.InvokeHTTP(context.Background(), "sb-fresh", req); err != nil {
		t.Fatal(err)
	} else {
		_ = resp.Body.Close()
	}
	if sup.spawns != 1 {
		t.Fatalf("reload spawns = %d, want 1", sup.spawns)
	}
	if _, ok := d.byID["sb-stopped"]; ok {
		t.Fatal("a stopped row was registered")
	}
	if _, ok := d.byID["sb-wasm"]; ok {
		t.Fatal("a WASM row was registered")
	}
	// Registering for a reload twice keeps the first record.
	d.registerForReload(isoRow("sb-1", "acme"))
	if d.byID["sb-1"].needsReload {
		t.Fatal("reload registration replaced an adopted record")
	}
}

// TestAdoptSandboxesConflictsAndNoAdopter: two hosts claiming one group
// keep the first; a supervisor that cannot adopt registers every row for
// a reload.
func TestAdoptSandboxesConflictsAndNoAdopter(t *testing.T) {
	first, second := newFakeGroupHost(), newFakeGroupHost()
	sup := &adoptingSupervisor{groups: []AdoptedGroup{
		{Key: "a", Host: first, Loaded: []string{"sb-1"}},
		{Key: "b", Host: second, Loaded: []string{"sb-2"}},
	}}
	d := New(Config{}, nil)
	d.SetHostSupervisor(sup)
	d.SetBundleResolver(stubResolver{})
	report := d.AdoptSandboxes(context.Background(), []*models.Sandbox{isoRow("sb-1", "acme"), isoRow("sb-2", "acme")})
	if report.Groups != 1 || report.Adopted != 1 || report.Reloading != 1 || !second.isStopped() {
		t.Fatalf("report = %+v second stopped=%v", report, second.isStopped())
	}
	// Per-sandbox granularity: a host holding two sandboxes keeps the one
	// whose key it serves first.
	per := newFakeGroupHost()
	d2 := New(Config{GroupGranularity: GroupPerSandbox}, nil)
	d2.SetHostSupervisor(&adoptingSupervisor{groups: []AdoptedGroup{{Key: "x", Host: per, Loaded: []string{"sb-a", "sb-b"}}}})
	d2.SetBundleResolver(stubResolver{})
	if r := d2.AdoptSandboxes(context.Background(), []*models.Sandbox{isoRow("sb-a", ""), isoRow("sb-b", "")}); r.Adopted != 1 || r.Reloading != 1 {
		t.Fatalf("per-sandbox report = %+v", r)
	}
	// No resolver: nothing can be pinned again.
	d3 := New(Config{}, nil)
	h3 := newFakeGroupHost()
	d3.SetHostSupervisor(&adoptingSupervisor{groups: []AdoptedGroup{{Key: "y", Host: h3, Loaded: []string{"sb-1"}}}})
	if r := d3.AdoptSandboxes(context.Background(), []*models.Sandbox{isoRow("sb-1", "")}); r.Adopted != 0 || !h3.isStopped() {
		t.Fatalf("no-resolver report = %+v", r)
	}
	plain := New(Config{}, nil)
	plain.SetHostSupervisor(&fakeSupervisor{})
	if r := plain.AdoptSandboxes(context.Background(), []*models.Sandbox{isoRow("sb-1", ""), nil}); r.Reloading != 1 || r.Groups != 0 {
		t.Fatalf("no-adopter report = %+v", r)
	}
	if r := plain.AdoptSandboxes(context.Background(), nil); r != (AdoptReport{}) {
		t.Fatalf("empty report = %+v", r)
	}
}

func TestLocalBundleRef(t *testing.T) {
	bound := models.JSBundleRefForNode("sha256:abc", "node-1")
	if got := localBundleRef(&models.Sandbox{ModuleRef: bound}); got != "sha256:abc" {
		t.Fatalf("node-bound ref = %q", got)
	}
	if got := localBundleRef(&models.Sandbox{Image: "sha256:img"}); got != "sha256:img" {
		t.Fatalf("image ref = %q", got)
	}
}

// TestSupervisorAdoptGroupsSweepsWhatItDoesNotKeep: the production
// supervisor wraps every adopted host, installs its observers, and sweeps
// leftovers with the adopted keys and pids kept; the jail dirs are swept
// only with the jail on.
func TestSupervisorAdoptGroupsSweepsWhatItDoesNotKeep(t *testing.T) {
	host, err := pkgisolate.NewHost(pkgisolate.HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	var swept pkgisolate.Leftovers
	oldAdopt, oldSweep := adoptHosts, sweepLeftovers
	t.Cleanup(func() { adoptHosts, sweepLeftovers = oldAdopt, oldSweep })
	var gotBase pkgisolate.HostConfig
	adoptHosts = func(_ context.Context, base pkgisolate.HostConfig) []pkgisolate.AdoptedHost {
		gotBase = base
		return []pkgisolate.AdoptedHost{{Host: host, Loaded: []string{"sb-1"}}}
	}
	sweepLeftovers = func(l pkgisolate.Leftovers) int { swept = l; return 2 }
	for _, jail := range []bool{false, true} {
		s := newWorkerdSupervisor(Config{RunDir: "/run/sandboxd/isolate", UseJail: jail, JailCgroupRoot: "/sys/fs/cgroup/aerolvm-isolate", JailChrootBase: "/srv/isolate-jail"}, nil)
		s.SetEgressObserver(func(string, string, string) {})
		s.SetEgressDenialObserver(func(string, string, string) {})
		s.SetLearnObserver(func(string, string, uint16) {})
		got := s.AdoptGroups(context.Background())
		if len(got) != 1 || got[0].Key != "acme" || len(got[0].Loaded) != 1 {
			t.Fatalf("adopted = %+v", got)
		}
		if gotBase.RecordDir != "/run/sandboxd/isolate/.hosts" || gotBase.Cgroup == nil {
			t.Fatalf("adopt base = %+v", gotBase)
		}
		if !swept.Keep["acme"] || swept.HostsCgroup == nil {
			t.Fatalf("swept = %+v", swept)
		}
		if jail != (swept.JailCgroupRoot != "") || jail != (swept.JailChrootBase != "") {
			t.Fatalf("jail=%v swept jail dirs %q %q", jail, swept.JailCgroupRoot, swept.JailChrootBase)
		}
	}
	if (&workerdSupervisor{}).recordDir() != "" {
		t.Fatal("record dir without a run dir")
	}
	if NewHostSupervisorWithLogger(Config{}, nil) == nil {
		t.Fatal("nil supervisor")
	}
}
