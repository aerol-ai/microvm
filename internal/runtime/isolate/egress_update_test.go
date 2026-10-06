package isolate

import (
	"context"
	"slices"
	"testing"
	"time"

	pkgisolate "github.com/aerol-ai/microvm/pkg/isolate"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestUpdateEgressPolicy(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()
	if err := d.UpdateEgressPolicy("missing", true, nil, nil, false, nil); err == nil {
		t.Fatal("an unknown sandbox must be an error")
	}
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "a.js", TenantID: "acme",
		NetworkAllowOut: []string{"example.com"}}, "sb-1", "", nil); err != nil {
		t.Fatal(err)
	}
	host := sup.hosts[0]
	hostPolicy := func() EgressPolicy {
		host.mu.Lock()
		defer host.mu.Unlock()
		return host.egress["sb-1"]
	}

	// Loaded: the host gets the new policy now.
	if err := d.UpdateEgressPolicy("sb-1", false, []string{"pypi.org"}, []string{"10.0.0.0/8"}, false, nil); err != nil {
		t.Fatal(err)
	}
	if got := hostPolicy(); got.BlockAll || !slices.Equal(got.Allow, []string{"pypi.org"}) || !slices.Equal(got.Deny, []string{"10.0.0.0/8"}) {
		t.Fatalf("host policy = %+v", got)
	}

	// Reaped: only the record changes, and the reload pushes it.
	d.groupsMu.Lock()
	for _, g := range d.groups {
		g.lastUsed = time.Now().Add(-2 * time.Hour)
	}
	d.groupsMu.Unlock()
	d.reapIdleGroups(time.Hour)
	if err := d.UpdateEgressPolicy("sb-1", true, nil, nil, false, nil); err != nil {
		t.Fatal(err)
	}
	if hostPolicy().BlockAll {
		t.Fatal("a reaped group's host must not be written")
	}
	if _, err := d.Start(ctx, "sb-1"); err != nil {
		t.Fatal(err)
	}
	reloaded := sup.hosts[len(sup.hosts)-1]
	reloaded.mu.Lock()
	got := reloaded.egress["sb-1"]
	reloaded.mu.Unlock()
	if !got.BlockAll {
		t.Fatalf("the reload pushed %+v, want the updated block-all", got)
	}
}

// TestIsolateLearnMode (P2-7): the supervisor's hosts report learn-mode
// destinations to the driver, whose recording outlives an idle reap and a
// switch to enforce, and goes with the sandbox.
func TestIsolateLearnMode(t *testing.T) {
	sup := &learnSupervisor{fakeSupervisor: &fakeSupervisor{}}
	d := newCreateDriver(t, GroupPerTenant, sup.fakeSupervisor)
	d.SetHostSupervisor(sup)
	if sup.observer == nil {
		t.Fatal("the driver must install its learn observer")
	}
	ctx := context.Background()
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "a.js", TenantID: "acme", NetworkEgressMode: "learn"}, "sb-l", "", nil); err != nil {
		t.Fatal(err)
	}
	host := sup.hosts[0]
	host.mu.Lock()
	learnPolicy := host.egress["sb-l"]
	host.mu.Unlock()
	if !learnPolicy.Learn {
		t.Fatalf("host policy = %+v", learnPolicy)
	}
	sup.observer("sb-l", "pypi.org", 443)
	sup.observer("unknown", "x.example", 443) // ignored
	d.groupsMu.Lock()
	for _, g := range d.groups {
		g.lastUsed = time.Now().Add(-2 * time.Hour)
	}
	d.groupsMu.Unlock()
	d.reapIdleGroups(time.Hour)
	if err := d.UpdateEgressPolicy("sb-l", false, []string{"pypi.org"}, nil, false, nil); err != nil {
		t.Fatal(err)
	}
	l, err := d.EgressLearned("sb-l")
	if err != nil || len(l.Entries) != 1 || l.Entries[0].Host != "pypi.org" {
		t.Fatalf("recording = %+v %v", l, err)
	}
	if _, err := d.EgressLearned("unknown"); err == nil {
		t.Fatal("an unknown sandbox must be an error")
	}
	if err := d.Destroy(ctx, &models.Sandbox{ID: "sb-l"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.EgressLearned("sb-l"); err == nil {
		t.Fatal("the recording must go with the sandbox")
	}
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "a.js", TenantID: "acme"}, "sb-e", "", nil); err != nil {
		t.Fatal(err)
	}
	if l, err := d.EgressLearned("sb-e"); err != nil || len(l.Entries) != 0 {
		t.Fatalf("no recording yet = %+v %v", l, err)
	}
}

// learnSupervisor is a fakeSupervisor that accepts a learn observer.
type learnSupervisor struct {
	*fakeSupervisor
	observer pkgisolate.LearnObserver
}

func (s *learnSupervisor) SetLearnObserver(obs pkgisolate.LearnObserver) { s.observer = obs }

// TestPolicyFromCreateCarriesRules (P3-1): the host gets the rules with the
// lists, on create and on every update.
func TestPolicyFromCreateCarriesRules(t *testing.T) {
	rules := ruleSpecs([]models.EgressRule{{Host: "api.example.com", Inspect: true, Methods: []string{"GET"}}})
	p := policyFromCreate(false, []string{"api.example.com"}, nil, false, rules)
	if len(p.Rules) != 1 || p.Rules[0].Host != "api.example.com" || !p.Rules[0].Inspect || p.Rules[0].Methods[0] != "GET" {
		t.Fatalf("policy = %+v", p)
	}
	if len(ruleSpecs(nil)) != 0 {
		t.Fatal("no rules")
	}
}
