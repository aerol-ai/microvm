package isolate

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestUpdateEgressPolicy(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()
	if err := d.UpdateEgressPolicy("missing", true, nil, nil); err == nil {
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
	if err := d.UpdateEgressPolicy("sb-1", false, []string{"pypi.org"}, []string{"10.0.0.0/8"}); err != nil {
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
	if err := d.UpdateEgressPolicy("sb-1", true, nil, nil); err != nil {
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
