package isolate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCoverage97JailPidsAndFreshGroup(t *testing.T) {
	spec := JailSpec{GroupKey: "tenant", ChrootDir: t.TempDir(), UID: 1, GID: 1, PidsMax: -1}
	if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "pids max") {
		t.Fatalf("validate = %v", err)
	}

	d := &Driver{cfg: Config{IdleTTL: time.Millisecond}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.RunIdleReaper(ctx)

	sup := &fakeSupervisor{}
	d2 := newCreateDriver(t, GroupPerTenant, sup)
	if _, err := d2.Create(context.Background(), models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, "sb-cov97", "", nil); err != nil {
		t.Fatal(err)
	}
	d2.groupsMu.Lock()
	for _, g := range d2.groups {
		if g != nil {
			g.lastUsed = time.Time{}
		}
	}
	d2.groupsMu.Unlock()
	d2.reapIdleGroups(time.Minute)
	d2.groupsMu.Lock()
	defer d2.groupsMu.Unlock()
	for _, g := range d2.groups {
		if g != nil && g.lastUsed.IsZero() {
			t.Fatal("fresh group kept a zero lastUsed")
		}
	}
}
