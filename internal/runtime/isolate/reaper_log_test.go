package isolate

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestIdleReapIsLogged: the idle reaper says which group it stopped, how
// many sandboxes lose their in-memory state, and why (idle against the
// TTL). It used to stop groups silently, so an isolate that came back
// fresh after a long idle wait (UC-703's slow upload) left no trace.
func TestIdleReapIsLogged(t *testing.T) {
	var logged bytes.Buffer
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	d.logger = slog.New(slog.NewTextHandler(&logged, nil))
	ctx := context.Background()
	for _, id := range []string{"sb-1", "sb-2"} {
		if _, err := d.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, id, "", nil); err != nil {
			t.Fatal(err)
		}
	}
	d.groupsMu.Lock()
	for _, g := range d.groups {
		g.lastUsed = time.Now().Add(-6 * time.Minute)
	}
	d.groupsMu.Unlock()

	d.reapIdleGroups(5 * time.Minute)

	out := logged.String()
	for _, want := range []string{"isolate idle reaper stopped a group", "group=acme", "sandboxes=2", "idle=6m", "idle_ttl=5m0s"} {
		if !strings.Contains(out, want) {
			t.Fatalf("reap log lacks %q:\n%s", want, out)
		}
	}
	if n := d.markGroupMembersStopped("acme"); n != 0 {
		t.Fatalf("members still in the reaped group: %d", n)
	}
}
