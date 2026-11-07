package containerd

import (
	"context"
	"testing"

	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Plan PR #1000 item L1: 74-92 ms of a cold containerd create was covered by
// no Server-Timing stage. Each step of the driver's cold path now has one,
// and containerd_create keeps its old span (NewContainer through NewTask) so
// older reports stay comparable, with its two parts recorded beside it.
func TestCreateRecordsColdCreateStages(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	ctx, timing := createtiming.With(context.Background())
	if _, err := d.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-stages", "tok", nil); err != nil {
		t.Fatal(err)
	}

	var order []string
	seen := map[string]createtiming.Stage{}
	for _, st := range timing.Stages() {
		order = append(order, st.Name)
		seen[st.Name] = st
	}
	want := []string{
		"containerd_image",
		"containerd_spec",
		"containerd_lease",
		"containerd_container",
		"containerd_task",
		"containerd_create",
		"containerd_start",
		"containerd_address",
	}
	next := 0
	for _, name := range order {
		if next < len(want) && name == want[next] {
			next++
		}
	}
	if next != len(want) {
		t.Fatalf("stages = %v, want these in order: %v", order, want)
	}
	// The namespace stage belongs to the netns handoff, which knows hit from
	// miss and times it (internal/network/netns). This fake records none, so
	// any containerd_netns here is the driver inventing one.
	if st, ok := seen["containerd_netns"]; ok {
		t.Fatalf("driver recorded its own containerd_netns stage %+v; only the handoff measures it", st)
	}
	parts := seen["containerd_container"].DurMS + seen["containerd_task"].DurMS
	if total := seen["containerd_create"].DurMS; total+0.2 < parts {
		t.Fatalf("containerd_create %.1f ms is less than its parts %.1f ms", total, parts)
	}
}
