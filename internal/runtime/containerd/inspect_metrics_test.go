package containerd

import (
	"context"
	"errors"
	"testing"

	cntr "github.com/containerd/containerd/v2/client"
)

// The counter is the operator's signal that running sandboxes are being
// reported without an address.
func TestInspectCountsUnreadableAddress(t *testing.T) {
	orig := containerIPv4FromTaskFn
	containerIPv4FromTaskFn = func(context.Context, cntr.Task) (string, error) { return "", errors.New("no ip") }
	t.Cleanup(func() { containerIPv4FromTaskFn = orig })
	tr := newFakeTransport()
	tr.containers["sb-noip"] = &fakeContainer{id: "sb-noip", task: &fakeTask{status: cntr.Running}}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	d.logger = nil // a Driver built without New has no logger; must not panic

	before := inspectIPUnavailableTotal.Value()
	if _, err := d.Inspect(context.Background(), "sb-noip"); err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if got := inspectIPUnavailableTotal.Value() - before; got != 1 {
		t.Fatalf("aerolvm_containerd_inspect_ip_unavailable_total moved by %d, want 1", got)
	}
}
