package containerd

import (
	"context"
	"errors"
	"fmt"
	"testing"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Reconcile deletes a sandbox's row (and its cluster placement) when Inspect
// says the container is gone. Inspect used to error whenever the running
// task's address could not be read, and that error was read as "gone": a
// healthy gVisor sandbox next to a fork bomb was deleted (UC-320). These pin
// the contract: gone only on containerd's NotFound for the container; a
// container that exists always yields a state; anything else is "unknown".
func TestInspectStateContract(t *testing.T) {
	const id = "sb-inspect"
	ipOK := func(context.Context, cntr.Task) (string, error) { return "10.88.0.21", nil }
	ipFails := func(context.Context, cntr.Task) (string, error) {
		return "", errors.New("netns from pid: no such file or directory")
	}
	withContainer := func(c *fakeContainer) func(*fakeTransport) {
		return func(tr *fakeTransport) {
			c.id = id
			tr.containers[id] = c
		}
	}

	cases := []struct {
		name    string
		setup   func(*fakeTransport)
		ip      func(context.Context, cntr.Task) (string, error)
		wantErr bool
		gone    bool
		status  models.SandboxStatus
		wantIP  string
		// containerID is the container Inspect resolves to; id unless set.
		containerID string
	}{
		{
			name:    "container not found is gone",
			setup:   func(*fakeTransport) {},
			ip:      ipOK,
			wantErr: true,
			gone:    true,
		},
		{
			name: "containerd unreachable is unknown, not gone",
			setup: func(tr *fakeTransport) {
				tr.loadContainerFn = func(context.Context, string) (cntr.Container, error) {
					return nil, fmt.Errorf("connection error: %w", errdefs.ErrUnavailable)
				}
			},
			ip:      ipOK,
			wantErr: true,
		},
		{
			// A warm-adopted sandbox keeps its park container's id; asked
			// by sandbox id, it is found by label, not reported gone.
			name: "adopted container found by sandbox-id label",
			setup: func(tr *fakeTransport) {
				tr.containers["park-7"] = &fakeContainer{
					id: "park-7", task: &fakeTask{status: cntr.Running},
					labels: map[string]string{sandboxIDLabelKey: id},
				}
			},
			ip:          ipOK,
			status:      models.SandboxStatusStarted,
			wantIP:      "10.88.0.21",
			containerID: "park-7",
		},
		{
			name: "label lookup failure is unknown, not gone",
			setup: func(tr *fakeTransport) {
				tr.listErr = errors.New("list containers: connection reset")
			},
			ip:      ipOK,
			wantErr: true,
		},
		{
			name:   "no task is stopped",
			setup:  withContainer(&fakeContainer{}),
			ip:     ipOK,
			status: models.SandboxStatusStopped,
		},
		{
			name:    "task load failure is unknown",
			setup:   withContainer(&fakeContainer{taskErr: errors.New("ttrpc: closed")}),
			ip:      ipOK,
			wantErr: true,
		},
		{
			name:   "task gone between load and status is stopped",
			setup:  withContainer(&fakeContainer{task: &fakeTask{statusErr: errdefs.ErrNotFound}}),
			ip:     ipOK,
			status: models.SandboxStatusStopped,
		},
		{
			name:    "task status failure is unknown",
			setup:   withContainer(&fakeContainer{task: &fakeTask{statusErr: context.DeadlineExceeded}}),
			ip:      ipOK,
			wantErr: true,
		},
		{
			name:    "task in unknown state is unknown",
			setup:   withContainer(&fakeContainer{task: &fakeTask{status: cntr.Unknown}}),
			ip:      ipOK,
			wantErr: true,
		},
		{
			name:   "running task reports its address",
			setup:  withContainer(&fakeContainer{task: &fakeTask{status: cntr.Running}}),
			ip:     ipOK,
			status: models.SandboxStatusStarted,
			wantIP: "10.88.0.21",
		},
		{
			// The UC-320 neighbour: the task runs, the netns probe fails.
			name:   "running task with unreadable address is started without one",
			setup:  withContainer(&fakeContainer{task: &fakeTask{status: cntr.Running}}),
			ip:     ipFails,
			status: models.SandboxStatusStarted,
		},
		{
			// A running gVisor sandbox: the probe can't succeed, the address
			// recorded at create stands in.
			name: "gvisor running task reports its recorded address",
			setup: withContainer(&fakeContainer{
				task:   &fakeTask{status: cntr.Running},
				labels: map[string]string{containerIPLabelKey: "10.88.0.22"},
			}),
			ip:     gvisorProbe,
			status: models.SandboxStatusStarted,
			wantIP: "10.88.0.22",
		},
		{
			name:   "paused task (snapshot commit) is started",
			setup:  withContainer(&fakeContainer{task: &fakeTask{status: cntr.Paused}}),
			ip:     ipOK,
			status: models.SandboxStatusStarted,
			wantIP: "10.88.0.21",
		},
		{
			// The UC-320 bomb: runsc died, its exit status unavailable; the
			// task is still there, stopped, and has no pid to probe.
			name:   "dead task is stopped",
			setup:  withContainer(&fakeContainer{task: &fakeTask{status: cntr.Stopped}}),
			ip:     ipFails,
			status: models.SandboxStatusStopped,
		},
		{
			// A pinned netns outlives the task, so its address is still
			// readable; that used to report a dead task as started.
			name:   "dead task with a readable pinned netns is still stopped",
			setup:  withContainer(&fakeContainer{task: &fakeTask{status: cntr.Stopped}}),
			ip:     ipOK,
			status: models.SandboxStatusStopped,
		},
		{
			name:   "created task that never started is stopped",
			setup:  withContainer(&fakeContainer{task: &fakeTask{status: cntr.Created}}),
			ip:     ipOK,
			status: models.SandboxStatusStopped,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orig := containerIPv4FromTaskFn
			containerIPv4FromTaskFn = tc.ip
			t.Cleanup(func() { containerIPv4FromTaskFn = orig })
			tr := newFakeTransport()
			tc.setup(tr)
			d := newTestDriver(t)
			d.SetClient(NewTestClient("aerolvm", tr))

			st, err := d.Inspect(context.Background(), id)
			if got := sbruntime.InstanceGone(st, err); got != tc.gone {
				t.Fatalf("InstanceGone = %v, want %v (state=%+v err=%v)", got, tc.gone, st, err)
			}
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Inspect() = %+v, want an error", st)
				}
				return
			}
			if err != nil {
				t.Fatalf("Inspect() error = %v", err)
			}
			wantContainer := tc.containerID
			if wantContainer == "" {
				wantContainer = id
			}
			if st.Status != tc.status || st.ContainerIP != tc.wantIP || st.SandboxID != id || st.ContainerID != wantContainer {
				t.Fatalf("state = %+v, want status %q ip %q for %s in %s", st, tc.status, tc.wantIP, id, wantContainer)
			}
		})
	}
}

// ListManaged is reconcile's bulk view: a container missing from it is
// re-inspected and, if gone, deleted. A dead task and a running task with no
// readable address must both be listed, so neither row is touched.
func TestListManagedKeepsDeadAndAddresslessTasks(t *testing.T) {
	orig := containerIPv4FromTaskFn
	containerIPv4FromTaskFn = func(context.Context, cntr.Task) (string, error) { return "", errors.New("no ip") }
	t.Cleanup(func() { containerIPv4FromTaskFn = orig })
	tr := newFakeTransport()
	tr.containers["sb-dead"] = &fakeContainer{id: "sb-dead", task: &fakeTask{status: cntr.Stopped}}
	tr.containers["sb-live"] = &fakeContainer{id: "sb-live", task: &fakeTask{status: cntr.Running}}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))

	got, err := d.ListManaged(context.Background())
	if err != nil {
		t.Fatalf("ListManaged() error = %v", err)
	}
	if st := got["sb-dead"]; st == nil || st.Status != models.SandboxStatusStopped {
		t.Fatalf("dead task state = %+v, want stopped", st)
	}
	if st := got["sb-live"]; st == nil || st.Status != models.SandboxStatusStarted {
		t.Fatalf("running task state = %+v, want started", st)
	}
}

// A container whose task containerd can't read is left out of the listing,
// not reported stopped: reconcile then asks about it directly, gets the same
// "unknown" answer, and keeps the row instead of syncing a guess into it.
func TestListManagedSkipsUnreadableContainer(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	tr.containers["sb-unreadable"] = &fakeContainer{id: "sb-unreadable", taskErr: errors.New("ttrpc: closed")}
	tr.containers["sb-ok"] = &fakeContainer{id: "sb-ok", task: &fakeTask{status: cntr.Running}}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))

	got, err := d.ListManaged(context.Background())
	if err != nil {
		t.Fatalf("ListManaged() error = %v", err)
	}
	if _, listed := got["sb-unreadable"]; listed {
		t.Fatalf("unreadable container listed as %+v", got["sb-unreadable"])
	}
	if st := got["sb-ok"]; st == nil || st.Status != models.SandboxStatusStarted || st.ContainerIP != "10.88.0.9" {
		t.Fatalf("readable container state = %+v", st)
	}
}
