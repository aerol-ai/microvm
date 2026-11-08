package containerd

import (
	"context"
	"errors"
	"testing"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
)

var _ sbruntime.Freezer = (*Driver)(nil)

// Freeze pauses only a running task and Thaw resumes only a paused one, so
// both are safe to repeat; a container or task that is gone has nothing to
// freeze or thaw.
func TestDriverFreezeThaw(t *testing.T) {
	for _, tc := range []struct {
		name        string
		container   *fakeContainer
		freeze      bool
		wantPauses  int
		wantResumes int
		wantErr     bool
	}{
		{name: "freeze running", freeze: true, container: &fakeContainer{task: &fakeTask{status: cntr.Running}}, wantPauses: 1},
		{name: "freeze paused", freeze: true, container: &fakeContainer{task: &fakeTask{status: cntr.Paused}}},
		{name: "freeze stopped", freeze: true, container: &fakeContainer{task: &fakeTask{status: cntr.Stopped}}},
		{name: "freeze no task", freeze: true, container: &fakeContainer{taskErr: errdefs.ErrNotFound}},
		{name: "freeze no container", freeze: true},
		{name: "freeze pause fails", freeze: true, container: &fakeContainer{task: &fakeTask{status: cntr.Running, pauseErr: errors.New("freezer busy")}}, wantPauses: 1, wantErr: true},
		{name: "freeze status fails", freeze: true, container: &fakeContainer{task: &fakeTask{statusErr: errors.New("shim gone")}}, wantErr: true},
		{name: "freeze task load fails", freeze: true, container: &fakeContainer{taskErr: errors.New("ttrpc closed")}, wantErr: true},
		{name: "thaw paused", container: &fakeContainer{task: &fakeTask{status: cntr.Paused}}, wantResumes: 1},
		{name: "thaw pausing", container: &fakeContainer{task: &fakeTask{status: cntr.Pausing}}, wantResumes: 1},
		{name: "thaw running", container: &fakeContainer{task: &fakeTask{status: cntr.Running}}},
		{name: "thaw no task", container: &fakeContainer{taskErr: errdefs.ErrNotFound}},
		{name: "thaw resume fails", container: &fakeContainer{task: &fakeTask{status: cntr.Paused, resumeErr: errors.New("freezer busy")}}, wantResumes: 1, wantErr: true},
		{name: "thaw status fails", container: &fakeContainer{task: &fakeTask{statusErr: errors.New("shim gone")}}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := newFakeTransport()
			if tc.container != nil {
				tc.container.id = "sb-f"
				tr.containers["sb-f"] = tc.container
			}
			d := newTestDriver(t)
			d.SetClient(NewTestClient("aerolvm", tr))
			var err error
			if tc.freeze {
				err = d.Freeze(context.Background(), "sb-f")
			} else {
				err = d.Thaw(context.Background(), "sb-f")
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.container != nil && tc.container.task != nil {
				if got := tc.container.task.pauses; got != tc.wantPauses {
					t.Fatalf("Pause calls = %d, want %d", got, tc.wantPauses)
				}
				if got := tc.container.task.resumes; got != tc.wantResumes {
					t.Fatalf("Resume calls = %d, want %d", got, tc.wantResumes)
				}
			}
		})
	}
}

func TestDriverFreezeLoadErrors(t *testing.T) {
	if err := New(Config{}, nil, nil).Freeze(context.Background(), "sb"); err == nil {
		t.Fatal("Freeze without a client must fail")
	}
	tr := newFakeTransport()
	tr.loadContainerFn = func(context.Context, string) (cntr.Container, error) { return nil, errors.New("containerd down") }
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	if err := d.Thaw(context.Background(), "sb"); err == nil {
		t.Fatal("Thaw must report a container load failure")
	}
}
