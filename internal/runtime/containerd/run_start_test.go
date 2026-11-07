package containerd

import (
	"context"
	"testing"
	"time"

	apievents "github.com/containerd/containerd/api/events"
	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/core/runtime"
	"github.com/containerd/containerd/v2/pkg/protobuf"
	"github.com/containerd/typeurl/v2"
)

// TestStartReportsTheRunStart: a start that makes a new task reports when,
// on the host clock its shim stamps exits with, so the service can tell an
// exit of an earlier run (internal/service/run_starts.go). A start that
// finds the task running makes no new run and reports none.
func TestStartReportsTheRunStart(t *testing.T) {
	cases := []struct {
		name    string
		status  cntr.ProcessStatus
		wantRun bool
	}{
		{name: "stopped task: a new run", status: cntr.Stopped, wantRun: true},
		{name: "running task: no new run", status: cntr.Running, wantRun: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubToolboxProbe(t)
			tr := newFakeTransport()
			tr.containers["sb-run"] = &fakeContainer{id: "sb-run", task: &fakeTask{status: tc.status}}
			d := newTestDriver(t)
			d.SetClient(NewTestClient("aerolvm", tr))
			before := time.Now()
			state, err := d.Start(context.Background(), "sb-run")
			if err != nil {
				t.Fatal(err)
			}
			after := time.Now()
			if !tc.wantRun {
				if !state.StartedAt.IsZero() {
					t.Fatalf("StartedAt = %v, want none", state.StartedAt)
				}
				return
			}
			if state.StartedAt.Before(before) || state.StartedAt.After(after) {
				t.Fatalf("StartedAt = %v, want within [%v, %v]", state.StartedAt, before, after)
			}
		})
	}
}

// TestExitIsStampedWhenItHappened: a TaskExit is stamped with the shim's
// exited_at, not the envelope's publish time; the shim publishes from a
// queue, and a late publish of the old task's exit can come after the next
// start. Every other event, and an exit without exited_at, keeps the
// envelope's time.
func TestExitIsStampedWhenItHappened(t *testing.T) {
	published := time.Date(2026, 11, 7, 10, 0, 5, 0, time.UTC)
	exited := time.Date(2026, 11, 7, 10, 0, 1, 250, time.UTC)
	cases := []struct {
		name    string
		topic   string
		payload any
		want    time.Time
	}{
		{name: "exit with exited_at", topic: runtime.TaskExitEventTopic,
			payload: &apievents.TaskExit{ContainerID: "sb-1", ExitStatus: 1, ExitedAt: protobuf.ToTimestamp(exited)}, want: exited},
		{name: "exit without exited_at", topic: runtime.TaskExitEventTopic,
			payload: &apievents.TaskExit{ContainerID: "sb-1", ExitStatus: 1}, want: published},
		{name: "start", topic: runtime.TaskStartEventTopic,
			payload: &apievents.TaskStart{ContainerID: "sb-1"}, want: published},
		{name: "container delete", topic: containerDeleteEventTopic,
			payload: &apievents.ContainerDelete{ID: "sb-1"}, want: published},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			any, err := typeurl.MarshalAny(tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := normalizeContainerdEvent(&events.Envelope{Topic: tc.topic, Timestamp: published, Event: any})
			if !ok {
				t.Fatal("event dropped")
			}
			if !got.Time.Equal(tc.want) {
				t.Fatalf("Time = %v, want %v", got.Time, tc.want)
			}
		})
	}
}
