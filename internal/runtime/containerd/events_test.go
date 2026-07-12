package containerd

import (
	"testing"
	"time"

	apievents "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/typeurl/v2"
)

func TestNormalizeContainerdEvent(t *testing.T) {
	mkEnvelope := func(t *testing.T, topic string, payload any) *events.Envelope {
		t.Helper()
		any, err := typeurl.MarshalAny(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		return &events.Envelope{Topic: topic, Timestamp: time.Now(), Event: any}
	}

	cases := []struct {
		name       string
		env        *events.Envelope
		wantOK     bool
		wantAction string
		wantID     string
	}{
		{
			name:       "task exit maps to die",
			env:        mkEnvelope(t, runtime.TaskExitEventTopic, &apievents.TaskExit{ContainerID: "sb-1"}),
			wantOK:     true,
			wantAction: "die",
			wantID:     "sb-1",
		},
		{
			name:       "task start maps to start",
			env:        mkEnvelope(t, runtime.TaskStartEventTopic, &apievents.TaskStart{ContainerID: "sb-2"}),
			wantOK:     true,
			wantAction: "start",
			wantID:     "sb-2",
		},
		{
			name:       "task delete maps to destroy",
			env:        mkEnvelope(t, runtime.TaskDeleteEventTopic, &apievents.TaskDelete{ContainerID: "sb-3"}),
			wantOK:     true,
			wantAction: "destroy",
			wantID:     "sb-3",
		},
		{
			name:       "task oom maps to oom",
			env:        mkEnvelope(t, runtime.TaskOOMEventTopic, &apievents.TaskOOM{ContainerID: "sb-4"}),
			wantOK:     true,
			wantAction: "oom",
			wantID:     "sb-4",
		},
		{
			name:   "unrelated topic ignored",
			env:    mkEnvelope(t, "/images/create", &apievents.TaskStart{ContainerID: "sb-5"}),
			wantOK: false,
		},
		{
			name:   "nil envelope ignored",
			env:    nil,
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := normalizeContainerdEvent(tc.env)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if got.Action != tc.wantAction {
				t.Fatalf("action = %q, want %q", got.Action, tc.wantAction)
			}
			if got.ContainerID != tc.wantID || got.SandboxID != tc.wantID {
				t.Fatalf("id = %q/%q, want %q", got.ContainerID, got.SandboxID, tc.wantID)
			}
		})
	}
}
