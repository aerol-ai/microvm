package containerd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	apievents "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/core/runtime"
	"github.com/containerd/typeurl/v2"

	"github.com/aerol-ai/microvm/pkg/docker"
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
			// Regression: TaskPaused must be IGNORED, not mapped to "stop". The
			// service consumer folds "stop" into markSandboxStopped (route +
			// netrules + admitter teardown); mapping pause→stop made an internal
			// CreateSnapshot pause tear the live sandbox down, and TaskResumed
			// (below, also ignored) never restored it. Docker's pause/unpause are
			// ignored by the consumer too — this is the parity fix.
			name:   "task paused is ignored (snapshot pause must not stop the sandbox)",
			env:    mkEnvelope(t, runtime.TaskPausedEventTopic, &apievents.TaskPaused{ContainerID: "sb-pause"}),
			wantOK: false,
		},
		{
			name:   "task resumed is ignored",
			env:    mkEnvelope(t, runtime.TaskResumedEventTopic, &apievents.TaskResumed{ContainerID: "sb-resume"}),
			wantOK: false,
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

func TestContainerIDFromEventBadPayload(t *testing.T) {
	if got := containerIDFromEvent(&events.Envelope{Event: nil}); got != "" {
		t.Fatalf("got %q", got)
	}
	any, err := typeurl.MarshalAny(&apievents.TaskStart{ContainerID: "sb-ok"})
	if err != nil {
		t.Fatal(err)
	}
	if got := containerIDFromEvent(&events.Envelope{Event: any}); got != "sb-ok" {
		t.Fatalf("got %q", got)
	}
}

func TestStreamEventsContextCancel(t *testing.T) {
	tr := newFakeTransport()
	tr.emitEvents = true
	d := New(Config{}, nil, nil)
	d.SetClient(NewTestClient("aerolvm", tr))
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan docker.DockerEvent, 1)
	errCh := make(chan error, 1)
	go func() { errCh <- d.StreamEvents(ctx, out) }()
	select {
	case <-out:
		cancel()
	case <-time.After(2 * time.Second):
		cancel()
	}
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StreamEvents did not exit")
	}
}

func TestStreamEventsSubscribeError(t *testing.T) {
	tr := &errorSubscribeTransport{}
	d := New(Config{}, nil, nil)
	d.SetClient(NewTestClient("aerolvm", tr))
	ctx := context.Background()
	err := d.StreamEvents(ctx, make(chan docker.DockerEvent))
	if err == nil || !strings.Contains(err.Error(), "containerd event stream") {
		t.Fatalf("want stream error, got %v", err)
	}
}

func TestPollToolboxHealthConnectionRefused(t *testing.T) {
	err := pollToolboxHealth(context.Background(), "127.0.0.1", 1)
	if err == nil {
		t.Fatal("want connection error")
	}
}

func TestContainerIDFromEventEmptyID(t *testing.T) {
	any, err := typeurl.MarshalAny(&apievents.TaskStart{ContainerID: ""})
	if err != nil {
		t.Fatal(err)
	}
	if got := containerIDFromEvent(&events.Envelope{Event: any}); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeContainerdEventEmptyID(t *testing.T) {
	any, err := typeurl.MarshalAny(&apievents.TaskExit{ContainerID: ""})
	if err != nil {
		t.Fatal(err)
	}
	env := &events.Envelope{Topic: runtime.TaskExitEventTopic, Event: any}
	if _, ok := normalizeContainerdEvent(env); ok {
		t.Fatal("want false for empty container id")
	}
}

func TestStreamEventsClosedChannel(t *testing.T) {
	tr := &closedSubscribeTransport{}
	d := New(Config{}, nil, nil)
	d.SetClient(NewTestClient("aerolvm", tr))
	err := d.StreamEvents(context.Background(), make(chan docker.DockerEvent))
	if err != nil {
		t.Fatal(err)
	}
}

type closedSubscribeTransport struct{ fakeTransport }

func (*closedSubscribeTransport) subscribe(context.Context, ...string) (<-chan *events.Envelope, <-chan error) {
	ch := make(chan *events.Envelope)
	close(ch)
	return ch, make(chan error)
}

type errorSubscribeTransport struct{ fakeTransport }

func (*errorSubscribeTransport) subscribe(context.Context, ...string) (<-chan *events.Envelope, <-chan error) {
	errCh := make(chan error, 1)
	errCh <- errors.New("subscribe failed")
	return make(chan *events.Envelope), errCh
}
