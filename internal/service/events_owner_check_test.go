package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// clearRecordingRuntime records event-driven rule clears and can play the
// runtime's live IP-owner view.
type clearRecordingRuntime struct {
	*recordingRuntime
	mu        sync.Mutex
	clears    []string
	policies  []string
	owner     string
	ownerErr  error
	hasOwners bool
}

func (r *clearRecordingRuntime) ClearNetworkRules(ip string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clears = append(r.clears, ip)
	return nil
}

func (r *clearRecordingRuntime) ClearEgressPolicy(ip string, _, _ []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policies = append(r.policies, ip)
	return nil
}

// ownerRuntime adds the optional IPOwnerResolver.
type ownerRuntime struct{ *clearRecordingRuntime }

func (r ownerRuntime) IPOwner(context.Context, string) (string, error) {
	return r.owner, r.ownerErr
}

// TestEventClearsAreOwnerChecked is the P0-6 regression: a stop or destroy
// event for an old sandbox that arrives after its IP was handed to a new
// sandbox must leave the new owner's rules alone.
func TestEventClearsAreOwnerChecked(t *testing.T) {
	ctx := context.Background()
	const ip = "10.88.0.40"
	now := time.Now().UTC()
	cases := []struct {
		name      string
		newOwner  bool // another started row holds the IP
		runtime   func(*clearRecordingRuntime) any
		wantClear bool
	}{
		{name: "no other owner clears", wantClear: true},
		{name: "store row of new owner skips", newOwner: true, wantClear: false},
		{name: "runtime reports new owner skips", runtime: func(r *clearRecordingRuntime) any {
			r.owner = "sb-new"
			return ownerRuntime{r}
		}, wantClear: false},
		{name: "runtime reports same owner clears", runtime: func(r *clearRecordingRuntime) any {
			r.owner = "sb-old"
			return ownerRuntime{r}
		}, wantClear: true},
		{name: "runtime reports free slot clears", runtime: func(r *clearRecordingRuntime) any {
			r.owner = ""
			return ownerRuntime{r}
		}, wantClear: true},
		{name: "runtime lookup error skips", runtime: func(r *clearRecordingRuntime) any {
			r.ownerErr = errors.New("dockerd down")
			return ownerRuntime{r}
		}, wantClear: false},
	}
	for _, tc := range cases {
		for _, event := range []string{"stop", "destroy"} {
			t.Run(tc.name+"/"+event, func(t *testing.T) {
				svc, _, st := newCapacityHarness(t, nil, nil)
				rec := &clearRecordingRuntime{recordingRuntime: &recordingRuntime{}}
				var rt any = rec
				if tc.runtime != nil {
					rt = tc.runtime(rec)
				}
				switch v := rt.(type) {
				case ownerRuntime:
					svc.docker = v
				default:
					svc.docker = rec
				}
				if tc.newOwner {
					if err := st.Upsert(ctx, &models.Sandbox{
						ID: "sb-new", Image: "img", Status: models.SandboxStatusStarted,
						ContainerIP: ip, Runtime: models.RuntimeDocker,
						CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
					}); err != nil {
						t.Fatal(err)
					}
				}
				old := &models.Sandbox{
					ID: "sb-old", Image: "img", Status: models.SandboxStatusStarted,
					ContainerIP: ip, Runtime: models.RuntimeDocker,
					NetworkAllowOut:    []string{"1.1.1.1/32"},
					AuditIncarnationID: "inc-sb-old",
					CreatedAt:          now, UpdatedAt: now, LastActiveAt: now,
				}
				var err error
				if event == "stop" {
					err = svc.markSandboxStopped(ctx, old, docker.DockerEvent{SandboxID: old.ID, Action: "die", Time: now})
				} else {
					err = svc.handleDestroyEvent(ctx, old)
				}
				if err != nil {
					t.Fatalf("%s event: %v", event, err)
				}
				gotClear := len(rec.clears) > 0
				if gotClear != tc.wantClear || (len(rec.policies) > 0) != tc.wantClear {
					t.Fatalf("clears=%v policies=%v, want clear=%v", rec.clears, rec.policies, tc.wantClear)
				}
			})
		}
	}
}

func TestEventClearSkipsOnStoreLookupError(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	rec := &clearRecordingRuntime{recordingRuntime: &recordingRuntime{}}
	svc.docker = rec
	_ = st.Close()
	old := &models.Sandbox{ID: "sb-old", ContainerIP: "10.88.0.41", Runtime: models.RuntimeDocker}
	if svc.ipClaimedByOther(ctx, old.ID, old.ContainerIP, rec) != true {
		t.Fatal("a failed owner lookup must count as claimed (fail closed)")
	}
}
