package runtime_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/models"
)

// InstanceGone is the only gate in front of reconcile's reap. It must say
// "gone" for a definitive not-found and for nothing else.
func TestInstanceGone(t *testing.T) {
	present := &models.SandboxRuntimeState{SandboxID: "sb", Status: models.SandboxStatusStarted}
	cases := []struct {
		name  string
		state *models.SandboxRuntimeState
		err   error
		gone  bool
	}{
		{name: "state", state: present},
		{name: "state without container id or address", state: &models.SandboxRuntimeState{SandboxID: "sb"}},
		{name: "registry miss (nil, nil)", gone: true},
		{name: "wrapped not found", err: fmt.Errorf("inspect container: %w: 404", runtime.ErrInstanceNotFound), gone: true},
		{name: "timeout", err: context.DeadlineExceeded},
		{name: "netns probe failure", err: errors.New("netns from pid: no such file or directory")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runtime.InstanceGone(tc.state, tc.err); got != tc.gone {
				t.Fatalf("InstanceGone(%v, %v) = %v, want %v", tc.state, tc.err, got, tc.gone)
			}
		})
	}
}
