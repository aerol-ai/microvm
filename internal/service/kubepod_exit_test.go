package service

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/runtime/kubepod"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A pod-mode sandbox whose pod went away with no end seen (removed by
// force, or its node lost) gets kubepod.ExitLost. The service must read
// that as a crash, so restart-on-failure restarts it; exit 0 would read as
// "the program exited" and the sandbox would stay down (review of #1487).
func TestPodModeLostSandboxIsACrash(t *testing.T) {
	reason, code := stopReasonForExit(false, kubepod.ExitLost)
	if reason != models.StatusReasonCrashed || code == nil || *code != kubepod.ExitLost {
		t.Fatalf("stopReasonForExit(lost pod) = %q %v; want %q with exit %d", reason, code, models.StatusReasonCrashed, kubepod.ExitLost)
	}
}
