package cluster

import (
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// cloneCreateSandboxRequest must deep-copy CompatState so the FSM never shares a
// facade-state map across placements (B11).
func TestCloneCreateSandboxRequestCopiesCompatState(t *testing.T) {
	in := &models.CreateSandboxRequest{
		Image:       "alpine",
		CompatState: map[string]string{models.FacadeRunloop: `{"a":1}`},
	}
	out := cloneCreateSandboxRequest(in)
	if out.CompatState[models.FacadeRunloop] != `{"a":1}` {
		t.Fatalf("CompatState not copied: %+v", out.CompatState)
	}
	// Mutating the copy must not touch the original.
	out.CompatState[models.FacadeRunloop] = "changed"
	if in.CompatState[models.FacadeRunloop] != `{"a":1}` {
		t.Fatal("clone shares the CompatState map with the original")
	}
}
