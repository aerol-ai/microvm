package daytona

import (
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestSandboxMetaFromStateRoundTripCoverage95(t *testing.T) {
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-meta", Name: "", OSUser: "dev",
		CreatedAt: now, UpdatedAt: now,
		Lifecycle: models.Lifecycle{StopIfIdleFor: 2 * time.Minute, DestroyIfIdleFor: 3 * time.Minute},
	}
	meta := sandboxMetaFromNative(sb, compatBlob{
		Snapshot: "snap", Target: "target", NetworkAllowList: "10.0.0.0/8", AutoArchiveInterval: 15,
	})
	stateJSON, err := sandboxMetaToState(meta)
	if err != nil {
		t.Fatalf("sandboxMetaToState: %v", err)
	}
	got, err := sandboxMetaFromState(&models.SandboxCompatState{StateJSON: stateJSON}, sb)
	if err != nil || got.Target != "target" {
		t.Fatalf("got = %+v err=%v", got, err)
	}
	_, err = sandboxMetaFromState(&models.SandboxCompatState{StateJSON: "{bad"}, sb)
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
}
