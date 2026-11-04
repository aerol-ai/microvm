package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// identityStartRuntime is a runtime whose start needs the sandbox's identity,
// as Docker's does for a container adopted from the warm pool.
type identityStartRuntime struct {
	*recordingRuntime
	gotRef, gotID, gotToken string
}

func (r *identityStartRuntime) StartWithIdentity(ctx context.Context, containerRef, sandboxID, toolboxToken string) (*models.SandboxRuntimeState, error) {
	r.gotRef, r.gotID, r.gotToken = containerRef, sandboxID, toolboxToken
	return r.recordingRuntime.Start(ctx, containerRef)
}

// A runtime that can re-hand a container its identity gets the sandbox's ID
// and toolbox token on every start; without them a restarted warm-pool
// container boots parked and serves nothing (UC-206/207/227 live).
func TestStartSandboxHandsTheRuntimeTheSandboxIdentity(t *testing.T) {
	ctx := context.Background()
	base := &recordingRuntime{startState: &models.SandboxRuntimeState{
		SandboxID: "sb-ident", ContainerID: "ctr-ident", ContainerIP: "10.0.0.51", Status: models.SandboxStatusStarted,
	}}
	svc, st, _ := newServiceRuntimeHarness(t, base)
	rt := &identityStartRuntime{recordingRuntime: base}
	svc.docker = rt

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-ident", Image: "alpine:3.20", Status: models.SandboxStatusStopped,
		ContainerID: "ctr-ident", ContainerIP: "10.0.0.50", Runtime: models.RuntimeDocker,
		ToolboxToken: "ident-token", CPU: 1, MemoryMB: 512, DiskGB: 10,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	got, err := svc.StartSandbox(ctx, "sb-ident")
	if err != nil {
		t.Fatalf("StartSandbox: %v", err)
	}
	if rt.gotRef != "ctr-ident" || rt.gotID != "sb-ident" || rt.gotToken != "ident-token" {
		t.Fatalf("StartWithIdentity(%q, %q, %q), want the container ref, sandbox ID and its toolbox token", rt.gotRef, rt.gotID, rt.gotToken)
	}
	if got.Status != models.SandboxStatusStarted || got.ContainerIP != "10.0.0.51" {
		t.Fatalf("started sandbox = %+v", got)
	}
}
