package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// stageSnapshotRuntime notes which stages were on the create's recorder when
// the service handed the create to the runtime driver.
type stageSnapshotRuntime struct {
	*recordingRuntime
	atDriver []string
}

func (r *stageSnapshotRuntime) Create(ctx context.Context, req models.CreateSandboxRequest, sandboxID, toolboxToken string, binds []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	for _, st := range createtiming.From(ctx).Stages() {
		r.atDriver = append(r.atDriver, st.Name)
	}
	return r.recordingRuntime.Create(ctx, req, sandboxID, toolboxToken, binds)
}

// Plan PR #1000 item L1: the service's work before the runtime driver
// (validation, quota, policy, key generation, admission, mounts) was covered
// by no Server-Timing stage. By the time the driver runs, each step must have
// recorded one, back to back and in order.
func TestCreateSandboxRecordsStagesBeforeDriver(t *testing.T) {
	rt := &stageSnapshotRuntime{recordingRuntime: &recordingRuntime{}}
	svc, _, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})

	ctx, _ := createtiming.With(context.Background())
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 256, DiskGB: 5,
	}); err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	want := []string{"svc_validate", "svc_quota", "svc_policy", "svc_keygen", "svc_admit", "svc_pre_driver"}
	if len(rt.atDriver) != len(want) {
		t.Fatalf("stages at driver call = %v, want %v", rt.atDriver, want)
	}
	for i := range want {
		if rt.atDriver[i] != want[i] {
			t.Fatalf("stages at driver call = %v, want %v", rt.atDriver, want)
		}
	}
}
