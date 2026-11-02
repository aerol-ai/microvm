package service

import (
	"context"
	"maps"
	"testing"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestFirecrackerCreateHandsTheDriverTheGuestEnv: the Firecracker driver now
// delivers the env into the guest, so it must get exactly what a container
// would see, with a key the egress gateway injects left as a placeholder
// (P3-2), while the store keeps the real values sealed. On origin/main the
// driver got the raw env, which was harmless only because it dropped it.
func TestFirecrackerCreateHandsTheDriverTheGuestEnv(t *testing.T) {
	ctx := context.Background()
	rt := &fireRecordingRuntime{ok: &models.SandboxRuntimeState{
		ContainerID: "/var/run/sb/fcenv/api.sock",
		ContainerIP: "172.16.0.2",
		Status:      models.SandboxStatusStarted,
	}}
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableFirecracker = true
	svc.admitter = nil
	svc.SetFirecrackerRuntime(rt)

	env := map[string]string{"BANK_SECRET": "canary-5c1e9d", "API_KEY": "real-key"}
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image:             "alpine:3.20",
		Runtime:           models.RuntimeFirecracker,
		MemoryMB:          256,
		Env:               maps.Clone(env),
		EgressWithheldEnv: []string{"API_KEY"},
	})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	want := map[string]string{"BANK_SECRET": "canary-5c1e9d", "API_KEY": egresspolicy.InjectPlaceholder("API_KEY")}
	if !maps.Equal(rt.lastCreateReq.Env, want) {
		t.Fatalf("driver env = %v, want %v", rt.lastCreateReq.Env, want)
	}
	stored, err := svc.loadEnv(ctx, resp.Sandbox.ID, resp.Sandbox.AuditIncarnationID)
	if err != nil {
		t.Fatalf("loadEnv: %v", err)
	}
	if !maps.Equal(stored, env) {
		t.Fatalf("sealed env = %v, want the real values %v", stored, env)
	}
}
