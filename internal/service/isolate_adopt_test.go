package service

import (
	"context"
	"errors"
	"testing"
	"time"

	isolateruntime "github.com/aerol-ai/microvm/internal/runtime/isolate"
	"github.com/aerol-ai/microvm/pkg/models"
)

// adoptingIsolateRuntime is an isolate driver that adopts at boot.
type adoptingIsolateRuntime struct {
	*policyMediatorRuntime
	rows   []string
	report isolateruntime.AdoptReport
}

func (r *adoptingIsolateRuntime) AdoptSandboxes(_ context.Context, rows []*models.Sandbox) isolateruntime.AdoptReport {
	for _, sb := range rows {
		r.rows = append(r.rows, sb.ID)
	}
	return r.report
}

// TestAdoptIsolateSandboxesAtBoot: every started isolate row goes to the
// driver, and each gets its full egress policy back from the row.
func TestAdoptIsolateSandboxesAtBoot(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	rt := &adoptingIsolateRuntime{policyMediatorRuntime: newMediator(), report: isolateruntime.AdoptReport{Groups: 1, Adopted: 1, Reloading: 1}}
	svc.SetIsolateRuntime(rt)
	now := time.Now().UTC()
	yes, no := true, false
	rows := []*models.Sandbox{
		{ID: "sb-a", Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStarted, NetworkAllowOut: []string{"example.com"}, AllowPublicTraffic: &no},
		{ID: "sb-b", Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStarted, NetworkBlockAll: true, AllowPublicTraffic: &yes, ContainerIP: "127.0.0.1"},
		{ID: "sb-stopped", Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStopped},
		{ID: "sb-docker", Runtime: models.RuntimeDocker, Status: models.SandboxStatusStarted},
	}
	for _, sb := range rows {
		sb.CreatedAt, sb.UpdatedAt = now, now
		if err := st.Create(ctx, sb); err != nil {
			t.Fatal(err)
		}
	}
	report := svc.AdoptIsolateSandboxes(ctx)
	if report != rt.report {
		t.Fatalf("report = %+v", report)
	}
	if len(rt.rows) != 2 {
		t.Fatalf("driver got rows %v, want the two started isolates", rt.rows)
	}
	if got := rt.set["sb-a"]; len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("sb-a policy = %v", got)
	}
	if !rt.blocked["sb-b"] {
		t.Fatal("sb-b block-all not set again")
	}
}

func TestAdoptIsolateSandboxesNoopAndErrors(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if r := svc.AdoptIsolateSandboxes(context.Background()); r != (isolateruntime.AdoptReport{}) {
		t.Fatalf("no isolate runtime: %+v", r)
	}
	svc.SetIsolateRuntime(&recordingRuntime{})
	if r := svc.AdoptIsolateSandboxes(context.Background()); r != (isolateruntime.AdoptReport{}) {
		t.Fatalf("runtime without adoption: %+v", r)
	}
	// A policy that cannot be set is logged; the pass goes on.
	m := newMediator()
	m.err = errors.New("host gone")
	rt := &adoptingIsolateRuntime{policyMediatorRuntime: m}
	svc.SetIsolateRuntime(rt)
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{ID: "sb-x", Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	svc.AdoptIsolateSandboxes(context.Background())
	if len(rt.rows) != 1 {
		t.Fatalf("rows = %v", rt.rows)
	}
	// A store that cannot list: nothing reaches the driver.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if r := svc.AdoptIsolateSandboxes(canceled); r != (isolateruntime.AdoptReport{}) || len(rt.rows) != 1 {
		t.Fatalf("failed list: %+v rows %v", r, rt.rows)
	}
}
