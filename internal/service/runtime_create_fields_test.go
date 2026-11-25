package service

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/scaleobs"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// dockerOnly gives svc a node that offers docker only, as a node with no
// other runtime switched on is set up (supportedRuntimesForConfig).
func dockerOnly(svc *Service) {
	svc.admitter = capacity.New(capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384, SupportedRuntimes: []string{models.RuntimeDocker}},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1}, nil)
}

// TestCreateRefusalNamesOfferedRuntimes: a create that asks for a runtime
// this node does not offer is refused as before (same sentinel, so the same
// HTTP status), and the refusal names what is offered.
func TestCreateRefusalNamesOfferedRuntimes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		runtime string
		is      error // the refusal's class before this change; nil: a plain error
		cause   string
	}{
		{name: "reserved kata", runtime: models.RuntimeKata, is: models.ErrRuntimeNotImplemented, cause: "not yet implemented"},
		{name: "gvisor not on this host", runtime: models.RuntimeGvisor, is: capacity.ErrCapacityExceeded, cause: "not supported on this host"},
		{name: "firecracker switched off", runtime: models.RuntimeFirecracker, is: models.ErrRuntimeNotImplemented, cause: "SB_ENABLE_FIRECRACKER"},
		{name: "unknown name", runtime: "nope", cause: "unsupported runtime"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingRuntime{}
			svc, _, _ := newServiceRuntimeHarness(t, rt)
			dockerOnly(svc)
			for _, create := range []func() error{
				func() error {
					_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: tc.runtime})
					return err
				},
				func() error {
					_, err := svc.CreateSandboxWithID(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: tc.runtime}, "sb-refused")
					return err
				},
			} {
				err := create()
				want := `runtime "` + tc.runtime + `" is not offered here (offered: docker): `
				if err == nil || !strings.HasPrefix(err.Error(), want) || !strings.Contains(err.Error(), tc.cause) {
					t.Fatalf("error = %v, want it to start %q and keep %q", err, want, tc.cause)
				}
				if tc.is != nil && !errors.Is(err, tc.is) {
					t.Fatalf("error = %v, no longer %v: its status would change", err, tc.is)
				}
				var notOffered *models.RuntimeNotOfferedError
				if !errors.As(err, &notOffered) || !slices.Equal(notOffered.Offered, []string{models.RuntimeDocker}) {
					t.Fatalf("error = %#v, want a RuntimeNotOfferedError offering docker", err)
				}
			}
			if rt.createCalls != 0 {
				t.Fatalf("runtime Create calls = %d: nothing may be started in its place", rt.createCalls)
			}
		})
	}
}

// TestExplainRuntimeRefusalLeavesOtherErrorsAlone: only a refused create of
// a runtime that is not offered gains the list.
func TestExplainRuntimeRefusalLeavesOtherErrorsAlone(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	dockerOnly(svc)
	cause := errors.New("image pull failed")
	explained := svc.ExplainRuntimeRefusal(models.RuntimeGvisor, cause)
	for _, tc := range []struct {
		name    string
		runtime string
		err     error
		want    error
	}{
		{"success", models.RuntimeGvisor, nil, nil},
		{"no runtime named", "", cause, cause},
		{"runtime offered", models.RuntimeDocker, cause, cause},
		{"runtime offered, padded", " docker ", cause, cause},
		{"already explained", models.RuntimeGvisor, explained, explained},
	} {
		if got := svc.ExplainRuntimeRefusal(tc.runtime, tc.err); got != tc.want {
			t.Errorf("%s: ExplainRuntimeRefusal = %v, want %v unchanged", tc.name, got, tc.want)
		}
	}
	if !errors.Is(explained, cause) || strings.Count(explained.Error(), "not offered") != 1 {
		t.Fatalf("explained = %v", explained)
	}

	// A failed create of an offered runtime is returned as the runtime
	// gave it.
	rt := &recordingRuntime{createErr: errors.New("create failed")}
	svc, _, _ = newServiceRuntimeHarness(t, rt)
	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeDocker})
	if err == nil || strings.Contains(err.Error(), "not offered") {
		t.Fatalf("offered runtime's failure = %v, want it unexplained", err)
	}
}

// TestRuntimeNotOfferedErrorText covers the message with no cause and with
// nothing offered.
func TestRuntimeNotOfferedErrorText(t *testing.T) {
	err := &models.RuntimeNotOfferedError{Runtime: "gvisor"}
	if got := err.Error(); got != `runtime "gvisor" is not offered here (offered: none)` {
		t.Fatalf("Error() = %q", got)
	}
	if err.Unwrap() != nil {
		t.Fatal("Unwrap of no cause is not nil")
	}
}

// TestCreateRecordsBackendAndWarm: a create's backend and warm start ride
// in the row it already writes, so the create, its replay and a later read
// all say the same.
func TestCreateRecordsBackendAndWarm(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		parkID   string
		wantWarm string
	}{
		{name: "cold container", wantWarm: models.WarmPoolKindNone},
		{name: "parked container", parkID: "park-1", wantWarm: models.WarmPoolKindParked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := "sb-" + strings.ReplaceAll(tc.name, " ", "-")
			rt := &recordingRuntime{createState: &models.SandboxRuntimeState{SandboxID: id, ContainerID: "ctr-1", ContainerIP: "10.0.0.40",
				Status: models.SandboxStatusStarted, AdoptedParkID: tc.parkID}}
			svc, st, _ := newServiceRuntimeHarness(t, rt)
			req := models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeDocker}
			resp, err := svc.CreateSandboxWithID(ctx, req, id)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			if resp.Sandbox.Warm != tc.wantWarm || resp.Sandbox.Backend != "" {
				t.Fatalf("create answer warm=%q backend=%q, want %q and none", resp.Sandbox.Warm, resp.Sandbox.Backend, tc.wantWarm)
			}
			stored, err := st.Get(ctx, id)
			if err != nil || stored.Warm != tc.wantWarm {
				t.Fatalf("stored row = %+v, %v; want warm %q", stored, err, tc.wantWarm)
			}
			replay, err := svc.CreateSandboxWithID(ctx, req, id)
			if err != nil || !replay.Replayed || replay.Sandbox.Warm != tc.wantWarm {
				t.Fatalf("replay = %+v, %v; want the same warm %q", replay, err, tc.wantWarm)
			}
		})
	}
}

// TestPersistSandboxCreateSetsBackendAndWarm drives the one row write every
// runtime's create shares, for the cases a container create cannot reach:
// a Firecracker VM from the warm pool, and a path with no warm marker.
func TestPersistSandboxCreateSetsBackendAndWarm(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	row := func(id, runtime, warm string) *models.Sandbox {
		return &models.Sandbox{ID: id, Image: "img", Status: models.SandboxStatusStarted, Runtime: runtime, Warm: warm,
			CPU: 1, MemoryMB: 256, OSUser: "root", CreatedAt: now, UpdatedAt: now, LastActiveAt: now}
	}

	warmCtx, _ := scaleobs.WithWarmStart(context.Background())
	scaleobs.MarkWarmStart(warmCtx)
	vm := row("sb-fc", models.RuntimeFirecracker, "")
	if err := svc.persistSandboxCreate(warmCtx, vm); err != nil {
		t.Fatalf("persist firecracker: %v", err)
	}
	if vm.Backend != "kvm" || vm.Warm != models.WarmPoolKindSnapshot {
		t.Fatalf("firecracker row backend=%q warm=%q, want kvm and snapshot", vm.Backend, vm.Warm)
	}

	// No marker (a WASM move's or a durable WASM failover's ctx): the row is
	// written with its own value. Those paths build a fresh row, so in use
	// they save none; this row carries a value to show it is not overwritten.
	moved := row("sb-moved", models.RuntimeWasm, models.WarmPoolKindParked)
	if err := svc.persistSandboxCreate(context.Background(), moved); err != nil {
		t.Fatalf("persist moved: %v", err)
	}
	unknown := row("sb-unknown", models.RuntimeDocker, "")
	if err := svc.persistSandboxCreate(context.Background(), unknown); err != nil {
		t.Fatalf("persist unknown: %v", err)
	}

	for id, want := range map[string][2]string{
		"sb-fc":      {"kvm", models.WarmPoolKindSnapshot},
		"sb-moved":   {"", models.WarmPoolKindParked},
		"sb-unknown": {"", ""},
	} {
		got, err := st.Get(context.Background(), id)
		if err != nil || got.Backend != want[0] || got.Warm != want[1] {
			t.Fatalf("%s read back = %+v, %v; want backend %q warm %q", id, got, err, want[0], want[1])
		}
	}
}
