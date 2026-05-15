package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

type hostPortReserveCluster struct {
	*cluster.Noop
	reserved map[int]bool
	added    []int
	removed  []int
}

func (h *hostPortReserveCluster) AddExposedPort(_ context.Context, _ string, _ int, route cluster.ExposedPortRoute) error {
	h.added = append(h.added, route.HostPort)
	if h.reserved[route.HostPort] {
		return cluster.ErrHostPortReserved
	}
	return nil
}

func (h *hostPortReserveCluster) RemoveExposedPort(_ context.Context, _ string, port int) error {
	h.removed = append(h.removed, port)
	return nil
}

func TestExposePortRejectsProtocolSwitchBeforeOverwritingRow(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)

	now := time.Now().UTC()
	const sandboxID = "sb-proto-switch"
	if err := st.Create(ctx, &models.Sandbox{
		ID:          sandboxID,
		Image:       "postgres:16",
		Status:      models.SandboxStatusStarted,
		ContainerID: "ctr-proto-switch",
		ContainerIP: "10.0.0.20",
		CPU:         1,
		MemoryMB:    512,
		Runtime:     models.RuntimeDocker,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: sandboxID,
		Port:      5432,
		Protocol:  models.ExposedPortProtocolTCP,
		HostPort:  22432,
		PublicURL: "tcp://sandbox.test:22432",
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed tcp exposure: %v", err)
	}

	_, err := svc.ExposePort(ctx, sandboxID, 5432, models.ExposedPortProtocolHTTP)
	if err == nil || !strings.Contains(err.Error(), "already exposed as tcp") {
		t.Fatalf("ExposePort protocol switch error = %v", err)
	}
	got, err := st.Get(ctx, sandboxID)
	if err != nil {
		t.Fatalf("get sandbox: %v", err)
	}
	exposure := findExposure(got, 5432)
	if exposure == nil || exposure.Protocol != models.ExposedPortProtocolTCP || exposure.HostPort != 22432 {
		t.Fatalf("tcp exposure was overwritten: %+v", exposure)
	}
}

func TestRecreateSandboxReplaysPortsForExistingSandbox(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)

	now := time.Now().UTC()
	const sandboxID = "sb-replay-existing"
	if err := st.Create(ctx, &models.Sandbox{
		ID:          sandboxID,
		Image:       "alpine",
		Status:      models.SandboxStatusStarted,
		ContainerID: "ctr-replay-existing",
		ContainerIP: "10.0.0.21",
		CPU:         1,
		MemoryMB:    512,
		Runtime:     models.RuntimeDocker,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	err := svc.RecreateSandbox(ctx, sandboxID, models.CreateSandboxRequest{}, nil, map[int]cluster.ExposedPortRoute{
		3000: {Protocol: models.ExposedPortProtocolHTTP},
	})
	if err != nil {
		t.Fatalf("RecreateSandbox existing replay: %v", err)
	}
	got, err := st.Get(ctx, sandboxID)
	if err != nil {
		t.Fatalf("get sandbox: %v", err)
	}
	exposure := findExposure(got, 3000)
	if exposure == nil || exposure.Protocol != models.ExposedPortProtocolHTTP {
		t.Fatalf("expected replayed http exposure, got %+v", exposure)
	}
}

func TestAllocateHostPortHonorsClusterReservationBeforeLocalStore(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	svc.cfg.EnableCluster = true
	svc.cfg.L4PortRangeStart = 22430
	svc.cfg.L4PortRangeEnd = 22431
	reserver := &hostPortReserveCluster{
		Noop:     cluster.NewNoop("self", "http://self"),
		reserved: map[int]bool{22430: true, 22431: true},
	}
	svc.AttachCluster(reserver)

	now := time.Now().UTC()
	const sandboxID = "sb-cluster-port-reserve"
	if err := st.Create(ctx, &models.Sandbox{
		ID:          sandboxID,
		Image:       "postgres:16",
		Status:      models.SandboxStatusStarted,
		ContainerID: "ctr-cluster-port-reserve",
		ContainerIP: "10.0.0.22",
		CPU:         1,
		MemoryMB:    512,
		Runtime:     models.RuntimeDocker,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	_, _, _, err := svc.allocateHostPort(ctx, sandboxID, 5432, now, 0)
	if err == nil || !errors.Is(err, cluster.ErrHostPortReserved) && !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("allocateHostPort error = %v", err)
	}
	got, err := st.Get(ctx, sandboxID)
	if err != nil {
		t.Fatalf("get sandbox: %v", err)
	}
	if exposure := findExposure(got, 5432); exposure != nil {
		t.Fatalf("local store reserved a port even though the cluster rejected every candidate: %+v", exposure)
	}
	if len(reserver.added) == 0 {
		t.Fatal("expected allocator to ask the cluster before local reservation")
	}
}

func TestDataPlaneHostForPlacementPrefersDedicatedHost(t *testing.T) {
	p := cluster.Placement{
		OwnerAPIURL:        "http://shared-api-lb.internal:21212",
		OwnerDataPlaneHost: "10.0.0.7",
	}
	if got := dataPlaneHostForPlacement(p); got != "10.0.0.7" {
		t.Fatalf("dataPlaneHostForPlacement() = %q", got)
	}

	p.OwnerDataPlaneHost = ""
	if got := dataPlaneHostForPlacement(p); got != "shared-api-lb.internal" {
		t.Fatalf("fallback dataPlaneHostForPlacement() = %q", got)
	}
}
