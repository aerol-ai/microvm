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

	err := svc.RecreateSandbox(ctx, sandboxID, models.CreateSandboxRequest{}, cluster.PlacementSecrets{}, map[int]cluster.ExposedPortRoute{
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

// TestAllocateHostPortPreferredUnavailableParksInsteadOfReallocating pins B6's
// park-don't-reallocate policy. When a TCP failover replay supplies a specific
// preferredHostPort that's already reserved cluster-wide, the allocator MUST
// surface ErrPreferredHostPortUnavailable and MUST NOT silently fall through
// to a fresh random port — that would invisibly mutate the public endpoint
// (host:port is the entire B6 contract) and break every client that memorized
// it.
func TestAllocateHostPortPreferredUnavailableParksInsteadOfReallocating(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	svc.cfg.EnableCluster = true
	// Wide pool so a "fall through to random" regression would visibly bind
	// some *other* port; with a one-port pool the test couldn't distinguish
	// "parked" from "exhausted".
	svc.cfg.L4PortRangeStart = 30000
	svc.cfg.L4PortRangeEnd = 30999
	const preferred = 30500
	reserver := &hostPortReserveCluster{
		Noop:     cluster.NewNoop("self", "http://self"),
		reserved: map[int]bool{preferred: true},
	}
	svc.AttachCluster(reserver)

	now := time.Now().UTC()
	const sandboxID = "sb-park-not-reallocate"
	if err := st.Create(ctx, &models.Sandbox{
		ID:          sandboxID,
		Image:       "postgres:16",
		Status:      models.SandboxStatusStarted,
		ContainerID: "ctr-park-not-reallocate",
		ContainerIP: "10.0.0.23",
		CPU:         1,
		MemoryMB:    512,
		Runtime:     models.RuntimeDocker,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	hp, _, _, err := svc.allocateHostPort(ctx, sandboxID, 5432, now, preferred)
	if err == nil {
		t.Fatalf("allocateHostPort returned host_port=%d with no error; replay reallocated instead of parking", hp)
	}
	if !errors.Is(err, ErrPreferredHostPortUnavailable) {
		t.Fatalf("error = %v, want ErrPreferredHostPortUnavailable so callers can surface the parked state", err)
	}
	if hp != 0 {
		t.Fatalf("host_port = %d, want 0 (parked, no rebind)", hp)
	}
	// The store must NOT carry a fresh reservation for sandboxID:5432; a
	// regression that fell through to the random/linear allocator would have
	// inserted some other host port here.
	got, err := st.Get(ctx, sandboxID)
	if err != nil {
		t.Fatalf("get sandbox: %v", err)
	}
	if exposure := findExposure(got, 5432); exposure != nil {
		t.Fatalf("local store reserved host_port=%d behind a park; allocator must not reallocate", exposure.HostPort)
	}
	if reserver.added[len(reserver.added)-1] != preferred {
		t.Fatalf("allocator asked cluster for host_port=%d as its LAST attempt, want %d; a non-park path retried other ports",
			reserver.added[len(reserver.added)-1], preferred)
	}
	if len(reserver.added) > 1 {
		t.Fatalf("allocator asked cluster for %d candidates after a preferred-port reject; park policy must try exactly once: %v",
			len(reserver.added), reserver.added)
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
