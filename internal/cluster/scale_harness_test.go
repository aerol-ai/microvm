package cluster

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

func TestScaleHarness1000NodeCreateBurstCapacityAndWorkerDeath(t *testing.T) {
	requireScaleGates(t)

	const (
		servers          = 3
		workers          = 990
		ingress          = 7
		perWorkerCreates = 50
	)
	now := time.Unix(1_800_000_000, 0)
	members := scaleHarnessMembers(servers, workers, ingress)
	leases := newCapacityLeaseCache("", nil, 5*time.Second, nil)
	for i := 0; i < workers; i++ {
		leases.set(fmt.Sprintf("worker-%04d", i), scaleWorkerCapacity(), now)
	}
	members = leases.apply(members, now)

	if got := LiveMemberCount(members); got != servers+workers+ingress {
		t.Fatalf("live members=%d, want %d", got, servers+workers+ingress)
	}
	if err := LargeClusterTopologyError(members); err != nil {
		t.Fatalf("1000-node dedicated topology rejected: %v", err)
	}

	fsm := newPlacementFSM()
	expiry := now.Add(10 * time.Minute).Unix()
	logIndex := uint64(1)
	for worker := 0; worker < workers; worker++ {
		owner := fmt.Sprintf("worker-%04d", worker)
		batch := make([]reservationCommand, 0, perWorkerCreates)
		for create := 0; create < perWorkerCreates; create++ {
			batch = append(batch, reservationCommand{
				SandboxID:   fmt.Sprintf("burst-%04d-%02d", worker, create),
				OwnerNodeID: owner,
				OwnerAPIURL: fmt.Sprintf("http://%s:21212", owner),
				Spec:        &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 256, DiskGB: 1},
				ExpiresUnix: expiry,
			})
		}
		pending := fsm.pendingReservationsByNode(expiry - 1)
		counts := map[string]int{owner: fsm.livePendingReservationCount(owner, expiry-1)}
		if err := admitReservationCommands(members, pending, counts, perWorkerCreates, batch); err != nil {
			t.Fatalf("admit batch for %s: %v", owner, err)
		}
		payload, err := encodeCommand(command{Op: opReserveBatch, Reservations: batch})
		if err != nil {
			t.Fatalf("encode batch for %s: %v", owner, err)
		}
		if got := fsm.Apply(&raft.Log{Index: logIndex, Data: payload}); got != nil {
			t.Fatalf("apply batch for %s: %v", owner, got)
		}
		logIndex++
	}

	if got := len(fsm.pendingReservationClaims); got != workers*perWorkerCreates {
		t.Fatalf("pending claims=%d, want %d", got, workers*perWorkerCreates)
	}
	if got := fsm.pendingReservationsByNode(expiry - 1)["worker-0000"].CPU; got != perWorkerCreates {
		t.Fatalf("worker-0000 pending CPU=%v, want %d", got, perWorkerCreates)
	}
	err := admitReservationCommands(members, fsm.pendingReservationsByNode(expiry-1),
		map[string]int{"worker-0000": fsm.livePendingReservationCount("worker-0000", expiry-1)},
		perWorkerCreates,
		[]reservationCommand{{
			SandboxID:   "burst-over-cap",
			OwnerNodeID: "worker-0000",
			Spec:        &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 256, DiskGB: 1},
			ExpiresUnix: expiry,
		}},
	)
	if !errors.Is(err, ErrCreateBackpressure) {
		t.Fatalf("extra create admission error=%v, want ErrCreateBackpressure", err)
	}

	missingLease := scaleHarnessMembers(servers, workers, ingress)
	missingLease = leases.apply(missingLease, now.Add(30*time.Second))
	err = admitReservationCommands(missingLease, nil, nil, perWorkerCreates,
		[]reservationCommand{{
			SandboxID:   "stale-worker-create",
			OwnerNodeID: "worker-0001",
			Spec:        &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 256, DiskGB: 1},
			ExpiresUnix: expiry,
		}},
	)
	if !errors.Is(err, ErrNoPlacementTarget) {
		t.Fatalf("stale capacity admission error=%v, want ErrNoPlacementTarget", err)
	}

	for i := 0; i < perWorkerCreates; i++ {
		payload, err := encodeCommand(command{
			Op:          opPlace,
			SandboxID:   fmt.Sprintf("dead-owned-%02d", i),
			OwnerNodeID: "worker-dead",
			OwnerAPIURL: "http://worker-dead:21212",
			Spec:        &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 256, DiskGB: 1},
		})
		if err != nil {
			t.Fatalf("encode dead placement: %v", err)
		}
		if got := fsm.Apply(&raft.Log{Index: logIndex, Data: payload}); got != nil {
			t.Fatalf("apply dead placement: %v", got)
		}
		logIndex++
	}
	if got := len(fsm.idsOwnedBy("worker-dead")); got != perWorkerCreates {
		t.Fatalf("worker-dead owned ids=%d, want %d", got, perWorkerCreates)
	}
	orphan, _ := encodeCommand(command{Op: opOrphanOwner, NodeID: "worker-dead"})
	if got := fsm.Apply(&raft.Log{Index: logIndex, Data: orphan}); got != nil {
		t.Fatalf("orphan dead worker: %v", got)
	}
	if got := len(fsm.idsOwnedBy("worker-dead")); got != 0 {
		t.Fatalf("worker-dead still owns %d placements after orphan", got)
	}
}

func scaleHarnessMembers(servers, workers, ingress int) []Member {
	out := make([]Member, 0, servers+workers+ingress)
	for i := 0; i < servers; i++ {
		out = append(out, Member{NodeID: fmt.Sprintf("server-%02d", i), APIURL: fmt.Sprintf("http://server-%02d:21212", i), Alive: true, Role: config.NodeRoleServer})
	}
	for i := 0; i < workers; i++ {
		out = append(out, Member{NodeID: fmt.Sprintf("worker-%04d", i), APIURL: fmt.Sprintf("http://worker-%04d:21212", i), Alive: true, Role: config.NodeRoleWorker})
	}
	for i := 0; i < ingress; i++ {
		out = append(out, Member{NodeID: fmt.Sprintf("ingress-%02d", i), APIURL: fmt.Sprintf("http://ingress-%02d:21212", i), Alive: true, Role: config.NodeRoleIngress})
	}
	return out
}

func scaleWorkerCapacity() capacity.Snapshot {
	return capacity.Snapshot{
		HostCPUCores:      64,
		HostMemoryTotalMB: 262144,
		HostDiskTotalGB:   4096,
		CPUBudget:         64,
		MemoryBudgetMB:    262144,
		DiskBudgetGB:      4096,
		AvailableCPU:      64,
		AvailableMemoryMB: 262144,
		AvailableDiskGB:   4096,
		CanAdmit:          true,
	}
}
