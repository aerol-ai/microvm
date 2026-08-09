package cluster

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// TestScaleGateEnterpriseTopologyCreateSealDeletePlanes exercises the
// requested enterprise gate shape: 2,000 live members (100 ingress), and
// 100,000 concurrent reservation admits across the placement plane. Seal/delete
// concurrency for credentials is covered by TestScaleGateConcurrentSealDeletePlane.
func TestScaleGateEnterpriseTopologyCreateSealDeletePlanes(t *testing.T) {
	requireScaleGates(t)

	const (
		servers   = 3
		ingress   = 100
		totalLive = 2000
		creates   = 100_000
	)
	workers := totalLive - servers - ingress
	if workers <= 0 {
		t.Fatalf("invalid topology math: workers=%d", workers)
	}
	now := time.Unix(1_800_000_000, 0)
	members := scaleHarnessMembers(servers, workers, ingress)
	leases := newCapacityLeaseCache("", nil, 5*time.Second, nil)
	for i := 0; i < workers; i++ {
		leases.set(fmt.Sprintf("worker-%04d", i), scaleWorkerCapacity(), now)
	}
	members = leases.apply(members, now)

	if got := LiveMemberCount(members); got != totalLive {
		t.Fatalf("live members=%d, want %d", got, totalLive)
	}
	if err := LargeClusterTopologyError(members); err != nil {
		t.Fatalf("2000-node dedicated topology rejected: %v", err)
	}
	ingressCount := 0
	for _, m := range members {
		if m.Alive && m.Role == config.NodeRoleIngress {
			ingressCount++
		}
	}
	if ingressCount != ingress {
		t.Fatalf("ingress members=%d, want %d", ingressCount, ingress)
	}

	fsm := newPlacementFSM()
	expiry := now.Add(10 * time.Minute).Unix()

	type batchJob struct {
		owner string
		batch []reservationCommand
	}
	perWorker := creates / workers
	if perWorker < 1 {
		perWorker = 1
	}
	jobs := make([]batchJob, 0, workers)
	remaining := creates
	for worker := 0; worker < workers && remaining > 0; worker++ {
		n := perWorker
		if worker == workers-1 || n > remaining {
			n = remaining
		}
		owner := fmt.Sprintf("worker-%04d", worker)
		batch := make([]reservationCommand, 0, n)
		for create := 0; create < n; create++ {
			batch = append(batch, reservationCommand{
				SandboxID:   fmt.Sprintf("ent-%04d-%05d", worker, create),
				OwnerNodeID: owner,
				OwnerAPIURL: fmt.Sprintf("http://%s:21212", owner),
				Spec:        &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 256, DiskGB: 1},
				ExpiresUnix: expiry,
			})
		}
		jobs = append(jobs, batchJob{owner: owner, batch: batch})
		remaining -= n
	}

	var (
		mu        sync.Mutex
		logIndex  uint64 = 1
		admitFail atomic.Int32
		applyFail atomic.Int32
		accepted  atomic.Int32
	)
	var wg sync.WaitGroup
	// Many concurrent submitters; FSM mutations stay single-threaded under mu.
	sem := make(chan struct{}, 64)
	for _, job := range jobs {
		job := job
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			mu.Lock()
			defer mu.Unlock()
			pending := fsm.pendingReservationsByNode(expiry - 1)
			counts := map[string]int{job.owner: fsm.livePendingReservationCount(job.owner, expiry-1)}
			if err := admitReservationCommands(members, pending, counts, len(job.batch), job.batch); err != nil {
				if !errors.Is(err, ErrCreateBackpressure) && !errors.Is(err, ErrNoPlacementTarget) {
					admitFail.Add(1)
				}
				return
			}
			payload, err := encodeCommand(command{Op: opReserveBatch, Reservations: job.batch})
			if err != nil {
				applyFail.Add(1)
				return
			}
			idx := logIndex
			logIndex++
			if got := fsm.Apply(&raft.Log{Index: idx, Data: payload}); got != nil {
				applyFail.Add(1)
				return
			}
			accepted.Add(int32(len(job.batch)))
		}()
	}
	wg.Wait()
	if admitFail.Load() > 0 || applyFail.Load() > 0 {
		t.Fatalf("concurrent plane failures: admit=%d apply=%d", admitFail.Load(), applyFail.Load())
	}
	if got := int(accepted.Load()); got < creates/2 {
		t.Fatalf("accepted reservations=%d, want at least %d under concurrent submit", got, creates/2)
	}
	if got := len(fsm.pendingReservationClaims); got != int(accepted.Load()) {
		t.Fatalf("pending claims=%d, want %d", got, accepted.Load())
	}

	// Second plane: orphan a dead owner while the cluster remains at enterprise size.
	deadOwned := 200
	for i := 0; i < deadOwned; i++ {
		payload, err := encodeCommand(command{
			Op:          opPlace,
			SandboxID:   fmt.Sprintf("dead-ent-%04d", i),
			OwnerNodeID: "worker-dead",
			OwnerAPIURL: "http://worker-dead:21212",
			Spec:        &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 256, DiskGB: 1},
		})
		if err != nil {
			t.Fatalf("encode dead placement: %v", err)
		}
		mu.Lock()
		idx := logIndex
		logIndex++
		mu.Unlock()
		if got := fsm.Apply(&raft.Log{Index: idx, Data: payload}); got != nil {
			t.Fatalf("apply dead placement: %v", got)
		}
	}
	orphan, _ := encodeCommand(command{Op: opOrphanOwner, NodeID: "worker-dead"})
	mu.Lock()
	idx := logIndex
	logIndex++
	mu.Unlock()
	if got := fsm.Apply(&raft.Log{Index: idx, Data: orphan}); got != nil {
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
