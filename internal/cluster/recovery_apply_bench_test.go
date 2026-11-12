package cluster

import (
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// BenchmarkFSMApplyRecoveryStore measures E4's premise (plans/
// kubernetes-v2-architecture.md §9.4, L-c): what writing a sandbox's
// recovery file costs the apply loop, which holds the table's write lock
// for every opPlace. "memory" is the in-memory store the cell-ceiling bench
// uses; "file" is the real one (no fsync: it waits for the snapshot). The
// difference per apply is the time the lock is held for the file; raft
// applies on one goroutine, so 1e6/apply-us also bounds applies per second.
//
//	go test -run '^$' -bench BenchmarkFSMApplyRecoveryStore -benchtime 20000x ./internal/cluster/
func BenchmarkFSMApplyRecoveryStore(b *testing.B) {
	for _, kind := range []string{"memory", "file"} {
		b.Run(kind, func(b *testing.B) {
			fsm := newPlacementFSM()
			if kind == "file" {
				store, err := newPlacementRecoveryFileStore(b.TempDir())
				if err != nil {
					b.Fatal(err)
				}
				fsm = newPlacementFSMWithRecoveryStore(store)
			}
			cmds := make([][]byte, b.N)
			for i := range cmds {
				id := fmt.Sprintf("sb-%08d", i)
				cmds[i], _ = encodeCommand(command{
					Op:          opPlace,
					SandboxID:   id,
					OwnerNodeID: fmt.Sprintf("node-%03d", i%32),
					OwnerAPIURL: "http://10.1.0.1:21212",
					// A typical spec: an image, a few env vars, resources.
					Spec: &models.CreateSandboxRequest{Image: "python:3.12-slim", CPU: 1, MemoryMB: 1024,
						Env: map[string]string{"A": "1", "B": "two", "PATH_EXTRA": "/opt/bin"}},
					IncarnationID: "inc-" + id,
				})
			}
			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				if got := fsm.Apply(&raft.Log{Index: uint64(i + 1), Data: cmds[i]}); got != nil {
					b.Fatalf("place %d: %v", i, got)
				}
			}
			b.ReportMetric(float64(time.Since(start).Microseconds())/float64(b.N), "apply-us")
		})
	}
}
