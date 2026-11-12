package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestReplicatedLifecycleCurrent pins when a lifecycle change may skip its
// Raft write: only an age timer moved later by at most a minute, with the
// replicated deadline still at least a minute away. The sandbox is an hour
// old, so StopAtAge 1h30m is a deadline 30 minutes from now.
func TestReplicatedLifecycleCurrent(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	created := now.Add(-time.Hour)
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	stop := func(age time.Duration) models.Lifecycle { return models.Lifecycle{StopAtAge: age} }
	const far = 90 * time.Minute
	year10000 := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		replicated *models.Lifecycle
		next       models.Lifecycle
		createdAt  time.Time
		want       bool
	}{
		{"nothing replicated yet", nil, stop(far), created, false},
		{"create time unknown", &models.Lifecycle{StopAtAge: far}, stop(far + time.Second), time.Time{}, false},
		{"same lifecycle", &models.Lifecycle{StopAtAge: far}, stop(far), created, true},
		{"keep-alive 5s later", &models.Lifecycle{StopAtAge: far}, stop(far + 5*time.Second), created, true},
		{"keep-alive exactly the lag later", &models.Lifecycle{StopAtAge: far}, stop(far + time.Minute), created, true},
		{"keep-alive 61s later", &models.Lifecycle{StopAtAge: far}, stop(far + 61*time.Second), created, false},
		{"deadline moved earlier", &models.Lifecycle{StopAtAge: far}, stop(far - 5*time.Second), created, false},
		{"timer turned on", &models.Lifecycle{}, stop(far), created, false},
		{"timer turned off", &models.Lifecycle{StopAtAge: far}, stop(0), created, false},
		{"replicated deadline 59s away", &models.Lifecycle{StopAtAge: time.Hour + 59*time.Second}, stop(time.Hour + 64*time.Second), created, false},
		{"replicated deadline exactly the lag away", &models.Lifecycle{StopAtAge: time.Hour + time.Minute}, stop(time.Hour + time.Minute + 5*time.Second), created, true},
		{"replicated deadline already passed", &models.Lifecycle{StopAtAge: 30 * time.Minute}, stop(30*time.Minute + 5*time.Second), created, false},
		{"destroy timer keep-alive", &models.Lifecycle{DestroyAtAge: far}, models.Lifecycle{DestroyAtAge: far + 5*time.Second}, created, true},
		{"both age timers kept alive", &models.Lifecycle{StopAtAge: far, DestroyAtAge: 2 * far}, models.Lifecycle{StopAtAge: far + 5*time.Second, DestroyAtAge: 2*far + 5*time.Second}, created, true},
		{"one timer kept alive, the other moved earlier", &models.Lifecycle{StopAtAge: far, DestroyAtAge: 2 * far}, models.Lifecycle{StopAtAge: far + 5*time.Second, DestroyAtAge: far}, created, false},
		{"idle timer changed", &models.Lifecycle{StopAtAge: far}, models.Lifecycle{StopAtAge: far, StopIfIdleFor: time.Minute}, created, false},
		{"destroy_at changed", &models.Lifecycle{StopAtAge: far, DestroyAt: at(time.Hour)}, models.Lifecycle{StopAtAge: far, DestroyAt: at(2 * time.Hour)}, created, false},
		{"destroy_at the same", &models.Lifecycle{StopAtAge: far, DestroyAt: at(time.Hour)}, models.Lifecycle{StopAtAge: far + time.Second, DestroyAt: at(time.Hour)}, created, true},
		{"serverless turned on", &models.Lifecycle{StopAtAge: far}, models.Lifecycle{StopAtAge: far, Serverless: true}, created, false},
		// time.Time cannot encode a year past 9999; such a copy is never "current".
		{"unencodable lifecycle", &models.Lifecycle{StopAtAge: far, DestroyAt: &year10000}, models.Lifecycle{StopAtAge: far, DestroyAt: &year10000}, created, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := replicatedLifecycleCurrent(tc.replicated, tc.next, tc.createdAt, now); got != tc.want {
				t.Fatalf("replicatedLifecycleCurrent = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestLifecycleKeepAliveRaftWrites counts Raft spec writes for a run of
// keep-alives through UpdateLifecycle, each one setting StopAtAge to the
// sandbox's age plus 30 minutes, the way E2B's setTimeout does.
func TestLifecycleKeepAliveRaftWrites(t *testing.T) {
	cases := []struct {
		name       string
		recreate   bool
		replicated *models.Lifecycle // the stub's replicated lifecycle before the calls
		calls      int
		wantWrites int
		wantReads  int // -1: not asserted
	}{
		{"default sandbox", false, nil, 3, 0, 0},
		{"failover sandbox, first keep-alive then two more within the minute", true, nil, 3, 1, -1},
		{"failover sandbox, replicated deadline 2 minutes behind", true, &models.Lifecycle{StopAtAge: 28 * time.Minute}, 1, 1, -1},
		{"failover sandbox, replicated deadline 10s behind", true, &models.Lifecycle{StopAtAge: 30*time.Minute - 10*time.Second}, 1, 0, 1},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			svc, _, st := newCapacityHarness(t, nil, nil)
			stub := &specWriteThroughCluster{
				Noop: cluster.NewNoop("self", "http://self", ""),
				spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 512, DiskGB: 1, Lifecycle: tc.replicated},
			}
			svc.AttachCluster(stub)
			id := fmt.Sprintf("sb-keepalive-%d", i)
			sb := &models.Sandbox{
				ID: id, Image: "alpine", Status: models.SandboxStatusStarted,
				ContainerID: "ctr-" + id, ContainerIP: fmt.Sprintf("10.0.2.%d", i+1),
				CPU: 1, MemoryMB: 512, DiskGB: 1, Runtime: models.RuntimeDocker,
				CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
			}
			if tc.recreate {
				sb.Failover = recreateFailover()
			}
			if err := st.Create(ctx, sb); err != nil {
				t.Fatalf("seed sandbox: %v", err)
			}
			row, err := st.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			for n := 0; n < tc.calls; n++ {
				l := models.Lifecycle{StopAtAge: time.Since(row.CreatedAt) + 30*time.Minute}
				if _, err := svc.UpdateLifecycle(ctx, id, l); err != nil {
					t.Fatalf("keep-alive %d: %v", n+1, err)
				}
			}
			if got := len(stub.calls()); got != tc.wantWrites {
				t.Errorf("Raft spec writes = %d, want %d", got, tc.wantWrites)
			}
			if tc.wantReads >= 0 {
				if got := stub.readCount(); got != tc.wantReads {
					t.Errorf("spec reads (server round trips) = %d, want %d", got, tc.wantReads)
				}
			}
		})
	}
}
