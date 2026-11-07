package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// slowDestroyRuntime fails the destroy of every "bad-" sandbox: it hangs
// until the caller's deadline, or fails after a delay.
type slowDestroyRuntime struct {
	*recordingRuntime
	hang  bool
	delay time.Duration
	mu    sync.Mutex
	tries map[string]int
}

func (r *slowDestroyRuntime) Destroy(ctx context.Context, sb *models.Sandbox) error {
	r.mu.Lock()
	r.tries[sb.ID]++
	r.mu.Unlock()
	if !strings.HasPrefix(sb.ID, "bad-") {
		return r.recordingRuntime.Destroy(ctx, sb)
	}
	if r.hang {
		<-ctx.Done()
		return ctx.Err()
	}
	time.Sleep(r.delay)
	return errors.New("engine refused the delete")
}

func (r *slowDestroyRuntime) triesOf(id string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tries[id]
}

// TestLifecycleSweepReachesDeletesBehindOnesThatKeepFailing is finding 11's
// note on the older serial sweep: 40 sandboxes past their max age whose
// delete keeps failing, listed ahead of an older one whose delete works.
// Before, each pass tried them newest first until its deadline, so the same
// head used every pass and the older sandbox was never deleted. Now each
// pass starts with the least recently tried, and a delete that failed waits
// a growing number of passes.
func TestLifecycleSweepReachesDeletesBehindOnesThatKeepFailing(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hang      bool
		delay     time.Duration
		pass      time.Duration
		maxPasses int
	}{
		// One try a pass (it hangs until the deadline, which is not
		// counted against it): reached in pass 41, later on a slow
		// machine where a pass ends before its first try.
		{name: "hangs until the pass deadline", hang: true, pass: 40 * time.Millisecond, maxPasses: 80},
		// About three tries a pass, each a counted failure: reached in
		// about pass 15.
		{name: "fails slowly", delay: 15 * time.Millisecond, pass: 50 * time.Millisecond, maxPasses: 80},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			rt := &slowDestroyRuntime{recordingRuntime: &recordingRuntime{}, hang: tc.hang, delay: tc.delay, tries: map[string]int{}}
			svc, st, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
			now := time.Now().UTC()
			seed := func(id string, created time.Time) {
				if err := st.Create(ctx, &models.Sandbox{
					ID: id, Image: "alpine", Runtime: models.RuntimeDocker, Status: models.SandboxStatusStarted,
					ContainerID: id, ContainerIP: "10.0.0.9", CPU: 1, MemoryMB: 256, AuditIncarnationID: "inc-" + id,
					Lifecycle: models.Lifecycle{DestroyAtAge: time.Minute},
					CreatedAt: created, UpdatedAt: now, LastActiveAt: now,
				}); err != nil {
					t.Fatal(err)
				}
			}
			seed("old-good", now.Add(-2*time.Hour))
			for i := 0; i < 40; i++ {
				seed(fmt.Sprintf("bad-%02d", i), now.Add(-time.Hour+time.Duration(i)*time.Second))
			}

			reached := 0
			for pass := 1; pass <= tc.maxPasses; pass++ {
				passCtx, cancel := context.WithTimeout(ctx, tc.pass)
				svc.runLifecycleSweep(passCtx)
				cancel()
				if _, err := st.Get(ctx, "old-good"); err != nil {
					reached = pass
					break
				}
			}
			if reached == 0 {
				t.Fatalf("the older sandbox was not deleted in %d passes", tc.maxPasses)
			}
			if reached == 1 {
				t.Fatal("deleted in the first pass: the failing deletes were not in its way")
			}
			// Every failing delete was tried before it (a try the pass
			// deadline cut short may not have reached the runtime), and
			// none took every pass.
			svc.lifecycleRotation.mu.Lock()
			defer svc.lifecycleRotation.mu.Unlock()
			for i := 0; i < 40; i++ {
				id := fmt.Sprintf("bad-%02d", i)
				rec := svc.lifecycleRotation.records[id]
				if rec == nil || rec.lastTried == 0 {
					t.Fatalf("%s never tried in %d passes", id, reached)
				}
				if n := rt.triesOf(id); n > reached/2+1 {
					t.Fatalf("%s reached the runtime %d times in %d passes", id, n, reached)
				}
			}
		})
	}
}
