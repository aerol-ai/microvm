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

// slowDestroyRuntime fails the destroy of every "bad-" sandbox. In each pass
// the first failsPerPass of them fail, each a counted failure. The next one
// is the try the pass's deadline catches: it ends the pass and hangs until
// the pass's context is done, which the sweep does not count against it.
//
// The runtime ends each pass, not a wall clock. With a fixed 40ms pass, a
// loaded CI runner under -race sometimes used the whole budget before the
// older sandbox's own delete (several SQLite writes) finished. The sweep is
// right to rotate a try its deadline cut short to the back, so that one
// waited 40 more passes and the test failed at 80. How many tries fit in a
// pass is the scenario; how fast the machine is must not change it.
type slowDestroyRuntime struct {
	*recordingRuntime
	failsPerPass int

	mu      sync.Mutex
	tries   map[string]int
	failed  int                // counted failures in this pass
	endPass context.CancelFunc // ends this pass
}

// startPass arms the runtime for a pass that end ends.
func (r *slowDestroyRuntime) startPass(end context.CancelFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed, r.endPass = 0, end
}

func (r *slowDestroyRuntime) Destroy(ctx context.Context, sb *models.Sandbox) error {
	r.mu.Lock()
	r.tries[sb.ID]++
	if !strings.HasPrefix(sb.ID, "bad-") {
		r.mu.Unlock()
		return r.recordingRuntime.Destroy(ctx, sb)
	}
	if r.failed < r.failsPerPass {
		r.failed++
		r.mu.Unlock()
		return errors.New("engine refused the delete")
	}
	end := r.endPass
	r.mu.Unlock()
	end()
	<-ctx.Done()
	return ctx.Err()
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
		name         string
		failsPerPass int
		// maxPasses is the rotation's promise: each record is tried
		// within ceil(records / tries per pass) passes, here 41 records
		// and failsPerPass+1 tries a pass.
		maxPasses int
	}{
		// One try a pass, which hangs until the deadline and is not
		// counted against it: reached in pass 41.
		{name: "hangs until the pass deadline", failsPerPass: 0, maxPasses: 41},
		// Three slow failures fill a pass and a fourth try is cut short:
		// reached in pass 11.
		{name: "fails slowly", failsPerPass: 3, maxPasses: 11},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			rt := &slowDestroyRuntime{recordingRuntime: &recordingRuntime{}, failsPerPass: tc.failsPerPass, tries: map[string]int{}}
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
				// The minute is only a backstop: the runtime ends the pass.
				passCtx, cancel := context.WithTimeout(ctx, time.Minute)
				rt.startPass(cancel)
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
			// Every failing delete was tried before it, and none took
			// every pass.
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
