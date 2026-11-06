package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// deleteTimeout bounds one delete; the SDK retries inside it.
var deleteTimeout = 2 * time.Minute

// failurePause is how long a worker waits after a failed create.
var failurePause = 100 * time.Millisecond

// pause waits d or until ctx ends.
func pause(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

type bench struct {
	api   sandboxAPI
	cfg   config
	runID string
	log   io.Writer

	interrupted atomic.Bool
	seq         atomic.Int64

	mu         sync.Mutex
	createLat  []time.Duration
	deleteLat  []time.Duration
	failed     map[string]int
	example    map[string]string
	notStarted int
	abandoned  int
	// unsure counts creates whose answer never came (timed out or
	// abandoned): the server may finish one after the final check.
	unsure       int
	deleteFailed int
	// live holds the sandboxes made and not deleted yet.
	live    map[string]bool
	lastEnd time.Time
}

func newBench(api sandboxAPI, cfg config, log io.Writer) *bench {
	return &bench{api: api, cfg: cfg, runID: cfg.runID, log: log,
		failed: map[string]int{}, example: map[string]string{}, live: map[string]bool{}}
}

// run creates sandboxes until stopCtx ends, then deletes every one it
// made. abortCtx ending stops waiting for creates in flight.
func (b *bench) run(stopCtx, abortCtx context.Context) *report {
	start := time.Now()
	fmt.Fprintf(b.log, "aerolvm-bench: run %s, %d workers for %s; sandboxes are named %s<n> and tagged %s=%s\n",
		b.runID, b.cfg.concurrency, b.cfg.duration, sandboxNamePrefix(b.runID), runTagKey, b.runID)

	// Deleting as the run goes keeps the number of live sandboxes near
	// the concurrency, so a long run measures creates and not how many
	// sandboxes the server can hold. A full queue holds the workers back:
	// creating faster than the server deletes is not a rate it can keep.
	deletes := make(chan string, 4*b.cfg.concurrency)
	var deleters sync.WaitGroup
	if !b.cfg.hold {
		for i := 0; i < b.cfg.concurrency; i++ {
			deleters.Add(1)
			go func() {
				defer deleters.Done()
				for id := range deletes {
					_ = b.destroy(id)
				}
			}()
		}
	}

	var workers sync.WaitGroup
	for i := 0; i < b.cfg.concurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for stopCtx.Err() == nil && abortCtx.Err() == nil {
				id, ok := b.createOne(abortCtx)
				if !ok {
					// A server that is down or saying "busy" answers
					// at once; without a pause each worker would send
					// thousands of creates a second at it.
					pause(stopCtx, failurePause)
					continue
				}
				if b.cfg.hold {
					continue
				}
				select {
				case deletes <- id:
				case <-abortCtx.Done():
					// Left in live for the cleanup below.
				}
			}
		}()
	}
	workers.Wait()
	close(deletes)
	deleters.Wait()

	b.mu.Lock()
	end := b.lastEnd
	b.mu.Unlock()
	if end.IsZero() {
		end = time.Now()
	}
	left := b.cleanup()
	return b.report(end.Sub(start), left)
}

func (b *bench) createOne(abortCtx context.Context) (string, bool) {
	name := fmt.Sprintf("%s%d", sandboxNamePrefix(b.runID), b.seq.Add(1))
	opts := sdktypes.CreateSandboxOptions{
		Name:       name,
		Image:      b.cfg.image,
		Runtime:    b.cfg.runtime,
		TemplateID: b.cfg.template,
		Tags:       map[string]string{runTagKey: b.runID},
	}
	if b.cfg.maxAge > 0 {
		opts.Lifecycle = &models.Lifecycle{DestroyAtAge: b.cfg.maxAge}
	}
	ctx, cancel := context.WithTimeout(abortCtx, b.cfg.createTimeout)
	defer cancel()
	t0 := time.Now()
	sb, err := b.api.Create(ctx, opts)
	took := time.Since(t0)

	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case err != nil && abortCtx.Err() != nil:
		// Stopped waiting on purpose: not the server's failure.
		b.abandoned++
		b.unsure++
		return "", false
	case err != nil:
		kind := errorKind(err)
		b.failed[kind]++
		if _, ok := b.example[kind]; !ok {
			b.example[kind] = err.Error()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			b.unsure++
		}
		b.lastEnd = time.Now()
		return "", false
	}
	b.createLat = append(b.createLat, took)
	if sb.Status != string(models.SandboxStatusStarted) {
		b.notStarted++
	}
	b.live[sb.ID] = true
	b.lastEnd = time.Now()
	return sb.ID, true
}

// destroy deletes one sandbox and reports whether it is gone.
func (b *bench) destroy(id string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), deleteTimeout)
	defer cancel()
	t0 := time.Now()
	err := b.api.Destroy(ctx, id)
	took := time.Since(t0)
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		// Kept in live: the cleanup tries it again.
		b.deleteFailed++
		return false
	}
	b.deleteLat = append(b.deleteLat, took)
	delete(b.live, id)
	return true
}

// cleanup deletes what is still live, then every sandbox the API holds
// with the run's tag (a create whose answer was lost made one too), and
// returns how many are left: -1 when the API could not say.
func (b *bench) cleanup() int {
	b.mu.Lock()
	ids := make([]string, 0, len(b.live))
	for id := range b.live {
		ids = append(ids, id)
	}
	b.mu.Unlock()
	if len(ids) > 0 {
		fmt.Fprintf(b.log, "aerolvm-bench: deleting %d sandboxes\n", len(ids))
	}
	forEach(ids, cleanupWorkers(b.cfg.concurrency), func(id string) { _ = b.destroy(id) })

	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	_, left, err := sweepRun(ctx, b.api, b.runID, cleanupWorkers(b.cfg.concurrency), b.destroy)
	if err != nil {
		fmt.Fprintf(b.log, "aerolvm-bench: could not check for sandboxes left behind: %v; run: aerolvm-bench -cleanup %s\n", err, b.runID)
		return -1
	}
	return left
}

func cleanupWorkers(concurrency int) int {
	if concurrency < defaultCleanupWorkers {
		return defaultCleanupWorkers
	}
	return concurrency
}

// sweepRun deletes every sandbox the API lists for runID, through destroy
// (api.Destroy when nil), then lists again and returns how many it deleted
// and how many are left.
func sweepRun(ctx context.Context, api sandboxAPI, runID string, workers int, destroy func(string) bool) (deleted, left int, err error) {
	ids, err := api.ListRun(ctx, runID)
	if err != nil {
		return 0, 0, err
	}
	if destroy == nil {
		destroy = func(id string) bool {
			dctx, cancel := context.WithTimeout(ctx, deleteTimeout)
			defer cancel()
			return api.Destroy(dctx, id) == nil
		}
	}
	var gone atomic.Int64
	forEach(ids, workers, func(id string) {
		if destroy(id) {
			gone.Add(1)
		}
	})
	rest, err := api.ListRun(ctx, runID)
	if err != nil {
		return int(gone.Load()), 0, err
	}
	return int(gone.Load()), len(rest), nil
}

// forEach runs fn on every id, at most workers at once.
func forEach(ids []string, workers int, fn func(string)) {
	work := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < workers && i < len(ids); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range work {
				fn(id)
			}
		}()
	}
	for _, id := range ids {
		work <- id
	}
	close(work)
	wg.Wait()
}
