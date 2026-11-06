// Command aerolvm-bench measures how fast an AerolVM server creates
// sandboxes: creates per second, and how long each create takes at p50, p90
// and p99 (plans/agent-sandbox-feature-parity.md, O3).
//
// It drives the public API through the Go SDK, so it measures what a client
// sees, against any AerolVM URL and token. Workers create sandboxes in a
// closed loop for -duration; each sandbox is deleted in the background as
// soon as it exists (or all at the end with -hold). Every sandbox it makes
// is named and tagged with the run's id, deleted before the tool exits,
// interrupted or not, and set to delete itself after -max-age in case the
// tool is killed outright.
//
//	go run ./cmd/aerolvm-bench -api https://api.example.com -concurrency 8 -duration 60s
//
// The token comes from -token, SB_PAT_TOKEN or SB_API_TOKEN, the URL from
// -api or SB_API_URL. -json prints the report as JSON. -cleanup <run id>
// deletes whatever an earlier run left behind.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	signals := make(chan os.Signal, 3)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, signals, newSDKAPI))
}

// Exit codes.
const (
	exitOK = 0
	// exitFailed: no create succeeded, or sandboxes were left behind (or
	// the final check could not tell).
	exitFailed = 1
	exitUsage  = 2
	// exitAbandoned: a third interrupt stopped the tool before its cleanup
	// finished.
	exitAbandoned = 130
)

// run is main without the process: it parses args, runs the benchmark (or
// a cleanup) against the API newAPI builds, and returns the exit code.
func run(args []string, stdout, stderr io.Writer, signals <-chan os.Signal, newAPI func(apiURL, token string) (sandboxAPI, error)) int {
	cfg, err := parseFlags(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(stderr, "aerolvm-bench:", err)
		return exitUsage
	}
	api, err := newAPI(cfg.apiURL, cfg.token)
	if err != nil {
		fmt.Fprintln(stderr, "aerolvm-bench:", err)
		return exitUsage
	}
	if cfg.cleanupRun != "" {
		return runCleanup(api, cfg.cleanupRun, stdout, stderr)
	}

	// The first interrupt stops new creates and waits for those in flight,
	// so each one's sandbox is known and deleted. The second stops waiting:
	// cleanup deletes what the API has by the run's tag. The third leaves
	// at once; -max-age deletes what is left.
	stopCtx, stop := context.WithTimeout(context.Background(), cfg.duration)
	defer stop()
	abortCtx, abort := context.WithCancel(context.Background())
	defer abort()
	abandoned := make(chan struct{})
	b := newBench(api, cfg, stderr)
	go func() {
		for n := 1; ; n++ {
			if _, ok := <-signals; !ok {
				return
			}
			switch n {
			case 1:
				b.interrupted.Store(true)
				fmt.Fprintln(stderr, "aerolvm-bench: stopping; waiting for creates in flight, then deleting every sandbox this run made (interrupt again to stop waiting)")
				stop()
			case 2:
				fmt.Fprintln(stderr, "aerolvm-bench: no longer waiting for creates in flight; deleting what the API holds for this run (interrupt again to leave now)")
				abort()
			default:
				close(abandoned)
				return
			}
		}
	}()

	done := make(chan *report, 1)
	go func() { done <- b.run(stopCtx, abortCtx) }()
	select {
	case rep := <-done:
		if err := rep.write(stdout, cfg.json); err != nil {
			fmt.Fprintln(stderr, "aerolvm-bench:", err)
		}
		return rep.exitCode()
	case <-abandoned:
		fmt.Fprintf(stderr, "aerolvm-bench: left before cleanup finished; sandboxes tagged %s=%s may remain until -max-age (%s) deletes them, or run: aerolvm-bench -cleanup %s\n",
			runTagKey, b.runID, cfg.maxAge, b.runID)
		return exitAbandoned
	}
}

// runCleanup deletes every sandbox tagged with runID.
func runCleanup(api sandboxAPI, runID string, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	deleted, left, err := sweepRun(ctx, api, runID, defaultCleanupWorkers, nil)
	if err != nil {
		fmt.Fprintln(stderr, "aerolvm-bench:", err)
		return exitFailed
	}
	fmt.Fprintf(stdout, "deleted %d sandboxes of run %s; %d left\n", deleted, runID, left)
	if left > 0 {
		return exitFailed
	}
	return exitOK
}

// cleanupTimeout bounds the end-of-run cleanup: deletes, the sweep by tag
// and the final check.
var cleanupTimeout = 10 * time.Minute

const defaultCleanupWorkers = 8
