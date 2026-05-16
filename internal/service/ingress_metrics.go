package service

import (
	"context"
	"expvar"
	"hash/fnv"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// clusterIngressMaxConcurrentWrites caps in-flight Caddy admin calls per
// reconcile tick. Caddy's admin API is single-process; pushing too many
// concurrent writes through it adds queueing latency without actually
// shortening the wall clock. 8 keeps a 10K-route tick saturating the admin
// HTTP pipeline without overrunning it.
const clusterIngressMaxConcurrentWrites = 8

// runIngressOps fans `ops` out across at most `concurrency` worker goroutines
// and returns the first error any op produced. Cancellation is propagated
// via ctx; remaining queued ops short-circuit once an error is recorded so
// we don't pile up admin calls behind a known-failing reconcile.
func runIngressOps(ctx context.Context, ops []func(context.Context) error, concurrency int) error {
	if len(ops) == 0 {
		return nil
	}
	if concurrency < 1 {
		concurrency = 1
	}

	work := make(chan func(context.Context) error)
	var (
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)
	worker := func() {
		defer wg.Done()
		for op := range work {
			// Bail out early if a previous op already errored — saves us
			// from posting 9999 admin calls behind a connection failure.
			mu.Lock()
			haveErr := firstErr != nil
			mu.Unlock()
			if haveErr {
				continue
			}
			if err := op(ctx); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}
	}
	if concurrency > len(ops) {
		concurrency = len(ops)
	}
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go worker()
	}
	for _, op := range ops {
		select {
		case <-ctx.Done():
			close(work)
			wg.Wait()
			return ctx.Err()
		case work <- op:
		}
	}
	close(work)
	wg.Wait()
	return firstErr
}

// expvar names exposed at /debug/vars by the standard library. Stage-2 §06
// (release gates) calls out route-lag, Caddy admin latency, and route counts
// as the SLO targets — these are the cheapest place to land them without
// dragging in a metrics library.
var (
	ingressRoutesTotal      = expvar.NewInt("aerolvm_ingress_routes_total")
	ingressRoutesHTTP       = expvar.NewInt("aerolvm_ingress_routes_http")
	ingressRoutesTLS        = expvar.NewInt("aerolvm_ingress_routes_tls")
	ingressRoutesTCP        = expvar.NewInt("aerolvm_ingress_routes_tcp")
	ingressReconcileTotal   = expvar.NewInt("aerolvm_ingress_reconcile_total")
	ingressReconcileSkipped = expvar.NewInt("aerolvm_ingress_reconcile_skipped_total")
	ingressReconcileErrors  = expvar.NewInt("aerolvm_ingress_reconcile_errors_total")
	// ingressReconcileNanos is the wall-clock duration of the most recent
	// reconcile pass. Exposed as a single value rather than a histogram
	// because we don't have a histogram dependency here; operators can pipe
	// /debug/vars into prom-exporter-for-expvar if they want percentiles.
	ingressReconcileNanos = expvar.NewInt("aerolvm_ingress_reconcile_last_nanos")
	// ingressPlacementVersionMax tracks the highest placement.Version the
	// reconciler has installed routes for. The gap between this and the
	// FSM's current max version is the route-lag signal stage-2 §06 asks
	// for; an operator can scrape both and subtract.
	ingressPlacementVersionMax = expvar.NewInt("aerolvm_ingress_placement_version_max")
	// ingressRouteLagVersions is route-lag pre-computed for operators who
	// don't want to subtract two gauges in their dashboard. Updated on every
	// reconcile pass as max(0, FSM.PlacementVersion - last reconciled max).
	// Lag of N means N placement-mutating raft applies have not yet been
	// reflected in this node's ingress routes. Persistent non-zero lag means
	// the reconciler is falling behind raft.
	ingressRouteLagVersions = expvar.NewInt("aerolvm_ingress_route_lag_versions")
	// ingressRouteMissesTotal increments when a cross-node API forward can't
	// find a usable peer endpoint for the placement (no InternalURL AND no
	// APIURL — the peer is announced but has no advertised forwarding URL
	// yet, or the placement view is mid-rollover). A persistently growing
	// counter under steady-state traffic means gossip→placement convergence
	// is lagging or a peer is misconfigured. Distinct from
	// reconcile_errors_total: those count Caddy admin failures, not
	// API-routing failures.
	ingressRouteMissesTotal = expvar.NewInt("aerolvm_ingress_route_misses_total")
)

// RecordRouteMiss bumps the route-miss counter from the API layer. Exported so
// pkg/api/v1 can wire it in without exposing the expvar directly (keeps the
// metric name owned by this package). Service has no logical role here — this
// is a package-level counter the v1 wrap layer pokes when it observes the
// no-usable-URL case.
func RecordRouteMiss() {
	ingressRouteMissesTotal.Add(1)
}

// SetIngressRouteLag is the post-tick hook the reconciler calls with the
// FSM's current PlacementVersion. Lag is computed as
// max(0, fsmVersion - ingressPlacementVersionMax). Computed here (not at
// recordIngressReconcile) so callers that only have the FSM version can
// still publish the lag without needing the reconciler's maxVersion.
func SetIngressRouteLag(fsmVersion uint64) {
	installed := ingressPlacementVersionMax.Value()
	if fsmVersion == 0 || int64(fsmVersion) <= installed {
		ingressRouteLagVersions.Set(0)
		return
	}
	ingressRouteLagVersions.Set(int64(fsmVersion) - installed)
}

// recordIngressReconcile updates the expvar gauges after a reconcile pass.
// Called from ReconcileClusterIngress whether the pass succeeded, failed, or
// was idle-skipped — the gauges decompose the three outcomes.
func recordIngressReconcile(outcome reconcileOutcome, elapsed time.Duration, counts ingressRouteCounts, maxVersion uint64) {
	ingressReconcileTotal.Add(1)
	switch outcome {
	case reconcileSkipped:
		ingressReconcileSkipped.Add(1)
	case reconcileErrored:
		ingressReconcileErrors.Add(1)
	}
	ingressReconcileNanos.Set(elapsed.Nanoseconds())
	ingressRoutesHTTP.Set(int64(counts.http))
	ingressRoutesTLS.Set(int64(counts.tls))
	ingressRoutesTCP.Set(int64(counts.tcp))
	ingressRoutesTotal.Set(int64(counts.http + counts.tls + counts.tcp))
	if maxVersion > 0 && int64(maxVersion) > ingressPlacementVersionMax.Value() {
		ingressPlacementVersionMax.Set(int64(maxVersion))
	}
}

type reconcileOutcome int

const (
	reconcileApplied reconcileOutcome = iota
	reconcileSkipped
	reconcileErrored
)

type ingressRouteCounts struct {
	http int
	tls  int
	tcp  int
}

// hashPlacementView produces a stable digest of the placements relevant to
// the cluster-ingress reconciler. Routes the reconciler would skip (no owner,
// owner==self, no advertised data-plane host) are excluded so they don't
// trigger spurious "view changed" reruns. Identical input → identical hash →
// the reconciler skips Caddy admin calls entirely.
func hashPlacementView(self string, placements []cluster.Placement) (uint64, ingressRouteCounts, uint64) {
	h := fnv.New64a()
	var counts ingressRouteCounts
	var maxVersion uint64

	// Sort by sandbox ID so an unrelated map iteration order doesn't flip
	// the hash on every tick.
	ids := make([]string, 0, len(placements))
	idx := make(map[string]cluster.Placement, len(placements))
	for _, p := range placements {
		if p.SandboxID == "" {
			continue
		}
		ids = append(ids, p.SandboxID)
		idx[p.SandboxID] = p
	}
	sort.Strings(ids)

	for _, id := range ids {
		p := idx[id]
		if p.OwnerNodeID == "" || p.OwnerNodeID == self {
			continue
		}
		if p.Version > maxVersion {
			maxVersion = p.Version
		}
		h.Write([]byte(id))
		h.Write([]byte{0})
		h.Write([]byte(p.OwnerNodeID))
		h.Write([]byte{0})
		h.Write([]byte(p.OwnerAPIURL))
		h.Write([]byte{0})
		h.Write([]byte(p.OwnerDataPlaneHost))
		h.Write([]byte{0})
		h.Write([]byte(strconv.FormatUint(p.Version, 10)))
		h.Write([]byte{0})
		// Per-placement route count, also stable-sorted by port number.
		ports := cluster.ExposedPortRoutesForPlacement(p)
		portNums := make([]int, 0, len(ports))
		for port := range ports {
			portNums = append(portNums, port)
		}
		sort.Ints(portNums)
		for _, port := range portNums {
			route := ports[port]
			h.Write([]byte(strconv.Itoa(port)))
			h.Write([]byte{0})
			h.Write([]byte(route.Protocol))
			h.Write([]byte{0})
			h.Write([]byte(strconv.Itoa(route.HostPort)))
			h.Write([]byte{0})
			switch route.Protocol {
			case models.ExposedPortProtocolTLS:
				counts.tls++
			case models.ExposedPortProtocolTCP:
				counts.tcp++
			default:
				counts.http++
			}
		}
		// The sandbox itself contributes one HTTP-or-TLS route depending on
		// whether the deployment uses a domain. We count it generically here
		// so the metric matches the work the reconciler actually does; the
		// reconciler itself decides HTTP vs TLS at apply time.
		counts.http++
	}

	return h.Sum64(), counts, maxVersion
}
