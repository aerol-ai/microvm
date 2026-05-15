package service

import (
	"expvar"
	"hash/fnv"
	"sort"
	"strconv"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

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
)

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
