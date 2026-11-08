package netns

import "expvar"

// The containerd native netns pool's counters. The aerolvm_ prefix is what
// the observability exporter publishes into /v1/metrics. The docker engine's
// pause-container pool has its own aerolvm_docker_netns_pool_* family; these
// count only this pool.
//
// Hits and misses count every claim: a create's and a warm-pool park's.
// Both take a slot from the same queue, so both decide whether the refiller
// keeps up.
var (
	metricHits           = expvar.NewInt("aerolvm_containerd_netns_pool_hits_total")
	metricMisses         = expvar.NewInt("aerolvm_containerd_netns_pool_misses_total")
	metricRefills        = expvar.NewInt("aerolvm_containerd_netns_pool_refills_total")
	metricRefillFailures = expvar.NewInt("aerolvm_containerd_netns_pool_refill_failures_total")
)
