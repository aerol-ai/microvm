package service

// template_metrics.go is the Phase 6 PR-C operator-visibility surface
// for Firecracker templates. Two metric shapes are exposed:
//
//   - Gauges (pending/error/unhealthy) reflect *current* row counts in
//     firecracker_templates. Sampled at the start of each
//     push-reconciler tick and at every health-state transition; not
//     sampled in createFirecrackerSandbox so they don't add a query to
//     the boot path.
//   - Counters (succeeded_total / failed_total / rebuild_*_total) tick
//     once per terminal outcome. Used for rate panels (push throughput,
//     rebuild error rate) and for SLO arithmetic.
//
// Style mirrors pkg/capacity/metrics.go and internal/pool/vmm/metrics.go
// — expvar globals at package init, no constructor. Names use the
// existing aerolvm_<subsystem>_<metric>_<unit> convention.

import "expvar"

var (
	// Gauges — current counts of rows in each notable state. Set, not
	// added; recordTemplatePushGauges and recordTemplateHealthGauges are
	// the only writers.
	templatePushPendingGauge = expvar.NewInt("aerolvm_template_push_pending")
	templatePushErrorGauge   = expvar.NewInt("aerolvm_template_push_error")
	templateUnhealthyGauge   = expvar.NewInt("aerolvm_template_unhealthy")

	// Counters — incremented at terminal transitions in the reconciler,
	// rebuild path, and puller. Rates over these power alert rules:
	//   rate(aerolvm_template_push_failed_total[5m]) > 0
	//   rate(aerolvm_template_rebuild_failed_total[5m]) > 0
	templatePushSucceededTotal    = expvar.NewInt("aerolvm_template_push_succeeded_total")
	templatePushFailedTotal       = expvar.NewInt("aerolvm_template_push_failed_total")
	templateRebuildStartedTotal   = expvar.NewInt("aerolvm_template_rebuild_started_total")
	templateRebuildSucceededTotal = expvar.NewInt("aerolvm_template_rebuild_succeeded_total")
	templateRebuildFailedTotal    = expvar.NewInt("aerolvm_template_rebuild_failed_total")
	templatePullSucceededTotal    = expvar.NewInt("aerolvm_template_pull_succeeded_total")
	templatePullFailedTotal       = expvar.NewInt("aerolvm_template_pull_failed_total")
)

// recordTemplatePushGauges takes the rows the reconciler already
// fetched via ListTemplatesPendingPush and partitions them by push_state
// into the two gauges. The reconciler is the natural sampling point
// because (a) the query already happened, no extra SQL, and (b) the
// cadence (SnapshotPushReconcileInterval, default seconds) matches what
// operators want from a "current pending count" panel.
//
// Pushing-state rows are not surfaced — a `pushing` row is transient by
// definition (a goroutine inside this very tick) and a gauge on it would
// just blip up and down with the fanout semaphore.
func recordTemplatePushGauges(rows []*templatePushGaugeRow) {
	var pending, errored int64
	for _, r := range rows {
		switch r.PushState {
		case "pending":
			pending++
		case "error":
			errored++
		}
	}
	templatePushPendingGauge.Set(pending)
	templatePushErrorGauge.Set(errored)
}

// templatePushGaugeRow is the minimal view of a Template the gauge
// sampler needs. The reconciler passes the rows it already loaded; this
// indirection keeps the metrics package from importing pkg/models just
// for one field (the existing snapshot-push and capacity metrics both
// use the same trick).
type templatePushGaugeRow struct {
	PushState string
}

// recordTemplateUnhealthyGauge stamps the current unhealthy count. The
// startup scanner already has the slice in hand; the rebuild path calls
// us with a delta (-1 on successful rebuild) so the gauge doesn't drift
// between scans.
func recordTemplateUnhealthyGauge(count int64) {
	templateUnhealthyGauge.Set(count)
}

// addTemplateUnhealthyGauge applies a signed delta to the gauge. Used
// by RebuildTemplateSnapshot's success path (-1) and by
// MarkSnapshotCorrupt's first-observer path (+1) so the gauge tracks
// transitions without re-querying SQLite on every state change.
func addTemplateUnhealthyGauge(delta int64) {
	templateUnhealthyGauge.Add(delta)
}
