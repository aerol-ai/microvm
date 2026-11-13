package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// The operator's metrics, on its /metrics with controller-runtime's own.
// The chart's PrometheusRule (P9) alerts on these names; keep them stable.
var (
	reconcileErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "aerolvm_operator_reconcile_errors_total",
		Help: "Reconciles that ended in an error, by controller.",
	}, []string{"controller"})
	nodeStates = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "aerolvm_operator_nodes",
		Help: "AerolNodes by state and role.",
	}, []string{"state", "role"})
	workerPodsLost = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "aerolvm_operator_worker_pods_lost_total",
		Help: "Worker pods that ended without a decommission: their sandboxes failed over or were lost.",
	})
	decommissionSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "aerolvm_operator_decommission_seconds",
		Help:    "How long a worker's decommission took, start to node removed.",
		Buckets: []float64{60, 300, 600, 900, 1800, 2700, 3600, 7200},
	})
	upgradeStepFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "aerolvm_operator_upgrade_step_failures_total",
		Help: "Upgrade steps the operator could not take (an apply, a rollback, an image swap).",
	})
	joinTokenErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "aerolvm_operator_join_token_errors_total",
		Help: "Join tokens the operator could not mint for a new pod.",
	})
	maintenanceServers = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "aerolvm_operator_maintenance_servers",
		Help: "Servers held in maintenance mode (C22).",
	})
	nodeCertsPending = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "aerolvm_operator_node_certificates_pending",
		Help: "AerolNodes whose certificate waits for the bank's issuer (external-CA mode, C23); they have no pod yet.",
	})
	certRenewalFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "aerolvm_operator_cert_renewal_failures_total",
		Help: "Times the edge certificate was seen not ready after it had been issued (C25).",
	})
)

func init() {
	metrics.Registry.MustRegister(reconcileErrors, nodeStates, workerPodsLost, decommissionSeconds,
		upgradeStepFailures, joinTokenErrors, maintenanceServers, nodeCertsPending, certRenewalFailures)
}
