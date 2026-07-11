package netrules

import "expvar"

// backendSelected reports which RuleBackend this daemon actually constructed
// (exec | netlink | disabled), keyed once at boot. SB_NETRULES_BACKEND is
// otherwise silent config: nothing tells an operator — or the benchmark
// harness — that the value took effect, short of reading boot logs. Exposing
// the selection as an aerolvm_ expvar puts it on /v1/metrics, where the bench
// gates on it (AEROL_BENCH_EXPECT_NETRULES) so latency numbers can't silently
// measure the wrong backend.
var backendSelected = expvar.NewMap("aerolvm_netrules_backend")

func recordBackendSelected(name string) {
	backendSelected.Add(name, 1)
}
