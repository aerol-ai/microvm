package remotemcp

import (
	"expvar"
	"sync"
	"time"
)

// Exported through CollectAerolVMExpvars and /v1/metrics. The _total suffix
// makes the Prometheus exporter type them as counters, so rate() works;
// nested maps become labels key (tool) and key2 (outcome).
//
//	aerolvm_mcp_tool_calls_total{key=<tool>,key2=<outcome>}
//	aerolvm_mcp_tool_latency_ms_total{key=<tool>}
//	aerolvm_mcp_requests_total{key=<accepted|bad_request|unauthorized|rate_limited|forbidden_origin|forbidden_host>}
var (
	toolCalls   = expvar.NewMap("aerolvm_mcp_tool_calls_total")
	toolLatency = expvar.NewMap("aerolvm_mcp_tool_latency_ms_total")
	requests    = expvar.NewMap("aerolvm_mcp_requests_total")
)

// toolMapMu guards creating a tool's outcome map, so two first calls for
// one tool can't each Set a map and lose the other's count.
var toolMapMu sync.Mutex

func recordToolCall(tool, outcome string, d time.Duration) {
	byTool, ok := toolCalls.Get(tool).(*expvar.Map)
	if !ok {
		toolMapMu.Lock()
		if byTool, ok = toolCalls.Get(tool).(*expvar.Map); !ok {
			byTool = new(expvar.Map)
			toolCalls.Set(tool, byTool)
		}
		toolMapMu.Unlock()
	}
	byTool.Add(outcome, 1)
	toolLatency.Add(tool, d.Milliseconds())
}

func recordRequest(outcome string) { requests.Add(outcome, 1) }
