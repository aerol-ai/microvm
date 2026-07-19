//go:build integration

package sims

import (
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// Result is one simulation outcome (recorded per-sim for UC-108).
type Result struct {
	SimID       string
	CatalogueID string
	Question    string
	Category    string
	Subcategory string
	Runtime     string
	Success     bool
	Skipped     bool
	SkipReason  string
	LatencyMS   int64
	PublicURL   string
	Notes       string
}

// Sim is one executable workload simulation.
type Sim struct {
	ID           string
	Title        string
	CatalogueIDs []string
	Runtime      string
	Category     string
	Subcategory  string
	Stub         bool
	Run          func(ctx *RunContext) Result
}

// RunContext carries live test dependencies.
type RunContext struct {
	T        *testing.T
	Scenario *harness.Scenario
	Client   *harness.Client
	Started  time.Time
}

// Registry lists every simulation (real + stub).
var Registry = buildRegistry()

func buildRegistry() []Sim {
	var sims []Sim
	sims = append(sims,
		Sim{ID: "postgres-supabase", Title: "Postgres + TLS expose", CatalogueIDs: []string{"SVC-01", "SVC-02", "SVC-03"}, Runtime: "containerd", Category: "Real long-running services", Subcategory: "Database", Run: runPostgresSupabase},
		Sim{ID: "redis-upstash", Title: "Redis REST/TCP", CatalogueIDs: []string{"SVC-04", "SVC-05"}, Runtime: "containerd", Category: "Real long-running services", Subcategory: "Cache", Run: runRedisUpstash},
		Sim{ID: "temporal-workflow", Title: "5-step durable workflow", CatalogueIDs: []string{"SVC-06"}, Runtime: "containerd", Category: "Real long-running services", Subcategory: "Workflow", Run: runTemporalWorkflowSim},
		Sim{ID: "jupyter-headless", Title: "JupyterLab tokenized URL", CatalogueIDs: []string{"SVC-10"}, Runtime: "containerd", Category: "Real long-running services", Subcategory: "Notebook", Run: runJupyterHeadless},
		Sim{ID: "hyperparam-farm", Title: "3 parallel trainers", CatalogueIDs: []string{"COMP-01"}, Runtime: "containerd", Category: "Heavy compute & data", Subcategory: "ML fan-out", Run: runHyperparamFarm},
		Sim{ID: "code-interpreter", Title: "matplotlib chart artifact", CatalogueIDs: []string{"COMP-05"}, Runtime: "containerd", Category: "Heavy compute & data", Subcategory: "Code-interpreter", Run: runCodeInterpreterCharts},
		Sim{ID: "gvisor-kernel-probe", Title: "gVisor kernel probe", CatalogueIDs: []string{"ISO-01", "ISO-02"}, Runtime: "containerd", Category: "Isolation & untrusted code", Subcategory: "Kernel probe", Run: runGvisorKernelProbe},
		Sim{ID: "burner-browser", Title: "secure burner browser (noVNC)", CatalogueIDs: []string{"ISO-06"}, Runtime: "gvisor", Category: "Isolation & untrusted code", Subcategory: "Remote browser", Run: runBurnerBrowserSim},
		Sim{ID: "isolate-egress-ext", Title: "Isolate egress extension", CatalogueIDs: []string{"EGR-08"}, Runtime: "isolate", Category: "Egress & network policy", Subcategory: "", Run: runIsolateEgressExt},
		Sim{ID: "claude-code-arch", Title: "AI agent arch.md stub", CatalogueIDs: []string{"AI-01"}, Runtime: "containerd", Category: "AI agents", Subcategory: "Repo agent", Run: runClaudeCodeArch},
		Sim{ID: "serverless-wake", Title: "scale-to-zero wake", CatalogueIDs: []string{"SLESS-01"}, Runtime: "containerd", Category: "Serverless & lifecycle automation", Subcategory: "", Run: runServerlessWakeSim},
	)
	sims = append(sims, stubSims()...)
	return sims
}

// RunAll executes every registered sim and returns per-sim results (never rolled up).
func RunAll(ctx *RunContext) []Result {
	out := make([]Result, 0, len(Registry))
	for _, sim := range Registry {
		ctx.Started = time.Now()
		res := sim.Run(ctx)
		if res.SimID == "" {
			res.SimID = sim.ID
		}
		if res.Runtime == "" {
			res.Runtime = sim.Runtime
		}
		if res.Category == "" {
			res.Category = sim.Category
		}
		if res.Subcategory == "" {
			res.Subcategory = sim.Subcategory
		}
		if res.LatencyMS == 0 {
			res.LatencyMS = time.Since(ctx.Started).Milliseconds()
		}
		out = append(out, res)
		_ = PushHeartbeat(res.SimID)
	}
	return out
}
