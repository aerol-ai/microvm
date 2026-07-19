package harness

import (
	"fmt"
	"strings"
)

// Runtime labels match plans/benchmark-usecase-catalogue.md legend.
type Runtime string

const (
	RTContainerd  Runtime = "containerd"
	RTGvisor      Runtime = "gvisor"
	RTWasm        Runtime = "wasm"
	RTIsolate     Runtime = "isolate"
	RTFirecracker Runtime = "firecracker"
	RTAll         Runtime = "all"
)

// Scenario tags from the catalogue doc.
type ScenarioTag string

const (
	ScnMixed  ScenarioTag = "M"
	ScnHetero ScenarioTag = "H"
	ScnBoth   ScenarioTag = "M+H"
)

// CatalogueRow is one investor question from benchmark-usecase-catalogue.md.
// UCRef rows store only Question/Category/UCRef; runtime and signal may be
// derived from harness.Registry at report time (CQ-2).
type CatalogueRow struct {
	ID          string
	Question    string
	Category    string
	Subcategory string
	Runtimes    []Runtime
	Scenarios   []ScenarioTag
	UCRef       string
	SignalDesc  string
}

// AllRuntimes is the five sandbox runtimes for "all" rows.
var AllRuntimes = []Runtime{RTContainerd, RTGvisor, RTWasm, RTIsolate, RTFirecracker}

// CatalogueRegistry is the 287-row master list (range IDs expanded).
var CatalogueRegistry = buildCatalogueRegistry()

// ExpandedEntries expands runtime crossings for JSON/gen output.
func ExpandedEntries(rows []CatalogueRow) []ExpandedCatalogueEntry {
	out := make([]ExpandedCatalogueEntry, 0, len(rows)*2)
	for _, row := range rows {
		rts := row.Runtimes
		if len(rts) == 0 {
			out = append(out, row.expandOne(""))
			continue
		}
		if len(rts) == 1 && rts[0] == RTAll {
			for _, rt := range AllRuntimes {
				out = append(out, row.expandOne(string(rt)))
			}
			continue
		}
		for _, rt := range rts {
			out = append(out, row.expandOne(string(rt)))
		}
	}
	return out
}

// ExpandedCatalogueEntry is a runtime-resolved catalogue row for artifacts.
type ExpandedCatalogueEntry struct {
	ID          string
	Question    string
	Category    string
	Subcategory string
	Runtime     string
	Scenarios   []ScenarioTag
	UCRef       string
	SignalDesc  string
}

func (row CatalogueRow) expandOne(runtime string) ExpandedCatalogueEntry {
	q, sig := row.Question, row.SignalDesc
	if row.UCRef != "" {
		if uc, ok := Lookup(row.UCRef); ok {
			if sig == "" {
				sig = uc.Title
			}
		}
	}
	return ExpandedCatalogueEntry{
		ID:          row.ID,
		Question:    q,
		Category:    row.Category,
		Subcategory: row.Subcategory,
		Runtime:     runtime,
		Scenarios:   row.Scenarios,
		UCRef:       row.UCRef,
		SignalDesc:  sig,
	}
}

func buildCatalogueRegistry() []CatalogueRow {
	var rows []CatalogueRow
	rows = append(rows, provRows()...)
	rows = append(rows, lifeRows()...)
	rows = append(rows, rtRows()...)
	rows = append(rows, execRows()...)
	rows = append(rows, fileRows()...)
	rows = append(rows, sessRows()...)
	rows = append(rows, netRows()...)
	rows = append(rows, egrRows()...)
	rows = append(rows, isoRows()...)
	rows = append(rows, snapRows()...)
	rows = append(rows, svcRows()...)
	rows = append(rows, compRows()...)
	rows = append(rows, aiRows()...)
	rows = append(rows, mntRows()...)
	rows = append(rows, haRows()...)
	rows = append(rows, denRows()...)
	rows = append(rows, latRows()...)
	rows = append(rows, slessRows()...)
	rows = append(rows, sshRows()...)
	rows = append(rows, tmplRows()...)
	rows = append(rows, facRows()...)
	rows = append(rows, regRows()...)
	rows = append(rows, gpuRows()...)
	rows = append(rows, obsRows()...)
	rows = append(rows, idemRows()...)
	return rows
}

func catProv() string  { return "Provisioning & control plane" }
func catLife() string  { return "Sandbox lifecycle" }
func catRT() string    { return "Runtime specialization" }
func catExec() string  { return "Exec & code execution" }
func catFile() string  { return "Files & filesystem" }
func catSess() string  { return "Sessions & PTY" }
func catNet() string   { return "Networking & ingress" }
func catEgr() string   { return "Egress & network policy" }
func catISO() string   { return "Isolation & untrusted code" }
func catSnap() string  { return "Snapshots & fast boot" }
func catSVC() string   { return "Real long-running services" }
func catComp() string  { return "Heavy compute & data" }
func catAI() string    { return "AI agents" }
func catMNT() string   { return "Mounts & external storage" }
func catHA() string    { return "Cluster correctness & HA" }
func catDEN() string   { return "Capacity & density" }
func catLAT() string   { return "Latency benchmarks" }
func catSLESS() string { return "Serverless & lifecycle automation" }
func catSSH() string   { return "SSH gateway" }
func catTMPL() string  { return "Templates & images" }
func catFAC() string   { return "Facade compatibility (Daytona/E2B)" }
func catREG() string   { return "Multi-region & multi-arch" }
func catGPU() string   { return "GPU" }
func catOBS() string   { return "Observability" }
func catIDEM() string  { return "Idempotency & resilience" }

func row(id, q, cat, sub, sig string, scn ScenarioTag, rt Runtime, uc string) CatalogueRow {
	return CatalogueRow{
		ID: id, Question: q, Category: cat, Subcategory: sub, SignalDesc: sig,
		Scenarios: []ScenarioTag{scn}, Runtimes: []Runtime{rt}, UCRef: uc,
	}
}

func rowNA(id, q, cat, sub, sig string, scn ScenarioTag, uc string) CatalogueRow {
	return CatalogueRow{
		ID: id, Question: q, Category: cat, Subcategory: sub, SignalDesc: sig,
		Scenarios: []ScenarioTag{scn}, UCRef: uc,
	}
}

func rowMultiRT(id, q, cat, sub, sig string, scn ScenarioTag, rts []Runtime, uc string) CatalogueRow {
	return CatalogueRow{
		ID: id, Question: q, Category: cat, Subcategory: sub, SignalDesc: sig,
		Scenarios: []ScenarioTag{scn}, Runtimes: rts, UCRef: uc,
	}
}

func expandRT(prefix string, from, to int, q, cat, sub, sig string, scn ScenarioTag, rts []Runtime, ucs []string) []CatalogueRow {
	if len(rts) != to-from+1 {
		panic(fmt.Sprintf("expandRT %s: %d runtimes for %d ids", prefix, len(rts), to-from+1))
	}
	out := make([]CatalogueRow, 0, to-from+1)
	for i := 0; i <= to-from; i++ {
		id := fmt.Sprintf("%s-%02d", prefix, from+i)
		uc := ""
		if i < len(ucs) {
			uc = ucs[i]
		}
		out = append(out, row(id, q, cat, sub, sig, scn, rts[i], uc))
	}
	return out
}

func scnBoth() ScenarioTag   { return ScnBoth }
func scnMixed() ScenarioTag  { return ScnMixed }
func scnHetero() ScenarioTag { return ScnHetero }

func joinScn(tags ...ScenarioTag) []ScenarioTag { return tags }

func rowAll(id, q, cat, sub, sig string, scn ScenarioTag, uc string) CatalogueRow {
	return CatalogueRow{
		ID: id, Question: q, Category: cat, Subcategory: sub, SignalDesc: sig,
		Scenarios: []ScenarioTag{scn}, Runtimes: []Runtime{RTAll}, UCRef: uc,
	}
}

// SimIDForCatalogue maps catalogue IDs to simulation package IDs when a live
// sim exists (priority subset); empty means registry-only / stub.
func SimIDForCatalogue(catalogueID string) string {
	if id, ok := catalogueSimMap[catalogueID]; ok {
		return id
	}
	return ""
}

var catalogueSimMap = map[string]string{
	"SVC-01": "postgres-supabase", "SVC-02": "postgres-supabase", "SVC-03": "postgres-supabase",
	"SVC-04": "redis-upstash", "SVC-05": "redis-upstash",
	"SVC-06":  "temporal-workflow",
	"SVC-10":  "jupyter-headless",
	"COMP-01": "hyperparam-farm",
	"COMP-05": "code-interpreter",
	"ISO-01":  "gvisor-kernel-probe", "ISO-02": "gvisor-kernel-probe",
	"ISO-06":   "burner-browser",
	"EGR-08":   "isolate-egress-ext",
	"AI-01":    "claude-code-arch",
	"SLESS-01": "serverless-wake",
}

// CatalogueCategoryOrder returns stable category ordering for reports.
func CatalogueCategoryOrder() []string {
	return []string{
		catProv(), catLife(), catRT(), catExec(), catFile(), catSess(), catNet(), catEgr(),
		catISO(), catSnap(), catSVC(), catComp(), catAI(), catMNT(), catHA(), catDEN(),
		catLAT(), catSLESS(), catSSH(), catTMPL(), catFAC(), catREG(), catGPU(), catOBS(), catIDEM(),
	}
}

// FormatScenarios renders scenario tags for markdown tables.
func FormatScenarios(tags []ScenarioTag) string {
	parts := make([]string, len(tags))
	for i, t := range tags {
		parts[i] = string(t)
	}
	return strings.Join(parts, ",")
}
