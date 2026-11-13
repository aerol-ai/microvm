package prometheus_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The Helm chart's monitoring (plans/kubernetes-v2-architecture.md P6, P9):
// the rules in charts/aerolvm/monitoring/rules.yaml, the dashboards in
// charts/aerolvm/dashboards, the runbook setup/runbooks/kubernetes.md, and
// the objects the chart renders from them with monitoring.enabled.
//
// The rule and dashboard checks need no tools. The promtool and helm checks
// skip when the tool is missing, unless AEROLVM_CHART_TOOLS=require (the
// kubernetes CI job sets it, with CI's pinned Helm and promtool).

const k8sRunbookURL = "https://github.com/aerol-ai/microvm/blob/main/setup/runbooks/kubernetes.md#"

// k8sAlerts is every alert the chart ships, with its severity: the §19
// list as far as a metric exists for it (setup/runbooks/kubernetes.md
// names the ones still waiting for theirs).
var k8sAlerts = map[string]string{
	"AerolVMMetricsDown":                  "warning",
	"AerolVMPodNotReady":                  "critical",
	"AerolVMRuntimeContainerRestarted":    "critical",
	"AerolVMPodImagePullStuck":            "warning",
	"AerolVMWorkerPodLost":                "critical",
	"AerolVMDecommissionStuck":            "warning",
	"AerolVMNodePending":                  "warning",
	"AerolVMNodeJoinSlow":                 "warning",
	"AerolVMNodeLost":                     "warning",
	"AerolVMOperatorReconcileErrors":      "warning",
	"AerolVMServerMaintenanceTooLong":     "warning",
	"AerolVMHeadroomLow":                  "warning",
	"AerolVMCreatesRefusedNoRoom":         "critical",
	"AerolVMWorkerDiskHigh":               "warning",
	"AerolVMDecommissionMovesFailing":     "warning",
	"AerolVMCertSignerDenied":             "critical",
	"AerolVMJoinTokenErrors":              "warning",
	"AerolVMNodeCertificateFailing":       "warning",
	"AerolVMRolloutFailed":                "critical",
	"AerolVMRolloutStuck":                 "warning",
	"AerolVMUpgradeStepFailing":           "warning",
	"AerolVMFinalizePending":              "warning",
	"AerolVMUsageExporterStale":           "warning",
	"AerolVMSandboxEgressToClusterRanges": "warning",
}

// operatorMetrics are the operator's (P2) series, registered in its own Go
// module (operator/); TestKubernetesChartOperatorMetricsRegistered checks
// each one is, so a renamed metric cannot leave an alert that never fires.
var operatorMetrics = []string{
	"aerolvm_operator_reconcile_errors_total",
	"aerolvm_operator_nodes",
	"aerolvm_operator_worker_pods_lost_total",
	"aerolvm_operator_upgrade_step_failures_total",
	"aerolvm_operator_join_token_errors_total",
	"aerolvm_operator_maintenance_servers",
	"aerolvm_operator_cert_renewal_failures_total",
}

// operatorHistograms are operator histograms: their _bucket, _count and
// _sum series exist.
var operatorHistograms = []string{"aerolvm_operator_decommission_seconds"}

// kubeStateMetrics are the kube-state-metrics series the chart reads. The
// alerts that use them can be turned off (monitoring.prometheusRule.
// disabledAlerts) on a cluster without kube-state-metrics.
var kubeStateMetrics = []string{
	"kube_pod_status_ready",
	"kube_pod_container_status_restarts_total",
	"kube_pod_container_status_waiting_reason",
	"kube_pod_container_resource_requests",
}

// chartTargetLabels are the labels the chart's ServiceMonitors add. They
// are named aerolvm_* but are labels, not series.
var chartTargetLabels = []string{"aerolvm_component", "aerolvm_cluster", "aerolvm_zone"}

type k8sRule struct {
	Alert       string            `yaml:"alert"`
	Record      string            `yaml:"record"`
	Expr        string            `yaml:"expr"`
	For         string            `yaml:"for"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

type k8sRuleFile struct {
	Groups []struct {
		Name  string    `yaml:"name"`
		Rules []k8sRule `yaml:"rules"`
	} `yaml:"groups"`
}

func chartRulesPath(root string) string {
	return filepath.Join(root, "charts", "aerolvm", "monitoring", "rules.yaml")
}

func loadChartRules(t *testing.T, root string) k8sRuleFile {
	t.Helper()
	raw, err := os.ReadFile(chartRulesPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var rules k8sRuleFile
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		t.Fatalf("charts/aerolvm/monitoring/rules.yaml does not parse: %v", err)
	}
	if len(rules.Groups) == 0 {
		t.Fatal("charts/aerolvm/monitoring/rules.yaml has no groups")
	}
	return rules
}

// knownSeries is every series name a chart query may read: the aerolvm_
// names the Go code registers, the operator's, kube-state-metrics' and up.
func knownSeries(t *testing.T, root string) map[string]bool {
	t.Helper()
	known := goMetricLiterals(t, root)
	for _, name := range operatorMetrics {
		known[name] = true
	}
	for _, name := range operatorHistograms {
		for _, suffix := range []string{"_bucket", "_count", "_sum"} {
			known[name+suffix] = true
		}
	}
	for _, name := range kubeStateMetrics {
		known[name] = true
	}
	return known
}

var (
	promQuotedRE  = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	grafanaVarRE  = regexp.MustCompile(`\$\{?[A-Za-z_][A-Za-z0-9_]*\}?`)
	promTokenRE   = regexp.MustCompile(`[A-Za-z_:][A-Za-z0-9_:]*`)
	recordedRE    = regexp.MustCompile(`^[a-z_]+:[a-z0-9_]+:[a-z0-9_]+$`)
	recordedNames = func(rules k8sRuleFile) map[string]bool {
		out := map[string]bool{}
		for _, g := range rules.Groups {
			for _, r := range g.Rules {
				if r.Record != "" {
					out[r.Record] = true
				}
			}
		}
		return out
	}
)

// queriedSeries returns the series a query reads that this test can check:
// every aerolvm_ and kube_ name and every recorded (level:name:op) name,
// leaving out quoted strings, Grafana variables and the chart's target
// labels.
func queriedSeries(expr string) []string {
	expr = promQuotedRE.ReplaceAllString(expr, `""`)
	expr = grafanaVarRE.ReplaceAllString(expr, " ")
	labels := map[string]bool{}
	for _, l := range chartTargetLabels {
		labels[l] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, tok := range promTokenRE.FindAllString(expr, -1) {
		if labels[tok] || seen[tok] {
			continue
		}
		if strings.HasPrefix(tok, "aerolvm_") || strings.HasPrefix(tok, "kube_") || recordedRE.MatchString(tok) {
			seen[tok] = true
			out = append(out, tok)
		}
	}
	return out
}

func runbookAlertHeadings(t *testing.T, root string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "setup", "runbooks", "kubernetes.md"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		if name, ok := strings.CutPrefix(line, "## "); ok && strings.HasPrefix(name, "AerolVM") {
			out[strings.TrimSpace(name)] = true
		}
	}
	return out
}

// TestKubernetesChartRules checks the chart's rule file: the alerts are the
// expected ones with their severities, each is complete, its runbook link
// lands on its own heading of setup/runbooks/kubernetes.md, and every
// series it reads is registered in the Go tree, is the operator's, is
// kube-state-metrics' or is recorded in the same file.
func TestKubernetesChartRules(t *testing.T) {
	root := repoRoot(t)
	rules := loadChartRules(t, root)
	known := knownSeries(t, root)
	recorded := recordedNames(rules)
	headings := runbookAlertHeadings(t, root)

	seen := map[string]bool{}
	for _, g := range rules.Groups {
		if !strings.HasPrefix(g.Name, "aerolvm.kubernetes.") {
			t.Errorf("group %q: name it aerolvm.kubernetes.<area>", g.Name)
		}
		for _, r := range g.Rules {
			name := r.Alert + r.Record
			switch {
			case r.Alert != "" && r.Record != "":
				t.Errorf("%s: a rule is an alert or a record, not both", name)
			case r.Record != "":
				if !recordedRE.MatchString(r.Record) || r.Expr == "" {
					t.Errorf("record %q: want level:name:operation and an expression", r.Record)
				}
			default:
				if seen[r.Alert] {
					t.Errorf("alert %s is defined twice", r.Alert)
				}
				seen[r.Alert] = true
				if sev, ok := k8sAlerts[r.Alert]; !ok {
					t.Errorf("unexpected alert %s: add it to k8sAlerts and the runbook", r.Alert)
				} else if r.Labels["severity"] != sev {
					t.Errorf("%s: severity %q, want %q", r.Alert, r.Labels["severity"], sev)
				}
				if _, err := time.ParseDuration(r.For); err != nil {
					t.Errorf("%s: for %q is not a duration", r.Alert, r.For)
				}
				if r.Expr == "" || r.Labels["component"] == "" || r.Annotations["summary"] == "" || r.Annotations["description"] == "" {
					t.Errorf("%s: incomplete rule %+v", r.Alert, r)
				}
				if want := k8sRunbookURL + strings.ToLower(r.Alert); r.Annotations["runbook_url"] != want {
					t.Errorf("%s: runbook_url %q, want %q", r.Alert, r.Annotations["runbook_url"], want)
				}
				if !headings[r.Alert] {
					t.Errorf("%s has no '## %s' entry in setup/runbooks/kubernetes.md", r.Alert, r.Alert)
				}
			}
			for _, series := range queriedSeries(r.Expr) {
				if recordedRE.MatchString(series) {
					if !recorded[series] {
						t.Errorf("%s reads %s, which no rule records", name, series)
					}
				} else if !known[series] {
					t.Errorf("%s reads %s, which no Go file registers and the operator and kube-state-metrics lists do not name", name, series)
				}
			}
		}
	}
	for name := range k8sAlerts {
		if !seen[name] {
			t.Errorf("alert %s is missing from charts/aerolvm/monitoring/rules.yaml", name)
		}
	}
	for name := range headings {
		if !seen[name] {
			t.Errorf("setup/runbooks/kubernetes.md has an entry for %s, which no rule defines", name)
		}
	}
}

type grafanaTarget struct {
	Expr string `json:"expr"`
}

type grafanaPanel struct {
	Type       string            `json:"type"`
	Title      string            `json:"title"`
	Datasource *json.RawMessage  `json:"datasource"`
	Targets    []grafanaTarget   `json:"targets"`
	Panels     []json.RawMessage `json:"panels"`
}

type grafanaDashboard struct {
	UID        string         `json:"uid"`
	Title      string         `json:"title"`
	Panels     []grafanaPanel `json:"panels"`
	Templating struct {
		List []struct {
			Name       string          `json:"name"`
			Type       string          `json:"type"`
			Query      json.RawMessage `json:"query"`
			Definition string          `json:"definition"`
		} `json:"list"`
	} `json:"templating"`
}

func chartDashboards(t *testing.T, root string) map[string]grafanaDashboard {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(root, "charts", "aerolvm", "dashboards", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("charts/aerolvm/dashboards has no dashboards")
	}
	out := map[string]grafanaDashboard{}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var d grafanaDashboard
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatalf("%s is not a dashboard: %v", filepath.Base(p), err)
		}
		out[filepath.Base(p)] = d
	}
	return out
}

// dashboardQueries returns every query of a dashboard: its panels' targets
// and its variables' definitions.
func dashboardQueries(d grafanaDashboard) []string {
	var out []string
	for _, p := range d.Panels {
		for _, target := range p.Targets {
			out = append(out, target.Expr)
		}
	}
	for _, v := range d.Templating.List {
		if v.Type == "query" {
			out = append(out, v.Definition)
		}
	}
	return out
}

// TestKubernetesChartDashboards checks the chart's Grafana dashboards: each
// has its own uid, reads Prometheus through the datasource variable (a
// fixed uid would break on any Grafana but one), and every series it reads
// exists, as for the rules.
func TestKubernetesChartDashboards(t *testing.T) {
	root := repoRoot(t)
	known := knownSeries(t, root)
	recorded := recordedNames(loadChartRules(t, root))
	uids := map[string]string{}
	for file, d := range chartDashboards(t, root) {
		if d.Title == "" || !strings.HasPrefix(d.UID, "aerolvm-k8s-") {
			t.Errorf("%s: title %q, uid %q; want a title and an aerolvm-k8s- uid", file, d.Title, d.UID)
		}
		if other, ok := uids[d.UID]; ok {
			t.Errorf("%s and %s share the uid %s", file, other, d.UID)
		}
		uids[d.UID] = file
		hasDatasourceVar := false
		for _, v := range d.Templating.List {
			hasDatasourceVar = hasDatasourceVar || (v.Name == "datasource" && v.Type == "datasource")
		}
		if !hasDatasourceVar {
			t.Errorf("%s has no datasource variable", file)
		}
		panels := 0
		for _, p := range d.Panels {
			if len(p.Panels) > 0 {
				t.Errorf("%s: row %q is collapsed; keep its panels at the top level", file, p.Title)
			}
			if p.Type == "row" || p.Type == "text" {
				continue
			}
			panels++
			if p.Datasource == nil || !strings.Contains(string(*p.Datasource), `"${datasource}"`) {
				t.Errorf("%s: panel %q does not use the datasource variable", file, p.Title)
			}
			if len(p.Targets) == 0 {
				t.Errorf("%s: panel %q has no query", file, p.Title)
			}
		}
		if panels == 0 {
			t.Errorf("%s has no panels", file)
		}
		for _, q := range dashboardQueries(d) {
			for _, series := range queriedSeries(q) {
				if recordedRE.MatchString(series) {
					if !recorded[series] {
						t.Errorf("%s reads %s, which no chart rule records", file, series)
					}
				} else if !known[series] {
					t.Errorf("%s reads %s, which no Go file registers and the operator and kube-state-metrics lists do not name", file, series)
				}
			}
		}
	}
}

// chartTool finds a tool by its environment variable, then on PATH. Without
// it the test skips, unless AEROLVM_CHART_TOOLS=require.
func chartTool(t *testing.T, env, name string) string {
	t.Helper()
	path := os.Getenv(env)
	if path == "" {
		path, _ = exec.LookPath(name)
	}
	if path == "" {
		if os.Getenv("AEROLVM_CHART_TOOLS") == "require" {
			t.Fatalf("%s not found (set %s or put it on PATH)", name, env)
		}
		t.Skipf("%s not found; set %s or AEROLVM_CHART_TOOLS=require", name, env)
	}
	return path
}

func runTool(t *testing.T, dir, tool string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(tool, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf("%s %s: %w\n%s%s", filepath.Base(tool), strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
	return stdout.String(), err
}

// TestKubernetesChartRulesPromtool runs promtool on the rule file, on its
// unit tests (testdata/k8s-chart-rules.test.yaml), and on every dashboard
// query, each written as a recording rule with Grafana's variables filled
// in, so a query that does not parse fails here and not on an empty panel.
func TestKubernetesChartRulesPromtool(t *testing.T) {
	root := repoRoot(t)
	promtool := chartTool(t, "PROMTOOL", "promtool")
	if _, err := runTool(t, root, promtool, "check", "rules", chartRulesPath(root)); err != nil {
		t.Fatal(err)
	}
	if _, err := runTool(t, root, promtool, "test", "rules", filepath.Join(root, "setup", "prometheus", "testdata", "k8s-chart-rules.test.yaml")); err != nil {
		t.Fatal(err)
	}

	fill := strings.NewReplacer(
		"$__rate_interval", "5m", "$__range_s", "3600", "$__range", "1h",
		"${datasource}", "prometheus", "$cluster", ".*", "$owner", ".*",
	)
	var rules []map[string]string
	dashboards := chartDashboards(t, root)
	names := make([]string, 0, len(dashboards))
	for file := range dashboards {
		names = append(names, file)
	}
	sort.Strings(names)
	for _, file := range names {
		for i, q := range dashboardQueries(dashboards[file]) {
			q = fill.Replace(q)
			if inner, ok := strings.CutPrefix(q, "label_values("); ok {
				// label_values(<selector>, <label>) is Grafana's, not PromQL:
				// check its selector.
				q = inner[:strings.LastIndex(inner, ",")]
			}
			if strings.Contains(q, "$") {
				t.Errorf("%s: query %d has a Grafana variable this test does not fill: %s", file, i, q)
				continue
			}
			rules = append(rules, map[string]string{
				"record": "dashboard:" + strings.NewReplacer("-", "_", ".", "_").Replace(file) + ":q" + strconv.Itoa(i),
				"expr":   q,
			})
		}
	}
	out, err := yaml.Marshal(map[string]any{"groups": []any{map[string]any{"name": "dashboards", "rules": rules}}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "dashboard-queries.yaml")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runTool(t, root, promtool, "check", "rules", path); err != nil {
		t.Fatal(err)
	}
}

// renderChart runs helm template on the chart with the given --set values.
func renderChart(t *testing.T, root, helm string, sets ...string) ([]map[string]any, error) {
	t.Helper()
	args := []string{"template", "t", filepath.Join(root, "charts", "aerolvm"), "--namespace", "aerolvm"}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	out, err := runTool(t, root, helm, args...)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(strings.NewReader(out))
	var docs []map[string]any
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("helm template printed invalid YAML: %v", err)
		}
		if doc != nil {
			docs = append(docs, doc)
		}
	}
	return docs, nil
}

func docsOfKind(docs []map[string]any, kind string) []map[string]any {
	var out []map[string]any
	for _, d := range docs {
		if d["kind"] == kind {
			out = append(out, d)
		}
	}
	return out
}

// dig walks nested maps and lists: a string key indexes a map, an int a list.
func dig(v any, path ...any) any {
	for _, p := range path {
		switch key := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				return nil
			}
			v = m[key]
		case int:
			l, ok := v.([]any)
			if !ok || key >= len(l) {
				return nil
			}
			v = l[key]
		}
	}
	return v
}

// TestKubernetesChartRendersMonitoring renders the chart with helm: off by
// default; on, a headless Service and a ServiceMonitor for the worker with
// the token and the labels the rules group by, a PrometheusRule holding
// exactly the rule file less the disabled alerts, and one dashboard
// ConfigMap per file. promtool then checks the rules as rendered.
func TestKubernetesChartRendersMonitoring(t *testing.T) {
	root := repoRoot(t)
	helm := chartTool(t, "HELM", "helm")
	if v, _ := runTool(t, root, helm, "version", "--short"); !helmAtLeast(v, 3, 8) {
		if os.Getenv("AEROLVM_CHART_TOOLS") == "require" {
			t.Fatalf("helm %s is older than 3.8, the chart's minimum", strings.TrimSpace(v))
		}
		t.Skipf("helm %s is older than 3.8, the chart's minimum", strings.TrimSpace(v))
	}

	docs, err := renderChart(t, root, helm)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"ServiceMonitor", "PrometheusRule"} {
		if n := len(docsOfKind(docs, kind)); n != 0 {
			t.Errorf("monitoring is off by default, but %d %s rendered", n, kind)
		}
	}
	for _, cm := range docsOfKind(docs, "ConfigMap") {
		if dig(cm, "metadata", "labels", "grafana_dashboard") != nil {
			t.Error("monitoring is off by default, but a dashboard ConfigMap rendered")
		}
	}

	docs, err = renderChart(t, root, helm, "monitoring.enabled=true", "monitoring.labels.release=kps",
		"monitoring.prometheusRule.disabledAlerts={AerolVMPodNotReady}")
	if err != nil {
		t.Fatal(err)
	}

	// The scrape target: one headless Service and one ServiceMonitor, for
	// the worker, in single mode.
	var svc map[string]any
	for _, s := range docsOfKind(docs, "Service") {
		if dig(s, "metadata", "labels", "aerolvm.io/metrics") == "worker" {
			svc = s
		}
	}
	if svc == nil {
		t.Fatal("no metrics Service for the worker")
	}
	if dig(svc, "spec", "clusterIP") != "None" || dig(svc, "spec", "publishNotReadyAddresses") != true ||
		dig(svc, "spec", "selector", "app.kubernetes.io/component") != "worker" || dig(svc, "spec", "ports", 0, "name") != "api" {
		t.Errorf("metrics Service: %v", svc["spec"])
	}
	monitors := docsOfKind(docs, "ServiceMonitor")
	if len(monitors) != 1 {
		t.Fatalf("single mode rendered %d ServiceMonitors, want 1 (the worker)", len(monitors))
	}
	sm := monitors[0]
	if dig(sm, "metadata", "labels", "release") != "kps" {
		t.Error("monitoring.labels did not reach the ServiceMonitor")
	}
	ep := dig(sm, "spec", "endpoints", 0)
	if dig(ep, "port") != "api" || dig(ep, "path") != "/v1/metrics" ||
		dig(ep, "authorization", "credentials", "name") != "t-api-token" ||
		dig(ep, "authorization", "credentials", "key") != "SB_PAT_TOKEN" {
		t.Errorf("worker ServiceMonitor endpoint: %v", ep)
	}
	if dig(sm, "spec", "selector", "matchLabels", "aerolvm.io/metrics") != "worker" ||
		dig(sm, "spec", "namespaceSelector", "matchNames", 0) != "aerolvm" {
		t.Errorf("worker ServiceMonitor selects %v in %v", dig(sm, "spec", "selector"), dig(sm, "spec", "namespaceSelector"))
	}
	targets := map[string]bool{}
	relabels, _ := dig(ep, "relabelings").([]any)
	for _, r := range relabels {
		if l, ok := dig(r, "targetLabel").(string); ok {
			targets[l] = true
		}
	}
	for _, l := range chartTargetLabels {
		if !targets[l] {
			t.Errorf("the ServiceMonitor does not set %s, which the rules and dashboards group by", l)
		}
	}

	// The rules: the file, less the disabled alert.
	rulesDocs := docsOfKind(docs, "PrometheusRule")
	if len(rulesDocs) != 1 {
		t.Fatalf("rendered %d PrometheusRules, want 1", len(rulesDocs))
	}
	raw, err := os.ReadFile(chartRulesPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]any
	if err := yaml.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	var want []any
	for _, g := range file["groups"].([]any) {
		group := g.(map[string]any)
		var kept []any
		for _, r := range group["rules"].([]any) {
			if r.(map[string]any)["alert"] != "AerolVMPodNotReady" {
				kept = append(kept, r)
			}
		}
		want = append(want, map[string]any{"name": group["name"], "rules": kept})
	}
	got := dig(rulesDocs[0], "spec", "groups")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the PrometheusRule's groups differ from charts/aerolvm/monitoring/rules.yaml less AerolVMPodNotReady")
	}

	// The dashboards: one ConfigMap per file, holding it unchanged.
	files := chartDashboards(t, root)
	found := 0
	for _, cm := range docsOfKind(docs, "ConfigMap") {
		if dig(cm, "metadata", "labels", "grafana_dashboard") != "1" {
			continue
		}
		data, _ := cm["data"].(map[string]any)
		for name, body := range data {
			onDisk, err := os.ReadFile(filepath.Join(root, "charts", "aerolvm", "dashboards", name))
			if err != nil {
				t.Errorf("ConfigMap holds %s, which is not a dashboard file", name)
				continue
			}
			if strings.TrimRight(body.(string), "\n") != strings.TrimRight(string(onDisk), "\n") {
				t.Errorf("ConfigMap's %s differs from the file", name)
			}
			found++
		}
	}
	if found != len(files) {
		t.Errorf("%d dashboards rendered, want %d", found, len(files))
	}

	// A scrape token of its own, and the switches.
	docs, err = renderChart(t, root, helm, "monitoring.enabled=true", "monitoring.scrapeToken.existingSecret=prom",
		"monitoring.prometheusRule.enabled=false", "monitoring.grafanaDashboards=false")
	if err != nil {
		t.Fatal(err)
	}
	cred := dig(docsOfKind(docs, "ServiceMonitor")[0], "spec", "endpoints", 0, "authorization", "credentials")
	if dig(cred, "name") != "prom" || dig(cred, "key") != "token" {
		t.Errorf("scrapeToken.existingSecret: credentials %v", cred)
	}
	if len(docsOfKind(docs, "PrometheusRule")) != 0 {
		t.Error("prometheusRule.enabled=false still rendered a PrometheusRule")
	}
	for _, cm := range docsOfKind(docs, "ConfigMap") {
		if dig(cm, "metadata", "labels", "grafana_dashboard") != nil {
			t.Error("grafanaDashboards=false still rendered a dashboard")
		}
	}
	if _, err := renderChart(t, root, helm, "monitoring.enabled=true", "monitoring.prometheusRule.disabledAlerts={AerolVMNoSuchAlert}"); err == nil ||
		!strings.Contains(err.Error(), "no alert is named AerolVMNoSuchAlert") {
		t.Errorf("a misspelled disabled alert rendered: %v", err)
	}

	// promtool on the rules exactly as rendered.
	if promtool := os.Getenv("PROMTOOL"); promtool != "" || os.Getenv("AEROLVM_CHART_TOOLS") == "require" {
		if promtool == "" {
			promtool = chartTool(t, "PROMTOOL", "promtool")
		}
		out, err := yaml.Marshal(map[string]any{"groups": got})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "rendered-rules.yaml")
		if err := os.WriteFile(path, out, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := runTool(t, root, promtool, "check", "rules", path); err != nil {
			t.Fatal(err)
		}
	}
}

// helmAtLeast reports whether `helm version --short` output (v3.22.1+g...)
// is at least major.minor.
func helmAtLeast(v string, major, minor int) bool {
	m := regexp.MustCompile(`v(\d+)\.(\d+)`).FindStringSubmatch(v)
	if m == nil {
		return false
	}
	gotMajor, _ := strconv.Atoi(m[1])
	gotMinor, _ := strconv.Atoi(m[2])
	return gotMajor > major || (gotMajor == major && gotMinor >= minor)
}

// The operator's metrics the chart's alerts and dashboards read are the
// ones its code registers: the operator is its own module, outside the
// cmd/internal/pkg scan that checks sandboxd's.
func TestKubernetesChartOperatorMetricsRegistered(t *testing.T) {
	root := repoRoot(t)
	literal := regexp.MustCompile(`"(aerolvm_operator_[a-z0-9_]+)"`)
	registered := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(root, "operator"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range literal.FindAllStringSubmatch(string(src), -1) {
			registered[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range append(append([]string{}, operatorMetrics...), operatorHistograms...) {
		if !registered[name] {
			t.Errorf("the chart reads %s, which the operator does not register", name)
		}
	}
}

// The agent-sandbox API (C17): off by default; on, the APIService and its
// Service, certificate and two RBAC bindings render, every role's template
// carries the setting, and only the gateway's has a service account, the
// API port and the serving pair.
// gatewayOpenPorts is the gateways' ports anyone may reach: the ports of
// the gateway-ingress policy's rules that name no peer.
func gatewayOpenPorts(t *testing.T, docs []map[string]any) map[int]bool {
	t.Helper()
	for _, np := range docsOfKind(docs, "NetworkPolicy") {
		if name, _ := dig(np, "metadata", "name").(string); !strings.HasSuffix(name, "-gateway-ingress") {
			continue
		}
		open := map[int]bool{}
		rules, _ := dig(np, "spec", "ingress").([]any)
		for _, r := range rules {
			rule, _ := r.(map[string]any)
			if rule["from"] != nil {
				continue
			}
			ports, _ := rule["ports"].([]any)
			for _, p := range ports {
				if n, ok := dig(p.(map[string]any), "port").(int); ok {
					open[n] = true
				}
			}
		}
		return open
	}
	t.Fatal("no gateway-ingress NetworkPolicy")
	return nil
}

func TestKubernetesChartRendersTheAgentSandboxAPI(t *testing.T) {
	root := repoRoot(t)
	helm := chartTool(t, "HELM", "helm")
	if v, _ := runTool(t, root, helm, "version", "--short"); !helmAtLeast(v, 3, 8) {
		t.Skipf("helm %s is older than 3.8, the chart's minimum", strings.TrimSpace(v))
	}
	cluster := []string{"mode=cluster", "cluster.zones={a}", "cluster.workerPools[0].name=g",
		"cluster.workerPools[0].machine.cpu=8", "cluster.workerPools[0].machine.memoryGiB=32"}
	docs, err := renderChart(t, root, helm, cluster...)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(docsOfKind(docs, "APIService")); n != 0 {
		t.Fatalf("the API is off by default, but %d APIService rendered", n)
	}
	if gatewayOpenPorts(t, docs)[9443] {
		t.Fatal("the gateways' port 9443 is open with the API off")
	}
	docs, err = renderChart(t, root, helm, append(cluster, "cluster.agentSandboxAPI.enabled=true", "cluster.agentSandboxAPI.namespaces.acct=acct:k1")...)
	if err != nil {
		t.Fatal(err)
	}
	// The kube-apiserver is no pod of the install: without its port open to
	// all, every call to the APIService times out (p6-kubeapi-2).
	if open := gatewayOpenPorts(t, docs); !open[9443] || !open[443] {
		t.Fatalf("the gateways' ports open to all = %v, want 9443 among them", open)
	}
	api := docsOfKind(docs, "APIService")
	groups := map[any]bool{}
	for _, a := range api {
		groups[dig(a, "spec", "group")] = true
		if dig(a, "spec", "service", "name") != "aerolvm-agent-sandbox-api" ||
			dig(a, "metadata", "annotations", "cert-manager.io/inject-ca-from") != "aerolvm/aerolvm-agent-sandbox-api" {
			t.Fatalf("APIService = %v", a)
		}
	}
	if len(api) != 2 || !groups["agents.x-k8s.io"] || !groups["extensions.agents.x-k8s.io"] {
		t.Fatalf("APIServices = %v", groups)
	}
	crds := map[any]bool{}
	for _, c := range docsOfKind(docs, "CustomResourceDefinition") {
		crds[dig(c, "metadata", "name")] = true
		// Without keep, turning the API off deletes the CRDs, and with
		// them every stored template and warm pool.
		if dig(c, "metadata", "annotations", "helm.sh/resource-policy") != "keep" {
			t.Fatalf("CRD %v is not kept by helm", dig(c, "metadata", "name"))
		}
	}
	if !crds["sandboxtemplates.k8s.aerolvm.io"] || !crds["sandboxwarmpools.k8s.aerolvm.io"] {
		t.Fatalf("internal CRDs = %v", crds)
	}
	roles := map[string]bool{}
	for _, b := range append(docsOfKind(docs, "ClusterRoleBinding"), docsOfKind(docs, "RoleBinding")...) {
		if dig(b, "subjects", 0, "name") == "aerolvm-gateway" {
			roles[dig(b, "roleRef", "name").(string)] = true
		}
	}
	if !roles["system:auth-delegator"] || !roles["extension-apiserver-authentication-reader"] || !roles["aerolvm-gateway-store"] || len(roles) != 3 {
		t.Fatalf("the gateway's roles = %v", roles)
	}
	if n := len(docsOfKind(docs, "Certificate")); n < 1 {
		t.Fatal("no serving certificate")
	}
	var templates map[string]any
	for _, cm := range docsOfKind(docs, "ConfigMap") {
		if d, ok := cm["data"].(map[string]any); ok && d["gateway"] != nil && d["worker"] != nil {
			templates = d
		}
	}
	if templates == nil {
		t.Fatal("no pod-template ConfigMap")
	}
	for role, want := range map[string][]string{
		"gateway": {"SB_AGENT_SANDBOX_API", "acct=acct:k1", "serviceAccountName: aerolvm-gateway", "automountServiceAccountToken: true", "containerPort: 9443", "aerolvm-agent-sandbox-api-tls"},
		"server":  {"SB_AGENT_SANDBOX_API", "automountServiceAccountToken: false"},
		"worker":  {"SB_AGENT_SANDBOX_API"},
	} {
		body, _ := templates[role].(string)
		for _, w := range want {
			if !strings.Contains(body, w) {
				t.Errorf("the %s template lacks %q", role, w)
			}
		}
	}
	if strings.Contains(templates["server"].(string), "serviceAccountName") {
		t.Error("a server got a service account")
	}
}
