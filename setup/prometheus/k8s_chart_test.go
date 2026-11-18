package prometheus_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	"aerolvm_operator_node_certificates_pending",
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

// podTemplates is the pod-templates ConfigMap's data: each role's template
// as the operator reads it.
func podTemplates(t *testing.T, docs []map[string]any) map[string]string {
	t.Helper()
	for _, cm := range docsOfKind(docs, "ConfigMap") {
		d, ok := cm["data"].(map[string]any)
		if !ok || d["server"] == nil || d["gateway"] == nil || d["worker"] == nil {
			continue
		}
		out := map[string]string{}
		for role, body := range d {
			out[role], _ = body.(string)
		}
		return out
	}
	t.Fatal("no pod-template ConfigMap")
	return nil
}

// API tokens and the scrape token in cluster mode (issue #1343):
// identity.enabled reaches servers, gateways and workers alike (the admin
// token stays the servers'), worker.extraEnv may not turn tokens on for
// workers alone, and monitoring has no default scrape token: the API
// token Secret is single mode's, and the admin token is no default to
// hand Prometheus. A Secret named explicitly, the admin one included,
// renders. Single mode keeps its default.
func TestKubernetesChartIdentityAndScrapeToken(t *testing.T) {
	root := repoRoot(t)
	helm := chartTool(t, "HELM", "helm")
	if v, _ := runTool(t, root, helm, "version", "--short"); !helmAtLeast(v, 3, 8) {
		t.Skipf("helm %s is older than 3.8, the chart's minimum", strings.TrimSpace(v))
	}
	cluster := []string{"mode=cluster", "cluster.zones={a}", "cluster.workerPools[0].name=g",
		"cluster.workerPools[0].machine.cpu=8", "cluster.workerPools[0].machine.memoryGiB=32"}
	with := func(sets ...string) []string { return append(append([]string{}, cluster...), sets...) }
	const identityOn = `SB_IDENTITY_ENABLED, value: "true"`

	// Identity: off by default on every role; on, on every role.
	for _, tc := range []struct {
		sets []string
		want bool
	}{{nil, false}, {[]string{"identity.enabled=true"}, true}} {
		docs, err := renderChart(t, root, helm, with(tc.sets...)...)
		if err != nil {
			t.Fatal(err)
		}
		templates := podTemplates(t, docs)
		for _, role := range []string{"server", "gateway", "worker"} {
			if got := strings.Contains(templates[role], identityOn); got != tc.want {
				t.Errorf("identity %v: the %s template turns API tokens on = %v", tc.sets, role, got)
			}
			if got := strings.Contains(templates[role], "SB_PAT_TOKEN"); got != (role == "server") {
				t.Errorf("identity %v: the %s template holds the admin token = %v; only servers may", tc.sets, role, got)
			}
		}
	}
	if _, err := renderChart(t, root, helm, with("worker.extraEnv.SB_IDENTITY_ENABLED=true")...); err == nil ||
		!strings.Contains(err.Error(), "Remove it, and set identity.enabled.") {
		t.Errorf("cluster mode took worker.extraEnv.SB_IDENTITY_ENABLED, which reaches workers only: %v", err)
	}
	// A false value turns nothing on: cluster mode lets it be (PR 2 review).
	for _, off := range []string{"false", "0"} {
		if _, err := renderChart(t, root, helm, with("worker.extraEnv.SB_IDENTITY_ENABLED="+off)...); err != nil {
			t.Errorf("cluster mode refused worker.extraEnv.SB_IDENTITY_ENABLED=%s, which turns nothing on: %v", off, err)
		}
	}
	if _, err := renderChart(t, root, helm, with("identity.enabled=true", "worker.extraEnv.SB_IDENTITY_ENABLED=false")...); err == nil ||
		!strings.Contains(err.Error(), "set twice") {
		t.Errorf("identity.enabled beside a false worker.extraEnv one (workers would end up off) rendered: %v", err)
	}

	// Single mode: the value reaches the worker; worker.extraEnv alone still
	// works as before; both at once is refused.
	docs, err := renderChart(t, root, helm, "identity.enabled=true")
	if err != nil {
		t.Fatal(err)
	}
	sts := docsOfKind(docs, "StatefulSet")
	if len(sts) != 1 || !envHas(dig(sts[0], "spec", "template", "spec", "containers"), "SB_IDENTITY_ENABLED", "true") {
		t.Error("single mode: identity.enabled did not reach the worker")
	}
	docs, err = renderChart(t, root, helm, "worker.extraEnv.SB_IDENTITY_ENABLED=true")
	if err != nil || !envHas(dig(docsOfKind(docs, "StatefulSet")[0], "spec", "template", "spec", "containers"), "SB_IDENTITY_ENABLED", "true") {
		t.Errorf("single mode: worker.extraEnv.SB_IDENTITY_ENABLED no longer works: %v", err)
	}
	if _, err := renderChart(t, root, helm, "identity.enabled=true", "worker.extraEnv.SB_IDENTITY_ENABLED=true"); err == nil ||
		!strings.Contains(err.Error(), "set twice") {
		t.Errorf("single mode: API tokens set twice rendered: %v", err)
	}

	// The scrape token: cluster mode refuses none, with the command that
	// makes a read-only one.
	_, err = renderChart(t, root, helm, with("monitoring.enabled=true")...)
	for _, want := range []string{"monitoring.scrapeToken.existingSecret", "identity.enabled=true",
		"aerolvm token create --name prometheus --role viewer --team '*'", "aerolvm-admin",
		// An existing install meets this on helm upgrade: its running pods
		// must be replaced before the token works on them (PR 2 review).
		"replace its pods", "gateway pods one at a time"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("cluster mode with no scrape token: %v; want a refusal naming %q", err, want)
		}
	}
	for _, secret := range []string{"prom", "aerolvm-admin"} {
		docs, err := renderChart(t, root, helm, with("monitoring.enabled=true", "monitoring.scrapeToken.existingSecret="+secret)...)
		if err != nil {
			t.Fatalf("scrape token %s: %v", secret, err)
		}
		monitors := docsOfKind(docs, "ServiceMonitor")
		if len(monitors) != 4 {
			t.Fatalf("cluster mode rendered %d ServiceMonitors, want 4", len(monitors))
		}
		for _, sm := range monitors {
			name, _ := dig(sm, "metadata", "name").(string)
			cred := dig(sm, "spec", "endpoints", 0, "authorization", "credentials")
			if strings.HasSuffix(name, "-operator") {
				if cred != nil {
					t.Errorf("the operator's ServiceMonitor sends a token: %v", cred)
				}
				continue
			}
			if dig(cred, "name") != secret || dig(cred, "key") != "token" {
				t.Errorf("%s reads %v, want the Secret %s", name, cred, secret)
			}
		}
	}

	// The bank preset relies on a viewer token, so turns tokens on everywhere.
	bank, err := runTool(t, root, helm, "template", "t", filepath.Join(root, "charts", "aerolvm"),
		"-f", filepath.Join(root, "charts", "aerolvm", "values-bank-eks.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(bank, identityOn); n != 3 {
		t.Errorf("the bank preset turns API tokens on in %d pod templates, want 3", n)
	}
}

// The settings a server needs once the servers sign. cloudIdentity.issuerURL
// reaches every role: the servers sign each sandbox's cloud-identity token,
// the gateways serve the public keys, the workers take the creates.
// worker.extraEnv may not set it for the workers alone in cluster mode, and
// an issuer sandboxd refuses at boot does not render. The
// SB_PLATFORM_VOLUMES_* settings in worker.extraEnv reach the servers, which
// make platform-volume records, and not the gateways.
func TestKubernetesChartServerSigningSettings(t *testing.T) {
	root := repoRoot(t)
	helm := chartTool(t, "HELM", "helm")
	if v, _ := runTool(t, root, helm, "version", "--short"); !helmAtLeast(v, 3, 8) {
		t.Skipf("helm %s is older than 3.8, the chart's minimum", strings.TrimSpace(v))
	}
	cluster := []string{"mode=cluster", "cluster.zones={a}", "cluster.workerPools[0].name=g",
		"cluster.workerPools[0].machine.cpu=8", "cluster.workerPools[0].machine.memoryGiB=32"}
	with := func(sets ...string) []string { return append(append([]string{}, cluster...), sets...) }
	const url = "https://api.example.test"
	issuerOn := `SB_IDENTITY_ISSUER_URL, value: "` + url + `"`

	for _, tc := range []struct {
		sets []string
		want bool
	}{{nil, false}, {[]string{"cloudIdentity.issuerURL=" + url}, true}} {
		docs, err := renderChart(t, root, helm, with(tc.sets...)...)
		if err != nil {
			t.Fatal(err)
		}
		templates := podTemplates(t, docs)
		for _, role := range []string{"server", "gateway", "worker"} {
			if got := strings.Contains(templates[role], issuerOn); got != tc.want {
				t.Errorf("cloud identity %v: the %s template carries the issuer = %v", tc.sets, role, got)
			}
		}
	}
	for _, tc := range []struct {
		set, want string
	}{
		{"worker.extraEnv.SB_IDENTITY_ISSUER_URL=" + url, "Remove it, and set cloudIdentity.issuerURL."},
		{"cloudIdentity.issuerURL=http://api.example.test", "not an HTTPS address with no path"},
		{"cloudIdentity.issuerURL=" + url + "/v1", "not an HTTPS address with no path"},
	} {
		if _, err := renderChart(t, root, helm, with(tc.set)...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("cluster mode with %s: %v; want a refusal naming %q", tc.set, err, tc.want)
		}
	}
	// An empty one turns nothing on: cluster mode lets it be.
	if _, err := renderChart(t, root, helm, with("worker.extraEnv.SB_IDENTITY_ISSUER_URL=")...); err != nil {
		t.Errorf("cluster mode refused an empty worker.extraEnv.SB_IDENTITY_ISSUER_URL: %v", err)
	}

	// Single mode: the value reaches the worker; worker.extraEnv alone still
	// works as before; both at once is refused.
	for _, set := range []string{"cloudIdentity.issuerURL=" + url, "worker.extraEnv.SB_IDENTITY_ISSUER_URL=" + url} {
		docs, err := renderChart(t, root, helm, set)
		if err != nil || !envHas(dig(docsOfKind(docs, "StatefulSet")[0], "spec", "template", "spec", "containers"), "SB_IDENTITY_ISSUER_URL", url) {
			t.Errorf("single mode with %s: the worker has no issuer (%v)", set, err)
		}
	}
	if _, err := renderChart(t, root, helm, "cloudIdentity.issuerURL="+url, "worker.extraEnv.SB_IDENTITY_ISSUER_URL="+url); err == nil ||
		!strings.Contains(err.Error(), "set twice") {
		t.Errorf("single mode: the issuer set twice rendered: %v", err)
	}

	docs, err := renderChart(t, root, helm, with("worker.extraEnv.SB_PLATFORM_VOLUMES_ENABLED=true", "worker.extraEnv.SB_PLATFORM_VOLUMES_S3_BUCKET=vols")...)
	if err != nil {
		t.Fatal(err)
	}
	templates := podTemplates(t, docs)
	for role, want := range map[string]bool{"server": true, "gateway": false, "worker": true} {
		if got := strings.Contains(templates[role], `SB_PLATFORM_VOLUMES_S3_BUCKET, value: "vols"`); got != want {
			t.Errorf("the %s template carries the platform-volume settings = %v, want %v", role, got, want)
		}
	}
}

// envHas reports whether any container in containers sets name to value.
func envHas(containers any, name, value string) bool {
	list, _ := containers.([]any)
	for _, c := range list {
		env, _ := dig(c, "env").([]any)
		for _, e := range env {
			if dig(e, "name") == name && dig(e, "value") == value {
				return true
			}
		}
	}
	return false
}

// renderNotes renders the chart's NOTES.txt as Helm prints it after an
// install, or after an upgrade with isUpgrade: helm template skips NOTES, so
// a copy of the chart carries it as a template.
func renderNotes(t *testing.T, root, helm string, isUpgrade bool, sets ...string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "aerolvm")
	if err := os.CopyFS(dir, os.DirFS(filepath.Join(root, "charts", "aerolvm"))); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "templates", "NOTES.txt"), filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatal(err)
	}
	tpl := "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: notes}\ndata:\n  notes: |\n{{- tpl (.Files.Get \"notes.txt\") . | nindent 4 }}\n"
	if err := os.WriteFile(filepath.Join(dir, "templates", "zz-notes.yaml"), []byte(tpl), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"template", "t", dir, "--namespace", "aerolvm-system", "--show-only", "templates/zz-notes.yaml"}
	if isUpgrade {
		args = append(args, "--is-upgrade")
	}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	out, err := runTool(t, root, helm, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// After an upgrade with identity on, the notes say the running pods must be
// replaced (a pod reads identity.enabled when it is made), in both modes;
// after an install, or with identity off, they say nothing of it (PR 2
// review). Single mode's says replacing its pod ends every sandbox.
func TestKubernetesChartNotesOnTurningIdentityOn(t *testing.T) {
	root := repoRoot(t)
	helm := chartTool(t, "HELM", "helm")
	if v, _ := runTool(t, root, helm, "version", "--short"); !helmAtLeast(v, 3, 8) {
		t.Skipf("helm %s is older than 3.8, the chart's minimum", strings.TrimSpace(v))
	}
	cluster := []string{"mode=cluster", "cluster.zones={a}", "cluster.workerPools[0].name=g",
		"cluster.workerPools[0].machine.cpu=8", "cluster.workerPools[0].machine.memoryGiB=32"}
	for _, tc := range []struct {
		name    string
		upgrade bool
		sets    []string
		want    []string
	}{
		{"cluster upgrade, identity on", true, append(cluster, "identity.enabled=true"),
			[]string{"replace the running pods", "gateway pods one at a time", "kubectl cordon"}},
		{"cluster install, identity on", false, append(cluster, "identity.enabled=true"), nil},
		{"cluster upgrade, identity off", true, cluster, nil},
		{"single upgrade, identity on", true, []string{"identity.enabled=true"}, []string{"delete pod t-0", "ends every sandbox"}},
		{"single upgrade, identity off", true, nil, nil},
	} {
		notes := renderNotes(t, root, helm, tc.upgrade, tc.sets...)
		said := strings.Contains(notes, "API tokens (identity.enabled) reach")
		if said != (tc.want != nil) {
			t.Errorf("%s: the notes speak of replacing pods = %v, want %v", tc.name, said, tc.want != nil)
		}
		for _, w := range tc.want {
			if !strings.Contains(notes, w) {
				t.Errorf("%s: the notes lack %q", tc.name, w)
			}
		}
	}
}

// identity.tokenMaxTTL, identity.file and enterprise.enabled reach every
// node, as identity.enabled does (issue #1343): a cap or an identity file on
// the workers alone binds nodes that take no token write. The identity file
// is a ConfigMap in every namespace a node runs in, mounted on each.
// worker.extraEnv may not set any of them in cluster mode. The bank preset
// caps tokens at 90 days everywhere.
func TestKubernetesChartTokenSettingsOnEveryNode(t *testing.T) {
	root := repoRoot(t)
	helm := chartTool(t, "HELM", "helm")
	if v, _ := runTool(t, root, helm, "version", "--short"); !helmAtLeast(v, 3, 8) {
		t.Skipf("helm %s is older than 3.8, the chart's minimum", strings.TrimSpace(v))
	}
	cluster := []string{"mode=cluster", "cluster.zones={a}", "cluster.workerPools[0].name=g",
		"cluster.workerPools[0].machine.cpu=8", "cluster.workerPools[0].machine.memoryGiB=32"}
	with := func(sets ...string) []string { return append(append([]string{}, cluster...), sets...) }
	docs, err := renderChart(t, root, helm, with(append([]string{"identity.enabled=true", "identity.tokenMaxTTL=2160h",
		"identity.file.content=version: 1"}, enterpriseSets...)...)...)
	if err != nil {
		t.Fatal(err)
	}
	templates := podTemplates(t, docs)
	for _, role := range []string{"server", "gateway", "worker"} {
		for _, want := range []string{`SB_TOKEN_MAX_TTL, value: "2160h"`, `SB_IDENTITY_FILE, value: "/etc/aerolvm/identity/identity.yaml"`,
			`SB_ENTERPRISE_MODE, value: "true"`, "name: identity-file, mountPath: /etc/aerolvm/identity", "name: t-identity"} {
			if !strings.Contains(templates[role], want) {
				t.Errorf("the %s template lacks %q", role, want)
			}
		}
	}
	namespaces := map[any]bool{}
	for _, cm := range docsOfKind(docs, "ConfigMap") {
		if dig(cm, "metadata", "name") == "t-identity" && dig(cm, "data", "identity.yaml") != nil {
			namespaces[dig(cm, "metadata", "namespace")] = true
		}
	}
	if !namespaces["aerolvm"] || !namespaces["aerolvm-workers"] || len(namespaces) != 2 {
		t.Errorf("the identity file's ConfigMap is in %v, want the release and worker namespaces", namespaces)
	}
	// Off by default: nothing set, nothing mounted.
	docs, err = renderChart(t, root, helm, with("identity.enabled=true")...)
	if err != nil {
		t.Fatal(err)
	}
	for role, body := range podTemplates(t, docs) {
		for _, never := range []string{"SB_TOKEN_MAX_TTL", "SB_IDENTITY_FILE", "SB_ENTERPRISE_MODE", "identity-file"} {
			if strings.Contains(body, never) {
				t.Errorf("by default the %s template carries %s", role, never)
			}
		}
	}

	for _, tc := range []struct {
		sets []string
		want string
	}{
		{[]string{"worker.extraEnv.SB_TOKEN_MAX_TTL=2160h"}, "worker.extraEnv.SB_TOKEN_MAX_TTL (2160h) reaches workers only"},
		{[]string{"worker.extraEnv.SB_IDENTITY_FILE=/x"}, "set identity.file"},
		{[]string{"worker.extraEnv.SB_ENTERPRISE_MODE=true"}, "set enterprise.enabled"},
		{[]string{"identity.enabled=true", "identity.tokenMaxTTL=90d"}, "is not a duration sandboxd reads"},
		{[]string{"identity.file.content=x"}, "identity.file needs identity.enabled=true"},
		{[]string{"enterprise.enabled=true"}, "enterprise.enabled needs identity.enabled=true"},
	} {
		if _, err := renderChart(t, root, helm, with(tc.sets...)...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v rendered or failed otherwise: %v; want %q", tc.sets, err, tc.want)
		}
	}
	// Enterprise mode refuses a cap over 90 days at boot, so the render
	// does too, whatever the units (PR 3 review, round 3).
	for ttl, refused := range map[string]bool{"2161h": true, "2159h59m61s": true, "7776001s": true, "2160h": false, "1h30m": false} {
		_, err := renderChart(t, root, helm, with(append([]string{"identity.enabled=true", "identity.tokenMaxTTL=" + ttl}, enterpriseSets...)...)...)
		if got := err != nil && strings.Contains(err.Error(), "longer than enterprise mode allows"); got != refused {
			t.Errorf("enterprise mode with tokenMaxTTL %s: refused %v (%v), want %v", ttl, got, err, refused)
		}
	}
	// The scrape token the refusal and the notes tell you to make lasts
	// no longer than the cap, or 90 days without one.
	for ttl, want := range map[string]string{"720h": "--expires-in 720h", "": "--expires-in 90d"} {
		sets := with("monitoring.enabled=true", "identity.enabled=true")
		if ttl != "" {
			sets = append(sets, "identity.tokenMaxTTL="+ttl)
		}
		if _, err := renderChart(t, root, helm, sets...); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("the scrape-token refusal with tokenMaxTTL %q: %v; want %q", ttl, err, want)
		}
		notes := renderNotes(t, root, helm, false, append(sets, "monitoring.scrapeToken.existingSecret=aerolvm-metrics-token")...)
		if !strings.Contains(notes, want) {
			t.Errorf("the notes with tokenMaxTTL %q lack %q", ttl, want)
		}
	}
	if _, err := renderChart(t, root, helm, with("worker.extraEnv.SB_ENTERPRISE_MODE=false")...); err != nil {
		t.Errorf("a false worker.extraEnv.SB_ENTERPRISE_MODE, which turns nothing on, was refused: %v", err)
	}
	// Single mode: the worker carries them, and worker.extraEnv still may,
	// but not both.
	if _, err := renderChart(t, root, helm, "identity.enabled=true", "identity.tokenMaxTTL=2160h", "worker.extraEnv.SB_TOKEN_MAX_TTL=1h"); err == nil ||
		!strings.Contains(err.Error(), "set twice") {
		t.Errorf("single mode took SB_TOKEN_MAX_TTL twice: %v", err)
	}

	bank, err := runTool(t, root, helm, "template", "t", filepath.Join(root, "charts", "aerolvm"),
		"-f", filepath.Join(root, "charts", "aerolvm", "values-bank-eks.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(bank, `SB_TOKEN_MAX_TTL, value: "2160h"`); n != 3 {
		t.Errorf("the bank preset caps tokens at 90 days in %d pod templates, want 3", n)
	}
}

// enterpriseSets are the least an enterprise install renders with: API
// tokens, the audit witness and an off-node export.
var enterpriseSets = []string{"enterprise.enabled=true", "audit.witness.bucket=witness",
	"audit.export.backend=s3", "audit.export.s3.bucket=audit"}

// containerNamed is the container (or init container) name in a template.
func containerNamed(tpl map[string]any, name string) map[string]any {
	for _, list := range []string{"containers", "initContainers"} {
		cs, _ := dig(tpl, "spec", list).([]any)
		for _, c := range cs {
			if dig(c, "name") == name {
				m, _ := c.(map[string]any)
				return m
			}
		}
	}
	return nil
}

func envValue(c map[string]any, name string) (string, bool) {
	env, _ := dig(c, "env").([]any)
	for _, e := range env {
		if dig(e, "name") == name {
			v, _ := dig(e, "value").(string)
			return v, true
		}
	}
	return "", false
}

func mounts(c map[string]any) map[string]string {
	out := map[string]string{}
	list, _ := dig(c, "volumeMounts").([]any)
	for _, m := range list {
		out[fmt.Sprint(dig(m, "name"))] = fmt.Sprint(dig(m, "mountPath"))
	}
	return out
}

// Enterprise mode on Kubernetes (issue #1349). Every node takes the admin
// token only from its own pod (SB_PAT_SCOPE=host) and opens the public
// socket, on a folder its edge shares, for group 65532; the edge's
// Caddyfile, in both namespaces, sends the API there. The audit witness,
// the export and their credentials reach every node; the nodes run under
// a service account of their own with the IRSA annotation (the gateway's
// own, with the agent-sandbox API, gets it too). The operator may
// port-forward in its own namespace only, and only in enterprise mode.
// Off, none of it renders. Each setting sandboxd would refuse at start is
// refused here.
func TestKubernetesChartEnterpriseMode(t *testing.T) {
	root := repoRoot(t)
	helm := chartTool(t, "HELM", "helm")
	if v, _ := runTool(t, root, helm, "version", "--short"); !helmAtLeast(v, 3, 8) {
		t.Skipf("helm %s is older than 3.8, the chart's minimum", strings.TrimSpace(v))
	}
	cluster := []string{"mode=cluster", "cluster.zones={a}", "cluster.workerPools[0].name=g",
		"cluster.workerPools[0].machine.cpu=8", "cluster.workerPools[0].machine.memoryGiB=32",
		"edge.enabled=true", "edge.domain=sb.example.test", "edge.existingTLSSecret=edge-tls"}
	with := func(sets ...string) []string { return append(append([]string{}, cluster...), sets...) }
	on := with(append([]string{"identity.enabled=true", "audit.witness.region=eu-west-1",
		"audit.witness.endpoint=https://s3.example.test", "audit.witness.pathStyle=true", "audit.witness.prefix=w/",
		"audit.export.s3.region=eu-west-1", "audit.export.s3.endpoint=https://s3.example.test", "audit.export.s3.pathStyle=true",
		"audit.export.s3.prefix=x/", "audit.credentials.existingSecret=aws-keys", "audit.credentials.caBundle.existingConfigMap=s3-ca",
		"audit.credentials.serviceAccount.create=true", "audit.credentials.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn=arn:aws:iam::1:role/a",
		"cluster.agentSandboxAPI.enabled=true"}, enterpriseSets...)...)
	docs, err := renderChart(t, root, helm, on...)
	if err != nil {
		t.Fatal(err)
	}
	wantEnv := map[string]string{
		"SB_PAT_SCOPE": "host", "SB_PUBLIC_API_SOCKET": "/run/sandboxd-public/api/api.sock", "SB_PUBLIC_API_SOCKET_GROUP": "65532",
		"SB_PAT_LOCAL_LISTEN":      "127.0.0.1:21219",
		"SB_ENTERPRISE_MODE":       "true",
		"SB_AUDIT_WITNESS_BACKEND": "s3", "SB_AUDIT_WITNESS_S3_BUCKET": "witness", "SB_AUDIT_WITNESS_S3_REGION": "eu-west-1",
		"SB_AUDIT_WITNESS_S3_ENDPOINT": "https://s3.example.test", "SB_AUDIT_WITNESS_S3_PATH_STYLE": "true", "SB_AUDIT_WITNESS_S3_PREFIX": "w/",
		"SB_AUDIT_EXPORT_BACKEND": "s3", "SB_AUDIT_EXPORT_S3_BUCKET": "audit", "SB_AUDIT_EXPORT_S3_REGION": "eu-west-1",
		"SB_AUDIT_EXPORT_S3_ENDPOINT": "https://s3.example.test", "SB_AUDIT_EXPORT_S3_PATH_STYLE": "true", "SB_AUDIT_EXPORT_S3_PREFIX": "x/",
		"AWS_CA_BUNDLE": "/etc/aerolvm/aws-ca/ca.crt",
	}
	for role, body := range podTemplates(t, docs) {
		var tpl map[string]any
		if err := yaml.Unmarshal([]byte(body), &tpl); err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		agent := containerNamed(tpl, "agent")
		for k, v := range wantEnv {
			if got, ok := envValue(agent, k); !ok || got != v {
				t.Errorf("%s: %s = %q (set %v), want %q", role, k, got, ok, v)
			}
		}
		// The admin listener's port is no other listener's in the pod: the
		// first choice, 21213, was the gateway's ingress proxy, and every
		// gateway failed to start. internal/config refuses sandboxd's own
		// defaults; this covers the addresses and ports the chart sets.
		if _, adminPort, err := net.SplitHostPort(wantEnv["SB_PAT_LOCAL_LISTEN"]); err == nil {
			env, _ := dig(agent, "env").([]any)
			for _, e := range env {
				name, _ := dig(e, "name").(string)
				v, _ := dig(e, "value").(string)
				if name == "SB_PAT_LOCAL_LISTEN" {
					continue
				}
				_, p, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(v, "http://"), "https://"))
				if (err == nil && p == adminPort) || (strings.HasSuffix(name, "_PORT") && v == adminPort) {
					t.Errorf("%s: %s=%q takes the admin listener's port %s", role, name, v, adminPort)
				}
			}
			for _, c := range []string{"agent", "edge"} {
				ports, _ := dig(containerNamed(tpl, c), "ports").([]any)
				for _, p := range ports {
					if fmt.Sprint(dig(p, "containerPort")) == adminPort {
						t.Errorf("%s: container %s opens the admin listener's port %s", role, c, adminPort)
					}
				}
			}
		}
		for _, k := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
			if _, ok := envValue(agent, k); !ok || !strings.Contains(body, "name: \"aws-keys\", key: "+k) {
				t.Errorf("%s: %s does not come from the Secret aws-keys", role, k)
			}
		}
		if m := mounts(agent); m["public-api"] != "/run/sandboxd-public" || m["aws-ca"] != "/etc/aerolvm/aws-ca" {
			t.Errorf("%s: agent mounts %v", role, m)
		}
		if edge := containerNamed(tpl, "edge"); role != "server" && mounts(edge)["public-api"] != "/run/sandboxd-public" {
			t.Errorf("%s: the edge does not share the socket folder: %v", role, mounts(edge))
		}
		if !strings.Contains(body, "name: public-api, emptyDir: {}") || !strings.Contains(body, "name: s3-ca") {
			t.Errorf("%s: no socket or CA volume", role)
		}
		// Review S3, S4: no mesh sidecar; IRSA's role in the agent alone.
		skip := map[string]string{"server": "setup", "gateway": "edge,setup", "worker": "runtime,edge,egress,preflight,setup"}[role]
		for k, v := range map[string]string{"sidecar.istio.io/inject": "false", "linkerd.io/inject": "disabled", "eks.amazonaws.com/skip-containers": skip} {
			if got := dig(tpl, "metadata", "annotations", k); got != v {
				t.Errorf("%s: annotation %s = %v, want %q", role, k, got, v)
			}
		}
		wantSA := "t-node"
		if role == "gateway" {
			wantSA = "aerolvm-gateway"
		}
		if got := dig(tpl, "spec", "serviceAccountName"); got != wantSA {
			t.Errorf("%s: service account %v, want %s", role, got, wantSA)
		}
	}
	accounts := map[string]any{}
	for _, sa := range docsOfKind(docs, "ServiceAccount") {
		accounts[fmt.Sprint(dig(sa, "metadata", "namespace"), "/", dig(sa, "metadata", "name"))] =
			dig(sa, "metadata", "annotations", "eks.amazonaws.com/role-arn")
	}
	for _, sa := range []string{"aerolvm/t-node", "aerolvm-workers/t-node", "<nil>/aerolvm-gateway"} {
		if accounts[sa] != "arn:aws:iam::1:role/a" {
			t.Errorf("service account %s: role annotation %v (accounts %v)", sa, accounts[sa], accounts)
		}
	}
	caddy := 0
	for _, cm := range docsOfKind(docs, "ConfigMap") {
		if f, ok := dig(cm, "data", "Caddyfile").(string); ok {
			caddy++
			if !strings.Contains(f, "reverse_proxy unix//run/sandboxd-public/api/api.sock {") || strings.Contains(f, "127.0.0.1:21212") ||
				!strings.Contains(f, "@api path /health /ready /v1 /v1/*") {
				t.Errorf("%v: Caddyfile does not send the API to the public socket:\n%s", dig(cm, "metadata", "namespace"), f)
			}
		}
	}
	if caddy != 2 {
		t.Errorf("%d Caddyfiles, want the release and worker namespaces'", caddy)
	}
	portForward := func(docs []map[string]any) map[any]bool {
		out := map[any]bool{}
		for _, role := range docsOfKind(docs, "Role") {
			rules, _ := dig(role, "rules").([]any)
			for _, r := range rules {
				if fmt.Sprint(dig(r, "resources")) == "[pods/portforward]" && fmt.Sprint(dig(r, "verbs")) == "[create]" {
					out[dig(role, "metadata", "namespace")] = true
				}
			}
		}
		return out
	}
	if got := portForward(docs); len(got) != 1 || !got["aerolvm"] {
		t.Errorf("port-forward granted in %v, want the release namespace alone", got)
	}

	// Off: none of it, and Caddy on 127.0.0.1.
	docs, err = renderChart(t, root, helm, with("identity.enabled=true")...)
	if err != nil {
		t.Fatal(err)
	}
	for role, body := range podTemplates(t, docs) {
		// No annotations at all: with enterprise mode off a node pod is as
		// it was before it (round-2 review).
		var tpl map[string]any
		if err := yaml.Unmarshal([]byte(body), &tpl); err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		if a := dig(tpl, "metadata", "annotations"); a != nil {
			t.Errorf("off: the %s template has annotations %v", role, a)
		}
		for _, never := range []string{"SB_PAT_SCOPE", "SB_PUBLIC_API_SOCKET", "SB_PAT_LOCAL_LISTEN", "public-api", "SB_AUDIT_", "AWS_", "serviceAccountName: t-node", "skip-containers", "sidecar.istio.io", "linkerd.io"} {
			if strings.Contains(body, never) {
				t.Errorf("off: the %s template carries %s", role, never)
			}
		}
	}
	for _, cm := range docsOfKind(docs, "ConfigMap") {
		if f, ok := dig(cm, "data", "Caddyfile").(string); ok && !strings.Contains(f, "reverse_proxy 127.0.0.1:21212 {") {
			t.Errorf("off: Caddyfile:\n%s", f)
		}
	}
	if got := portForward(docs); len(got) != 0 {
		t.Errorf("off: port-forward granted in %v", got)
	}
	if len(docsOfKind(docs, "ServiceAccount")) != 2 {
		t.Errorf("off: %d service accounts, want the operator's and the CRD job's", len(docsOfKind(docs, "ServiceAccount")))
	}

	// The witness and the export work without enterprise mode too; a
	// webhook export takes its token from a Secret.
	docs, err = renderChart(t, root, helm, with("audit.witness.bucket=w", "audit.export.backend=webhook",
		"audit.export.webhook.url=http://collector:8080/x", "audit.export.webhook.bearerTokenSecret=hook")...)
	if err != nil {
		t.Fatal(err)
	}
	for role, body := range podTemplates(t, docs) {
		for _, want := range []string{`SB_AUDIT_WITNESS_S3_BUCKET, value: "w"`, "SB_AUDIT_EXPORT_BACKEND, value: webhook",
			`SB_SECRET_AUDIT_EXPORT_URL, value: "http://collector:8080/x"`, `secretKeyRef: { name: "hook", key: "token" }`} {
			if !strings.Contains(body, want) {
				t.Errorf("open-source witness and webhook: the %s template lacks %q", role, want)
			}
		}
		if strings.Contains(body, "SB_PAT_SCOPE") {
			t.Errorf("%s: host scope without enterprise mode", role)
		}
	}

	for _, tc := range []struct {
		sets []string
		want string
	}{
		{[]string{"identity.enabled=true", "enterprise.enabled=true", "audit.export.backend=s3", "audit.export.s3.bucket=a"}, "needs audit.witness.bucket"},
		{[]string{"identity.enabled=true", "enterprise.enabled=true", "audit.witness.bucket=w"}, "needs audit.export.backend s3 or webhook"},
		{append([]string{"identity.enabled=true", "audit.witness.endpoint=http://minio:9000"}, enterpriseSets...), "audit.witness.endpoint http://minio:9000 must be https"},
		{append([]string{"identity.enabled=true", "audit.export.s3.endpoint=http://minio:9000"}, enterpriseSets...), "audit.export.s3.endpoint http://minio:9000 must be https"},
		{[]string{"identity.enabled=true", "enterprise.enabled=true", "audit.witness.bucket=w", "audit.export.backend=webhook",
			"audit.export.webhook.url=https://c"}, "needs bearerTokenSecret"},
		{[]string{"identity.enabled=true", "enterprise.enabled=true", "audit.witness.bucket=w", "audit.export.backend=webhook",
			"audit.export.webhook.url=http://c", "audit.export.webhook.bearerTokenSecret=h"}, "audit.export.webhook.url http://c must be https"},
		{[]string{"audit.export.backend=stdout"}, `audit.export.backend "stdout"`},
		{[]string{"audit.export.backend=s3"}, "needs audit.export.s3.bucket"},
		{[]string{"audit.export.backend=webhook"}, "needs audit.export.webhook.url"},
		{append([]string{"identity.enabled=true", "worker.extraEnv.SB_PAT_SCOPE=any"}, enterpriseSets...), "SB_PAT_SCOPE is set twice"},
		{append([]string{"identity.enabled=true", "worker.extraEnv.SB_PAT_LOCAL_LISTEN=127.0.0.1:1"}, enterpriseSets...), "SB_PAT_LOCAL_LISTEN is set twice"},
		{[]string{"audit.credentials.existingSecret=k", "worker.extraEnv.AWS_ACCESS_KEY_ID=x"}, "AWS_ACCESS_KEY_ID is set twice"},
		{[]string{"audit.credentials.caBundle.existingConfigMap=c", "worker.extraEnv.AWS_CA_BUNDLE=/x"}, "AWS_CA_BUNDLE is set twice"},
		{[]string{"audit.witness.bucket=w", "worker.extraEnv.SB_AUDIT_WITNESS_S3_BUCKET=x"}, "SB_AUDIT_WITNESS_S3_BUCKET is set twice"},
		// Past 10 gateways enterprise mode needs shard-aware traffic in
		// front of them, which only the bank can vouch for.
		{append([]string{"identity.enabled=true", "cluster.gateways.minReplicas=11"}, enterpriseSets...), "enterprise.enabled with 11 gateways"},
		{append([]string{"identity.enabled=true", "cluster.gateways.minReplicas=11", "worker.extraEnv.SB_CLUSTER_SHARD_AWARE_INGRESS=false"}, enterpriseSets...), "enterprise.enabled with 11 gateways"},
		// One gateway per zone at least.
		{append([]string{"identity.enabled=true", "cluster.zones={a,b,c,d,e,f,g,h,i,j,k}"}, enterpriseSets...), "enterprise.enabled with 11 gateways"},
	} {
		if _, err := renderChart(t, root, helm, with(tc.sets...)...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v; want a refusal naming %q", tc.sets, err, tc.want)
		}
	}
	for _, sets := range [][]string{{"cluster.gateways.minReplicas=10"}, {"cluster.gateways.minReplicas=11", "worker.extraEnv.SB_CLUSTER_SHARD_AWARE_INGRESS=true"},
		// sandboxd reads the opt-in with ParseBool; the chart reads it the same.
		{"cluster.gateways.minReplicas=11", "worker.extraEnv.SB_CLUSTER_SHARD_AWARE_INGRESS=TRUE"},
		{"cluster.gateways.minReplicas=11", "worker.extraEnv.SB_CLUSTER_SHARD_AWARE_INGRESS=1"},
		// A URL's scheme is not case-sensitive.
		{"audit.witness.endpoint=HTTPS://s3.example.test"},
		// Only the export backend in use is held to https.
		{"audit.export.s3.endpoint=http://unused.example", "audit.export.backend=webhook", "audit.export.webhook.url=https://c", "audit.export.webhook.bearerTokenSecret=h"},
	} {
		if _, err := renderChart(t, root, helm, with(append(append([]string{"identity.enabled=true"}, enterpriseSets...), sets...)...)...); err != nil {
			t.Errorf("enterprise mode with %v: %v", sets, err)
		}
	}
	// Single mode never runs enterprise mode: its pod has no annotations,
	// as before, unless the chart makes the IRSA account; then only IRSA's.
	single, err := renderChart(t, root, helm)
	if err != nil {
		t.Fatal(err)
	}
	if sts := docsOfKind(single, "StatefulSet"); len(sts) != 1 || dig(sts[0], "spec", "template", "metadata", "annotations") != nil {
		t.Errorf("single mode: the worker pod has annotations")
	}
	single, err = renderChart(t, root, helm, "audit.credentials.serviceAccount.create=true")
	if err != nil {
		t.Fatal(err)
	}
	if sts := docsOfKind(single, "StatefulSet"); len(sts) != 1 || !reflect.DeepEqual(dig(sts[0], "spec", "template", "metadata", "annotations"),
		map[string]any{"eks.amazonaws.com/skip-containers": "runtime,edge,egress,preflight,setup"}) {
		t.Errorf("single mode with IRSA: annotations %v", dig(docsOfKind(single, "StatefulSet")[0], "spec", "template", "metadata", "annotations"))
	}
	// Single mode has no operator to make a token for: refused.
	if _, err := renderChart(t, root, helm, append([]string{"identity.enabled=true"}, enterpriseSets...)...); err == nil ||
		!strings.Contains(err.Error(), "enterprise.enabled needs mode=cluster") {
		t.Errorf("single mode took enterprise mode: %v", err)
	}

	// The bank preset runs enterprise mode, with the witness, an s3 export
	// and IRSA.
	bank, err := runTool(t, root, helm, "template", "t", filepath.Join(root, "charts", "aerolvm"),
		"-f", filepath.Join(root, "charts", "aerolvm", "values-bank-eks.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for want, n := range map[string]int{`SB_ENTERPRISE_MODE, value: "true"`: 3, "SB_PAT_SCOPE, value: host": 3,
		`SB_AUDIT_WITNESS_S3_BUCKET, value: "<audit-witness-bucket>"`: 3, "SB_AUDIT_EXPORT_BACKEND, value: s3": 3,
		"serviceAccountName: t-node": 3, "eks.amazonaws.com/role-arn:": 2, "reverse_proxy unix//run/sandboxd-public/api/api.sock": 2} {
		if got := strings.Count(bank, want); got != n {
			t.Errorf("the bank preset renders %q %d times, want %d", want, got, n)
		}
	}
}

// In enterprise mode the notes say the admin token works only through a
// port-forward to a server pod, with no step that sends it to the public
// address; after an upgrade they list the pods to replace (issue #1349).
func TestKubernetesChartNotesInEnterpriseMode(t *testing.T) {
	root := repoRoot(t)
	helm := chartTool(t, "HELM", "helm")
	if v, _ := runTool(t, root, helm, "version", "--short"); !helmAtLeast(v, 3, 8) {
		t.Skipf("helm %s is older than 3.8, the chart's minimum", strings.TrimSpace(v))
	}
	sets := append([]string{"mode=cluster", "cluster.zones={a}", "cluster.workerPools[0].name=g",
		"cluster.workerPools[0].machine.cpu=8", "cluster.workerPools[0].machine.memoryGiB=32",
		"edge.enabled=true", "edge.domain=sb.example.test", "edge.existingTLSSecret=edge-tls", "identity.enabled=true"}, enterpriseSets...)
	install := renderNotes(t, root, helm, false, sets...)
	for _, want := range []string{"enterprise mode on", "port-forward pod/aerolvm-server-0 21212:21219",
		"aerolvm login http://127.0.0.1:21212 --token-stdin", "aerolvm token create --name <you> --role admin"} {
		if !strings.Contains(install, want) {
			t.Errorf("install notes lack %q:\n%s", want, install)
		}
	}
	if strings.Contains(install, "point an SDK at https://sb.example.test with it") || strings.Contains(install, "reaches only pods made after it was turned") ||
		strings.Count(install, "{.data.token}' | base64 -d") != 1 {
		t.Errorf("install notes send the admin token to the public address, or speak of an upgrade:\n%s", install)
	}
	upgrade := renderNotes(t, root, helm, true, sets...)
	for _, want := range []string{"Enterprise mode, like API tokens, reaches only pods made after", "gateway pods one at a time", "502",
		// Review F2: never in the same upgrade as a version upgrade.
		"after any version upgrade has", "finished",
		// Round 2: turning it off needs the pods replaced too.
		"To turn enterprise mode off later", "the server pods at the least", "stops renewing"} {
		if !strings.Contains(upgrade, want) {
			t.Errorf("upgrade notes lack %q", want)
		}
	}
	// Round 3: the turned-off note comes from the previous release's pod
	// templates (still in the cluster while helm upgrade renders the notes),
	// never from a Secret: helm template has no cluster to ask, so the
	// source holds the rule.
	notesSrc, err := os.ReadFile(filepath.Join(root, "charts", "aerolvm", "templates", "NOTES.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(notesSrc), `lookup "v1" "Secret"`) ||
		!strings.Contains(string(notesSrc), `lookup "v1" "ConfigMap" .Release.Namespace (printf "%s-pod-templates" (include "aerolvm.name" .))`) ||
		!strings.Contains(string(notesSrc), `contains "SB_PAT_SCOPE" (index ($previous.data | default dict) "server" | default "")`) {
		t.Error("NOTES.txt does not tell an upgrade that turned enterprise mode off by the previous pod templates alone")
	}
	off := renderNotes(t, root, helm, true, sets[:len(sets)-len(enterpriseSets)]...)
	if strings.Contains(off, "Enterprise mode") || strings.Contains(off, "port-forward pod/") ||
		!strings.Contains(off, "point an SDK at https://sb.example.test with it") {
		t.Errorf("enterprise off, the notes changed:\n%s", off)
	}
}

// worker.registryCA: the worker's agent trusts a bank's own CA for image
// pulls (Go reads SSL_CERT_DIR's folders beside the image's bundle), in
// both modes, with only the CA's key mounted. Off, nothing changes. The
// EKS bank drills' registry is HTTPS under a private CA through it.
func TestKubernetesChartRegistryCA(t *testing.T) {
	root := repoRoot(t)
	helm := chartTool(t, "HELM", "helm")
	if v, _ := runTool(t, root, helm, "version", "--short"); !helmAtLeast(v, 3, 8) {
		t.Skipf("helm %s is older than 3.8, the chart's minimum", strings.TrimSpace(v))
	}
	cluster := []string{"mode=cluster", "cluster.zones={a}", "cluster.workerPools[0].name=g",
		"cluster.workerPools[0].machine.cpu=8", "cluster.workerPools[0].machine.memoryGiB=32"}
	const env = `SSL_CERT_DIR, value: "/etc/ssl/certs:/etc/aerolvm/registry-ca"`
	for _, mode := range [][]string{cluster, nil} {
		on, err := renderChart(t, root, helm, append(append([]string{}, mode...), "worker.registryCA.existingConfigMap=bank-ca", "worker.registryCA.key=root.pem")...)
		if err != nil {
			t.Fatal(err)
		}
		off, err := renderChart(t, root, helm, mode...)
		if err != nil {
			t.Fatal(err)
		}
		worker := func(docs []map[string]any) string {
			if mode != nil {
				return podTemplates(t, docs)["worker"]
			}
			b, _ := yaml.Marshal(docsOfKind(docs, "StatefulSet")[0])
			return string(b)
		}
		w := worker(on)
		for _, want := range []string{"SSL_CERT_DIR", "/etc/ssl/certs:/etc/aerolvm/registry-ca", "registry-ca", "/etc/aerolvm/registry-ca", "bank-ca", "root.pem", "registry-ca.crt"} {
			if !strings.Contains(w, want) {
				t.Errorf("mode %v: the worker lacks %q", mode, want)
			}
		}
		if mode != nil && !strings.Contains(w, env) {
			t.Errorf("cluster mode: the worker template lacks %s", env)
		}
		for role, body := range map[string]string{"worker": worker(off)} {
			if strings.Contains(body, "SSL_CERT_DIR") || strings.Contains(body, "registry-ca") {
				t.Errorf("mode %v, off: the %s carries the registry CA", mode, role)
			}
		}
		if mode != nil {
			for _, role := range []string{"server", "gateway"} {
				if strings.Contains(podTemplates(t, on)[role], "registry-ca") {
					t.Errorf("the %s pulls no images, yet trusts the registry CA", role)
				}
			}
		}
	}
}
