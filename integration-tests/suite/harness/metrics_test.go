package harness

import (
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

const sampleMetrics = `# HELP aerolvm_auth_failures_total AerolVM expvar metric aerolvm_auth_failures_total.
# TYPE aerolvm_auth_failures_total counter
aerolvm_auth_failures_total{key="token",key2="malformed"} 3
aerolvm_auth_failures_total{key="token",key2="unknown_or_revoked"} 7
aerolvm_auth_failures_total_extra{key="token",key2="malformed"} 99
aerolvm_identity_jwks_fetch_total{key="itest",key2="ok"} 2
aerolvm_identity_jwks_last_success_timestamp{key="itest"} 1.7e+09
aerolvm_quoted{key="a \"b\" c",key2="x\\y"} 5
aerolvm_plain 11
`

func TestMetricValue(t *testing.T) {
	for _, tc := range []struct {
		name   string
		metric string
		labels map[string]string
		want   float64
		ok     bool
	}{
		{"labelled", "aerolvm_auth_failures_total", map[string]string{"key": "token", "key2": "malformed"}, 3, true},
		{"other label value", "aerolvm_auth_failures_total", map[string]string{"key": "token", "key2": "unknown_or_revoked"}, 7, true},
		{"partial labels match the first series", "aerolvm_auth_failures_total", map[string]string{"key": "token"}, 3, true},
		{"absent series", "aerolvm_auth_failures_total", map[string]string{"key": "oidc"}, 0, false},
		{"a longer name sharing the prefix is not the series", "aerolvm_auth_failures_total", map[string]string{"key2": "none"}, 0, false},
		{"exponent", "aerolvm_identity_jwks_last_success_timestamp", map[string]string{"key": "itest"}, 1.7e9, true},
		{"escaped label values", "aerolvm_quoted", map[string]string{"key": `a "b" c`, "key2": `x\y`}, 5, true},
		{"no labels", "aerolvm_plain", nil, 11, true},
		{"unknown metric", "aerolvm_nope", nil, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := MetricValue(sampleMetrics, tc.metric, tc.labels)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("MetricValue = %v, %v; want %v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
	if MetricValueOrZero(sampleMetrics, "aerolvm_nope", nil) != 0 || MetricValueOrZero(sampleMetrics, "aerolvm_plain", nil) != 11 {
		t.Fatal("MetricValueOrZero")
	}
	if got := parseMetricLabels(`broken`); len(got) != 0 {
		t.Fatalf("garbage labels = %v", got)
	}
}

func TestParseAuditLinesAndFilters(t *testing.T) {
	out := strings.Join([]string{
		`{"time":"2026-10-18T00:00:00Z","kind":"api","result":"ok","sandbox_id":"sb1","caller":{"kind":"token","id":"tok_A","via":"node-2"},"request":{"method":"POST","route":"/v1/sandboxes/{id}/toolbox/{path...}","status":200}}`,
		`{"time":"2026-10-18T00:00:01Z","kind":"auth_denied","result":"denied","request":{"method":"GET","route":"/v1/whoami","status":401,"source":"198.51.100.7"}}`,
		`{"torn`,
		`__AUDIT_END__`,
		``,
	}, "\n")
	evs := ParseAuditLines(out)
	if len(evs) != 2 {
		t.Fatalf("parsed %d events, want 2: %+v", len(evs), evs)
	}
	if CallerID(evs[0]) != "tok_A" || evs[0].Caller.Via != "node-2" || RouteOf(evs[0]) != "POST /v1/sandboxes/{id}/toolbox/{path...}" {
		t.Fatalf("event 0 = %+v", evs[0])
	}
	if CallerID(evs[1]) != "" || evs[1].Request.Source != "198.51.100.7" {
		t.Fatalf("event 1 = %+v", evs[1])
	}
	if RouteOf(auditlog.Event{}) != "" {
		t.Fatal("RouteOf an event with no request")
	}
	denied := FilterAudit(evs, func(ev auditlog.Event) bool { return ev.Kind == auditlog.KindAuthDenied })
	if len(denied) != 1 || denied[0].Result != "denied" {
		t.Fatalf("FilterAudit = %+v", denied)
	}
}

func TestNodeAuditEventsReadsByStdin(t *testing.T) {
	var script, stdin string
	prev := sshRunnerStdin
	t.Cleanup(func() { sshRunnerStdin = prev })
	sshRunnerStdin = func(_ *testing.T, _ string, s, in string) (string, error) {
		script, stdin = s, in
		return `{"kind":"api","result":"ok","caller":{"kind":"token","id":"tok_A"}}` + "\n__AUDIT_END__\n", nil
	}
	evs, err := NodeAuditEvents(t, testNode(), "tok_A")
	if err != nil || len(evs) != 1 || CallerID(evs[0]) != "tok_A" {
		t.Fatalf("NodeAuditEvents = %+v, %v", evs, err)
	}
	if stdin != "tok_A\n" || strings.Contains(script, "tok_A") {
		t.Fatalf("the needle must travel on stdin: script %q stdin %q", script, stdin)
	}
	for _, want := range []string{"grep -F", "secrets.jsonl", "secrets.spill.jsonl"} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	// No terminator: the read failed, and an empty answer would read as
	// "no record", which is a verdict for UC-273.
	sshRunnerStdin = func(*testing.T, string, string, string) (string, error) { return "sudo: unknown user", nil }
	if _, err := NodeAuditEvents(t, testNode(), "tok_A"); err == nil {
		t.Fatal("a failed read returned no error")
	}
	if _, err := NodeAuditEvents(t, IntegrationNode{Name: "x"}, "tok_A"); err == nil {
		t.Fatal("read a node with no address")
	}
}
