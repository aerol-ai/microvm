package api

import (
	"expvar"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/aerol-ai/microvm/internal/usagemetrics"
)

const prometheusContentType = "text/plain; version=0.0.4; charset=utf-8"

type prometheusSample struct {
	name   string
	labels []prometheusLabel
	value  string
	typ    string
}

type prometheusLabel struct {
	name  string
	value string
}

func (s *Server) servePrometheusMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", prometheusContentType)
	w.Header().Set("Cache-Control", "no-store")
	err := writePrometheusExpvars(w)
	if err == nil {
		err = writeUsageMetrics(w, s.usageMeter())
	}
	if err != nil {
		s.logger.Warn("prometheus metrics render failed", "error", err)
	}
}

// usageMeter is the per-owner usage exporter's counters (C20), or nil when
// it is off or there is no service (tests).
func (s *Server) usageMeter() *usagemetrics.Meter {
	if s.service == nil {
		return nil
	}
	return s.service.UsageMeter()
}

// writeUsageMetrics prints the usage exporter's families after the expvar
// ones. They are not expvars on purpose: an owner label needs a real label
// name (expvar maps only give key, key2), and staying out of expvar keeps
// owner names off /debug/vars and out of the OTEL exporter, so they leave
// the node only when Prometheus scrapes this endpoint. A family with no
// series is left out, so with the exporter off nothing is printed.
func writeUsageMetrics(w io.Writer, m *usagemetrics.Meter) error {
	if m == nil {
		return nil
	}
	for _, f := range m.Collect() {
		if len(f.Samples) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", f.Name, f.Help, f.Name, f.Type); err != nil {
			return err
		}
		for _, smp := range f.Samples {
			labels := make([]prometheusLabel, 0, len(smp.Labels))
			for _, l := range smp.Labels {
				labels = append(labels, prometheusLabel{name: l.Name, value: l.Value})
			}
			if _, err := fmt.Fprintf(w, "%s%s %s\n", f.Name, prometheusLabelsString(labels),
				strconv.FormatFloat(smp.Value, 'g', -1, 64)); err != nil {
				return err
			}
		}
	}
	return nil
}

func writePrometheusExpvars(w io.Writer) error {
	var samples []prometheusSample
	expvar.Do(func(kv expvar.KeyValue) {
		if !strings.HasPrefix(kv.Key, "aerolvm_") {
			return
		}
		collectPrometheusSamples(prometheusMetricName(kv.Key), kv.Value, nil, &samples)
	})
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].name != samples[j].name {
			return samples[i].name < samples[j].name
		}
		return prometheusLabelsString(samples[i].labels) < prometheusLabelsString(samples[j].labels)
	})
	seen := make(map[string]struct{})
	for _, s := range samples {
		if _, ok := seen[s.name]; !ok {
			seen[s.name] = struct{}{}
			if _, err := fmt.Fprintf(w, "# HELP %s AerolVM expvar metric %s.\n", s.name, s.name); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "# TYPE %s %s\n", s.name, s.typ); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s%s %s\n", s.name, prometheusLabelsString(s.labels), s.value); err != nil {
			return err
		}
	}
	return nil
}

func collectPrometheusSamples(name string, v expvar.Var, labels []prometheusLabel, samples *[]prometheusSample) {
	if m, ok := v.(*expvar.Map); ok {
		index := len(labels) + 1
		labelName := "key"
		if index > 1 {
			labelName = "key" + strconv.Itoa(index)
		}
		m.Do(func(kv expvar.KeyValue) {
			childLabels := append(append([]prometheusLabel(nil), labels...), prometheusLabel{name: labelName, value: kv.Key})
			collectPrometheusSamples(name, kv.Value, childLabels, samples)
		})
		return
	}
	value, ok := prometheusValue(v)
	if !ok {
		return
	}
	*samples = append(*samples, prometheusSample{
		name:   name,
		labels: append([]prometheusLabel(nil), labels...),
		value:  value,
		typ:    prometheusMetricType(name),
	})
}

func prometheusValue(v expvar.Var) (string, bool) {
	switch typed := v.(type) {
	case *expvar.Int:
		return strconv.FormatInt(typed.Value(), 10), true
	case *expvar.Float:
		value := typed.Value()
		if !isFinite(value) {
			return "", false
		}
		return strconv.FormatFloat(value, 'g', -1, 64), true
	default:
		raw := strings.TrimSpace(v.String())
		value, err := strconv.ParseFloat(raw, 64)
		if err != nil || !isFinite(value) {
			return "", false
		}
		return strconv.FormatFloat(value, 'g', -1, 64), true
	}
}

func isFinite(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}

func prometheusMetricType(name string) string {
	// Histogram families publish three monotonically non-decreasing series
	// (_bucket, _count, _sum) alongside their _total counters. Prometheus
	// tooling (rate(), histogram_quantile()) requires all of them to be
	// declared as counters; tagging them as gauges silently breaks queries.
	switch {
	case strings.HasSuffix(name, "_total"),
		strings.HasSuffix(name, "_bucket"),
		strings.HasSuffix(name, "_count"),
		strings.HasSuffix(name, "_sum"):
		return "counter"
	}
	return "gauge"
}

func prometheusMetricName(name string) string {
	var b strings.Builder
	for i, r := range name {
		valid := r == '_' || r == ':' || unicode.IsLetter(r) || (i > 0 && unicode.IsDigit(r))
		if !valid {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if out == "" || unicode.IsDigit(rune(out[0])) {
		return "_" + out
	}
	return out
}

func prometheusLabelsString(labels []prometheusLabel) string {
	if len(labels) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, label := range labels {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(label.name)
		b.WriteString("=\"")
		b.WriteString(escapePrometheusLabel(label.value))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func escapePrometheusLabel(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return value
}
