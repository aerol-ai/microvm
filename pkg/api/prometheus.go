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
	if err := writePrometheusExpvars(w); err != nil {
		s.logger.Warn("prometheus metrics render failed", "error", err)
	}
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
	if strings.HasSuffix(name, "_total") {
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
