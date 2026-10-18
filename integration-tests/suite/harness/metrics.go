package harness

import (
	"strconv"
	"strings"
)

// MetricValue reads one sample from /v1/metrics text: the series named name
// whose labels include every pair in labels. sandboxd exports nested expvar
// maps as positional key/key2 labels (pkg/api/prometheus.go), so
// aerolvm_auth_failures_total{key="token",key2="malformed"} is
// MetricValue(text, "aerolvm_auth_failures_total", map[string]string{"key":
// "token", "key2": "malformed"}). ok is false when no series matches, which
// for a counter means it has not been incremented on that node yet.
func MetricValue(text, name string, labels map[string]string) (float64, bool) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.HasPrefix(line, name) {
			continue
		}
		rest := line[len(name):]
		var labelText string
		switch {
		case strings.HasPrefix(rest, "{"):
			end := strings.Index(rest, "}")
			if end < 0 {
				continue
			}
			labelText, rest = rest[1:end], rest[end+1:]
		case strings.HasPrefix(rest, " "):
		default:
			continue // a longer metric name sharing this prefix
		}
		if !labelsMatch(parseMetricLabels(labelText), labels) {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			continue
		}
		return v, true
	}
	return 0, false
}

// MetricValueOrZero is MetricValue with an absent series read as 0, the
// value of a counter nothing has incremented.
func MetricValueOrZero(text, name string, labels map[string]string) float64 {
	v, _ := MetricValue(text, name, labels)
	return v
}

func labelsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// parseMetricLabels parses `a="x",b="y"`, honouring \" and \\ escapes.
func parseMetricLabels(s string) map[string]string {
	out := map[string]string{}
	for len(s) > 0 {
		eq := strings.IndexByte(s, '=')
		if eq < 0 || eq+1 >= len(s) || s[eq+1] != '"' {
			return out
		}
		key := strings.TrimSpace(s[:eq])
		var val strings.Builder
		i := eq + 2
		for ; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) {
				i++
				switch s[i] {
				case 'n':
					val.WriteByte('\n')
				default:
					val.WriteByte(s[i])
				}
				continue
			}
			if s[i] == '"' {
				break
			}
			val.WriteByte(s[i])
		}
		out[key] = val.String()
		s = strings.TrimPrefix(strings.TrimSpace(s[min(i+1, len(s)):]), ",")
	}
	return out
}
