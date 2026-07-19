package catalogue

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// PushgatewayURL reads AEROL_PUSHGATEWAY_URL. Empty means push is disabled.
func PushgatewayURL() string {
	return strings.TrimSpace(os.Getenv("AEROL_PUSHGATEWAY_URL"))
}

// PushText posts Prometheus text exposition to Pushgateway job/instance.
func PushText(job, instance, body string) error {
	base := PushgatewayURL()
	if base == "" {
		return nil
	}
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil {
		return fmt.Errorf("pushgateway: parse url: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/metrics/job/" + url.PathEscape(job) + "/instance/" + url.PathEscape(instance)
	req, err := http.NewRequest(http.MethodPut, u.String(), strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("pushgateway: push: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("pushgateway: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// FormatGauge renders a single Prometheus gauge line (no HELP/TYPE).
func FormatGauge(name string, value float64, labels map[string]string) string {
	var b bytes.Buffer
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		first := true
		for k, v := range labels {
			if !first {
				b.WriteByte(',')
			}
			first = false
			fmt.Fprintf(&b, `%s=%q`, k, v)
		}
		b.WriteByte('}')
	}
	fmt.Fprintf(&b, " %g\n", value)
	return b.String()
}

// FormatPercentileGauges emits p50/p90/p99 gauges for a runtime label.
func FormatPercentileGauges(metricPrefix, runtime string, p50, p90, p99 int64) string {
	labels := map[string]string{"runtime": runtime}
	var b strings.Builder
	b.WriteString(FormatGauge(metricPrefix+"_p50_ms", float64(p50), labels))
	b.WriteString(FormatGauge(metricPrefix+"_p90_ms", float64(p90), labels))
	b.WriteString(FormatGauge(metricPrefix+"_p99_ms", float64(p99), labels))
	return b.String()
}

// PushSimHeartbeat pushes a 1-valued gauge proving the sim runner is alive.
func PushSimHeartbeat(simID string) error {
	body := FormatGauge("aerolvm_sim_heartbeat", 1, map[string]string{"sim": simID})
	return PushText("aerolvm_sims", simID, body)
}
