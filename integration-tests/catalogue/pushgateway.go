package catalogue

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// PushgatewayURL reads AEROL_PUSHGATEWAY_URL. Empty means push is disabled.
func PushgatewayURL() string {
	return strings.TrimSpace(os.Getenv("AEROL_PUSHGATEWAY_URL"))
}

// defaultPushClient delivers the real metric payloads (bench percentiles,
// catalogue rollups). Those are the data we actually want in Prometheus and
// there are only a handful per run, so a generous timeout is worth paying.
var defaultPushClient = &http.Client{Timeout: 15 * time.Second}

// PushText posts Prometheus text exposition to Pushgateway job/instance.
func PushText(job, instance, body string) error {
	return pushTextWith(defaultPushClient, job, instance, body)
}

func pushTextWith(client *http.Client, job, instance, body string) error {
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

var (
	// heartbeatClient uses a short timeout because a heartbeat is disposable:
	// against a dead or unreachable Pushgateway we drop the beat rather than
	// wait out a full dial. PushText keeps the longer timeout for the real
	// metric payloads we actually want delivered.
	heartbeatClient = &http.Client{Timeout: 2 * time.Second}

	// heartbeatDisabled trips after the first failed heartbeat. Heartbeats fire
	// once per simulation (dozens per run); a dead Pushgateway used to stall the
	// sim loop 15s × N (~730s on a 56-sim pass). One failure ⇒ assume the
	// endpoint is gone and skip the rest for this process.
	heartbeatDisabled atomic.Bool
)

// PushSimHeartbeat fires a best-effort liveness gauge for one sim. It is
// fire-and-forget: it never blocks the caller and never fails a run — losing a
// heartbeat is harmless, stalling a run is not. The push runs in the
// background with a short timeout, and a single failure disables further
// heartbeats so an unreachable Pushgateway can't spawn a doomed goroutine per
// remaining sim.
func PushSimHeartbeat(simID string) error {
	if PushgatewayURL() == "" || heartbeatDisabled.Load() {
		return nil
	}
	go func() {
		if err := doSimHeartbeat(simID); err != nil {
			heartbeatDisabled.Store(true)
		}
	}()
	return nil
}

// doSimHeartbeat performs the synchronous heartbeat push. It is unexported and
// separate from PushSimHeartbeat's goroutine wrapper so tests can exercise the
// push (and the short-timeout client) deterministically.
func doSimHeartbeat(simID string) error {
	body := FormatGauge("aerolvm_sim_heartbeat", 1, map[string]string{"sim": simID})
	return pushTextWith(heartbeatClient, "aerolvm_sims", simID, body)
}
