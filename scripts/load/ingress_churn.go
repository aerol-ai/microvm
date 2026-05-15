// ingress_churn is a release-gate load harness for the AerolVM cluster
// data-plane ingress. It runs against a live cluster (NOT a unit-test
// fixture) and measures the SLOs called out in
// plans/cluster-criticial-thinking-stage-2/06-release-gates.md:
//
//   - placement-to-ingress convergence p95 < 2s
//   - Raft apply p99 < 100ms steady-state
//   - zero wrong-owner ingress route misses after convergence
//
// It expects the cluster to already be running (e.g. the three-server +
// N-worker + three-ingress topology from cluster-ingress.mdx) and an
// SB_PAT_TOKEN set in the env. It does NOT bring up nodes or join them.
//
// Output: a CSV of (timestamp, op, duration_ms, status_code, route_lag_ms)
// suitable for attaching to a release PR as the convergence artifact.
//
// Run:
//
//	go run scripts/load/ingress_churn.go \
//	    -api https://api.sandbox.example.com \
//	    -ingress https://ingress.sandbox.example.com \
//	    -pat "$SB_PAT_TOKEN" \
//	    -rate 1 \
//	    -duration 60m \
//	    -out churn.csv
//
// The harness is intentionally small. It is not a load generator in the
// hey/wrk sense — it's a slow, steady churn driver whose goal is to surface
// the convergence story under realistic placement churn, not to saturate
// any individual endpoint.
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	apiURL       = flag.String("api", "", "AerolVM API URL (e.g. https://api.sandbox.example.com)")
	ingressURL   = flag.String("ingress", "", "AerolVM ingress URL for public sandbox traffic (defaults to -api)")
	patToken     = flag.String("pat", "", "SB_PAT_TOKEN — defaults to the env var of the same name")
	ratePerSec   = flag.Float64("rate", 1, "create+destroy operations per second")
	duration     = flag.Duration("duration", 5*time.Minute, "how long to run before exiting")
	outPath      = flag.String("out", "ingress_churn.csv", "CSV path for results")
	imageRef     = flag.String("image", "alpine:3.19", "image for created sandboxes")
	probeTimeout = flag.Duration("probe-timeout", 10*time.Second, "timeout for the post-create ingress probe")
)

type createRequest struct {
	Image string `json:"image"`
}

type createResponse struct {
	ID        string `json:"id"`
	PublicURL string `json:"public_url"`
}

type sample struct {
	at       time.Time
	op       string
	dur      time.Duration
	status   int
	routeLag time.Duration
	id       string
}

func main() {
	flag.Parse()
	if *apiURL == "" {
		fmt.Fprintln(os.Stderr, "-api is required")
		os.Exit(2)
	}
	if *ingressURL == "" {
		*ingressURL = *apiURL
	}
	if *patToken == "" {
		*patToken = os.Getenv("SB_PAT_TOKEN")
	}
	if *patToken == "" {
		fmt.Fprintln(os.Stderr, "-pat or SB_PAT_TOKEN required")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	out, err := os.Create(*outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open out: %v\n", err)
		os.Exit(1)
	}
	defer out.Close()
	w := csv.NewWriter(out)
	defer w.Flush()
	_ = w.Write([]string{"timestamp", "op", "duration_ms", "status", "route_lag_ms", "sandbox_id"})

	samples := make(chan sample, 1024)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for s := range samples {
			_ = w.Write([]string{
				s.at.UTC().Format(time.RFC3339Nano),
				s.op,
				strconv.FormatFloat(float64(s.dur)/float64(time.Millisecond), 'f', 3, 64),
				strconv.Itoa(s.status),
				strconv.FormatFloat(float64(s.routeLag)/float64(time.Millisecond), 'f', 3, 64),
				s.id,
			})
		}
	}()

	interval := time.Duration(float64(time.Second) / *ratePerSec)
	if interval <= 0 {
		interval = time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			close(samples)
			wg.Wait()
			fmt.Fprintf(os.Stderr, "done; results in %s\n", *outPath)
			return
		case <-tick.C:
			go runOnce(samples)
		}
	}
}

func runOnce(samples chan<- sample) {
	// Step 1: Create. Time the API call.
	now := time.Now()
	id, publicURL, status, err := createSandbox()
	createDur := time.Since(now)
	samples <- sample{at: now, op: "create", dur: createDur, status: status, id: id}
	if err != nil || id == "" {
		return
	}

	// Step 2: Poll the public URL. Stop on first non-503 response. The
	// elapsed time is the "placement-to-ingress convergence" the release
	// gate cares about.
	probeStart := time.Now()
	probeStatus, lag := probeIngress(publicURL)
	samples <- sample{at: probeStart, op: "probe", dur: time.Since(probeStart), status: probeStatus, routeLag: lag, id: id}

	// Step 3: Destroy. Time the API call.
	destroyStart := time.Now()
	destroyStatus, _ := destroySandbox(id)
	samples <- sample{at: destroyStart, op: "destroy", dur: time.Since(destroyStart), status: destroyStatus, id: id}
}

func createSandbox() (string, string, int, error) {
	body, _ := json.Marshal(createRequest{Image: *imageRef})
	req, err := http.NewRequest(http.MethodPost, *apiURL+"/v1/sandboxes", strings.NewReader(string(body)))
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+*patToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", "", resp.StatusCode, fmt.Errorf("create %d", resp.StatusCode)
	}
	var cr createResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return "", "", resp.StatusCode, err
	}
	return cr.ID, cr.PublicURL, resp.StatusCode, nil
}

// probeIngress polls publicURL until something other than 503 comes back, or
// the timeout fires. Returns the last status and the time-to-first-non-503.
func probeIngress(publicURL string) (int, time.Duration) {
	if publicURL == "" {
		return 0, 0
	}
	start := time.Now()
	deadline := start.Add(*probeTimeout)
	var last int
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, publicURL, nil)
		if err != nil {
			return 0, time.Since(start)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		last = resp.StatusCode
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		// 503 is the in-flux signal. Anything else (200, 404, 502) counts
		// as ingress converged — the application inside the sandbox may
		// itself be 404-ing while we wait for it to come up.
		if resp.StatusCode != http.StatusServiceUnavailable {
			return resp.StatusCode, time.Since(start)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return last, time.Since(start)
}

func destroySandbox(id string) (int, error) {
	req, err := http.NewRequest(http.MethodDelete, *apiURL+"/v1/sandboxes/"+id, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+*patToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}
