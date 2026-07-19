//go:build integration

package suite

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

func TestUC106_GrafanaReachable(t *testing.T) {
	sc, err := harness.LoadScenario()
	if err != nil {
		t.Fatal(err)
	}
	harness.Require(t, sc, "UC-106")

	targets := harness.LoadIntegrationTargets()
	if targets == nil || targets.GrafanaURL == "" {
		t.Fatal("integration_targets.grafana_url empty — run via integration-tests/run.sh with observability cap")
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(strings.TrimRight(targets.GrafanaURL, "/") + "/api/health")
	if err != nil {
		t.Fatalf("grafana health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("grafana /api/health = %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
}

func TestUC107_PrometheusSandboxdTargetsUp(t *testing.T) {
	sc, err := harness.LoadScenario()
	if err != nil {
		t.Fatal(err)
	}
	harness.Require(t, sc, "UC-107")

	targets := harness.LoadIntegrationTargets()
	if targets == nil || targets.ObsPublicIP == "" {
		t.Fatal("integration_targets.obs_public_ip empty — run via integration-tests/run.sh with observability cap")
	}
	if len(targets.Nodes) == 0 {
		t.Fatal("integration_targets.nodes empty")
	}

	// Prometheus listens on loopback on the obs host; query via SSH.
	script := `curl -sf http://127.0.0.1:9090/api/v1/targets`
	out, err := exec.Command("ssh", append(sshHarnessOpts(), fmt.Sprintf("ubuntu@%s", targets.ObsPublicIP), script)...).CombinedOutput()
	if err != nil {
		t.Fatalf("prometheus targets query via obs ssh: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	var payload struct {
		Status string `json:"status"`
		Data   struct {
			ActiveTargets []struct {
				Labels           map[string]string `json:"labels"`
				Health           string            `json:"health"`
				LastError        string            `json:"lastError"`
				ScrapeURL        string            `json:"scrapeUrl"`
				DiscoveredLabels map[string]string `json:"discoveredLabels"`
			} `json:"activeTargets"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("decode prometheus targets: %v", err)
	}
	if payload.Status != "success" {
		t.Fatalf("prometheus targets status = %q", payload.Status)
	}

	want := len(targets.Nodes)
	var sandboxdUp int
	for _, tgt := range payload.Data.ActiveTargets {
		if tgt.Labels["job"] != "sandboxd" {
			continue
		}
		if tgt.Health == "up" {
			sandboxdUp++
			continue
		}
		t.Logf("sandboxd target not up: %s health=%s err=%s", tgt.ScrapeURL, tgt.Health, tgt.LastError)
	}
	if sandboxdUp < want {
		t.Fatalf("prometheus sandboxd targets up = %d, want >= %d (cluster nodes)", sandboxdUp, want)
	}
}

func sshHarnessOpts() []string {
	// Mirror integration-tests/lib/common.sh SSH_OPTS for harness subprocesses.
	return []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes",
	}
}
