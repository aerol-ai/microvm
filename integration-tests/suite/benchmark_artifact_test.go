//go:build integration

package suite

import "testing"

func TestMergeBenchReportsPreservesLatencyWhenDensityArrives(t *testing.T) {
	existing := benchReport{
		Latency: []latencyStats{{
			Runtime:  "docker",
			Samples:  10,
			APIp50MS: 900,
		}},
	}
	update := benchReport{
		Density: &densityStats{
			Runtime: "docker",
			Created: 200,
			Running: 200,
		},
	}

	got := mergeBenchReports(existing, update)
	if len(got.Latency) != 1 || got.Latency[0].Runtime != "docker" || got.Latency[0].APIp50MS != 900 {
		t.Fatalf("latency was not preserved: %#v", got.Latency)
	}
	if got.Density == nil || got.Density.Created != 200 || got.Density.Running != 200 {
		t.Fatalf("density was not updated: %#v", got.Density)
	}
}

func TestMissingBenchRuntimeTargetsDockerColdUsesDockerGossip(t *testing.T) {
	members := capacityView{}
	members.Members = append(members.Members, struct {
		NodeID        string `json:"node_id"`
		NodeName      string `json:"node_name"`
		Role          string `json:"role"`
		Alive         bool   `json:"alive"`
		Drained       bool   `json:"drained"`
		CapacityStale bool   `json:"capacity_stale"`
		Capacity      struct {
			CanAdmit          bool     `json:"can_admit"`
			SupportedRuntimes []string `json:"supported_runtimes"`
		} `json:"capacity"`
	}{
		Role:  "mixed",
		Alive: true,
		Capacity: struct {
			CanAdmit          bool     `json:"can_admit"`
			SupportedRuntimes []string `json:"supported_runtimes"`
		}{
			CanAdmit:          true,
			SupportedRuntimes: []string{"docker"},
		},
	})

	missing := missingBenchRuntimeTargets(members, []benchRuntimeSpec{
		{runtime: "docker"},
		{runtime: "docker-cold"},
	})
	if len(missing) != 0 {
		t.Fatalf("want no missing targets when docker is advertised, got %v", missing)
	}
}

func TestMergeBenchReportsPreservesDensityWhenLatencyArrives(t *testing.T) {
	existing := benchReport{
		Density: &densityStats{
			Runtime: "docker",
			Created: 200,
			Running: 200,
		},
	}
	update := benchReport{
		Latency: []latencyStats{{
			Runtime:  "wasm",
			Samples:  10,
			APIp50MS: 4700,
		}},
	}

	got := mergeBenchReports(existing, update)
	if got.Density == nil || got.Density.Created != 200 || got.Density.Running != 200 {
		t.Fatalf("density was not preserved: %#v", got.Density)
	}
	if len(got.Latency) != 1 || got.Latency[0].Runtime != "wasm" || got.Latency[0].APIp50MS != 4700 {
		t.Fatalf("latency was not updated: %#v", got.Latency)
	}
}
