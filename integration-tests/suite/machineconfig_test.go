package suite

import (
	"os"
	"path/filepath"
	"testing"
)

// The benchmark scenarios declare worker nodes with multi-line bodies that span
// an `extra_user_data` heredoc. The original single-line-only parser produced an
// empty Nodes list for them, so the flagship report stamped the default
// instance (m6i.large) instead of the c5.metal workers the numbers ran on. This
// test pins the multi-line + heredoc + single-line parse so that regression
// can't come back.
func TestParseMachineConfigMultiline(t *testing.T) {
	const tf = `
default_instance_type = "m6i.large"

caddy_shared_cert_storage = {
  enabled = true
}

nodes = {
  server-1 = {
    role = "server", spot = false
    instance_type = "t3.medium", volume_size_gb = 20
  }
  ingress-1 = { role = "ingress", spot = false, instance_type = "m6i.large" }
  worker-f = {
    role          = "worker"
    instance_type = "c5.metal", volume_size_gb = 80
    with_firecracker = true
    extra_user_data = <<-EOT
      #!/bin/bash
      # a brace { and a decoy: instance_type = "t3.nano"
      echo "SB_HOST_RUNTIMES=docker,gvisor" }
    EOT
  }
  worker-g = {
    role          = "worker"
    instance_type = "c5.metal"
    with_gvisor   = true
  }
}
`
	mc := parseMachineConfig([]byte(tf), "test.tfvars")

	if mc.DefaultInstance != "m6i.large" {
		t.Errorf("DefaultInstance = %q, want m6i.large", mc.DefaultInstance)
	}
	if len(mc.Nodes) != 4 {
		t.Fatalf("parsed %d nodes, want 4: %+v", len(mc.Nodes), mc.Nodes)
	}

	byName := map[string]nodeSpec{}
	for _, n := range mc.Nodes {
		byName[n.Name] = n
	}

	// The whole point: the metal worker's real instance type is captured, and the
	// heredoc decoy (`instance_type = "t3.nano"`) inside extra_user_data is NOT.
	if got := byName["worker-f"].InstanceType; got != "c5.metal" {
		t.Errorf("worker-f instance_type = %q, want c5.metal (heredoc decoy leaked?)", got)
	}
	if got := byName["worker-f"].Extras; got != "with_firecracker" {
		t.Errorf("worker-f extras = %q, want with_firecracker", got)
	}
	if got := byName["worker-g"].Extras; got != "with_gvisor" {
		t.Errorf("worker-g extras = %q, want with_gvisor", got)
	}
	// Single-line node still parses.
	if got := byName["ingress-1"].InstanceType; got != "m6i.large" {
		t.Errorf("ingress-1 instance_type = %q, want m6i.large", got)
	}
	if got := byName["ingress-1"].Role; got != "ingress" {
		t.Errorf("ingress-1 role = %q, want ingress", got)
	}
	// Server node body parses across lines.
	if got := byName["server-1"].InstanceType; got != "t3.medium" {
		t.Errorf("server-1 instance_type = %q, want t3.medium", got)
	}
}

// TestParseMachineConfigRealScenarios parses the actual benchmark scenario
// tfvars so a future reformat that the parser can't read is caught offline —
// the hetero flagship's headline hardware must resolve to c5.metal, never the
// m6i.large default.
func TestParseMachineConfigRealScenarios(t *testing.T) {
	hetero := filepath.Join("..", "scenarios", "cluster-hetero-benchmark-with-obs.tfvars")
	raw, err := os.ReadFile(hetero)
	if err != nil {
		t.Fatalf("read %s: %v", hetero, err)
	}
	mc := parseMachineConfig(raw, hetero)
	if len(mc.Nodes) == 0 {
		t.Fatal("hetero tfvars parsed zero nodes — machine stamp would be empty")
	}
	var metal, fc int
	for _, n := range mc.Nodes {
		if n.InstanceType == "c5.metal" {
			metal++
		}
		if n.Extras == "with_firecracker" || n.Extras == "with_gvisor,with_firecracker" {
			fc++
		}
	}
	if metal < 5 {
		t.Errorf("hetero: %d c5.metal workers parsed, want >=5 (CM-4 headline hardware)", metal)
	}
	if fc < 1 {
		t.Errorf("hetero: no with_firecracker worker parsed, want the FC metal node")
	}

	mixed := filepath.Join("..", "scenarios", "cluster-mixed-benchmark-with-obs.tfvars")
	if raw, err := os.ReadFile(mixed); err == nil {
		mmc := parseMachineConfig(raw, mixed)
		if len(mmc.Nodes) == 0 {
			t.Error("mixed tfvars parsed zero nodes")
		}
		for _, n := range mmc.Nodes {
			if n.Extras == "with_firecracker" {
				t.Errorf("mixed scenario must have NO firecracker node, found %s", n.Name)
			}
		}
	}
}
