package harness

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// IntegrationNode is one row from Terraform's integration_targets.nodes output.
type IntegrationNode struct {
	Name       string `json:"name"`
	Role       string `json:"role"`
	Seed       bool   `json:"seed"`
	PublicIP   string `json:"public_ip"`
	PrivateIP  string `json:"private_ip"`
	InstanceID string `json:"instance_id"`
	Spot       bool   `json:"spot"`
}

// IntegrationTargets mirrors Terraform output integration_targets.
type IntegrationTargets struct {
	BaseURL        string            `json:"base_url"`
	Domain         string            `json:"domain"`
	IngressIP      string            `json:"ingress_ip"`
	SeedIP         string            `json:"seed_ip"`
	Nodes          []IntegrationNode `json:"nodes"`
	GrafanaURL     string            `json:"grafana_url"`
	PushgatewayURL string            `json:"pushgateway_url"`
	ObsPublicIP    string            `json:"obs_public_ip"`
	ObsPrivateIP   string            `json:"obs_private_ip"`
}

// LoadIntegrationTargets parses AEROL_INTEGRATION_TARGETS (JSON from run.sh).
// Returns nil when unset — disruptive infra helpers skip in that case.
func LoadIntegrationTargets() *IntegrationTargets {
	raw := strings.TrimSpace(os.Getenv("AEROL_INTEGRATION_TARGETS"))
	if raw == "" {
		return nil
	}
	var t IntegrationTargets
	if err := json.Unmarshal([]byte(raw), &t); err != nil {
		return nil
	}
	return &t
}

// LookupIntegrationNode finds a provisioned node by terraform name (node_id).
func LookupIntegrationNode(targets *IntegrationTargets, name string) (IntegrationNode, bool) {
	if targets == nil {
		return IntegrationNode{}, false
	}
	for _, n := range targets.Nodes {
		if n.Name == name {
			return n, true
		}
	}
	return IntegrationNode{}, false
}

// EC2InstanceState runs `aws ec2 describe-instances` for one instance id.
func EC2InstanceState(t *testing.T, instanceID string) string {
	t.Helper()
	if instanceID == "" {
		return ""
	}
	out, err := exec.Command("aws", "ec2", "describe-instances",
		"--instance-ids", instanceID,
		"--query", "Reservations[0].Instances[0].State.Name",
		"--output", "text",
	).CombinedOutput()
	if err != nil {
		t.Logf("aws describe-instances %s: %v (%s)", instanceID, err, strings.TrimSpace(string(out)))
		return ""
	}
	return strings.TrimSpace(string(out))
}

// SetEC2InstanceRunning stops or starts an EC2 instance via the AWS CLI.
// region/profile follow the ambient AWS_* env (same as terraform apply).
func SetEC2InstanceRunning(t *testing.T, instanceID string, running bool) {
	t.Helper()
	if instanceID == "" {
		t.Fatalf("empty instance id")
	}
	verb := "stop-instances"
	if running {
		verb = "start-instances"
	}
	out, err := exec.Command("aws", "ec2", verb, "--instance-ids", instanceID).CombinedOutput()
	if err != nil {
		t.Fatalf("aws ec2 %s %s: %v (%s)", verb, instanceID, err, strings.TrimSpace(string(out)))
	}
}
