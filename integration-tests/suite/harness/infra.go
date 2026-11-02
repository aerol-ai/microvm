package harness

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
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
	// APILoadBalancer is Terraform's api_load_balancer summary: nil unless
	// the scenario was applied with api_load_balancer = "nlb" (run.sh does
	// that for the api-load-balancer capability).
	APILoadBalancer *IntegrationLoadBalancer `json:"api_load_balancer"`
}

// IntegrationLoadBalancer mirrors Terraform's api_load_balancer output.
type IntegrationLoadBalancer struct {
	// IP is the balancer's Elastic IP: the one address the domain and its
	// wildcard resolve to.
	IP      string `json:"ip"`
	DNSName string `json:"dns_name"`
	// L4Host is the name raw-TCP exposures are advertised under
	// (tcp.<domain>), which still resolves to every ingress node.
	L4Host          string `json:"l4_host"`
	HealthCheckPort int    `json:"health_check_port"`
	// TargetGroupARNs is keyed by listener port ("80", "443", "2220").
	TargetGroupARNs map[string]string `json:"target_group_arns"`
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

// IntegrationNodeForClusterID maps a cluster node ID (what placements report,
// e.g. "aerolvm-itest-cluster-3-mixed-routing-node3") to the provisioned
// node. Terraform prefixes the node's map key ("node3") with the cluster
// name, so an exact match is tried first, then the longest name the ID ends
// with after a "-". Longest wins, so "node13" never matches "node3".
func IntegrationNodeForClusterID(targets *IntegrationTargets, id string) (IntegrationNode, bool) {
	if n, ok := LookupIntegrationNode(targets, id); ok {
		return n, true
	}
	var best IntegrationNode
	if targets == nil {
		return best, false
	}
	for _, n := range targets.Nodes {
		if n.Name != "" && strings.HasSuffix(id, "-"+n.Name) && len(n.Name) > len(best.Name) {
			best = n
		}
	}
	return best, best.Name != ""
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

// awsRegionArgs returns ["--region", <region>] when a region is set in the
// environment, else nil. terraform reads its region from the var-file, not from
// AWS_*, so the aws CLI the suite shells out to has no region unless one is
// exported — run.sh exports AWS_REGION for exactly this. Passing it explicitly
// also makes a manual `go test` with AWS_REGION set work, and is harmless when
// unset (the CLI then falls back to its own config as before).
func awsRegionArgs() []string {
	for _, k := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if r := strings.TrimSpace(os.Getenv(k)); r != "" {
			return []string{"--region", r}
		}
	}
	return nil
}

// EC2InstanceState runs `aws ec2 describe-instances` for one instance id.
func EC2InstanceState(t *testing.T, instanceID string) string {
	t.Helper()
	if instanceID == "" {
		return ""
	}
	args := append([]string{"ec2", "describe-instances",
		"--instance-ids", instanceID,
		"--query", "Reservations[0].Instances[0].State.Name",
		"--output", "text",
	}, awsRegionArgs()...)
	out, err := exec.Command("aws", args...).CombinedOutput()
	if err != nil {
		t.Logf("aws describe-instances %s: %v (%s)", instanceID, err, strings.TrimSpace(string(out)))
		return ""
	}
	return strings.TrimSpace(string(out))
}

// SetKMSKeyEnabled disables or re-enables a customer-managed KMS key via the
// AWS CLI: what a customer does to revoke AerolVM's access to its key store
// (plans/customer-key-custody.md §10). Only the scenario's own key, which
// teardown schedules for deletion, may be passed here.
func SetKMSKeyEnabled(t *testing.T, keyID string, enabled bool) {
	t.Helper()
	if keyID == "" {
		t.Fatalf("empty KMS key id")
	}
	verb := "disable-key"
	if enabled {
		verb = "enable-key"
	}
	args := append([]string{"kms", verb, "--key-id", keyID}, awsRegionArgs()...)
	out, err := exec.Command("aws", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("aws kms %s %s: %v (%s)", verb, keyID, err, strings.TrimSpace(string(out)))
	}
}

// ReplaceRootVolume gives an instance a new root volume from its launch
// state (the AMI) via the AWS CLI and waits for the swap: the same machine,
// address and instance id with a fresh OS disk, so cloud-init runs the
// node's bootstrap again as on first boot. Everything on the old disk is
// deleted with it.
func ReplaceRootVolume(t *testing.T, instanceID string, timeout time.Duration) {
	t.Helper()
	if instanceID == "" {
		t.Fatalf("empty instance id")
	}
	args := append([]string{"ec2", "create-replace-root-volume-task", "--instance-id", instanceID,
		"--delete-replaced-root-volume", "--query", "ReplaceRootVolumeTask.ReplaceRootVolumeTaskId", "--output", "text"}, awsRegionArgs()...)
	out, err := exec.Command("aws", args...).CombinedOutput()
	task := strings.TrimSpace(string(out))
	if err != nil || task == "" {
		t.Fatalf("aws ec2 create-replace-root-volume-task %s: %v (%s)", instanceID, err, task)
	}
	deadline := time.Now().Add(timeout)
	for {
		args := append([]string{"ec2", "describe-replace-root-volume-tasks", "--replace-root-volume-task-ids", task,
			"--query", "ReplaceRootVolumeTasks[0].TaskState", "--output", "text"}, awsRegionArgs()...)
		out, err := exec.Command("aws", args...).CombinedOutput()
		state := strings.TrimSpace(string(out))
		switch {
		case err == nil && state == "succeeded":
			return
		case err == nil && strings.HasPrefix(state, "fail"):
			t.Fatalf("replace root volume task %s on %s: %s", task, instanceID, state)
		case time.Now().After(deadline):
			t.Fatalf("replace root volume task %s on %s not done within %s (last %q, %v)", task, instanceID, timeout, state, err)
		}
		time.Sleep(10 * time.Second)
	}
}

// SetEC2InstanceRunning stops or starts an EC2 instance via the AWS CLI.
// Region/profile follow the ambient AWS_* env (run.sh exports both for the
// suite); awsRegionArgs makes the region explicit so the node-kill failover
// helpers don't fail with "You must specify a region".
func SetEC2InstanceRunning(t *testing.T, instanceID string, running bool) {
	t.Helper()
	if instanceID == "" {
		t.Fatalf("empty instance id")
	}
	verb := "stop-instances"
	if running {
		verb = "start-instances"
	}
	args := append([]string{"ec2", verb, "--instance-ids", instanceID}, awsRegionArgs()...)
	out, err := exec.Command("aws", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("aws ec2 %s %s: %v (%s)", verb, instanceID, err, strings.TrimSpace(string(out)))
	}
}
