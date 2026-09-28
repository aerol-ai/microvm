package safety

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// ingressPreconditionRe matches the condition of the ingress-tier
// precondition in Terraform/nodes.tf.
var ingressPreconditionRe = regexp.MustCompile(
	`condition\s*=\s*length\(local\.ingress_node_names\)\s*<=\s*(\d+)\s*\|\|\s*var\.shard_aware_ingress`)

// The Terraform ingress gate hardcodes a node count; the daemon's refusal
// comes from a Go constant. If the constant moves and the literal does not,
// Terraform happily provisions a tier the daemon then rejects — the fleet
// gets built and does not serve.
//
// This lives in make test rather than only in UC-162's live arm because it
// costs nothing and the drift it catches is introduced at commit time, not
// at deploy time. Terraform/validate/ingress.go has no caller outside its own
// unit test, so nothing else connects the two numbers.
func TestTerraformIngressGateMatchesTheDaemonConstant(t *testing.T) {
	path := filepath.Join("..", "..", "Terraform", "nodes.tf")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	m := ingressPreconditionRe.FindStringSubmatch(string(b))
	if m == nil {
		t.Fatalf("no ingress-tier precondition found in %s. The gate that stops an operator provisioning a tier the daemon rejects is gone.", path)
	}
	limit, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("unparsable ingress limit %q: %v", m[1], err)
	}
	if limit != cluster.MaxReplicatedIngressRouteNodes {
		t.Fatalf("Terraform allows %d ingress-capable nodes but cluster.MaxReplicatedIngressRouteNodes is %d. Terraform would provision a tier the daemon refuses to serve.",
			limit, cluster.MaxReplicatedIngressRouteNodes)
	}
	if !strings.Contains(m[0], "var.shard_aware_ingress") {
		t.Fatalf("the ingress precondition has no shard_aware_ingress escape hatch: %q. A gate with no documented way past it gets deleted by whoever hits it.", m[0])
	}
}
