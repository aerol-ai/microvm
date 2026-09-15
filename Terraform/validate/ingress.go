package validate

import "strings"

// MaxReplicatedIngressRouteNodes mirrors internal/cluster.MaxReplicatedIngressRouteNodes:
// the largest ingress tier where every ingress-capable node holds the full
// public route table, so a router that picks any ingress node for any sandbox
// (DNS round-robin, a cloud TCP LB, a BGP VIP) is correct. Above it the daemon
// fails closed unless SB_CLUSTER_SHARD_AWARE_INGRESS declares a router that
// resolves owners through /v1/cluster/ingress-route/{id}. Keep in step with
// the Go constant and the precondition in Terraform/nodes.tf.
const MaxReplicatedIngressRouteNodes = 10

// IngressCapable mirrors locals.tf ingress_node_names: a role set containing
// "ingress", or the "mixed" shorthand, serves public ingress.
func IngressCapable(role string) bool {
	role = strings.ReplaceAll(strings.TrimSpace(role), " ", "")
	if role == "" || role == "mixed" {
		return true // mixed is the default role
	}
	for _, tok := range strings.Split(role, ",") {
		if tok == "ingress" || tok == "mixed" {
			return true
		}
	}
	return false
}

// IngressTierAllowed mirrors the nodes.tf precondition: more than
// MaxReplicatedIngressRouteNodes ingress-capable nodes need the operator's
// shard_aware_ingress declaration, or the daemon refuses the topology at boot.
func IngressTierAllowed(roles map[string]string, shardAwareIngress bool) bool {
	count := 0
	for _, role := range roles {
		if IngressCapable(role) {
			count++
		}
	}
	return count <= MaxReplicatedIngressRouteNodes || shardAwareIngress
}
