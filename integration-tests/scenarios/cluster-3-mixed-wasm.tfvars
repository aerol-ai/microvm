# Cluster (3× mixed) WASM integration scenario: three nodes, each a Raft voter +
# worker + ingress, with the WASM runtime enabled via the config overlay (see
# cluster-3-mixed-wasm.caps.yml). Topology is identical to cluster-3-mixed.tfvars;
# the only difference between the two scenarios is the `wasm` capability, which
# run.sh turns into wasm.enabled = true + staged standard modules on every node.
# Exercises cluster formation, leader election, placement, forwarding, and the
# shared Caddy cert store for wasm sandboxes — all on cheap spot t3 boxes.
#
# AWS access (profile, region, ssh_key_name) is inherited from
# config/terraform.tfvars (chained first by run.sh). This file overrides only
# the prod-specific bits below.
cluster_name = "aerolvm-itest-cluster-3-mixed-wasm"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

# Three mixed nodes share Caddy cert storage so any ingress can serve the
# wildcard cert without re-issuing (and burning the LE budget).
caddy_shared_cert_storage = {
  enabled = true
}

nodes = {
  node1 = { role = "mixed", seed = true, spot = true }
  node2 = { role = "mixed", spot = true }
  node3 = { role = "mixed", spot = true }
}
