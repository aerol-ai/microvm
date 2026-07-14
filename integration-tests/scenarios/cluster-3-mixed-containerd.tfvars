# Cluster (3× mixed) containerd-engine benchmark scenario: three nodes, each a
# Raft voter + worker + ingress. Topology is identical to cluster-3-mixed.tfvars;
# this scenario exists so the containerd engine is exercised through the FULL
# cluster path (Raft placement + cross-node forwarding + failover) — the piece
# single-node-containerd cannot cover — and so containerd benchmark artifacts are
# named cluster-3-mixed-containerd-* (parallel to cluster-3-mixed-docker-*).
#
# SB_CONTAINER_ENGINE=containerd is flipped by run.sh from the containerd-engine
# capability in the .caps.yml, NOT here (tfvars only carry AWS/topology). The
# nodes are plain: SB_NETRULES_BACKEND already defaults to netlink server-side,
# so — unlike cluster-3-mixed-docker.tfvars, which predates that default and
# forced netlink via extra_user_data — no per-node append+restart is needed, and
# the containerd numbers land on the same netlink egress backend as the docker
# baseline for an apples-to-apples comparison.
#
# AWS access (profile, region, ssh_key_name) is inherited from
# config/terraform.tfvars (chained first by run.sh). This file overrides only
# the prod-specific bits below.
cluster_name = "aerolvm-itest-cluster-3-mixed-containerd"

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
