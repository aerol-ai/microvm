# Cluster (3× mixed) Firecracker integration scenario: three nodes, each a Raft
# voter + worker + ingress, with Firecracker enabled on the seed bare-metal box.
# Topology mirrors cluster-3-mixed.tfvars except node1 is c5.metal (KVM) and
# advertises firecracker; node2/node3 stay cheap spot t3 workers for quorum and
# docker placement peers. Exercises cluster formation, leader election, placement,
# forwarding, shared Caddy cert storage, and firecracker snapshot-clone creates
# through a non-FC entry node — at lower cost than cluster-hetero.
#
# AWS access (profile, region, ssh_key_name) is inherited from
# config/terraform.tfvars (chained first by run.sh). This file overrides only
# the prod-specific bits below.
cluster_name = "aerolvm-itest-cluster-3-mixed-fc"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40
default_with_firecracker = false

# Three mixed nodes share Caddy cert storage so any ingress can serve the
# wildcard cert without re-issuing (and burning the LE budget).
caddy_shared_cert_storage = {
  enabled = true
}

nodes = {
  # Seed carries Firecracker (KVM). On-Demand only — bare metal exceeds the
  # account Spot vCPU quota (MaxSpotInstanceCountExceeded).
  node1 = {
    role              = "mixed"
    seed              = true
    instance_type     = "c5.metal"
    volume_size_gb    = 80
    with_firecracker  = true
    spot              = false
  }
  node2 = { role = "mixed", spot = true }
  node3 = { role = "mixed", spot = true }
}
