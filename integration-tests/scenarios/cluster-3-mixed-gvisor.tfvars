# Cluster (3× mixed) gVisor integration scenario: three nodes, each a Raft voter +
# worker + ingress, with gVisor (runsc) enabled on every node. Topology mirrors
# cluster-3-mixed.tfvars except default_with_gvisor=true so any mixed node can
# place gvisor sandboxes. Exercises cluster formation, leader election,
# placement, forwarding, and the shared Caddy cert store — all on cheap spot t3
# boxes.
#
# Engine: containerd (the harness default — no docker-engine cap), so runtime
# "gvisor" is served by the native containerd driver via the
# io.containerd.runsc.v1 shim. The docker-engine A/B twin is
# cluster-3-mixed-gvisor-docker.tfvars.
#
# AWS access (profile, region, ssh_key_name) is inherited from
# config/terraform.tfvars (chained first by run.sh). This file overrides only
# the prod-specific bits below.
cluster_name = "aerolvm-itest-cluster-3-mixed-gvisor"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40
default_with_gvisor    = true

# Three mixed nodes share Caddy cert storage so any ingress can serve the
# wildcard cert without re-issuing (and burning the LE budget).
caddy_shared_cert_storage = {
  enabled = true
}

# install.sh --with-gvisor installs runsc and containerd-shim-runsc-v1 from
# gVisor's release tarball (scripts/install.sh install_runsc_shim), so the
# nodes need no extra_user_data. gVisor stopped publishing the bare binaries
# under releases/release/latest on 2026-09-30, which broke the old per-node
# download.
nodes = {
  node1 = {
    role = "mixed", seed = true, spot = true
  }
  node2 = {
    role = "mixed", spot = true
  }
  node3 = {
    role = "mixed", spot = true
  }
}
