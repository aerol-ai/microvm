# Cluster (3× mixed) docker benchmark scenario: three nodes, each a Raft voter +
# worker + ingress. Topology is identical to cluster-3-mixed.tfvars; this
# scenario exists for docker-only benchmark naming (cluster-3-mixed-docker-*).
#
# AWS access (profile, region, ssh_key_name) is inherited from
# config/terraform.tfvars (chained first by run.sh). This file overrides only
# the prod-specific bits below.
cluster_name = "aerolvm-itest-cluster-3-mixed-docker"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

caddy_shared_cert_storage = {
  enabled = true
}

# T4 bench run (plans/warm-create-latency-tier1.md §8): Phase 1 gates require
# SB_NETRULES_BACKEND=netlink on every node. extra_user_data runs after the
# bootstrap template's env-write + sandboxd restart, so append-and-restart is
# the supported hook. tfvars are literal-only, hence the per-node repetition.
# Remove for exec-baseline runs.
nodes = {
  node1 = {
    role            = "mixed", seed = true, spot = true
    extra_user_data = <<-EOT
      echo 'SB_NETRULES_BACKEND=netlink' | sudo tee -a /etc/sandboxd/cluster.env >/dev/null
      sudo systemctl restart sandboxd
    EOT
  }
  node2 = {
    role            = "mixed", spot = true
    extra_user_data = <<-EOT
      echo 'SB_NETRULES_BACKEND=netlink' | sudo tee -a /etc/sandboxd/cluster.env >/dev/null
      sudo systemctl restart sandboxd
    EOT
  }
  node3 = {
    role            = "mixed", spot = true
    extra_user_data = <<-EOT
      echo 'SB_NETRULES_BACKEND=netlink' | sudo tee -a /etc/sandboxd/cluster.env >/dev/null
      sudo systemctl restart sandboxd
    EOT
  }
}
