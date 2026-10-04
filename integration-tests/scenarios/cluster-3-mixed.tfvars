# Cluster (3× mixed) integration scenario: three nodes, each a Raft voter +
# worker + ingress. Exercises cluster formation, leader election, placement,
# forwarding, and the shared Caddy cert store — all on cheap spot t3 boxes.
#
# AWS access (profile, region, ssh_key_name) is inherited from
# config/terraform.tfvars (chained first by run.sh). This file overrides only
# the prod-specific bits below.
cluster_name = "aerolvm-itest-cluster-3-mixed"

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

# SB_MCP_ENABLED serves the remote MCP endpoint at /mcp (UC-178, capability
# remote-mcp). extra_user_data runs after the bootstrap env-write + sandboxd
# start, so it's append-and-restart; the restart lands during cloud-init,
# before run.sh waits for 3 gossip members. tfvars are literal-only, hence
# the per-node repetition.
nodes = {
  node1 = {
    role            = "mixed", seed = true, spot = true
    extra_user_data = <<-EOT
      echo 'SB_MCP_ENABLED=true' | sudo tee -a /etc/sandboxd/cluster.env >/dev/null
      sudo systemctl restart sandboxd
    EOT
  }
  node2 = {
    role            = "mixed", spot = true
    extra_user_data = <<-EOT
      echo 'SB_MCP_ENABLED=true' | sudo tee -a /etc/sandboxd/cluster.env >/dev/null
      sudo systemctl restart sandboxd
    EOT
  }
  node3 = {
    role            = "mixed", spot = true
    extra_user_data = <<-EOT
      echo 'SB_MCP_ENABLED=true' | sudo tee -a /etc/sandboxd/cluster.env >/dev/null
      sudo systemctl restart sandboxd
    EOT
  }
}
