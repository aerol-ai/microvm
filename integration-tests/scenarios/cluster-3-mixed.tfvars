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

# Serve the remote MCP endpoint at /mcp on every node (UC-178, capability
# remote-mcp). extra_sandboxd_env lands in cluster.env before the bootstrap's
# final sandboxd restart, so no extra restart is needed.
extra_sandboxd_env = {
  SB_MCP_ENABLED = "true"
  # Identity and access (T12): named credentials on, and the identity file
  # the suite installs on every node (see single-node.tfvars).
  SB_IDENTITY_ENABLED = "true"
  SB_IDENTITY_FILE    = "/etc/sandboxd/itest-identity.yaml"
}

# Audit export to the scenario's S3 bucket (force_destroy, 3-day expiry), so
# `aerolvm audit search` and `aerolvm access review` run over a real export
# (UC-279). run.sh exports the bucket from the audit_export_bucket output.
audit_export_enabled = true
audit_export_backend = "s3"

# Each node declares its own zone and a label naming it, so the placement
# rule cases (UC-438..440) can tell the nodes apart. A create without a rule
# places exactly as before.
nodes = {
  node1 = { role = "mixed", seed = true, spot = true, sandboxd_env = { SB_NODE_ZONE = "itest-zone-a", SB_NODE_LABELS = "itest-node=node1" } }
  node2 = { role = "mixed", spot = true, sandboxd_env = { SB_NODE_ZONE = "itest-zone-b", SB_NODE_LABELS = "itest-node=node2" } }
  node3 = { role = "mixed", spot = true, sandboxd_env = { SB_NODE_ZONE = "itest-zone-c", SB_NODE_LABELS = "itest-node=node3" } }
}

# Sandbox cloud identity (plans/sandbox-cloud-identity.md, UC-431..437):
# every node is an OIDC issuer at https://<domain> (capability
# cloud-identity).
identity_issuer_enabled = true
