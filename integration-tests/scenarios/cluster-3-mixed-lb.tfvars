# cluster-3-mixed behind the health-checked load balancer (UC-356): the same
# three mixed nodes, with an AWS Network Load Balancer in front of their
# ingress (Terraform api_load_balancer = "nlb"). run.sh sets that variable
# from the api-load-balancer capability in cluster-3-mixed-lb.caps.yml, the
# one switch, so it is not repeated here. The domain resolves to the
# balancer's Elastic IP; raw TCP ports to tcp.<domain>, one record per node.
#
# Everything else is cluster-3-mixed, so the whole suite also runs through
# the balancer: TLS, sandbox URLs, TLS-SNI ports, the SSH gateway and raw TCP
# on tcp.<domain>.
#
# AWS access (profile, region, ssh_key_name) is inherited from
# config/terraform.tfvars (chained first by run.sh). This file overrides only
# the prod-specific bits below.
cluster_name = "aerolvm-itest-cluster-3-mixed-lb"

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
  # Capability api-list-fairness (UC-362): a list gate small enough that one
  # tenant's storm fills its share and is told 429, while the quiet tenant's
  # 4 clients (at most 2 per node over 3 nodes) fit inside theirs. The
  # default 16 slots with 4 per tenant may never fill: a healthy list holds
  # its slot for milliseconds. UC-361's operator storm here is mostly 429.
  SB_API_LIST_MAX_INFLIGHT            = "8"
  SB_API_LIST_MAX_INFLIGHT_PER_TENANT = "2"
}

# Audit export to the scenario's S3 bucket (force_destroy, 3-day expiry), so
# `aerolvm audit search` and `aerolvm access review` run over a real export
# (UC-279). run.sh exports the bucket from the audit_export_bucket output.
audit_export_enabled = true
audit_export_backend = "s3"

nodes = {
  node1 = { role = "mixed", seed = true, spot = true }
  node2 = { role = "mixed", spot = true }
  node3 = { role = "mixed", spot = true }
}
